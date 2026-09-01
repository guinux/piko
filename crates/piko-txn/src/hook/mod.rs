//! Transaction hooks: `.hook` files that run a command before or after a transaction.
//!
//! This module splits `_alpm_hook_run` (`hook.c:528`) into three parts, matching the rest of
//! the crate. [`parse`] turns a file into a value. [`trigger`] answers one question: does this
//! transaction set the hook off. This module touches the disk and starts the process.
//!
//! # Hook files come from the host; the command runs inside the root
//!
//! This asymmetry is real and worth stating up front. `pacman-conf --root=/mnt DBPath` answers
//! `/mnt/var/lib/pacman/`. `pacman-conf --root=/mnt HookDir` answers `/etc/pacman.d/hooks/` —
//! measured on a real system. libalpm reads `handle->hookdirs` with a plain `opendir` and no
//! root prefix (`hook.c:550`), then runs the command through `_alpm_run_chroot`. piko matches
//! this: [`Hooks::collect`] reads ordinary host paths, and [`run`] executes inside the root.
//!
//! A hook file is trusted host configuration. The program it names is not necessarily present.
//! `Exec = /usr/bin/locale-gen` must exist *inside* `--root`. A hook whose command is missing
//! there reports "could not be started" instead of failing the transaction.
//!
//! # Priority and overriding
//!
//! Directories are searched **last to first**. A hook file name already seen is skipped. So a
//! later entry in `HookDir` wins. This is why pacman's default list puts the system directory
//! first and `/etc/pacman.d/hooks/` after it. `alpm-hooks(5)` documents disabling a hook by
//! shadowing it with a symlink to `/dev/null`. That arrives here as an empty file. It parses
//! into an inert hook that still occupies the name — see [`parse`].
//!
//! Hooks run in order of their file name, **excluding the `.hook` suffix** (`_alpm_hook_cmp`,
//! `hook.c:439`). Ordering applies across all directories at once, not per directory.

pub mod parse;
pub mod trigger;
pub mod wordsplit;

use std::path::{Path, PathBuf};

use piko_db::LocalDatabase;

use crate::{
    error::Result,
    exec::{Command, Outcome, Runner},
};

pub use parse::{Hook, ParseError, TriggerKind, When};
pub use trigger::Summary;

/// The suffix a hook file must have.
const HOOK_SUFFIX: &str = ".hook";

/// pacman's built-in hook directory. `pacman.conf` never names it.
///
/// `alpm-hooks(5)` says hooks are read from "the system hook directory /usr/share/libalpm/hooks,
/// **and** additional custom directories specified in pacman.conf(5)". It is compiled into
/// libalpm, not configured. `pacman-conf HookDir` prints only `/etc/pacman.d/hooks/`, but a
/// real Arch system's actual hooks mostly live here. A caller that reads only `HookDir` would
/// silently run none of them. This constant lives next to [`Hooks::collect`], not in a
/// frontend, so every caller building a directory list gets it, not only this crate's own CLI.
pub const SYSTEM_HOOK_DIR: &str = "/usr/share/libalpm/hooks";

/// Largest `.hook` file piko reads, from [`piko_db::Limits`].
///
/// Every package that ships a hook writes into this directory. piko did not choose the file,
/// so an unbounded read would be an unbounded allocation.
fn max_hook_bytes() -> u64 {
    piko_db::Limits::default().get(piko_db::Limit::Hook)
}

/// Something that stopped one hook file being used.
///
/// Returned, not logged, like every other diagnostic in the workspace. libalpm makes a parse
/// failure fatal for `PreTransaction` and merely noisy for `PostTransaction` (`hook.c:625`).
/// Reproducing that decision is the caller's job. This type carries the fact; it does not act
/// on it.
#[derive(Clone, Debug, thiserror::Error)]
pub enum Problem {
    /// A hook directory could not be read. A missing directory is not a problem; it is skipped.
    #[error("could not read the hook directory {}: {reason}", path.display())]
    UnreadableDirectory {
        /// The directory.
        path: PathBuf,
        /// Why it could not be read.
        reason: String,
    },
    /// A `.hook` file could not be read.
    #[error("could not read the hook {}: {reason}", path.display())]
    UnreadableHook {
        /// The file.
        path: PathBuf,
        /// Why it could not be read.
        reason: String,
    },
    /// A `.hook` file did not parse.
    #[error("{0}")]
    Invalid(#[from] ParseError),
}

/// Every hook found, in the order they will run.
#[derive(Debug, Default)]
pub struct Hooks {
    hooks: Vec<Hook>,
}

impl Hooks {
    /// Reads every `.hook` in `directories`, in `pacman.conf` order.
    ///
    /// Returns what parsed and, separately, everything that did not. A single bad hook file
    /// does not hide the rest. This matches libalpm's behavior, and it is the only useful
    /// choice when a package drops the file there.
    #[must_use]
    pub fn collect(directories: &[PathBuf]) -> (Self, Vec<Problem>) {
        let mut hooks: Vec<Hook> = Vec::new();
        let mut problems = Vec::new();

        // Last to first: a later directory overrides an earlier one of the same file name.
        for directory in directories.iter().rev() {
            let entries = match read_directory(directory) {
                Ok(entries) => entries,
                Err(None) => continue,
                Err(Some(problem)) => {
                    problems.push(problem);
                    continue;
                }
            };

            for name in entries {
                if !name.ends_with(HOOK_SUFFIX) {
                    continue;
                }
                if hooks.iter().any(|hook| hook.name == name) {
                    // Already provided by a higher-priority directory.
                    continue;
                }
                let path = directory.join(&name);
                match read_hook(&path, &name) {
                    Ok(Some(hook)) => hooks.push(hook),
                    // A directory named `something.hook`. libalpm skips it silently.
                    Ok(None) => {}
                    Err(problem) => problems.push(problem),
                }
            }
        }

        // `_alpm_hook_cmp` compares names with the suffix excluded. So `10-a.hook` sorts before
        // `10-a-b.hook`, the way `10-a` sorts before `10-a-b`. Comparing the whole file name
        // would put the suffix's `.` in the way. This sort is stable, matching `alpm_list_msort`.
        hooks.sort_by(|left, right| stem(&left.name).cmp(stem(&right.name)));

        (Self { hooks }, problems)
    }

    /// Every hook, in the order they will run.
    #[must_use]
    pub fn all(&self) -> &[Hook] {
        &self.hooks
    }

    /// The hooks that `summary` sets off at `when`, each with the targets it matched.
    ///
    /// A masking hook has no `When`. It is never selected, regardless of the transaction.
    #[must_use]
    pub fn triggered(&self, when: When, summary: &Summary) -> Vec<(&Hook, Vec<String>)> {
        self.hooks
            .iter()
            .filter(|hook| hook.when == Some(when) && hook.is_active())
            .filter_map(|hook| trigger::triggered(hook, summary).map(|targets| (hook, targets)))
            .collect()
    }
}

/// A hook file name without its `.hook` suffix.
fn stem(name: &str) -> &str {
    name.strip_suffix(HOOK_SUFFIX).unwrap_or(name)
}

/// The file names in `directory`, sorted.
///
/// Returns `Err(None)` when the directory is simply not there. That is ordinary:
/// `/etc/pacman.d/hooks` does not exist until someone puts a hook in it.
fn read_directory(directory: &Path) -> std::result::Result<Vec<String>, Option<Problem>> {
    let reader = match std::fs::read_dir(directory) {
        Ok(reader) => reader,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err(None),
        Err(error) => {
            return Err(Some(Problem::UnreadableDirectory {
                path: directory.to_path_buf(),
                reason: error.to_string(),
            }));
        }
    };

    let mut names = Vec::new();
    for entry in reader {
        match entry {
            // A non-UTF-8 name cannot be a `.hook` under any encoding piko compares. It is
            // skipped, the same way a `.txt` file would be.
            Ok(entry) => names.extend(entry.file_name().to_str().map(str::to_owned)),
            Err(error) => {
                return Err(Some(Problem::UnreadableDirectory {
                    path: directory.to_path_buf(),
                    reason: error.to_string(),
                }));
            }
        }
    }
    // `readdir` order depends on the filesystem. Sorting here makes `collect` produce the same
    // list on the same input twice. The ordering below then refines it.
    names.sort();
    Ok(names)
}

/// Reads and parses one hook file, or returns `Ok(None)` for a directory.
///
/// # Why a symlink is followed, and why a device is empty rather than an error
///
/// `alpm-hooks(5)` says to disable a hook by shadowing it with **a symlink to `/dev/null`**.
/// Two of piko's usual protections stand in the way of that. Both are handled, not dropped:
///
/// - The read goes through [`piko_db::fs_util::read_capped_utf8_following`], the door that
///   resolves a final symlink. It is the same door repository archives use, instead of the
///   `O_NOFOLLOW` one the local database uses. A hook directory is host configuration named by
///   `pacman.conf`, not a package-controlled directory of entries.
/// - `/dev/null` is a character device, which that door still refuses. Rather than loosen the
///   check, a non-regular file is treated as **empty**. That parses into an inert masking
///   hook — exactly what reading `/dev/null` would have produced. It also means a FIFO planted
///   in a hook directory becomes inert, instead of blocking piko forever. libalpm's plain
///   `fopen` would hang there until a writer appeared.
fn read_hook(path: &Path, name: &str) -> std::result::Result<Option<Hook>, Problem> {
    match piko_db::fs_util::is_real_directory(path) {
        Ok(true) => return Ok(None),
        Ok(false) => {}
        Err(error) => {
            return Err(Problem::UnreadableHook {
                path: path.to_path_buf(),
                reason: error.to_string(),
            });
        }
    }

    let text = match piko_db::fs_util::read_capped_utf8_following(
        path,
        piko_db::Limit::Hook,
        max_hook_bytes(),
    ) {
        Ok(text) => text,
        Err(piko_db::Error::NotARegularFile { .. }) => String::new(),
        Err(error) => {
            return Err(Problem::UnreadableHook {
                path: path.to_path_buf(),
                reason: error.to_string(),
            });
        }
    };

    Ok(Some(parse::parse(name, &text)?))
}

/// What running one hook produced.
#[derive(Clone, Debug)]
pub struct Run {
    /// The hook's file name.
    pub name: String,
    /// Its `Description`, if it had one.
    pub description: Option<String>,
    /// How the command ended, or `None` if a `Depends` was not satisfied and it never ran.
    pub outcome: Option<Outcome>,
    /// The unsatisfied `Depends` entry, when there was one.
    pub unsatisfied: Option<String>,
    /// Whether this failure should stop the transaction.
    ///
    /// True only for a `PreTransaction` hook with `AbortOnFail` that did not succeed. libalpm
    /// warns when `AbortOnFail` appears on a `PostTransaction` hook, then ignores it. By then,
    /// nothing is left to abort.
    pub fatal: bool,
}

impl Run {
    /// Whether the hook ran and succeeded.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.outcome.as_ref().is_some_and(Outcome::succeeded)
    }
}

/// Runs one hook. The caller must already have established that it is triggered.
///
/// `targets` is fed to the command on stdin, one per line, when the hook sets `NeedsTargets`.
///
/// `on_line` is called with each line of the hook's merged stdout/stderr as it is produced —
/// see [`crate::exec::Runner::run`].
///
/// # Errors
///
/// Returns [`crate::Error`] only for a failure on piko's side. A hook whose `Depends` is
/// unsatisfied, whose command is missing, or which exits non-zero all come back as a [`Run`].
pub fn run(
    runner: &Runner,
    local: &LocalDatabase,
    hook: &Hook,
    targets: &[String],
    on_line: &mut dyn FnMut(&str),
) -> Result<Run> {
    let mut record = Run {
        name: hook.name.clone(),
        description: hook.description.clone(),
        outcome: None,
        unsatisfied: None,
        fatal: false,
    };

    if let Some(missing) = unsatisfied_dependency(local, hook) {
        record.unsatisfied = Some(missing);
        record.fatal = hook.abort_on_fail && hook.when == Some(When::PreTransaction);
        return Ok(record);
    }

    let Some((program, arguments)) = hook.exec.split_first() else {
        // `is_active` already excluded this; treating it as "nothing to run" rather than
        // panicking keeps the invariant local.
        return Ok(record);
    };

    let mut command = Command::new(PathBuf::from(program));
    for argument in arguments {
        command = command.arg(argument.clone());
    }
    if hook.needs_targets {
        // One per line, exactly as `_alpm_hook_feed_targets` writes them (`hook.c:465`).
        let mut payload = Vec::new();
        for target in targets {
            payload.extend_from_slice(target.as_bytes());
            payload.push(b'\n');
        }
        command = command.stdin(payload);
    }

    let outcome = runner.run(&command, on_line)?;
    record.fatal =
        !outcome.succeeded() && hook.abort_on_fail && hook.when == Some(When::PreTransaction);
    record.outcome = Some(outcome);
    Ok(record)
}

/// The first `Depends` entry no installed package satisfies.
///
/// A `Depends` line piko cannot parse counts as unsatisfied: libalpm's `alpm_find_satisfier`
/// returns nothing for an unparseable dependency string too, and running a hook whose stated
/// requirement could not even be understood is not the safe direction.
fn unsatisfied_dependency(local: &LocalDatabase, hook: &Hook) -> Option<String> {
    hook.depends
        .iter()
        .find(|entry| {
            let Ok(relation) = entry.parse::<alpm_types::PackageRelation>() else {
                return true;
            };
            !matches!(piko_db::resolve::installed_satisfier(local, &relation), Ok(Some(_)))
        })
        .cloned()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    const BODY: &str = "\
[Trigger]
Operation = Install
Type = Package
Target = *

[Action]
When = PostTransaction
Exec = /bin/true
";

    fn write(dir: &Path, name: &str, text: &str) {
        std::fs::write(dir.join(name), text).unwrap();
    }

    #[test]
    fn only_dot_hook_files_are_read() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.hook", BODY);
        write(dir.path(), "notes.txt", "nonsense");
        write(dir.path(), "hook", BODY);

        let (hooks, problems) = Hooks::collect(&[dir.path().to_path_buf()]);
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(hooks.all().len(), 1);
        assert_eq!(hooks.all().first().unwrap().name, "a.hook");
    }

    /// Ordering ignores the suffix, so `10-a` sorts before `10-a-b` — comparing whole file
    /// names would put `.` (0x2e) against `-` (0x2d) and reverse them.
    #[test]
    fn hooks_are_ordered_by_name_without_the_suffix() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["20-z.hook", "10-a-b.hook", "10-a.hook", "05-first.hook"] {
            write(dir.path(), name, BODY);
        }

        let (hooks, _) = Hooks::collect(&[dir.path().to_path_buf()]);
        let names: Vec<&str> = hooks.all().iter().map(|hook| hook.name.as_str()).collect();
        assert_eq!(names, ["05-first.hook", "10-a.hook", "10-a-b.hook", "20-z.hook"]);
    }

    /// A later directory wins, which is what makes `/etc/pacman.d/hooks` able to override the
    /// system directory.
    #[test]
    fn a_later_directory_overrides_an_earlier_one() {
        let system = tempfile::tempdir().unwrap();
        let custom = tempfile::tempdir().unwrap();
        write(system.path(), "same.hook", &BODY.replace("/bin/true", "/bin/system"));
        write(custom.path(), "same.hook", &BODY.replace("/bin/true", "/bin/custom"));

        let (hooks, _) =
            Hooks::collect(&[system.path().to_path_buf(), custom.path().to_path_buf()]);
        assert_eq!(hooks.all().len(), 1, "both copies were loaded");
        assert_eq!(
            hooks.all().first().unwrap().exec.first().unwrap(),
            std::ffi::OsStr::new("/bin/custom")
        );
    }

    /// The documented way to switch a hook off. It must load (so it occupies the name) and
    /// never fire.
    #[test]
    fn an_empty_override_masks_a_lower_priority_hook() {
        let system = tempfile::tempdir().unwrap();
        let custom = tempfile::tempdir().unwrap();
        write(system.path(), "noisy.hook", BODY);
        write(custom.path(), "noisy.hook", "");

        let (hooks, problems) =
            Hooks::collect(&[system.path().to_path_buf(), custom.path().to_path_buf()]);
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(hooks.all().len(), 1);

        let summary = Summary {
            added: vec![trigger::Added {
                name: "anything".to_owned(),
                ..trigger::Added::default()
            }],
            ..Summary::default()
        };
        assert!(
            hooks.triggered(When::PostTransaction, &summary).is_empty(),
            "the masked hook still fired"
        );
    }

    /// A symlink to `/dev/null` is the spelling `alpm-hooks(5)` actually gives, so the reader
    /// has to follow a final symlink.
    #[test]
    fn a_symlink_to_dev_null_masks_a_hook() {
        let system = tempfile::tempdir().unwrap();
        let custom = tempfile::tempdir().unwrap();
        write(system.path(), "noisy.hook", BODY);
        std::os::unix::fs::symlink("/dev/null", custom.path().join("noisy.hook")).unwrap();

        let (hooks, problems) =
            Hooks::collect(&[system.path().to_path_buf(), custom.path().to_path_buf()]);
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(hooks.all().len(), 1);
        assert!(!hooks.all().first().unwrap().is_active());
    }

    /// A missing directory is ordinary — `/etc/pacman.d/hooks` does not exist by default.
    #[test]
    fn a_missing_directory_is_not_a_problem() {
        let (hooks, problems) = Hooks::collect(&[PathBuf::from("/nonexistent/hooks")]);
        assert!(problems.is_empty(), "{problems:?}");
        assert!(hooks.all().is_empty());
    }

    /// One unparseable file must not hide the ones that are fine.
    #[test]
    fn a_broken_hook_is_reported_and_the_rest_still_load() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "good.hook", BODY);
        write(dir.path(), "bad.hook", "[Nonsense]\n");

        let (hooks, problems) = Hooks::collect(&[dir.path().to_path_buf()]);
        assert_eq!(hooks.all().len(), 1);
        assert_eq!(problems.len(), 1);
        assert!(problems.first().unwrap().to_string().contains("bad.hook"), "{problems:?}");
    }

    #[test]
    fn a_directory_named_like_a_hook_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("subdir.hook")).unwrap();
        write(dir.path(), "real.hook", BODY);

        let (hooks, problems) = Hooks::collect(&[dir.path().to_path_buf()]);
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(hooks.all().len(), 1);
    }

    /// The `When` filter is what keeps a `PreTransaction` hook out of the post pass.
    #[test]
    fn only_hooks_for_the_requested_phase_are_selected() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "post.hook", BODY);
        write(dir.path(), "pre.hook", &BODY.replace("PostTransaction", "PreTransaction"));

        let (hooks, _) = Hooks::collect(&[dir.path().to_path_buf()]);
        let summary = Summary {
            added: vec![trigger::Added { name: "x".to_owned(), ..trigger::Added::default() }],
            ..Summary::default()
        };

        let pre = hooks.triggered(When::PreTransaction, &summary);
        assert_eq!(pre.len(), 1);
        assert_eq!(pre.first().unwrap().0.name, "pre.hook");

        let post = hooks.triggered(When::PostTransaction, &summary);
        assert_eq!(post.len(), 1);
        assert_eq!(post.first().unwrap().0.name, "post.hook");
    }
}
