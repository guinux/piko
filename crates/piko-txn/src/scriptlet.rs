//! Runs a package's `.INSTALL` scriptlet.
//!
//! A package may ship a shell file defining up to six functions. libalpm sources that file and
//! calls one of them at a fixed point in the transaction (`trans.c:337`, `add.c:495` and `:667`,
//! `remove.c:711` and `:731`):
//!
//! | function | when |
//! |---|---|
//! | `pre_install` / `post_install` | a package that was not installed before |
//! | `pre_upgrade` / `post_upgrade` | a package that replaces an installed version |
//! | `pre_remove` / `post_remove` | a package being taken away |
//!
//! The `pre_*` half runs from the **archive**, before anything is extracted. The `post_*` half
//! runs from the copy in the database entry, after. That asymmetry is deliberate: a
//! `pre_install` must be able to run before the package's own files exist.
//!
//! # A failing scriptlet does not fail the transaction
//!
//! Every one of libalpm's call sites discards the return value. piko matches that on purpose.
//! By the time `post_install` runs, the files are already on disk and the database entry is
//! already written, so "undoing" is not available. Refusing to record a package whose files
//! exist would be worse than a scriptlet that did not finish.
//!
//! What piko adds is that the failure is **reported** rather than dropped. [`Outcome`] carries
//! the exit status and everything the script printed back to the caller, and `Transaction`'s
//! report carries it on to the user.

use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};

use crate::{
    error::{Error, IoAction, Result},
    exec::{Command, Outcome, Runner},
    rootfs::RootDir,
};

/// The shell a scriptlet is sourced by.
///
/// This mirrors libalpm's `SCRIPTLET_SHELL`, a compile-time constant that is `/bin/sh` on Arch.
/// It is a path *inside the root*, so a chroot being populated needs a shell before its
/// packages' scriptlets can run. pacman has the same requirement.
const SCRIPTLET_SHELL: &str = "/bin/sh";

/// The name the scriptlet is written under, inside the temporary directory.
const SCRIPTLET_FILE: &str = ".INSTALL";

/// Largest `.INSTALL` piko will read, from a package archive or a database entry alike.
///
/// A scriptlet is a short shell file, a few hundred bytes in practice, so this is generous by
/// three orders of magnitude. The bound exists so a package declaring a gigabyte-long
/// `.INSTALL` cannot make piko read it into memory. It does not constrain any real packager.
///
/// One constant covers both readers, not one per reader. [`crate::conflict`] reads the
/// scriptlet out of the archive during `verify`, and `transaction::read_entry_scriptlet` reads
/// it back out of the database entry at removal. The two must agree: a scriptlet that verified
/// and then could not be read back would leave a package whose `pre_remove` silently never
/// runs.
pub const MAX_SCRIPTLET_BYTES: u64 = 4 * 1024 * 1024;

/// Which of the six functions to call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Before extracting a package that was not installed.
    PreInstall,
    /// After extracting a package that was not installed.
    PostInstall,
    /// Before extracting a package over an installed version.
    PreUpgrade,
    /// After extracting a package over an installed version.
    PostUpgrade,
    /// Before removing a package's files.
    PreRemove,
    /// After removing a package's files.
    PostRemove,
}

impl Kind {
    /// The shell function name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PreInstall => "pre_install",
            Self::PostInstall => "post_install",
            Self::PreUpgrade => "pre_upgrade",
            Self::PostUpgrade => "post_upgrade",
            Self::PreRemove => "pre_remove",
            Self::PostRemove => "post_remove",
        }
    }

    /// The install-or-upgrade pair, chosen by whether a version is being replaced.
    #[must_use]
    pub const fn before_install(is_upgrade: bool) -> Self {
        if is_upgrade { Self::PreUpgrade } else { Self::PreInstall }
    }

    /// The install-or-upgrade pair, chosen by whether a version was replaced.
    #[must_use]
    pub const fn after_install(is_upgrade: bool) -> Self {
        if is_upgrade { Self::PostUpgrade } else { Self::PostInstall }
    }
}

/// Whether `script` appears to define `function`.
///
/// This transcribes libalpm's `grep` (`trans.c:310`). It is a **substring search, not a
/// parse**: any line mentioning the name counts, once anything from the first `#` is
/// discarded. A scriptlet that merely says `# see post_install below` in a line with no `#`
/// before it would match. Reproducing that behavior, rather than writing a real shell-function
/// detector, is the point: tightening it would make piko silently skip a function pacman runs.
///
/// One difference exists, in the safe direction. libalpm reads into a 1024-byte buffer, and its
/// own comment admits the needle can be split across two reads and missed. piko searches whole
/// lines instead, so it can only find *more* than libalpm, never fewer.
#[must_use]
pub fn declares(script: &[u8], function: &str) -> bool {
    let text = String::from_utf8_lossy(script);
    text.lines().any(|line| {
        let code = line.split('#').next().unwrap_or(line);
        code.contains(function)
    })
}

/// Where the scriptlet is put so that it is reachable after the chroot.
///
/// libalpm makes `$root/tmp/alpm_XXXXXX` with `mkdtemp`, then chops the root off the front to
/// name it inside the chroot (`trans.c:398`). piko does the same, through [`RootDir`] so the
/// path cannot leave the root. It cleans up on drop, so a failed run leaves nothing behind.
#[derive(Debug)]
struct Staging {
    /// The directory's name inside `<root>/tmp`.
    name: String,
    /// `<root>/tmp` and the directory's own name within it, for the final `rmdir`.
    tmp: crate::rootfs::Resolved,
    /// The created directory and the script's name within it, for the final `unlink`.
    ///
    /// This is a second [`crate::rootfs::Resolved`] rather than a flag, because the two
    /// removals happen in *different* directories. Holding only `tmp`'s descriptor would
    /// unlink `tmp/.INSTALL`, a path that does not exist — the real script sits one directory
    /// deeper. The unlink then does nothing, the script stays in place, `rmdir` fails with
    /// `ENOTEMPTY`, and every scriptlet leaks a directory into the root.
    script: Option<crate::rootfs::Resolved>,
}

impl Staging {
    /// Creates `<root>/tmp/alpm_<something>` and writes `script` into it.
    fn create(root: &RootDir, script: &[u8]) -> Result<Self> {
        // `tmp` itself may not exist yet, in a root being populated from nothing.
        let tmp_slot = root.resolve_parent(Path::new("tmp"))?;
        let created =
            match rustix::fs::mkdirat(tmp_slot.dir(), tmp_slot.name(), Mode::from_raw_mode(0o1777))
            {
                Ok(()) => true,
                Err(rustix::io::Errno::EXIST) => false,
                Err(source) => {
                    return Err(Error::io(
                        root.path().join("tmp"),
                        IoAction::CreateDir,
                        source.into(),
                    ));
                }
            };
        if created {
            // `mkdirat`'s mode is masked by the umask. `01777` would land as `01755` under the
            // usual `0022`, and a real `/tmp` would come out unwritable by anyone else. libalpm
            // has the same gap. piko closes it: a root piko created is a root someone will boot.
            let _ = rustix::fs::chmodat(
                tmp_slot.dir(),
                tmp_slot.name(),
                Mode::from_raw_mode(0o1777),
                rustix::fs::AtFlags::empty(),
            );
        }

        // `mkdirat` is atomic and refuses an existing name. `mkdtemp` relies on the same
        // property, so a predictable name cannot be turned into a planted symlink, only into a
        // collision. A collision is retried.
        let mut last: rustix::io::Errno = rustix::io::Errno::EXIST;
        for attempt in 0..16_u32 {
            let name = candidate_name(attempt);
            let dir = root.resolve_parent(&PathBuf::from("tmp").join(&name))?;
            match rustix::fs::mkdirat(dir.dir(), dir.name(), Mode::from_raw_mode(0o700)) {
                Ok(()) => {
                    let mut staging = Self { name, tmp: dir, script: None };
                    staging.write_script(root, script)?;
                    return Ok(staging);
                }
                Err(source) => last = source,
            }
        }

        Err(Error::io(root.path().join("tmp"), IoAction::CreateDir, last.into()))
    }

    /// Writes the scriptlet inside the freshly created directory.
    fn write_script(&mut self, root: &RootDir, script: &[u8]) -> Result<()> {
        let inside = root.resolve_parent(&self.relative().join(SCRIPTLET_FILE))?;
        let file = rustix::fs::openat(
            inside.dir(),
            inside.name(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|source| {
            Error::io(root.path().join(self.relative()), IoAction::Create, source.into())
        })?;

        let mut file = std::fs::File::from(file);
        std::io::Write::write_all(&mut file, script).map_err(|source| {
            Error::io(root.path().join(self.relative()), IoAction::Write, source)
        })?;
        self.script = Some(inside);
        Ok(())
    }

    /// The directory's path relative to the root.
    fn relative(&self) -> PathBuf {
        PathBuf::from("tmp").join(&self.name)
    }

    /// The script's absolute path *as seen from inside the chroot*.
    fn path_inside_root(&self) -> String {
        format!("/tmp/{}/{SCRIPTLET_FILE}", self.name)
    }
}

impl Drop for Staging {
    /// Removes the script and its directory. Failure is not reported. By the time this runs,
    /// the scriptlet's own result is what matters, and libalpm only warns here too.
    fn drop(&mut self) {
        if let Some(script) = self.script.as_ref() {
            let _ = rustix::fs::unlinkat(script.dir(), script.name(), rustix::fs::AtFlags::empty());
        }
        let _ =
            rustix::fs::unlinkat(self.tmp.dir(), self.tmp.name(), rustix::fs::AtFlags::REMOVEDIR);
    }
}

/// A candidate directory name for attempt `attempt`.
///
/// Not cryptographic, and it does not need to be. `mkdirat` decides who wins a race; this only
/// has to make repeated collisions unlikely.
fn candidate_name(attempt: u32) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.subsec_nanos());
    format!("alpm_{:06x}{:08x}{attempt:x}", std::process::id() & 0xff_ffff, nanos)
}

/// Runs one of a scriptlet's functions.
///
/// `version` is the version being installed or removed. `old_version` is the one being
/// replaced, `Some` exactly for the two `*_upgrade` kinds, matching what libalpm passes.
///
/// Returns `Ok(None)` when the scriptlet does not mention `kind`'s function at all. This is the
/// common case: most packages define only one or two of the six.
///
/// # Errors
///
/// [`Error::Io`] if the scriptlet cannot be staged inside the root. [`Error::UnusableSource`]
/// if a version string could reach the shell as code. Everything the *script* itself can do
/// wrong comes back as an [`Outcome`] instead.
///
/// `on_line` is called with each line of the scriptlet's merged stdout/stderr as it is
/// produced. See [`crate::exec::Runner::run`]. It is never called when this returns `Ok(None)`.
pub fn run(
    runner: &Runner,
    root: &RootDir,
    script: &[u8],
    kind: Kind,
    version: &str,
    old_version: Option<&str>,
    on_line: &mut dyn FnMut(&str),
) -> Result<Option<Outcome>> {
    if !declares(script, kind.as_str()) {
        return Ok(None);
    }

    // The command line is assembled by substitution, exactly as libalpm does. A version
    // carrying a shell metacharacter would become *code*. In practice these come from a parsed
    // `alpm_types` version and cannot. Refusing rather than trusting that is the difference
    // between a guarantee and an assumption, and this function runs as root.
    for value in [Some(version), old_version].into_iter().flatten() {
        if !is_shell_safe(value) {
            return Err(Error::UnusableSource {
                path: PathBuf::from(root.path()),
                reason: format!("the version {value:?} cannot be passed to a scriptlet safely"),
            });
        }
    }

    let staging = Staging::create(root, script)?;
    let script_path = staging.path_inside_root();
    let function = kind.as_str();
    let command_line = match old_version {
        Some(old) => format!(". {script_path}; {function} {version} {old}"),
        None => format!(". {script_path}; {function} {version}"),
    };

    let outcome =
        runner.run(&Command::new(SCRIPTLET_SHELL).arg("-c").arg(&command_line), on_line)?;
    drop(staging);
    Ok(Some(outcome))
}

/// Whether `value` is safe to paste into a shell command line unquoted.
///
/// This is deliberately a whitelist of what an alpm package version can contain
/// (`alpm-package-version`: alphanumerics plus `.`, `_`, `+`, `-`, and `:` for the epoch
/// separator), not a blacklist of metacharacters. A blacklist is one forgotten character away
/// from a shell injection.
fn is_shell_safe(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-' | ':'))
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

    #[test]
    fn a_declared_function_is_found() {
        let script = b"post_install() {\n  echo hi\n}\n";
        assert!(declares(script, "post_install"));
        assert!(!declares(script, "pre_install"));
        assert!(!declares(script, "post_remove"));
    }

    /// libalpm strips from the first `#` before searching, so a commented-out function is not
    /// found. This behavior is transcribed here, not improved.
    #[test]
    fn a_commented_out_function_is_not_found() {
        assert!(!declares(b"# post_install() { :; }\n", "post_install"));
        assert!(!declares(b"  # post_install\n", "post_install"));
    }

    /// The search is a substring match on the surviving text, not a parse. A mention in prose
    /// counts. That is libalpm's behavior, pinned here so it does not get "fixed" later.
    #[test]
    fn a_mere_mention_counts_as_a_declaration() {
        assert!(declares(b"echo 'run post_install first'\n", "post_install"));
    }

    /// Only the part before the first `#` is searched, even when code precedes it.
    #[test]
    fn only_the_text_before_the_first_hash_is_searched() {
        assert!(declares(b"post_install() { : ; } # a comment\n", "post_install"));
        assert!(!declares(b"true # post_install\n", "post_install"));
    }

    #[test]
    fn an_empty_scriptlet_declares_nothing() {
        assert!(!declares(b"", "post_install"));
        for kind in [
            Kind::PreInstall,
            Kind::PostInstall,
            Kind::PreUpgrade,
            Kind::PostUpgrade,
            Kind::PreRemove,
            Kind::PostRemove,
        ] {
            assert!(!declares(b"\n\n# nothing\n", kind.as_str()), "{kind:?}");
        }
    }

    /// Invalid UTF-8 must not make the search silently give up. A scriptlet is a shell file,
    /// and nothing guarantees its encoding.
    #[test]
    fn invalid_utf8_does_not_hide_a_function() {
        let mut script = vec![0xff, 0xfe, b'\n'];
        script.extend_from_slice(b"post_install() { :; }\n");
        assert!(declares(&script, "post_install"));
    }

    #[test]
    fn the_upgrade_pair_is_chosen_by_whether_a_version_is_replaced() {
        assert_eq!(Kind::before_install(false), Kind::PreInstall);
        assert_eq!(Kind::before_install(true), Kind::PreUpgrade);
        assert_eq!(Kind::after_install(false), Kind::PostInstall);
        assert_eq!(Kind::after_install(true), Kind::PostUpgrade);
    }

    #[test]
    fn a_normal_version_is_shell_safe() {
        for version in ["1.0.0-1", "2:1.2.3-4", "1.0.0+r12.g1a2b3c-1", "1_0-1"] {
            assert!(is_shell_safe(version), "{version}");
        }
    }

    /// The whole reason the check exists: the command line is built by substitution.
    #[test]
    fn a_version_carrying_shell_syntax_is_refused() {
        for hostile in ["1.0; rm -rf /", "1.0`id`", "1.0$(id)", "1.0 && id", "1.0\nid", ""] {
            assert!(!is_shell_safe(hostile), "{hostile:?} was accepted");
        }
    }

    /// A scriptlet that does not declare the function is not staged at all — no temporary
    /// directory, no shell, no chroot.
    #[test]
    fn a_missing_function_short_circuits_before_anything_is_created() {
        let root = tempfile::tempdir().unwrap();
        let dir = RootDir::open(root.path()).unwrap();
        let runner = Runner::new(root.path()).unwrap();

        let result = run(
            &runner,
            &dir,
            b"post_remove() { :; }\n",
            Kind::PostInstall,
            "1.0.0-1",
            None,
            &mut |_| {},
        )
        .unwrap();

        assert!(result.is_none());
        assert!(!root.path().join("tmp").exists(), "a temporary directory was created anyway");
    }

    /// Staging puts the script where the chroot can reach it, and takes it away again.
    #[test]
    fn staging_creates_then_removes_the_temporary() {
        let root = tempfile::tempdir().unwrap();
        let dir = RootDir::open(root.path()).unwrap();

        let leftover = {
            let staging = Staging::create(&dir, b"post_install() { :; }\n").unwrap();
            let path = root.path().join(staging.relative());
            assert_eq!(
                std::fs::read(path.join(SCRIPTLET_FILE)).unwrap(),
                b"post_install() { :; }\n"
            );
            assert_eq!(staging.path_inside_root(), format!("/tmp/{}/.INSTALL", staging.name));
            path
        };

        assert!(!leftover.exists(), "the temporary survived the drop");
        assert!(root.path().join("tmp").is_dir(), "tmp itself should stay");
    }

    /// `tmp` is created world-writable and sticky even under the usual `0022` umask, which is
    /// what a real `/tmp` has to be.
    #[test]
    fn a_created_tmp_is_sticky_and_world_writable() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let dir = RootDir::open(root.path()).unwrap();
        drop(Staging::create(&dir, b"post_install() { :; }\n").unwrap());

        let mode = std::fs::metadata(root.path().join("tmp")).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o1777, "tmp is {:o}", mode & 0o7777);
    }

    /// An existing `tmp` is used as it is, not re-permissioned. piko has no business changing
    /// the mode of a directory it did not create.
    #[test]
    fn an_existing_tmp_keeps_its_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("tmp")).unwrap();
        std::fs::set_permissions(root.path().join("tmp"), std::fs::Permissions::from_mode(0o700))
            .unwrap();

        let dir = RootDir::open(root.path()).unwrap();
        drop(Staging::create(&dir, b"post_install() { :; }\n").unwrap());

        let mode = std::fs::metadata(root.path().join("tmp")).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o700, "an existing tmp was re-permissioned");
    }

    /// Two scriptlets running against the same root do not collide.
    #[test]
    fn two_stagings_get_different_directories() {
        let root = tempfile::tempdir().unwrap();
        let dir = RootDir::open(root.path()).unwrap();

        let first = Staging::create(&dir, b"x\n").unwrap();
        let second = Staging::create(&dir, b"y\n").unwrap();
        assert_ne!(first.name, second.name);
    }
}
