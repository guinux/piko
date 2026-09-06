//! Telling a package name from a package file from a URL, on the command line.
//!
//! # Why piko has to decide this and pacman does not
//!
//! pacman never guesses. `-S` takes names, `-U` takes files, and the mode the user typed
//! settles which. piko has one `install` command that accepts all three, so the decision moves
//! from the mode to the argument.
//!
//! That decision is a policy, not a formatting detail: it picks which `SigLevel` directive
//! governs the package (`SigLevel`, `LocalFileSigLevel`, or `RemoteFileSigLevel`). A second
//! frontend that classified targets differently would verify packages differently. So it lives
//! here rather than in the CLI.
//!
//! # The rule
//!
//! In order, first match wins:
//!
//! 1. Contains `://` — a URL. This is pacman's own test (`upgrade.c` splits its targets on
//!    `strstr(i->data, "://")`), kept literally so the two agree on every string.
//! 2. Contains `/` — a path. Unambiguous: `alpm_types::Name` admits only
//!    `[[:alnum:]+_.@-]`, so no package name can contain a separator.
//! 3. Ends with a package-file suffix **and** names an existing regular file — a path.
//! 4. Anything else — a name.
//!
//! Rule 3 is the only one that can be wrong, and it is where pacman's mode would have
//! answered. `.` is a legal character in a package name, so `foo.pkg.tar.zst` is a name a
//! repository could really carry. Existence on disk decides, because a user who has that file
//! in the working directory almost certainly means it — and because the other reading stays
//! reachable by spelling the name differently, while a file has no second spelling that avoids
//! rule 3. A caller that can see both readings should say so; see
//! [`TargetKind::ambiguous_name`].

use std::path::{Path, PathBuf};

/// What one command-line target names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetKind {
    /// A dependency string or a `%GROUPS%` group name, to be resolved through a repository.
    Name(String),
    /// A package file on this machine.
    File(PathBuf),
    /// A package file to fetch first.
    Url(String),
}

/// The file-name suffixes a package archive can carry.
///
/// `alpm-package` names these, and `alpm_types::PackageFileName` parses exactly this set.
/// Sniffing the file's magic bytes instead would be a stronger test of what the file *is*,
/// and a worse test of what the user *meant*: this classifies an argument, and an argument
/// that does not look like a package should be read as a name even when some file of that
/// name happens to be a valid archive.
const PACKAGE_SUFFIXES: [&str; 5] =
    [".pkg.tar", ".pkg.tar.gz", ".pkg.tar.bz2", ".pkg.tar.xz", ".pkg.tar.zst"];

/// Classifies one command-line target. See the module documentation for the rule.
///
/// Rule 3 stats the target as written, so a bare file name is looked for in the working
/// directory — the directory the user typed it in.
#[must_use]
pub fn classify(target: &str) -> TargetKind {
    classify_with(target, is_regular_file)
}

/// [`classify`], with rule 3's filesystem probe supplied by the caller.
///
/// Split out so the rule can be tested without a working directory to move into, which two
/// tests running at once could not share.
fn classify_with(target: &str, exists: impl Fn(&Path) -> bool) -> TargetKind {
    if target.contains("://") {
        return TargetKind::Url(target.to_owned());
    }
    if target.contains('/') {
        return TargetKind::File(PathBuf::from(target));
    }
    if looks_like_package_file(target) && exists(Path::new(target)) {
        return TargetKind::File(PathBuf::from(target));
    }
    TargetKind::Name(target.to_owned())
}

impl TargetKind {
    /// The name this target would have been read as, had rule 3 not fired.
    ///
    /// `Some` only for the one ambiguous case: a bare argument that both names an existing
    /// package file and is a syntactically valid package name. A caller that can check its
    /// repositories for that name is the only one able to tell a real collision from a
    /// coincidence, so this reports the possibility rather than resolving it.
    #[must_use]
    pub fn ambiguous_name(&self) -> Option<&str> {
        let Self::File(path) = self else {
            return None;
        };
        let spelled = path.to_str()?;
        (!spelled.contains('/') && looks_like_package_file(spelled)).then_some(spelled)
    }
}

/// Whether `target` ends with a package-archive suffix.
fn looks_like_package_file(target: &str) -> bool {
    PACKAGE_SUFFIXES.iter().any(|suffix| target.ends_with(suffix))
}

/// Whether `path` exists and is a regular file, following symlinks.
///
/// A symlink to a package is a package. This matches how [`crate::source::CacheDirSource`]
/// stats a cache entry, and how libalpm stats a file target.
fn is_regular_file(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
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
    fn a_bare_word_is_a_name() {
        assert_eq!(classify("foo"), TargetKind::Name("foo".to_owned()));
        assert_eq!(classify("foo>=1.0"), TargetKind::Name("foo>=1.0".to_owned()));
        assert_eq!(classify("base-devel"), TargetKind::Name("base-devel".to_owned()));
    }

    #[test]
    fn anything_with_a_scheme_is_a_url() {
        assert_eq!(
            classify("https://host/foo-1.0-1-x86_64.pkg.tar.zst"),
            TargetKind::Url("https://host/foo-1.0-1-x86_64.pkg.tar.zst".to_owned())
        );
        // Every scheme, not only http. libalpm hands the string to libcurl, which supports
        // more than piko does; classifying it as a URL is what lets piko refuse it by name.
        assert!(matches!(classify("file:///tmp/foo.pkg.tar.zst"), TargetKind::Url(_)));
    }

    #[test]
    fn a_separator_makes_it_a_path_even_when_nothing_is_there() {
        // No existence check: a path that does not exist must be reported as a missing file,
        // not resolved as a package name that happens not to exist either.
        assert_eq!(
            classify("./nowhere/foo.pkg.tar.zst"),
            TargetKind::File(PathBuf::from("./nowhere/foo.pkg.tar.zst"))
        );
        assert_eq!(classify("/tmp/absent"), TargetKind::File(PathBuf::from("/tmp/absent")));
    }

    #[test]
    fn a_bare_package_file_name_is_a_name_until_the_file_exists() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar.zst";
        assert_eq!(classify_with(name, |_| false), TargetKind::Name(name.to_owned()));
        assert_eq!(classify_with(name, |_| true), TargetKind::File(PathBuf::from(name)));
    }

    #[test]
    fn a_name_that_does_not_look_like_a_package_file_is_never_stated() {
        // Rule 3 must not fire for `foo`, whatever is on disk. Otherwise a directory named
        // after a package would change what `piko install foo` means.
        assert_eq!(classify_with("foo", |_| true), TargetKind::Name("foo".to_owned()));
    }

    #[test]
    fn only_a_bare_file_name_reports_an_ambiguity() {
        assert_eq!(
            TargetKind::File(PathBuf::from("foo-1.0.0-1-x86_64.pkg.tar.zst")).ambiguous_name(),
            Some("foo-1.0.0-1-x86_64.pkg.tar.zst")
        );
        // Spelled with a separator, the user has already said which reading they meant.
        assert_eq!(
            TargetKind::File(PathBuf::from("./foo-1.0.0-1-x86_64.pkg.tar.zst")).ambiguous_name(),
            None
        );
        assert_eq!(TargetKind::Name("foo".to_owned()).ambiguous_name(), None);
    }
}
