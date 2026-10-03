//! Forward compatibility for `%SECTION%`-shaped metadata, shared by both databases.
//!
//! libalpm warns about a `%KEY%` it does not know, and skips the block. That is what lets
//! pacman keep reading a database after a newer pacman has written a section it never heard
//! of. A package manager that refuses to read its own database after a partial upgrade is not
//! robust. piko follows libalpm by default — see [`UnknownSectionPolicy`].
//!
//! The local `desc` is read in [`crate::local::desc`], and the repository one in
//! `repo::desc`. This module holds what both share: the policy, and makepkg's default
//! `%PACKAGER%`.

/// What to do about a `%SECTION%` this build does not recognise.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum UnknownSectionPolicy {
    /// Skip the section and record a diagnostic, as libalpm does.
    ///
    /// This is the default. It keeps a database written by a newer pacman readable, at the
    /// cost of ignoring data piko does not understand.
    #[default]
    Warn,

    /// Refuse to read the `desc`.
    ///
    /// Appropriate when a database is being audited rather than used, and any surprise
    /// should stop the process.
    Reject,
}

/// A `%SECTION%` that was skipped because this build does not recognise it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownSection {
    /// The section keyword, without the surrounding `%`.
    pub keyword: String,
    /// The 1-based line number the section header appeared on.
    pub line: usize,
}

/// makepkg's default `%PACKAGER%`, on every locally built package whose builder set none.
///
/// `makepkg` ends with `PACKAGER=${PACKAGER:-"Unknown Packager"}`, and `makepkg.conf` ships
/// the variable commented out. libalpm copies the value through untouched
/// (`be_local.c:786`, `be_sync.c:637`); `alpm_types::Packager` refuses it, because it carries
/// no `<email>`. piko keeps the value, gives it no typed form, and does not report it.
pub const UNKNOWN_PACKAGER: &str = "Unknown Packager";
