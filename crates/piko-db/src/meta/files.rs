//! The local database's `files` format: `%FILES%`, then an optional `%BACKUP%`.
//!
//! Both sections decide what a removal deletes and which configuration files it keeps. So
//! the reader is strict: every line must belong to one of the two sections, and every path
//! must be valid. A defect refuses the whole file, never one line of it.
//!
//! The checks are the ones the `alpm-db-files` specification states: a path is relative, a
//! path is listed once, the parent directory of a path is listed too, and a backup entry
//! names a listed file once. One rule is wider than `alpm-db`'s: a `(null)` backup entry is
//! kept. pacman writes one for a `backup` entry that names a file the package does not ship,
//! and keeps it in the package's backup list.
//!
//! Two rules of the specification are reported rather than enforced in a local `files`: a path
//! listed twice, and a path whose parent directory is not listed. Neither changes what a
//! removal deletes, and libalpm reads both. A refusal would leave the package impossible to
//! remove or upgrade. [`LocalFiles::defects`] names them. A repository member, read by
//! [`parse_repo`], still refuses them: refusing it costs only that package's file listing.
//!
//! [`LocalFiles::backups`] names each path once. pacman can write a `(null)` entry twice, and
//! every caller asks one question per path: which file to compare, keep or offer to merge.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    str::FromStr as _,
};

use alpm_types::{Md5Checksum, RelativeFilePath};

use super::section::{Section, Sections};

/// The `%FILES%` keyword.
const FILES: &str = "FILES";
/// The `%BACKUP%` keyword.
const BACKUP: &str = "BACKUP";
/// The value pacman writes for a backup entry it could not hash.
const NULL_HASH: &str = "(null)";

/// One `%BACKUP%` entry: a configuration file, and the hash of the version the package shipped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Backup {
    /// The file, relative to the installation root.
    pub path: RelativeFilePath,
    /// The MD5 hash of the file as the package shipped it.
    ///
    /// `None` for the `(null)` value pacman writes when the package does not ship the file.
    pub md5: Option<Md5Checksum>,
}

/// The most defects one local `files` names in [`LocalFiles::defects`].
pub const MAX_FILES_DEFECTS: usize = 32;

/// A rule of the `alpm-db-files` specification a local `files` breaks, without being refused.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum FilesDefect {
    /// A path listed twice. It is kept once.
    #[error("%FILES%: {} is listed twice", path.display())]
    DuplicatePath {
        /// The path.
        path: PathBuf,
    },
    /// A path whose parent directory is not listed. The package does not own that directory.
    #[error("%FILES%: the parent directory of {} is not listed", path.display())]
    MissingParent {
        /// The path.
        path: PathBuf,
    },
}

/// A parsed `files` file.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LocalFiles {
    /// Every `%FILES%` path, one after the other, with no separator.
    ///
    /// One buffer rather than one allocation for each path: reading every installed package's
    /// list builds about 300 000 paths, and one `PathBuf` each costs half as much memory again.
    data: Box<str>,
    /// Where each path ends in `data`. A path starts where the one before it ends.
    ends: Box<[usize]>,
    backups: Box<[Backup]>,
    defects: Box<[FilesDefect]>,
    defects_dropped: usize,
}

impl LocalFiles {
    /// The `%FILES%` paths, sorted by [`Path`]'s order, which compares component by component.
    #[must_use]
    pub fn files(&self) -> FilePaths<'_> {
        FilePaths { data: &self.data, ends: self.ends.iter(), start: 0 }
    }

    /// The rules this file breaks without being refused, at most [`MAX_FILES_DEFECTS`], in
    /// path order.
    #[must_use]
    pub fn defects(&self) -> &[FilesDefect] {
        &self.defects
    }

    /// The number of defects past [`MAX_FILES_DEFECTS`], which are not named.
    #[must_use]
    pub const fn defects_dropped(&self) -> usize {
        self.defects_dropped
    }

    /// The `%BACKUP%` entries, sorted by path, `(null)` entries included.
    ///
    /// Each path is named once. When a path has an entry with a hash and a `(null)` one, the
    /// entry with the hash is kept.
    #[must_use]
    pub fn backups(&self) -> &[Backup] {
        &self.backups
    }
}

/// The `%FILES%` paths of a [`LocalFiles`], in its order, borrowed from it.
#[derive(Clone, Debug)]
pub struct FilePaths<'a> {
    data: &'a str,
    ends: std::slice::Iter<'a, usize>,
    /// Where the next path starts in `data`.
    start: usize,
}

impl<'a> Iterator for FilePaths<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        let end = *self.ends.next()?;
        // Every end was recorded at a path boundary of `data`, so the slice exists.
        let path = self.data.get(self.start..end)?;
        self.start = end;
        Some(path)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.ends.size_hint()
    }
}

impl ExactSizeIterator for FilePaths<'_> {}

/// Why a `files` file was refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FilesError {
    /// A section other than `%FILES%` and `%BACKUP%`.
    #[error("line {line}: unknown section %{keyword}%")]
    UnknownSection {
        /// The keyword, without the surrounding `%`.
        keyword: String,
        /// The 1-based line number of the header.
        line: usize,
    },

    /// `%FILES%` or `%BACKUP%` appears twice.
    #[error("line {line}: section %{keyword}% appears twice")]
    DuplicateSection {
        /// The keyword, without the surrounding `%`.
        keyword: &'static str,
        /// The 1-based line number of the second header.
        line: usize,
    },

    /// A non-empty line outside every section.
    #[error("line {line}: a value outside any section")]
    StrayLine {
        /// The 1-based line number.
        line: usize,
    },

    /// A `%FILES%` line that is not a relative path.
    #[error("%FILES%: {value:?} is not a relative path")]
    InvalidPath {
        /// The line.
        value: String,
    },

    /// A rule a local `files` breaks without being refused, which refuses a repository member
    /// ([`parse_repo`]).
    #[error(transparent)]
    Defect(#[from] FilesDefect),

    /// A `%BACKUP%` line that is not `<path>\t<md5>` or `<path>\t(null)`.
    #[error("%BACKUP%: {value:?} is not a backup entry")]
    InvalidBackup {
        /// The line.
        value: String,
    },

    /// A `%BACKUP%` entry with a hash, for a file `%FILES%` does not list.
    #[error("%BACKUP%: {} is not listed in %FILES%", path.display())]
    BackupNotListed {
        /// The path.
        path: PathBuf,
    },

    /// Two `%BACKUP%` entries with a hash, for one file.
    #[error("%BACKUP%: {} is listed twice", path.display())]
    DuplicateBackup {
        /// The path.
        path: PathBuf,
    },
}

/// Parses a local `files` file.
///
/// An empty text is a package that owns no file.
///
/// # Errors
///
/// [`FilesError`] for the first defect found.
pub fn parse(text: &str) -> Result<LocalFiles, FilesError> {
    let [files, backups] = read_sections(text, [FILES, BACKUP])?;

    let mut sorted = sorted_paths(files)?;
    let Checked { defects, total, .. } = check_paths(&sorted, MAX_FILES_DEFECTS);
    // A path listed twice is kept once: the first spelling in text order, which the stable
    // sort put first.
    let spelling = sorted.spelling;
    sorted.paths.dedup_by(|later, kept| spelling.same(later, kept));
    let defects_dropped = total.saturating_sub(defects.len());
    let defects = defects.into_boxed_slice();

    let mut entries = Vec::new();
    for value in backups.iter().flat_map(Section::values) {
        entries.push(backup(value)?);
    }
    check_backups(&entries, &sorted)?;
    // For one path, the entry with a hash sorts first, and so is the one `dedup_by` keeps.
    // `check_backups` has refused a second entry with a hash, so only `(null)` ones are removed.
    entries.sort_by(|a, b| {
        a.path.inner().cmp(b.path.inner()).then_with(|| b.md5.is_some().cmp(&a.md5.is_some()))
    });
    entries.dedup_by(|later, kept| later.path == kept.path);

    let mut data = String::with_capacity(sorted.paths.iter().map(|path| path.len()).sum());
    let mut ends = Vec::with_capacity(sorted.paths.len());
    for path in &sorted.paths {
        data.push_str(path);
        ends.push(data.len());
    }

    Ok(LocalFiles {
        data: data.into_boxed_str(),
        ends: ends.into_boxed_slice(),
        backups: entries.into_boxed_slice(),
        defects,
        defects_dropped,
    })
}

/// Parses a repository `files` member, which holds `%FILES%` only.
///
/// Returns the paths sorted as [`LocalFiles::files`] sorts them, borrowed from `text`. A
/// repository's `.files` archive holds millions of paths, so the caller copies them into one
/// buffer instead of one allocation for each path.
///
/// # Errors
///
/// [`FilesError`] for the first defect found.
pub fn parse_repo(text: &str) -> Result<Vec<&str>, FilesError> {
    let [files] = read_sections(text, [FILES])?;
    let sorted = sorted_paths(files)?;
    if let Some(defect) = check_paths(&sorted, 1).defects.into_iter().next() {
        return Err(defect.into());
    }
    Ok(sorted.paths)
}

/// Finds the sections named in `keywords`, each at most once, and refuses every other line.
fn read_sections<'a, const N: usize>(
    text: &'a str,
    keywords: [&'static str; N],
) -> Result<[Option<Section<'a>>; N], FilesError> {
    let mut found = [None; N];
    let mut sections = Sections::new(text);

    for section in sections.by_ref() {
        let Some(index) = keywords.iter().position(|keyword| *keyword == section.keyword) else {
            return Err(FilesError::UnknownSection {
                keyword: section.keyword.to_owned(),
                line: section.line,
            });
        };
        let (Some(keyword), Some(slot)) = (keywords.get(index), found.get_mut(index)) else {
            continue;
        };
        if slot.is_some() {
            return Err(FilesError::DuplicateSection { keyword, line: section.line });
        }
        *slot = Some(section);
    }
    if let Some(line) = sections.first_stray_line() {
        return Err(FilesError::StrayLine { line });
    }
    Ok(found)
}

/// The `%FILES%` paths, sorted by [`Path`]'s order, and how they were compared.
struct Sorted<'a> {
    /// The paths, as written.
    paths: Vec<&'a str>,
    /// Whether every path has one spelling, so [`Spelling::Canonical`] gives [`Path`]'s answers.
    spelling: Spelling,
}

/// How the `%FILES%` paths of one file are compared.
///
/// Comparing, hashing or prefix-testing a [`Path`] walks its components, and that walk costs
/// most of the reader's time over a repository's millions of paths. For a path with one
/// spelling, the same answers come from its bytes: [`canonical_order`] gives [`Path`]'s order,
/// and a key without the trailing `/` gives [`Path`]'s equality. A file that holds any other
/// spelling is compared as [`Path`] compares it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Spelling {
    /// No empty, `.` or `..` component, no NUL byte, at most one trailing `/`.
    Canonical,
    /// Some path is spelled another way.
    Other,
}

/// Whether `path`, already known to be relative, has one spelling: no empty, `.` or `..`
/// component, no NUL byte, and at most one trailing `/`.
fn is_canonical(path: &str) -> bool {
    let key = key(path);
    !key.is_empty()
        && !key.contains('\0')
        && key.split('/').all(|component| !matches!(component, "" | "." | ".."))
}

/// `path` without its trailing `/`. Two canonical spellings name one path exactly when their
/// keys are equal, as [`Path`]'s equality ignores a trailing `/`.
fn key(path: &str) -> &str {
    path.strip_suffix('/').unwrap_or(path)
}

/// [`Path`]'s order over two canonical paths, from their bytes.
///
/// [`Path`] compares component by component. Over the keys, that is the byte order with `/`
/// counted below every other byte: a component that is a prefix of another then sorts first,
/// as it does in [`Path`]'s order. A canonical component holds neither `/` nor NUL, so the
/// mapping is exact.
fn canonical_order(a: &str, b: &str) -> std::cmp::Ordering {
    key(a)
        .bytes()
        .map(|byte| if byte == b'/' { 0 } else { byte })
        .cmp(key(b).bytes().map(|byte| if byte == b'/' { 0 } else { byte }))
}

/// Checks each `%FILES%` line, and sorts them by [`Path`]'s order.
///
/// A path must be relative. A line of white space only is refused: no package ships a file
/// with such a name, and a writer that emits one has lost the name.
fn sorted_paths(files: Option<Section<'_>>) -> Result<Sorted<'_>, FilesError> {
    let mut paths = Vec::new();
    let mut canonical = true;
    for value in files.iter().flat_map(Section::values) {
        if value.trim().is_empty() || !Path::new(value).is_relative() {
            return Err(FilesError::InvalidPath { value: value.to_owned() });
        }
        canonical = canonical && is_canonical(value);
        paths.push(value);
    }
    // Stable, so of two spellings of one path the first in text order stays first.
    let spelling = if canonical {
        paths.sort_by(|a, b| canonical_order(a, b));
        Spelling::Canonical
    } else {
        paths.sort_by(|a, b| Path::new(a).cmp(Path::new(b)));
        Spelling::Other
    };
    Ok(Sorted { paths, spelling })
}

impl Spelling {
    /// Whether `a` and `b` name one path.
    fn same(self, a: &str, b: &str) -> bool {
        match self {
            Self::Canonical => key(a) == key(b),
            Self::Other => Path::new(a) == Path::new(b),
        }
    }
}

impl Sorted<'_> {
    /// Whether `path` is listed. The paths are in [`Path`]'s order either way, so a search by
    /// [`Path`] finds a path of any spelling.
    fn lists(&self, path: &Path) -> bool {
        self.paths.binary_search_by(|listed| Path::new(listed).cmp(path)).is_ok()
    }
}

/// What [`check_paths`] found in the sorted `%FILES%` paths.
struct Checked {
    /// The first defects found, in path order, at most `limit`.
    defects: Vec<FilesDefect>,
    /// How many defects `defects` keeps.
    limit: usize,
    /// The number of defects found, those past `limit` included.
    total: usize,
}

impl Checked {
    /// Counts `defect`, and keeps it while `defects` has room.
    fn note(&mut self, defect: FilesDefect) {
        // The count is bounded by the number of paths, so this cannot overflow.
        self.total = self.total.saturating_add(1);
        if self.defects.len() < self.limit {
            self.defects.push(defect);
        }
    }
}

/// Checks the sorted `%FILES%` paths, and keeps the first `limit` defects it finds: a path
/// listed twice, and a path whose parent directory is not listed.
fn check_paths(sorted: &Sorted<'_>, limit: usize) -> Checked {
    let mut checked = Checked { defects: Vec::new(), limit, total: 0 };
    match sorted.spelling {
        Spelling::Canonical => check_canonical(&sorted.paths, &mut checked),
        Spelling::Other => check_by_components(&sorted.paths, &mut checked),
    }
    checked
}

/// [`check_paths`] over canonical paths, by their keys.
///
/// Sorted by [`Path`]'s order, the paths below a directory follow it, before any path that is
/// not below it. So the listed ancestors of the current path are a stack: a path pops each
/// entry it is not below, and its parent is listed exactly when it is the entry left on top.
fn check_canonical(paths: &[&str], checked: &mut Checked) {
    let mut ancestors: Vec<&str> = Vec::new();
    let mut previous: Option<(&str, bool)> = None;
    for path in paths {
        let current = key(path);
        // A path listed twice follows its first spelling, and has the same parent.
        if let Some((last, parent_missing)) = previous
            && last == current
        {
            if parent_missing {
                checked.note(FilesDefect::MissingParent { path: PathBuf::from(path) });
            }
            checked.note(FilesDefect::DuplicatePath { path: PathBuf::from(path) });
            continue;
        }
        while ancestors.last().is_some_and(|top| !is_below(current, top)) {
            ancestors.pop();
        }
        let parent_missing =
            current.rsplit_once('/').is_some_and(|(parent, _)| ancestors.last() != Some(&parent));
        if parent_missing {
            checked.note(FilesDefect::MissingParent { path: PathBuf::from(path) });
        }
        previous = Some((current, parent_missing));
        ancestors.push(current);
    }
}

/// Whether the canonical key `path` names something below the key `directory`.
fn is_below(path: &str, directory: &str) -> bool {
    path.strip_prefix(directory).is_some_and(|rest| rest.starts_with('/'))
}

/// [`check_paths`] over paths of any spelling, as [`Path`] compares them.
fn check_by_components(paths: &[&str], checked: &mut Checked) {
    let mut listed: HashSet<&Path> = HashSet::with_capacity(paths.len());
    for path in paths.iter().map(|path| Path::new(*path)) {
        // Sorted by components, a parent comes before every path below it.
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
            && !listed.contains(parent)
        {
            checked.note(FilesDefect::MissingParent { path: path.to_path_buf() });
        }
        if !listed.insert(path) {
            checked.note(FilesDefect::DuplicatePath { path: path.to_path_buf() });
        }
    }
}

/// Parses one `%BACKUP%` line: a path, one tab, then an MD5 hash or `(null)`.
fn backup(value: &str) -> Result<Backup, FilesError> {
    let invalid = || FilesError::InvalidBackup { value: value.to_owned() };
    let (path, hash) = value.split_once('\t').ok_or_else(invalid)?;
    if path.trim().is_empty() {
        return Err(invalid());
    }
    let path = RelativeFilePath::from_str(path).map_err(|_| invalid())?;
    let md5 = match hash {
        NULL_HASH => None,
        hash => Some(Md5Checksum::from_str(hash).map_err(|_| invalid())?),
    };
    Ok(Backup { path, md5 })
}

/// Checks the `%BACKUP%` entries that carry a hash against the listed paths.
///
/// A `(null)` entry is not checked: it names a file the package does not ship, so it is not
/// listed, and pacman can write it twice. [`parse`] keeps one entry per path.
fn check_backups(entries: &[Backup], listed: &Sorted<'_>) -> Result<(), FilesError> {
    let mut seen: HashSet<&Path> = HashSet::new();
    for entry in entries.iter().filter(|entry| entry.md5.is_some()) {
        let path = entry.path.inner();
        if !listed.lists(path) {
            return Err(FilesError::BackupNotListed { path: path.to_path_buf() });
        }
        if !seen.insert(path) {
            return Err(FilesError::DuplicateBackup { path: path.to_path_buf() });
        }
    }
    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Canonical paths over components chosen to stress the order: a prefix (`a`, `ab`), a
    /// byte below `/` (`a-b`, `a.b`), a hidden name, and a trailing `/` or not.
    fn canonical_paths() -> impl Strategy<Value = Vec<String>> {
        let component = prop::sample::select(vec!["a", "ab", "a-b", "a.b", ".x", "b0", "b"]);
        let path = (prop::collection::vec(component, 1..5), any::<bool>()).prop_map(
            |(components, directory)| {
                let joined = components.join("/");
                if directory { format!("{joined}/") } else { joined }
            },
        );
        prop::collection::vec(path, 0..40)
    }

    proptest! {
        /// Over canonical paths, the byte comparison sorts, deduplicates and finds defects
        /// exactly as the comparison by components does.
        #[test]
        fn the_canonical_check_agrees_with_the_one_by_components(paths in canonical_paths()) {
            let paths: Vec<&str> = paths.iter().map(String::as_str).collect();
            prop_assert!(paths.iter().all(|path| is_canonical(path)));

            let mut fast = paths.clone();
            fast.sort_by(|a, b| canonical_order(a, b));
            let mut slow = paths;
            slow.sort_by(|a, b| Path::new(a).cmp(Path::new(b)));
            prop_assert_eq!(&fast, &slow);

            let (mut by_bytes, mut by_components) =
                (Checked { defects: Vec::new(), limit: usize::MAX, total: 0 }, Checked { defects: Vec::new(), limit: usize::MAX, total: 0 });
            check_canonical(&fast, &mut by_bytes);
            check_by_components(&slow, &mut by_components);
            prop_assert_eq!(by_bytes.defects, by_components.defects);

            let (mut dedup_fast, mut dedup_slow) = (fast.clone(), slow.clone());
            dedup_fast.dedup_by(|later, kept| Spelling::Canonical.same(later, kept));
            dedup_slow.dedup_by(|later, kept| Spelling::Other.same(later, kept));
            prop_assert_eq!(dedup_fast, dedup_slow);
        }
    }

    /// A path with an empty, `.` or `..` component, or a NUL byte, sends the whole file to the
    /// comparison by components, which reads it as before.
    #[test]
    fn another_spelling_is_compared_by_components() {
        for path in ["usr//bin", "./usr", "usr/./bin", "usr/..", "usr/a\0b", "usr/bin//"] {
            assert!(!is_canonical(path), "{path:?}");
        }
        assert!(is_canonical("usr/bin/"));
        let files = parse("%FILES%\nusr/\nusr//bin/\nusr/bin/\n").unwrap();
        assert_eq!(files.files().len(), 2, "usr//bin/ and usr/bin/ name one path");
        assert!(matches!(files.defects(), [FilesDefect::DuplicatePath { .. }]));
    }

    const MD5: &str = "d41d8cd98f00b204e9800998ecf8427e";

    fn paths(files: &LocalFiles) -> Vec<&str> {
        files.files().collect()
    }

    #[test]
    fn an_empty_file_owns_nothing() {
        for text in ["", "%FILES%\n", "%FILES%\n\n", "%FILES%\n\n%BACKUP%\n\n"] {
            assert_eq!(parse(text).unwrap(), LocalFiles::default(), "{text:?}");
        }
    }

    #[test]
    fn reads_paths_and_backups() {
        let text = format!(
            "%FILES%\netc/\netc/foo.conf\nusr/\nusr/bin/\nusr/bin/foo\n\n\
             %BACKUP%\netc/foo.conf\t{MD5}\n\n"
        );
        let files = parse(&text).unwrap();

        assert_eq!(paths(&files), ["etc/", "etc/foo.conf", "usr/", "usr/bin/", "usr/bin/foo"]);
        assert_eq!(files.backups().len(), 1);
        assert_eq!(files.backups().first().map(|b| b.path.to_string()).unwrap(), "etc/foo.conf");
    }

    /// The order compares components, so `usr/share/makepkg/` sorts before
    /// `usr/share/makepkg-template/`, where a byte comparison puts it after.
    #[test]
    fn paths_are_sorted_by_component() {
        let text = "%FILES%\nusr/\nusr/share/\nusr/share/makepkg-template/\nusr/share/makepkg/\n";
        assert_eq!(
            paths(&parse(text).unwrap()),
            ["usr/", "usr/share/", "usr/share/makepkg/", "usr/share/makepkg-template/"]
        );
    }

    /// pacman writes `(null)` for a `backup` entry the package does not ship. The entry is
    /// kept, and it is not checked against `%FILES%`. A repeated entry is kept once, so a
    /// caller does not ask twice about one file.
    #[test]
    fn a_null_backup_entry_is_kept_once() {
        let text = "%FILES%\netc/\n\n%BACKUP%\netc/absent.conf\t(null)\netc/absent.conf\t(null)\n";
        let files = parse(text).unwrap();

        assert_eq!(files.backups().len(), 1);
        assert!(files.backups().iter().all(|backup| backup.md5.is_none()));
    }

    /// A path with an entry with a hash and a `(null)` one keeps the hash, whatever the order.
    #[test]
    fn a_hash_wins_over_null_for_one_path() {
        for backups in [
            format!("etc/foo.conf\t(null)\netc/foo.conf\t{MD5}\n"),
            format!("etc/foo.conf\t{MD5}\netc/foo.conf\t(null)\n"),
        ] {
            let text = format!("%FILES%\netc/\netc/foo.conf\n\n%BACKUP%\n{backups}");
            let files = parse(&text).unwrap();

            assert_eq!(files.backups().len(), 1, "{text:?}");
            assert!(files.backups().iter().all(|backup| backup.md5.is_some()), "{text:?}");
        }
    }

    /// A path listed twice and a path without its parent are read and named, not refused. The
    /// repaired list keeps each path once.
    #[test]
    fn reports_a_duplicate_and_a_missing_parent() {
        let files = parse("%FILES%\netc/\netc/foo\netc/foo\nusr/bin/x\n").unwrap();

        assert_eq!(paths(&files), ["etc/", "etc/foo", "usr/bin/x"]);
        assert_eq!(
            files.defects(),
            [
                FilesDefect::DuplicatePath { path: PathBuf::from("etc/foo") },
                FilesDefect::MissingParent { path: PathBuf::from("usr/bin/x") },
            ]
        );
        assert_eq!(files.defects_dropped(), 0);
    }

    /// The defects past the bound are counted, not named.
    #[test]
    fn defects_past_the_bound_are_counted() {
        let text: String = std::iter::once("%FILES%\n".to_owned())
            .chain((0..100).map(|i| format!("d/f{i}\n")))
            .collect();
        let files = parse(&text).unwrap();

        assert_eq!(files.files().len(), 100);
        assert_eq!(files.defects().len(), MAX_FILES_DEFECTS);
        assert_eq!(files.defects_dropped(), 100 - MAX_FILES_DEFECTS);
    }

    /// A repository member still refuses both: refusing it costs only its file listing.
    #[test]
    fn a_repository_member_refuses_a_duplicate_and_a_missing_parent() {
        assert!(matches!(
            parse_repo("%FILES%\netc/foo\n"),
            Err(FilesError::Defect(FilesDefect::MissingParent { .. }))
        ));
        assert!(matches!(
            parse_repo("%FILES%\netc/\netc/\n"),
            Err(FilesError::Defect(FilesDefect::DuplicatePath { .. }))
        ));
    }

    #[test]
    fn refuses_a_defect_in_either_section() {
        let cases = [
            ("%FILES%\n/etc/\n", "absolute"),
            ("%FILES%\n  \n", "white space"),
            ("%FILES%\netc/\n\nusr/\n", "stray"),
            ("%FILES%\netc/\n\n%FILES%\nusr/\n", "duplicate section"),
            ("%FILES%\netc/\n\n%OTHER%\nx\n", "unknown section"),
            ("%FILES%\netc/\n\n%BACKUP%\netc/\n", "no tab"),
            ("%FILES%\netc/\n\n%BACKUP%\netc/\tnot-a-hash\n", "bad hash"),
            ("%FILES%\netc/\n\n%BACKUP%\netc/\t(null)\n", "a directory"),
            ("%FILES%\netc/\n\n%BACKUP%\netc/x\td41d8cd98f00b204e9800998ecf8427e\n", "not listed"),
        ];
        for (text, case) in cases {
            assert!(parse(text).is_err(), "{case}: {text:?}");
        }
    }

    #[test]
    fn a_repository_member_holds_paths_only() {
        let text = "%FILES%\nusr/\nusr/bin/\nusr/bin/foo\n";
        assert_eq!(parse_repo(text).unwrap(), ["usr/", "usr/bin/", "usr/bin/foo"]);
        assert!(parse_repo("").unwrap().is_empty());

        let backup = format!("%FILES%\netc/\netc/a\n\n%BACKUP%\netc/a\t{MD5}\n");
        assert!(matches!(parse_repo(&backup), Err(FilesError::UnknownSection { .. })));
        assert!(matches!(
            parse_repo("%FILES%\nusr/bin/\n"),
            Err(FilesError::Defect(FilesDefect::MissingParent { .. }))
        ));
    }

    #[test]
    fn refuses_a_hashed_backup_listed_twice() {
        let text = format!("%FILES%\netc/\netc/a\n\n%BACKUP%\netc/a\t{MD5}\netc/a\t{MD5}\n");
        assert!(matches!(parse(&text), Err(FilesError::DuplicateBackup { .. })));
    }

    /// A hash followed by more text is refused, not read as its first 32 characters.
    #[test]
    fn refuses_text_after_the_hash() {
        let text = format!("%FILES%\netc/\netc/a\n\n%BACKUP%\netc/a\t{MD5}x\n");
        assert!(matches!(parse(&text), Err(FilesError::InvalidBackup { .. })));
    }

    /// Every `files` member of every `.files` archive on this machine: piko reads the same
    /// paths, in the same order, as `alpm-repo-db`. The archive reader is private to this crate,
    /// so this test lives here rather than in `tests/meta_real_system.rs`.
    #[test]
    #[ignore = "requires this machine's real /var/lib/pacman/sync"]
    fn repository_files_agree_with_alpm_repo_db() {
        use std::str::FromStr as _;

        use alpm_repo_db::files::RepoFilesV1;

        use crate::repo::archive::{self, ArchiveItem};

        let sync = Path::new("/var/lib/pacman/sync");
        if !sync.is_dir() {
            println!("skipping: {} not present", sync.display());
            return;
        }
        let (mut members, mut paths_seen, mut upstream_refused) = (0_usize, 0_usize, 0_usize);

        for entry in std::fs::read_dir(sync).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|ext| ext != "files") {
                continue;
            }
            archive::walk(
                &path,
                &crate::limits::Limits::default(),
                |item| {
                    let ArchiveItem::Files { entry, text } = item else { return Ok(()) };
                    let ours = parse_repo(&text)
                        .unwrap_or_else(|error| panic!("{}: {error}", entry.as_str()));
                    match RepoFilesV1::from_str(&text) {
                        Ok(theirs) => {
                            let theirs: Vec<_> =
                                theirs.as_ref().iter().map(|p| p.to_str().unwrap()).collect();
                            assert_eq!(ours, theirs, "{}", entry.as_str());
                        }
                        Err(_) => {
                            upstream_refused += 1;
                            println!("{}: alpm-repo-db refuses this member", entry.as_str());
                        }
                    }
                    members += 1;
                    paths_seen += ours.len();
                    Ok(())
                },
                |_skipped| {},
            )
            .unwrap();
        }

        println!(
            "{members} members, {paths_seen} paths agree; {upstream_refused} refused upstream"
        );
    }
}
