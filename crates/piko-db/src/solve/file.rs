//! A candidate that comes from a package file rather than from a database.
//!
//! `pacman -U foo.pkg.tar.zst` names a package no repository carries. It must still take part
//! in solving: its own dependencies are resolved from the configured repositories, it can
//! satisfy another package's dependency through `%PROVIDES%`, and it conflicts and replaces
//! like any other candidate.
//!
//! # Why this type holds data rather than reading it
//!
//! `piko-db` opens databases. It does not open package archives, and this module does not
//! change that: [`FilePackage`] is built from values a caller already has. The archive walk
//! that produces them lives in `piko-txn`, which owns extraction, bounded archive reading,
//! and `.PKGINFO` parsing. Pulling `alpm-pkginfo` in here to save one constructor would put a
//! second archive door in the crate whose whole discipline is that there is one.
//!
//! The values themselves are `alpm-types`' own, identical to what a `desc` yields. A
//! `.PKGINFO`'s `depend`, `provides`, `conflict`, `replaces` and `group` fields are already
//! `Vec<RelationOrSoname>`, `Vec<PackageRelation>` and `Vec<Group>`, so nothing is converted
//! on the way in.

use alpm_types::{FullVersion, Group, Name, PackageFileName, PackageRelation, RelationOrSoname};

use crate::EntryName;
use crate::eager::Relations;

/// One package file offered to [`Universe::build`](crate::solve::Universe::build) as a
/// candidate.
///
/// Name and version come from an [`EntryName`], the same source of truth every other
/// candidate uses. A package file's `.PKGINFO` is metadata, and metadata is advisory
/// everywhere else in piko; routing it through `EntryName` keeps one identity rule rather
/// than two.
#[derive(Debug)]
pub struct FilePackage {
    entry: EntryName,
    file_name: PackageFileName,
    relations: Relations,
    installed_size: u64,
}

impl FilePackage {
    /// Builds a candidate from the fields a `.PKGINFO` carries.
    ///
    /// `installed_size` is the `.PKGINFO` `size` field, which is `%ISIZE%` under another
    /// name. There is no compressed size: the file is already on disk, so a plan built from
    /// this candidate has nothing to download for it (see
    /// [`Solvable::download_size`](crate::solve::Solvable::download_size)).
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "each parameter is one `.PKGINFO` section; grouping them into a struct would \
                  only move the same list one level out"
    )]
    pub fn new(
        entry: EntryName,
        file_name: PackageFileName,
        depends: Vec<RelationOrSoname>,
        provides: Vec<RelationOrSoname>,
        conflicts: Vec<PackageRelation>,
        replaces: Vec<PackageRelation>,
        groups: Vec<Group>,
        installed_size: u64,
    ) -> Self {
        Self {
            entry,
            file_name,
            relations: Relations {
                depends: depends.into_boxed_slice(),
                provides: provides.into_boxed_slice(),
                conflicts: conflicts.into_boxed_slice(),
                replaces: replaces.into_boxed_slice(),
                groups: groups.into_boxed_slice(),
                depends_text: None,
            },
            installed_size,
        }
    }

    /// The name this package is addressed by inside a transaction.
    ///
    /// A file candidate has no `%FILENAME%`, so this is rendered from its own metadata. It is
    /// what a plan step carries, and what a caller maps back to a path on disk.
    #[must_use]
    pub const fn file_name(&self) -> &PackageFileName {
        &self.file_name
    }

    /// The entry this package would be installed as.
    #[must_use]
    pub const fn entry(&self) -> &EntryName {
        &self.entry
    }

    /// The package name.
    #[must_use]
    pub const fn name(&self) -> &Name {
        self.entry.name()
    }

    /// The package version.
    #[must_use]
    pub const fn version(&self) -> &FullVersion {
        self.entry.version()
    }

    /// The run-time dependencies, infallibly.
    ///
    /// Unlike a repository candidate's, these were converted when the file was read. There is
    /// no deferred tier here: a caller names a handful of files, never fifteen thousand.
    #[must_use]
    pub const fn depends(&self) -> &[RelationOrSoname] {
        &self.relations.depends
    }

    /// What the package provides.
    #[must_use]
    pub const fn provides(&self) -> &[RelationOrSoname] {
        &self.relations.provides
    }

    /// What the package conflicts with.
    #[must_use]
    pub const fn conflicts(&self) -> &[PackageRelation] {
        &self.relations.conflicts
    }

    /// What the package replaces.
    #[must_use]
    pub const fn replaces(&self) -> &[PackageRelation] {
        &self.relations.replaces
    }

    /// The groups the package belongs to.
    #[must_use]
    pub const fn groups(&self) -> &[Group] {
        &self.relations.groups
    }

    /// The space the package occupies once installed.
    #[must_use]
    pub const fn installed_size(&self) -> u64 {
        self.installed_size
    }
}
