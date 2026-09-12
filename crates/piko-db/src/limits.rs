//! Resource limits applied while reading a local database.
//!
//! Every file in an alpm-db entry is read fully into memory before being parsed. This is how
//! the `alpm-db` and `alpm-mtree` crates work; neither offers a streaming API. A database
//! directory is therefore an untrusted input that can dictate an allocation, so each read is
//! bounded.
//!
//! The local-database defaults are derived from measurements of a real 1166-package Arch
//! installation and leave roughly three orders of magnitude of headroom:
//!
//! | file    | largest observed | default limit |
//! |---------|------------------|---------------|
//! | `desc`  | 4 KiB            | 1 MiB         |
//! | `files` | 2.0 MiB          | 16 MiB        |
//! | `mtree` | 833 KiB (gzip)   | 16 MiB gzip / 256 MiB inflated |
//!
//! A `files` limit below 2 MiB would reject a real package (`code`). This is why the caps
//! are set well above "what looks reasonable".
//!
//! The repository-database defaults are sized differently. A real `extra.files` archive
//! measured at 50 MB compressed / 581 MB inflated, so the local database's "three orders of
//! magnitude" headroom rule does not transfer. Applying it here would allow multi-gigabyte
//! archives that are not a plausible repository database. These leave a smaller, deliberate
//! headroom instead:
//!
//! | archive                     | largest observed        | default limit |
//! |------------------------------|-------------------------|---------------|
//! | compressed (`repo_compressed_bytes`) | 50 MB (`extra.files`)   | 256 MiB |
//! | inflated (`repo_inflated_bytes`)     | 581 MB (`extra.files`)  | `u32::MAX` (~4 GiB) |
//! | one archive member (`repo_entry_bytes`) | 12.7 MB (largest `files`) | 64 MiB |
//! | packages (`repo_max_packages`)       | 14 885 (`extra`)        | 1 << 20 |
//!
//! `pacman.conf` (and every file it `Include`s) is small system configuration, not
//! attacker-influenced package data. Its limit is sized generously rather than tightly:
//!
//! | file                        | observed        | default limit |
//! |------------------------------|-----------------|---------------|
//! | `pacman_conf_bytes`          | 2.8 KB (`/etc/pacman.conf`) | 1 MiB |
//!
//! A `.hook` file shares that grammar but not that provenance. Every package may ship one into
//! the system hook directory, so the population is larger and less curated. It is still tiny:
//! the largest of the 45 installed on this machine is 638 bytes. The bound is generous for the
//! same reason `pacman_conf_bytes` is:
//!
//! | file                        | largest observed        | default limit |
//! |------------------------------|-------------------------|---------------|
//! | `hook_bytes`                 | 638 B                   | 1 MiB |
//!
//! Diagnostics are bounded separately (`max_diagnostics`, default 4096). They are the one
//! part of an open whose size is attacker-controlled *without* the package count growing: a
//! directory of a million badly-named entries yields no packages at all. So neither
//! `max_entries` nor `repo_max_packages` bounds them.

use std::fmt;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;

/// Identifies which limit was exceeded, for error reporting.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Limit {
    /// The maximum size of an entry's `desc` file.
    Desc,
    /// The maximum size of an entry's `files` file.
    Files,
    /// The maximum on-disk (possibly compressed) size of an entry's `mtree` file.
    MtreeCompressed,
    /// The maximum size of an entry's `mtree` file after decompression.
    MtreeInflated,
    /// The maximum size of the `ALPM_DB_VERSION` file.
    SchemaVersion,
    /// The maximum on-disk (compressed) size of a repository database archive.
    RepoCompressed,
    /// The maximum total size of a repository database archive after decompression.
    RepoInflated,
    /// The maximum size of a single member (`desc` or `files`) inside a repository archive.
    RepoEntry,
    /// The maximum size of a `pacman.conf` file, or any file it `Include`s.
    PacmanConf,
    /// The maximum size of an alpm `.hook` file.
    ///
    /// Separate from [`Self::PacmanConf`] even though the grammar is shared. A hook directory
    /// is written to by every package that ships one. The population of files behind this
    /// bound is much larger and much less curated than the single configuration file behind
    /// that one.
    Hook,
}

impl Limit {
    /// The human-readable name of this limit, as it appears in error messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Desc => "desc",
            Self::Files => "files",
            Self::MtreeCompressed => "compressed mtree",
            Self::MtreeInflated => "inflated mtree",
            Self::SchemaVersion => "schema version file",
            Self::RepoCompressed => "compressed repository archive",
            Self::RepoInflated => "inflated repository archive",
            Self::RepoEntry => "repository archive member",
            Self::PacmanConf => "pacman.conf file",
            Self::Hook => "hook file",
        }
    }
}

impl fmt::Display for Limit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Bounds on the resources a single local database may consume.
///
/// Use [`Limits::default`] unless you have a specific reason not to. The defaults are
/// generous enough for any real system.
///
/// ```
/// use piko_db::Limits;
///
/// // Tighten the mtree bound on a memory-constrained system.
/// let limits = Limits { mtree_inflated_bytes: 32 * 1024 * 1024, ..Limits::default() };
/// assert_eq!(limits.desc_bytes, Limits::default().desc_bytes);
/// ```
// Deliberately *not* `#[non_exhaustive]`. Functional update syntax
// (`Limits { desc_bytes: .., ..Default::default() }`) is the intended way to adjust one
// bound, and `#[non_exhaustive]` forbids it outside this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum size in bytes of a `desc` file.
    pub desc_bytes: u64,
    /// Maximum size in bytes of a `files` file.
    pub files_bytes: u64,
    /// Maximum on-disk size in bytes of an `mtree` file, before decompression.
    pub mtree_compressed_bytes: u64,
    /// Maximum size in bytes of an `mtree` file after decompression.
    ///
    /// This is the bound that makes a compression bomb in the database harmless. The
    /// `alpm-mtree` crate inflates gzip internally with no bound of its own. So
    /// [`crate::LocalPackage`] performs the decompression itself against this limit and
    /// never hands a compressed stream to the parser.
    pub mtree_inflated_bytes: u64,
    /// Maximum size in bytes of the `ALPM_DB_VERSION` file.
    pub schema_version_bytes: u64,
    /// Maximum number of entries a database directory may contain.
    ///
    /// Exceeding this is a hard error rather than a diagnostic. A directory this large is
    /// not a plausible package database, and continuing would mean an unbounded allocation.
    ///
    /// This counts **packages**, not directory entries. A stray file, a symlink or a
    /// badly-named directory consumes no budget. A database holding exactly this many
    /// packages opens regardless of what else sits next to them (`ALPM_DB_VERSION` always
    /// does). Those are bounded by [`Limits::max_diagnostics`] instead.
    pub max_entries: usize,
    /// Maximum number of diagnostics a single open may collect, after which further ones are
    /// counted but not stored.
    ///
    /// Diagnostics are the one part of an open whose size an attacker controls without the
    /// package count growing with it. A directory of a million badly-named entries produces
    /// a million diagnostics and zero packages, so [`Limits::max_entries`] and
    /// [`Limits::repo_max_packages`] do not bound them. Exceeding this is deliberately *not*
    /// an error. A database that is otherwise readable must stay readable, so the overflow is
    /// reported as a count (`diagnostics_dropped`) rather than by failing the open.
    pub max_diagnostics: usize,
    /// Maximum on-disk (compressed) size in bytes of a repository database archive.
    ///
    /// Checked before decompression begins.
    pub repo_compressed_bytes: u64,
    /// Maximum total size in bytes of a repository database archive after decompression.
    ///
    /// `alpm-compress` has no size cap of its own, verified by inspection of
    /// `CompressionDecoder` and every `DecompressionSettings` variant. So this is the bound
    /// that makes a decompression bomb in a repository archive harmless. A counting reader
    /// wrapped around the decoder enforces it; see `repo::archive::BoundedReader`.
    ///
    /// Defaults to exactly [`u32::MAX`]: the files arena indexes paths with `u32` offsets
    /// into a single `String` (measured 538 MiB vs ~800 MiB for `Vec<PathBuf>` on `extra`),
    /// so this is also the hard ceiling that arithmetic can address, not just a size policy.
    pub repo_inflated_bytes: u64,
    /// Maximum size in bytes of a single member (`desc` or `files`) inside a repository
    /// archive.
    pub repo_entry_bytes: u64,
    /// Maximum number of packages a repository database archive may contain.
    ///
    /// Exceeding this is a hard error, for the same reason as [`Limits::max_entries`]. It is
    /// detected **during** the archive walk rather than after it: the bound exists to stop
    /// the allocation, so it must fire before every `desc` in an oversized archive is parsed.
    pub repo_max_packages: usize,
    /// Maximum size in bytes of a `pacman.conf` file, or any file it `Include`s.
    pub pacman_conf_bytes: u64,
    /// Maximum size in bytes of an alpm `.hook` file.
    pub hook_bytes: u64,
    /// Maximum number of candidate packages a single planning run may consider.
    ///
    /// One candidate per installed package plus one per package in every configured
    /// repository. This bounds the whole problem the solver is handed, not any one database.
    /// [`Limits::repo_max_packages`] already bounds each repository on its own, but nothing
    /// bounds their *sum* — and the sum is what a solver allocates against.
    ///
    /// Measured on the machine this was developed against: 1157 installed packages plus
    /// 15 200 across `core` and `extra` — so the default leaves roughly two orders of
    /// magnitude of headroom over a large real system.
    ///
    /// A count rather than a byte size, so like [`Limits::max_entries`] it is reported
    /// through its own error ([`crate::Error::TooManySolvables`]) rather than through
    /// [`Limit`], which enumerates only the size bounds.
    pub solve_max_solvables: usize,
    /// Maximum number of conflicts the solver may resolve before giving up.
    ///
    /// This is what makes the search terminate. A hostile repository can craft a clause set
    /// with pathological backtracking behavior. "Takes forever" is not an acceptable outcome
    /// for a package manager, so the search is bounded, and exceeding the bound raises
    /// [`crate::Error::SolveBudgetExhausted`].
    ///
    /// Counted in conflicts rather than in elapsed time, so a run is reproducible. The same
    /// databases and the same targets either solve or fail identically on a fast machine and
    /// a slow one.
    ///
    /// Real dependency graphs need almost none. A plan that reproduces libalpm's greedy
    /// descent resolves zero by definition, so the default is set for headroom rather than
    /// tuned.
    pub solve_max_conflicts: usize,
    /// Maximum number of clauses a single encoding may emit.
    ///
    /// Bounds the compiled problem itself, which grows with the *product* of the reachable
    /// candidates and their relations, not with either alone. A repository whose packages
    /// each conflict with every other would emit a quadratic number of clauses from a linear
    /// number of packages. Neither [`Limits::solve_max_solvables`] nor
    /// [`Limits::repo_max_packages`] would notice.
    ///
    /// Enforced while clauses are emitted, not afterwards. An encoding crafted to explode is
    /// stopped, not merely reported once complete.
    pub solve_max_clauses: usize,
    /// Maximum number of package names one glob target may expand to.
    ///
    /// A pattern rewrites one command-line target into the names it selects. Without a bound,
    /// `piko install '*'` would hand the encoder every package a repository carries.
    ///
    /// Checked while the names accumulate, not once the scan has finished, so an oversized
    /// pattern costs one comparison per candidate rather than a full expansion and a solve.
    /// The refusal therefore carries no total: counting the matches is the work the bound
    /// declines to do. Neither [`Limits::solve_max_solvables`] nor [`Limits::solve_max_clauses`]
    /// stands in for this. The first bounds the universe rather than the request, and the
    /// second fires only once the targets are already in hand and their reachable cone
    /// computed.
    ///
    /// Measured on the machine this was developed against: 1243 installed packages, 15 252
    /// across `core` and `extra`, and a largest `%GROUPS%` group of 283 members (`pro-audio`,
    /// then `kde-applications` at 194 and `tesseract-data` at 128). So the default clears the
    /// widest legitimate single expansion — a whole group — with room to spare, while refusing
    /// `python-*` (2099 in the repositories) and `*` on any real system.
    ///
    /// A count, so like [`Limits::solve_max_solvables`] it is reported through its own error
    /// rather than through [`Limit`], which enumerates only the size bounds.
    pub glob_max_expansion: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            desc_bytes: MIB,
            files_bytes: 16 * MIB,
            mtree_compressed_bytes: 16 * MIB,
            mtree_inflated_bytes: 256 * MIB,
            schema_version_bytes: KIB,
            max_entries: 1 << 20,
            max_diagnostics: 4096,
            repo_compressed_bytes: 256 * MIB,
            repo_inflated_bytes: u64::from(u32::MAX),
            repo_entry_bytes: 64 * MIB,
            repo_max_packages: 1 << 20,
            pacman_conf_bytes: MIB,
            hook_bytes: MIB,
            solve_max_solvables: 1 << 21,
            solve_max_conflicts: 1 << 20,
            solve_max_clauses: 1 << 24,
            glob_max_expansion: 512,
        }
    }
}

impl Limits {
    /// The configured maximum for `limit`, in bytes.
    ///
    /// Public because `piko-db-write` reads through [`crate::fs_util`] and must pass the same
    /// bound the reader would have used. Looking the value up, rather than hardcoding one,
    /// keeps a writer's read subject to the same policy as a reader's.
    #[must_use]
    pub const fn get(&self, limit: Limit) -> u64 {
        match limit {
            Limit::Desc => self.desc_bytes,
            Limit::Files => self.files_bytes,
            Limit::MtreeCompressed => self.mtree_compressed_bytes,
            Limit::MtreeInflated => self.mtree_inflated_bytes,
            Limit::SchemaVersion => self.schema_version_bytes,
            Limit::RepoCompressed => self.repo_compressed_bytes,
            Limit::RepoInflated => self.repo_inflated_bytes,
            Limit::RepoEntry => self.repo_entry_bytes,
            Limit::PacmanConf => self.pacman_conf_bytes,
            Limit::Hook => self.hook_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The defaults must accommodate the largest files observed on a real system. A
    /// regression here would make piko reject a legitimately installed package.
    #[test]
    fn defaults_accommodate_observed_real_world_sizes() {
        let limits = Limits::default();
        assert!(limits.desc_bytes > 4 * KIB, "largest observed desc is 4 KiB");
        assert!(limits.files_bytes > 2 * MIB, "largest observed files is 2.0 MiB (code)");
        assert!(
            limits.mtree_compressed_bytes > MIB,
            "largest observed mtree is 833 KiB compressed"
        );
        assert!(limits.max_entries > 1166, "a real system has ~1166 entries");
        assert!(limits.max_diagnostics > 0, "a zero cap would silently discard every diagnostic");
        assert!(
            limits.repo_compressed_bytes > 50 * MIB,
            "largest observed repo archive (extra.files) is 50 MB compressed"
        );
        assert!(
            limits.repo_inflated_bytes > 581 * MIB,
            "largest observed repo archive (extra.files) is 581 MB inflated"
        );
        assert!(
            limits.repo_entry_bytes > 13 * MIB,
            "largest observed archive member (gstreamer-docs) is 12.7 MB"
        );
        assert!(limits.repo_max_packages > 14_885, "extra.db has 14 885 packages");
        assert!(limits.pacman_conf_bytes > 3 * KIB, "largest observed pacman.conf is 2.8 KB");
        assert!(
            limits.glob_max_expansion > 283,
            "the largest observed %GROUPS% group (pro-audio) has 283 members"
        );
        assert!(
            limits.glob_max_expansion < 1243,
            "a real system has 1243 installed packages; `piko remove '*'` must not expand"
        );
        assert_eq!(
            limits.repo_inflated_bytes,
            u64::from(u32::MAX),
            "this is also the arena's u32 offset ceiling, not just a size policy"
        );
    }

    #[test]
    fn get_returns_the_matching_field() {
        let limits = Limits::default();
        assert_eq!(limits.get(Limit::Desc), limits.desc_bytes);
        assert_eq!(limits.get(Limit::Files), limits.files_bytes);
        assert_eq!(limits.get(Limit::MtreeCompressed), limits.mtree_compressed_bytes);
        assert_eq!(limits.get(Limit::MtreeInflated), limits.mtree_inflated_bytes);
        assert_eq!(limits.get(Limit::SchemaVersion), limits.schema_version_bytes);
        assert_eq!(limits.get(Limit::RepoCompressed), limits.repo_compressed_bytes);
        assert_eq!(limits.get(Limit::RepoInflated), limits.repo_inflated_bytes);
        assert_eq!(limits.get(Limit::RepoEntry), limits.repo_entry_bytes);
        assert_eq!(limits.get(Limit::PacmanConf), limits.pacman_conf_bytes);
    }

    #[test]
    fn limit_names_are_stable() {
        assert_eq!(Limit::Desc.to_string(), "desc");
        assert_eq!(Limit::MtreeInflated.to_string(), "inflated mtree");
        assert_eq!(Limit::RepoInflated.to_string(), "inflated repository archive");
        assert_eq!(Limit::PacmanConf.to_string(), "pacman.conf file");
    }
}
