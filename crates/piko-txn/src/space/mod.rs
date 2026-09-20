//! `CheckSpace`: will this transaction fit?
//!
//! libalpm's `diskspace.c`, transcribed. The question is not "how much bigger does the system
//! get". An upgrade can answer that with zero and still need a gigabyte half-way through. The
//! question is "what is the **peak** occupancy, per filesystem, over the transaction's
//! timeline".
//!
//! So the accounting keeps two numbers per mount point. `blocks_needed` is the running net
//! delta. It is signed, because a removal drives it below zero. `max_blocks_needed` is the
//! highest value that delta ever reached.
//!
//! The peak is sampled at package boundaries. Every removal is credited first. Then each
//! install package subtracts the version it replaces and adds its own payload. Only then does
//! every mount point record its peak.
//!
//! Within one package the old version is credited before the new one is charged. So the moment
//! when both exist on disk at once is not modelled. That is libalpm's approximation, and
//! pacman's manual calls the whole check approximate for this reason.
//!
//! The verdict is per mount point and asks two different questions. A filesystem the
//! transaction touches at all is refused if it is mounted read only. A removal counts here:
//! deleting a file needs a writable filesystem as much as creating one does. A filesystem the
//! transaction *writes to* is then checked for space. One that only loses files is not, because
//! it can only end up emptier.
//!
//! Every refusal is collected before any is raised. So one run names every partition that is
//! in the way, rather than the first.
//!
//! Sizes come from two different places, and neither is the database's `%SIZE%`. An install is
//! measured by the archive's own member sizes, because the package is not installed yet. A
//! removal is measured by what is actually on disk. The installed size recorded in a `desc`
//! describes the build rather than this filesystem. Directories and symbolic links
//! count as zero on both sides, matching what libarchive reports for them.

pub mod mounts;

use std::{
    num::NonZeroU64,
    path::{Path, PathBuf},
};

use rustix::fs::{AtFlags, StatVfsMountFlags};

use crate::{
    error::{Error, Result},
    rootfs::RootDir,
    space::mounts::MountTable,
};

/// The cushion's flat ceiling: libalpm's `20 * 1024 * 1024`.
const TWENTY_MIB: u64 = 20 * 1024 * 1024;

/// One archive member that will occupy space, with the size the archive claims.
///
/// Collected while the archive is walked for conflict detection, because that walk is the only
/// place a not-yet-installed package's per-file sizes exist. Directories and links are not
/// collected at all: libarchive reports them as zero, so carrying them would only be work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberFootprint {
    /// The path as the archive spells it, relative to the root.
    pub path: PathBuf,
    /// Its size in bytes.
    pub size: u64,
}

/// One install step, as the disk-space estimate sees it.
#[derive(Clone, Copy, Debug)]
pub struct Install<'a> {
    /// What the incoming archive will write.
    pub footprint: &'a [MemberFootprint],
    /// The `%FILES%` of the version it replaces, if it replaces one.
    pub replaced: Option<&'a [PathBuf]>,
}

/// A filesystem that cannot hold what this transaction would write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartitionSpace {
    /// Its mount directory.
    pub mount_point: PathBuf,
    /// Blocks the peak occupancy needs, cushion included.
    pub blocks_needed: u64,
    /// Blocks available to this process.
    pub blocks_free: u64,
    /// The block size both counts are expressed in.
    pub block_size: u64,
}

impl PartitionSpace {
    /// Bytes the peak occupancy needs, cushion included.
    #[must_use]
    pub const fn bytes_needed(&self) -> u64 {
        self.blocks_needed.saturating_mul(self.block_size)
    }

    /// Bytes available to this process.
    #[must_use]
    pub const fn bytes_free(&self) -> u64 {
        self.blocks_free.saturating_mul(self.block_size)
    }
}

/// One mebibyte, the unit the message is rendered in.
const MIB: u64 = 1024 * 1024;

impl std::fmt::Display for PartitionSpace {
    /// libalpm's own message counts blocks (`diskspace.c:368`). A reader must then know this
    /// filesystem's block size to tell whether to delete a file or a gigabyte. The same two
    /// numbers are rendered in mebibytes here, rounded down so the shortfall is never
    /// understated. Both block counts and the block size stay on the struct for a caller that
    /// wants them.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} needs {} MiB, {} MiB free",
            self.mount_point.display(),
            self.bytes_needed() / MIB,
            self.bytes_free() / MIB
        )
    }
}

/// Something the estimate could not measure, which it worked around rather than failed over.
///
/// libalpm logs each of these as a warning and carries on. piko returns them instead
/// (`crate`'s "diagnostics are returned, never logged"), so the caller decides whether a user
/// sees them. None of them is an error. An estimate that refuses to run at all is strictly
/// worse than one that misses a few files' worth of blocks.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Problem {
    /// No mount point covers this path, so nothing was charged for it.
    MountPointUnknown {
        /// The path.
        path: PathBuf,
    },
    /// This filesystem's free space could not be read, so everything on it was skipped.
    MountUnreadable {
        /// Its mount directory.
        mount_point: PathBuf,
        /// Why `statvfs` refused.
        reason: String,
    },
    /// A file to be removed could not be stat'ed, so its size was not credited back.
    FileUnreadable {
        /// The path, relative to the root.
        path: PathBuf,
    },
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MountPointUnknown { path } => {
                write!(f, "could not determine the mount point for {}", path.display())
            }
            Self::MountUnreadable { mount_point, reason } => write!(
                f,
                "could not read filesystem information for {}: {reason}",
                mount_point.display()
            ),
            Self::FileUnreadable { path } => {
                write!(f, "could not read file information for {}", path.display())
            }
        }
    }
}

/// What one mount point's free space looks like.
#[derive(Clone, Copy, Debug)]
struct Stats {
    /// `f_bsize`, which is one unit for two purposes here. File sizes are rounded up to it,
    /// and `available` and `blocks` are counted in it. On Linux, rustix copies all three
    /// verbatim out of `statfs`. Reaching for `f_frsize` would compare two different units.
    block_size: NonZeroU64,
    /// `f_blocks`, the filesystem's capacity. Only the cushion reads it.
    blocks: u64,
    /// `f_bavail`. Not `f_bfree`: libalpm treats the root reserve as unusable even though it
    /// runs as root, and piko keeps that.
    available: u64,
    /// Whether the filesystem is mounted read only.
    read_only: bool,
}

/// Whether a mount point's `statvfs` has been attempted yet, and what came of it.
///
/// Loaded lazily, per mount point, the first time a file lands on it. A machine with a hung
/// network mount that this transaction does not touch is never made to wait for it.
#[derive(Clone, Copy, Debug)]
enum Fsinfo {
    Unloaded,
    Failed,
    Loaded(Stats),
}

/// What the transaction has been charged to one mount point.
#[derive(Clone, Copy, Debug)]
struct Entry {
    fsinfo: Fsinfo,
    /// The running net delta, in blocks. Negative while removals outweigh installs.
    blocks_needed: i64,
    /// The highest value `blocks_needed` has reached.
    max_blocks_needed: i64,
    /// Whether an install has written here.
    installs: bool,
    /// Whether a removal has freed space here.
    removes: bool,
}

impl Entry {
    const fn new() -> Self {
        Self {
            fsinfo: Fsinfo::Unloaded,
            blocks_needed: 0,
            max_blocks_needed: 0,
            installs: false,
            removes: false,
        }
    }

    /// Whether the transaction touches this filesystem at all — libalpm's `used`.
    const fn used(&self) -> bool {
        self.installs || self.removes
    }
}

/// The per-mount-point accounting, over one mount table.
#[derive(Debug)]
struct Ledger {
    table: MountTable,
    entries: Vec<Entry>,
    problems: Vec<Problem>,
}

impl Ledger {
    fn new(table: MountTable) -> Self {
        let entries = vec![Entry::new(); table.count()];
        Self { table, entries, problems: Vec::new() }
    }

    /// The mount point `path` belongs to, with its free space loaded.
    ///
    /// `None` when the path maps to nothing, or when the filesystem could not be read. Both
    /// are recorded as problems the first time they happen and skipped silently after.
    fn locate(&mut self, path: &Path) -> Option<usize> {
        let index = match self.table.match_point(path) {
            Some(index) => index,
            None => {
                self.problems.push(Problem::MountPointUnknown { path: path.to_path_buf() });
                return None;
            }
        };
        let entry = self.entries.get_mut(index)?;
        match entry.fsinfo {
            Fsinfo::Loaded(_) => Some(index),
            Fsinfo::Failed => None,
            Fsinfo::Unloaded => {
                let dir = self.table.dir(index)?.to_path_buf();
                match read_stats(&dir) {
                    Ok(stats) => {
                        entry.fsinfo = Fsinfo::Loaded(stats);
                        Some(index)
                    }
                    Err(reason) => {
                        entry.fsinfo = Fsinfo::Failed;
                        self.problems.push(Problem::MountUnreadable { mount_point: dir, reason });
                        None
                    }
                }
            }
        }
    }

    /// Charges `size` bytes to whichever filesystem holds `path`.
    ///
    /// `installing` says which of the two `used` flags this sets, and which way the delta
    /// moves. An install adds blocks. A removal gives them back.
    fn charge(&mut self, path: &Path, size: u64, installing: bool) {
        let Some(index) = self.locate(path) else { return };
        let Some(entry) = self.entries.get_mut(index) else { return };
        let Fsinfo::Loaded(stats) = entry.fsinfo else { return };
        let blocks = blocks_for(size, stats.block_size);
        if installing {
            entry.blocks_needed = entry.blocks_needed.saturating_add(blocks);
            entry.installs = true;
        } else {
            entry.blocks_needed = entry.blocks_needed.saturating_sub(blocks);
            entry.removes = true;
        }
    }

    /// Records the current delta as the peak, on every mount point at once.
    ///
    /// Called once per install package, never per file. A package writing to four filesystems
    /// produces four independent peaks from the one call.
    fn sample_peaks(&mut self) {
        for entry in &mut self.entries {
            entry.max_blocks_needed = entry.max_blocks_needed.max(entry.blocks_needed);
        }
    }

    /// Every filesystem that is in the way, by either of the two rules.
    fn verdict(&self) -> (Vec<PartitionSpace>, Vec<PathBuf>) {
        let mut too_full = Vec::new();
        let mut read_only = Vec::new();
        for (index, entry) in self.entries.iter().enumerate() {
            let Fsinfo::Loaded(stats) = entry.fsinfo else { continue };
            let Some(dir) = self.table.dir(index) else { continue };
            if entry.used() && stats.read_only {
                read_only.push(dir.to_path_buf());
            } else if entry.installs {
                too_full.extend(shortfall(dir, entry.max_blocks_needed, &stats));
            }
        }
        (too_full, read_only)
    }
}

/// Reads one mount directory's free space.
fn read_stats(mount_point: &Path) -> std::result::Result<Stats, String> {
    let fs = rustix::fs::statvfs(mount_point).map_err(|error| error.to_string())?;
    let block_size = NonZeroU64::new(fs.f_bsize)
        .ok_or_else(|| "the filesystem reports a block size of zero".to_owned())?;
    Ok(Stats {
        block_size,
        blocks: fs.f_blocks,
        available: fs.f_bavail,
        // On Linux this flag comes from `statfs`'s `f_flags`, where `ST_RDONLY` and `MS_RDONLY`
        // are the same bit. A kernel too old to report mount flags leaves it clear, which
        // reads as "writable". That is a missed refusal rather than a false one.
        read_only: fs.f_flag.contains(StatVfsMountFlags::RDONLY),
    })
}

/// `size` rounded up to whole blocks, as a signed count the ledger can subtract.
fn blocks_for(size: u64, block_size: NonZeroU64) -> i64 {
    i64::try_from(size.div_ceil(block_size.get())).unwrap_or(i64::MAX)
}

/// The margin libalpm leaves free: roughly `min(5% of capacity, 20 MiB)`.
///
/// Despite how it reads, this is a flat 20 MiB on any filesystem bigger than about 400 MiB.
/// The 5% term only takes over on a very small one.
fn cushion(stats: &Stats) -> u64 {
    let five_percent = (stats.blocks / 20).saturating_add(1);
    // `NonZeroU64` already rules out the division by zero; `checked_div` is how that is
    // spelled under the workspace's ban on bare arithmetic operators.
    let twenty_mib = TWENTY_MIB.checked_div(stats.block_size.get()).unwrap_or(0).saturating_add(1);
    five_percent.min(twenty_mib)
}

/// How much `peak` overruns what is available, or `None` if it fits.
fn shortfall(mount_point: &Path, peak: i64, stats: &Stats) -> Option<PartitionSpace> {
    let needed = peak.saturating_add_unsigned(cushion(stats));
    // A transaction that nets out smaller leaves `peak` negative, and a negative requirement
    // always fits. libalpm guards the same case, because the comparison below casts.
    let needed = u64::try_from(needed).ok()?;
    (needed > stats.available).then(|| PartitionSpace {
        mount_point: mount_point.to_path_buf(),
        blocks_needed: needed,
        blocks_free: stats.available,
        block_size: stats.block_size.get(),
    })
}

/// Refuses the transaction unless every filesystem it writes to can hold its peak occupancy.
///
/// `root` must be the canonical host path of the transaction's root. The mount table is the
/// host's, so a relative or symlinked root would match nothing.
///
/// `rootfs` is that same root as an open directory. It stats a file that is going away without
/// following a symlink out of the root.
///
/// `skips_extraction` answers `NoExtract`. libalpm does not consult it here. It charges for
/// bytes its own extraction will then decline to write. piko does not count what it will not
/// write.
///
/// Returns the problems it worked around. None of them is a failure.
///
/// # Errors
///
/// [`Error::DiskSpace`] if any filesystem is too full or mounted read only. Every offender is
/// named, not just the first. [`Error::MountTableUnreadable`] if the root maps to no mount
/// point at all. That means the table describes a different system than the one being written
/// to.
pub fn check_install(
    table: MountTable,
    root: &Path,
    rootfs: &RootDir,
    removals: &[&[PathBuf]],
    installs: &[Install<'_>],
    skips_extraction: &dyn Fn(&Path) -> bool,
) -> Result<Vec<Problem>> {
    let mut ledger = Ledger::new(table);
    // libalpm resolves the root's own mount point first and fails if it finds none, then never
    // looks at the answer again. It is a coherence check on the table, not an input.
    if ledger.table.match_point(root).is_none() {
        return Err(Error::MountTableUnreadable {
            path: root.to_path_buf(),
            reason: "no mount point covers the transaction root".to_owned(),
        });
    }

    // Every removal is credited before any install is charged. That is the order the commit
    // runs in. A replaced or conflicting package is gone before the next archive is
    // extracted.
    for files in removals {
        credit_removal(&mut ledger, root, rootfs, files);
    }

    for install in installs {
        if let Some(replaced) = install.replaced {
            credit_removal(&mut ledger, root, rootfs, replaced);
        }
        for member in install.footprint {
            if skips_extraction(&member.path) {
                continue;
            }
            ledger.charge(&root.join(&member.path), member.size, true);
        }
        ledger.sample_peaks();
    }

    let (too_full, read_only) = ledger.verdict();
    if too_full.is_empty() && read_only.is_empty() {
        Ok(ledger.problems)
    } else {
        Err(Error::DiskSpace { too_full, read_only })
    }
}

/// Gives back the blocks a package's installed files currently occupy.
fn credit_removal(ledger: &mut Ledger, root: &Path, rootfs: &RootDir, files: &[PathBuf]) {
    for file in files {
        // `%FILES%` spells a directory with a trailing slash, and a directory counts as zero.
        // The slash saves a stat here. A path without it that turns out to be a directory is
        // caught by its mode below.
        if file.as_os_str().as_encoded_bytes().last() == Some(&b'/') {
            continue;
        }
        let Some(size) = on_disk_size(rootfs, file) else {
            ledger.problems.push(Problem::FileUnreadable { path: file.clone() });
            continue;
        };
        let Some(size) = size else { continue };
        ledger.charge(&root.join(file), size, false);
    }
}

/// The size `file` occupies under `rootfs`, `None` if it cannot be stat'ed.
///
/// The inner `None` means "found, but counts as zero". That is a directory or a symbolic
/// link, which libarchive reports as zero-sized and libalpm therefore skips.
///
/// Resolution goes component by component through the root's own descent, not through a
/// concatenated path. libalpm uses a plain `lstat` here. piko already owns the descent that
/// stops a planted symlink from redirecting the answer. An estimate built on a redirected
/// answer is an estimate an attacker chose.
fn on_disk_size(rootfs: &RootDir, file: &Path) -> Option<Option<u64>> {
    let resolved = rootfs.resolve_parent(file).ok()?;
    let stat =
        rustix::fs::statat(resolved.dir(), resolved.name(), AtFlags::SYMLINK_NOFOLLOW).ok()?;
    let kind = rustix::fs::FileType::from_raw_mode(stat.st_mode);
    if matches!(kind, rustix::fs::FileType::Directory | rustix::fs::FileType::Symlink) {
        return Some(None);
    }
    Some(Some(u64::try_from(stat.st_size).unwrap_or(0)))
}

/// Refuses a batch of downloads unless the directory receiving them can hold it.
///
/// `sizes` are the bytes still to be fetched. A package already in the cache contributes
/// nothing, because it is not in the batch.
///
/// Unlike [`check_install`], every problem here is fatal. There is one directory and one
/// filesystem, so "worked around it" would mean checking nothing at all.
///
/// # Errors
///
/// [`Error::DiskSpace`] if the filesystem cannot hold the batch.
/// [`Error::MountTableUnreadable`] covers three cases. The table cannot be read, no mount
/// point covers the directory, or that filesystem's free space cannot be read.
pub fn check_download(directory: &Path, sizes: impl IntoIterator<Item = u64>) -> Result<()> {
    let table = MountTable::load()?;
    // libalpm resolves this path and only this one. So a symlinked cache directory is
    // charged to the filesystem that actually receives the bytes. A failure falls back to the
    // unresolved path, as it does there.
    let resolved = std::fs::canonicalize(directory).unwrap_or_else(|_| directory.to_path_buf());
    let index = table.match_point(&resolved).ok_or_else(|| Error::MountTableUnreadable {
        path: resolved.clone(),
        reason: "no mount point covers the download directory".to_owned(),
    })?;
    let Some(mount_point) = table.dir(index) else {
        return Err(Error::MountTableUnreadable {
            path: resolved,
            reason: "no mount point covers the download directory".to_owned(),
        });
    };
    let stats = read_stats(mount_point).map_err(|reason| Error::MountTableUnreadable {
        path: mount_point.to_path_buf(),
        reason,
    })?;

    // There is no interleaving to model: a download only ever grows the cache, so the running
    // total is the peak. No read-only check either — the directory was already proved writable
    // by the selection that chose it.
    let mut peak: i64 = 0;
    for size in sizes {
        peak = peak.saturating_add(blocks_for(size, stats.block_size));
    }

    match shortfall(mount_point, peak, &stats) {
        Some(partition) => {
            Err(Error::DiskSpace { too_full: vec![partition], read_only: Vec::new() })
        }
        None => Ok(()),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    const BSIZE: u64 = 4096;

    fn block_size() -> NonZeroU64 {
        NonZeroU64::new(BSIZE).unwrap()
    }

    fn stats(blocks: u64, available: u64) -> Stats {
        Stats { block_size: block_size(), blocks, available, read_only: false }
    }

    #[test]
    fn a_size_is_rounded_up_to_whole_blocks() {
        assert_eq!(blocks_for(0, block_size()), 0);
        assert_eq!(blocks_for(1, block_size()), 1);
        assert_eq!(blocks_for(BSIZE, block_size()), 1);
        assert_eq!(blocks_for(BSIZE + 1, block_size()), 2);
    }

    #[test]
    fn the_cushion_is_a_flat_twenty_mib_on_any_ordinary_filesystem() {
        // 100 GiB. Five percent would be 1 310 720 blocks; the 20 MiB term is 5121.
        let big = stats(100 * 1024 * 1024 * 1024 / BSIZE, 0);
        assert_eq!(cushion(&big), TWENTY_MIB / BSIZE + 1);
    }

    #[test]
    fn the_cushion_degrades_to_five_percent_on_a_tiny_filesystem() {
        // 40 MiB: five percent is 512 blocks, well under the 5121-block flat term.
        let small = stats(40 * 1024 * 1024 / BSIZE, 0);
        assert_eq!(cushion(&small), (40 * 1024 * 1024 / BSIZE) / 20 + 1);
    }

    #[test]
    fn a_zero_block_size_is_refused_rather_than_divided_by() {
        assert!(NonZeroU64::new(0).is_none());
    }

    #[test]
    fn a_requirement_that_fits_reports_no_shortfall() {
        let fs = stats(1 << 20, 1 << 20);
        assert_eq!(shortfall(Path::new("/"), 10, &fs), None);
    }

    #[test]
    fn a_requirement_that_overruns_reports_both_numbers() {
        let fs = stats(1 << 20, 100);
        let partition = shortfall(Path::new("/"), 10_000, &fs).unwrap();
        assert_eq!(partition.blocks_free, 100);
        assert_eq!(partition.blocks_needed, 10_000 + cushion(&fs));
        assert_eq!(partition.block_size, BSIZE);
    }

    #[test]
    fn a_net_negative_transaction_always_fits() {
        // A removal-heavy transaction drives the peak below zero. The cushion must not turn
        // that into a huge unsigned requirement, which is what libalpm's `needed >= 0` guards.
        let fs = stats(1 << 20, 0);
        assert_eq!(shortfall(Path::new("/"), i64::MIN, &fs), None);
        assert_eq!(shortfall(Path::new("/"), -1_000_000, &fs), None);
    }

    /// The table used by the ledger tests: one root, one separate `/boot`.
    fn ledger() -> Ledger {
        let table = MountTable::parse(b"x / ext4 rw 0 0\nx /boot vfat rw 0 0\n");
        let mut ledger = Ledger::new(table);
        for entry in &mut ledger.entries {
            entry.fsinfo = Fsinfo::Loaded(stats(1 << 20, 1 << 20));
        }
        ledger
    }

    fn index_of(ledger: &Ledger, dir: &str) -> usize {
        ledger.table.match_point(Path::new(dir)).unwrap()
    }

    #[test]
    fn the_peak_is_what_is_checked_not_the_final_balance() {
        // Three packages. The first installs 100 blocks' worth, the second replaces a 100-block
        // package with a 1-block one, the third the same. The balance ends at 3 blocks, but the
        // peak reached 100 — and 100 is what a filesystem has to hold.
        let mut ledger = ledger();
        let root = index_of(&ledger, "/");

        ledger.charge(Path::new("/one"), 100 * BSIZE, true);
        ledger.sample_peaks();
        ledger.charge(Path::new("/one"), 100 * BSIZE, false);
        ledger.charge(Path::new("/two"), BSIZE, true);
        ledger.sample_peaks();
        ledger.charge(Path::new("/three"), BSIZE, true);
        ledger.sample_peaks();

        assert_eq!(ledger.entries[root].blocks_needed, 2);
        assert_eq!(ledger.entries[root].max_blocks_needed, 100);
    }

    #[test]
    fn a_filesystem_that_only_loses_files_is_never_checked_for_space() {
        let mut ledger = ledger();
        let boot = index_of(&ledger, "/boot");
        ledger.entries[boot].fsinfo = Fsinfo::Loaded(stats(1 << 20, 0));
        ledger.charge(Path::new("/boot/vmlinuz"), 100 * BSIZE, false);
        ledger.sample_peaks();

        let (too_full, read_only) = ledger.verdict();
        assert!(too_full.is_empty(), "a removal cannot fill a partition: {too_full:?}");
        assert!(read_only.is_empty());
    }

    #[test]
    fn a_read_only_filesystem_is_refused_even_when_only_a_removal_touches_it() {
        let mut ledger = ledger();
        let boot = index_of(&ledger, "/boot");
        ledger.entries[boot].fsinfo =
            Fsinfo::Loaded(Stats { read_only: true, ..stats(1 << 20, 1 << 20) });
        ledger.charge(Path::new("/boot/vmlinuz"), BSIZE, false);

        let (too_full, read_only) = ledger.verdict();
        assert!(too_full.is_empty());
        assert_eq!(read_only, vec![PathBuf::from("/boot")]);
    }

    #[test]
    fn a_read_only_filesystem_is_reported_as_read_only_rather_than_as_too_full() {
        // libalpm's `else if`. The two verdicts never fire for the same mount point.
        // "Mounted read only" is the one that explains what to do about it.
        let mut ledger = ledger();
        let root = index_of(&ledger, "/");
        ledger.entries[root].fsinfo =
            Fsinfo::Loaded(Stats { read_only: true, ..stats(1 << 20, 0) });
        ledger.charge(Path::new("/usr/bin/ls"), 1_000_000 * BSIZE, true);
        ledger.sample_peaks();

        let (too_full, read_only) = ledger.verdict();
        assert!(too_full.is_empty(), "{too_full:?}");
        assert_eq!(read_only, vec![PathBuf::from("/")]);
    }

    #[test]
    fn every_partition_in_the_way_is_reported_not_just_the_first() {
        let mut ledger = ledger();
        for entry in &mut ledger.entries {
            entry.fsinfo = Fsinfo::Loaded(stats(1 << 20, 0));
        }
        ledger.charge(Path::new("/usr/bin/ls"), 100 * BSIZE, true);
        ledger.charge(Path::new("/boot/vmlinuz"), 100 * BSIZE, true);
        ledger.sample_peaks();

        let (too_full, _) = ledger.verdict();
        assert_eq!(too_full.len(), 2, "{too_full:?}");
    }

    #[test]
    fn a_path_under_no_mount_point_is_reported_and_charged_nowhere() {
        let table = MountTable::parse(b"x /boot vfat rw 0 0\n");
        let mut ledger = Ledger::new(table);
        ledger.charge(Path::new("/usr/bin/ls"), BSIZE, true);
        assert_eq!(
            ledger.problems,
            vec![Problem::MountPointUnknown { path: PathBuf::from("/usr/bin/ls") }]
        );
        let (too_full, read_only) = ledger.verdict();
        assert!(too_full.is_empty());
        assert!(read_only.is_empty());
    }

    #[test]
    fn a_filesystem_whose_stats_failed_is_excluded_rather_than_guessed_at() {
        let mut ledger = ledger();
        let root = index_of(&ledger, "/");
        ledger.entries[root].fsinfo = Fsinfo::Failed;
        ledger.charge(Path::new("/usr/bin/ls"), 1_000_000 * BSIZE, true);
        ledger.sample_peaks();

        assert_eq!(ledger.entries[root].blocks_needed, 0);
        assert!(ledger.verdict().0.is_empty());
    }
}
