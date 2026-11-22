//! The [`Message`] of each error this crate returns, for a frontend that renders it in the
//! language of its user.
//!
//! Each message renders in English exactly as the type's `Display` writes it. The tests below
//! build one value of every variant and compare the two.
//!
//! A reason this crate carries as a `String` stays English: what a hook, a server, GnuPG or the
//! system said. It is quoted as it is.

use piko_i18n::{Arg, Localize, Message};

use crate::conflict::{Blocker, FileConflict};
use crate::error::{
    Discarded, Error, IoAction, MAX_SHOWN, MemberType, Obstacle, PackageLimit, SignatureRefusal,
    said, shown,
};
use crate::extract::decision::RefuseReason;
use crate::journal::Unreadable;
use crate::rootfs::UnsafePath;
use crate::source::{RejectedCacheDir, RejectionReason, SkipReason, Skipped};
use crate::space::PartitionSpace;

/// One mebibyte, the unit [`PartitionSpace`] is rendered in.
const MIB: u64 = 1024 * 1024;

/// `texts` as one text, each one separated by `separator`.
fn listed<T: ToString>(texts: impl IntoIterator<Item = T>, separator: &str) -> String {
    texts.into_iter().map(|each| each.to_string()).collect::<Vec<_>>().join(separator)
}

/// The items of a list cut at [`MAX_SHOWN`], and a last item that counts the rest.
fn bounded(mut items: Vec<Message>, total: usize) -> Vec<Message> {
    let more = total.saturating_sub(MAX_SHOWN);
    if more > 0 {
        items.push(Message::new("txn-more").arg("count", more));
    }
    items
}

impl Localize for Error {
    fn message(&self) -> Message {
        match self {
            Self::Io { path, action, .. } => {
                let id = match action {
                    IoAction::Metadata => "txn-error-io-stat",
                    IoAction::Open => "txn-error-io-open",
                    IoAction::Read => "txn-error-io-read",
                    IoAction::CreateDir => "txn-error-io-create-dir",
                    IoAction::Decompress => "txn-error-io-decompress",
                    IoAction::Create => "txn-error-io-create",
                    IoAction::Write => "txn-error-io-write",
                    IoAction::Remove => "txn-error-io-remove",
                    IoAction::Rename => "txn-error-io-rename",
                    IoAction::Sync => "txn-error-io-sync",
                    IoAction::Chown => "txn-error-io-chown",
                };
                Message::new(id).arg("path", shown(path))
            }
            Self::NotAvailable { file_name, searched, skipped } => {
                let searched = listed(searched.iter().map(|path| shown(path)), ", ");
                if skipped.is_empty() {
                    Message::new("txn-error-not-available")
                        .arg("file_name", file_name.as_str())
                        .arg("searched", searched)
                } else {
                    let rejected = skipped.iter().map(Localize::message);
                    Message::new("txn-error-not-available-rejected")
                        .arg("file_name", file_name.as_str())
                        .arg("searched", searched)
                        .arg("rejected", Arg::list(rejected, "txn-join-comma"))
                }
            }
            Self::UnsupportedMemberType { path, member, kind } => {
                Message::new("txn-error-unsupported-member-type")
                    .arg("path", shown(path))
                    .arg("member", shown(member))
                    .arg("kind", kind.message())
            }
            Self::HardLinkOutsidePackage { path, member, target } => {
                Message::new("txn-error-hard-link-outside-package")
                    .arg("path", shown(path))
                    .arg("member", shown(member))
                    .arg("target", shown(target))
            }
            Self::UnusableMemberOwner { member, uid, gid } => {
                Message::new("txn-error-unusable-member-owner")
                    .arg("member", shown(member))
                    .arg("uid", uid.to_string())
                    .arg("gid", gid.to_string())
            }
            Self::UnsafeArchivePath { path, reason } => {
                Message::new("txn-error-unsafe-archive-path")
                    .arg("path", shown(path))
                    .arg("reason", reason.message())
            }
            Self::PathEscapesRoot { path, component, reason } => {
                Message::new("txn-error-path-escapes-root")
                    .arg("path", shown(path))
                    .arg("component", shown(component))
                    .arg("reason", reason.message())
            }
            Self::PackageLimitExceeded { path, limit, max } => {
                Message::new("txn-error-package-limit-exceeded")
                    .arg("path", shown(path))
                    .arg("limit", limit.message())
                    .arg("max", *max)
            }
            Self::UnsupportedCompression { path, format } => {
                Message::new("txn-error-unsupported-compression")
                    .arg("path", shown(path))
                    .arg("format", format.message())
            }
            Self::UnsupportedPackageCompression { packages } => {
                let packages = packages.iter().map(|(name, format)| {
                    Message::new("txn-name-format")
                        .arg("name", name.as_str())
                        .arg("format", format.message())
                });
                Message::new("txn-error-unsupported-package-compression")
                    .arg("packages", Arg::list(packages, "txn-join-comma"))
            }
            Self::ExtractionRefused { path, reason } => {
                Message::new("txn-error-extraction-refused")
                    .arg("path", shown(path))
                    .arg("reason", reason.message())
            }
            Self::FileConflicts { conflicts } => {
                let shown: Vec<Message> =
                    conflicts.iter().take(MAX_SHOWN).map(Localize::message).collect();
                Message::new("txn-error-file-conflicts")
                    .arg("count", conflicts.len())
                    .arg("list", Arg::list(bounded(shown, conflicts.len()), "txn-join-lines"))
            }
            Self::UnreadableEntry { entry, reason } => Message::new("txn-error-unreadable-entry")
                .arg("entry", entry.as_str())
                .arg("reason", said(reason)),
            Self::HookAborted { hook, reason, output } => {
                let output: String = output.iter().map(|line| format!("\n  {line}")).collect();
                Message::new("txn-error-hook-aborted")
                    .arg("hook", hook.as_str())
                    .arg("reason", said(reason))
                    .arg("output", output)
            }
            Self::HooksUnusable { problems } => {
                let problems: String =
                    problems.iter().map(|problem| format!("\n  {}", said(problem))).collect();
                Message::new("txn-error-hooks-unusable").arg("problems", problems)
            }
            Self::Cancelled { completed, total } => Message::new("txn-error-cancelled")
                .arg("completed", *completed)
                .arg("total", *total),
            Self::SignatureRejected { package, refusal, discarded, .. } => {
                Message::new("txn-error-signature-rejected")
                    .arg("package", shown(package))
                    .arg("reason", refusal.message())
                    .arg("discarded", discarded.message())
            }
            Self::SignatureUncheckable { package, error } => {
                Message::new("txn-error-signature-uncheckable")
                    .arg("package", shown(package))
                    .arg("reason", error.message())
            }
            Self::ChecksumMismatch { package, found, published, discarded } => {
                Message::new("txn-error-checksum-mismatch")
                    .arg("package", shown(package))
                    .arg("found", found.as_str())
                    .arg("published", published.as_str())
                    .arg("discarded", discarded.message())
            }
            Self::Database(error) => error.message(),
            Self::Download(error) => error.message(),
            Self::LocalDatabaseUnreadable { path, .. } => {
                Message::new("txn-error-local-database-unreadable").arg("path", shown(path))
            }
            Self::DiskSpace { too_full, read_only } => {
                let lines = too_full.iter().take(MAX_SHOWN).map(Localize::message).chain(
                    read_only
                        .iter()
                        .take(MAX_SHOWN)
                        .map(|path| Message::new("txn-read-only").arg("path", shown(path))),
                );
                Message::new("txn-error-disk-space").arg("list", Arg::list(lines, "txn-join-lines"))
            }
            Self::MountTableUnreadable { path, reason } => {
                Message::new("txn-error-mount-table-unreadable")
                    .arg("path", shown(path))
                    .arg("reason", said(reason))
            }
            Self::NoWritableCacheDir { rejected } => {
                let rejected = rejected.iter().map(Localize::message);
                Message::new("txn-error-no-writable-cache-dir")
                    .arg("rejected", Arg::list(rejected, "txn-join-semicolon"))
            }
            Self::PlanStale { name, planned, installed } => {
                let planned = planned
                    .as_deref()
                    .map_or_else(|| Message::new("txn-stale-not-installed").into(), Arg::from);
                match installed {
                    Some(installed) => Message::new("txn-error-plan-stale")
                        .arg("name", name.as_str())
                        .arg("planned", planned)
                        .arg("installed", installed.as_str()),
                    None => Message::new("txn-error-plan-stale-nothing-installed")
                        .arg("name", name.as_str())
                        .arg("planned", planned),
                }
            }
            Self::UnusableSource { path, reason } => Message::new("txn-error-unusable-source")
                .arg("path", shown(path))
                .arg("reason", said(reason)),
            Self::PlanInconsistent { id } => {
                Message::new("txn-error-plan-inconsistent").arg("id", format!("{id:?}"))
            }
            Self::NotARemoval => Message::new("txn-error-not-a-removal"),
            Self::NoRepositoryCandidate { name } => {
                Message::new("txn-error-no-repository-candidate").arg("name", name.as_str())
            }
            Self::RepositoryPackageUnreadable { name, .. } => {
                Message::new("txn-error-repository-package-unreadable").arg("name", name.as_str())
            }
            Self::WrongArchitecture { packages, configured } => {
                let configured = configured
                    .iter()
                    .map(|each| Message::new("txn-error-quoted").arg("text", each.as_str()));
                Message::new("txn-error-wrong-architecture")
                    .arg("configured", Arg::list(configured, "txn-join-or"))
                    .arg("packages", listed(packages, ", "))
            }
            Self::DuplicateTarget { package, first, second } => {
                Message::new("txn-error-duplicate-target")
                    .arg("package", package.as_str())
                    .arg("first", shown(first))
                    .arg("second", shown(second))
            }
            Self::InvalidPackageUrl { url, reason } => {
                Message::new("txn-error-invalid-package-url")
                    .arg("url", url.as_str())
                    .arg("reason", said(reason))
            }
            Self::UrlNotLoaded { url } => {
                Message::new("txn-error-url-not-loaded").arg("url", said(url))
            }
            Self::KeyringUnusable { path, .. } => {
                Message::new("txn-error-keyring-unusable").arg("path", shown(path))
            }
            Self::JournalUnreadable { path, reason } => {
                Message::new("txn-error-journal-unreadable")
                    .arg("path", shown(path))
                    .arg("reason", reason.message())
            }
            Self::UnconfiguredSource { package, reason } => {
                Message::new("txn-error-unconfigured-source")
                    .arg("package", package.as_str())
                    .arg("reason", said(reason))
            }
            Self::UnfinishedTransaction { path } => {
                Message::new("txn-error-unfinished-transaction").arg("path", shown(path))
            }
            Self::EmptyOwnerTarget => Message::new("txn-error-empty-owner-target"),
        }
    }
}

impl Localize for Skipped {
    fn message(&self) -> Message {
        Message::new("txn-skipped")
            .arg("path", self.path.display().to_string())
            .arg("reason", self.reason.message())
    }
}

impl Localize for SkipReason {
    fn message(&self) -> Message {
        match self {
            Self::NotARegularFile => Message::new("txn-skip-not-a-regular-file"),
            Self::Unreadable => Message::new("txn-skip-unreadable"),
            Self::SymbolicLink => Message::new("txn-skip-symbolic-link"),
            Self::Untrusted { path, distrust } => Message::new("txn-untrusted")
                .arg("path", path.display().to_string())
                .arg("distrust", distrust.message()),
        }
    }
}

impl Localize for RejectedCacheDir {
    fn message(&self) -> Message {
        Message::new("txn-rejected-cache-dir")
            .arg("path", self.path.display().to_string())
            .arg("reason", self.reason.message())
    }
}

impl Localize for RejectionReason {
    fn message(&self) -> Message {
        match self {
            Self::NotADirectory => Message::new("txn-rejection-not-a-directory"),
            Self::NotWritable => Message::new("txn-rejection-not-writable"),
            Self::NoWriteBits => Message::new("txn-rejection-no-write-bits"),
            Self::CreateFailed(kind) => {
                Message::new("txn-rejection-create-failed").arg("kind", kind.to_string())
            }
            Self::Untrusted { path, distrust } => Message::new("txn-untrusted")
                .arg("path", path.display().to_string())
                .arg("distrust", distrust.message()),
            Self::Untestable => Message::new("txn-rejection-untestable"),
        }
    }
}

impl Localize for UnsafePath {
    fn message(&self) -> Message {
        Message::new(match self {
            Self::Absolute => "txn-unsafe-absolute",
            Self::ParentTraversal => "txn-unsafe-parent-traversal",
            Self::CurrentDirectory => "txn-unsafe-current-directory",
            Self::Empty => "txn-unsafe-empty",
            Self::Blank => "txn-unsafe-blank",
            Self::InvalidComponent => "txn-unsafe-invalid-component",
            Self::NotUtf8 => "txn-unsafe-not-utf8",
        })
    }
}

impl Localize for RefuseReason {
    fn message(&self) -> Message {
        Message::new(match self {
            Self::DirectoryInTheWay => "txn-refuse-directory-in-the-way",
        })
    }
}

impl Localize for FileConflict {
    fn message(&self) -> Message {
        Message::new("txn-file-conflict")
            .arg("package", self.package.as_str())
            .arg("path", shown(&self.path))
            .arg("blocker", self.blocker.message())
    }
}

impl Localize for Blocker {
    fn message(&self) -> Message {
        match self {
            Self::Target { other } => {
                Message::new("txn-blocker-target").arg("other", other.as_str())
            }
            Self::Filesystem { owner: Some(owner) } => {
                Message::new("txn-blocker-owned").arg("owner", owner.as_str())
            }
            Self::Filesystem { owner: None } => Message::new("txn-blocker-exists"),
            Self::Unreachable { component, reason } => Message::new("txn-blocker-unreachable")
                .arg("component", shown(component))
                .arg("reason", reason.message()),
        }
    }
}

impl Localize for MemberType {
    fn message(&self) -> Message {
        Message::new(match self {
            Self::CharacterDevice => "txn-member-character-device",
            Self::BlockDevice => "txn-member-block-device",
            Self::Fifo => "txn-member-fifo",
            Self::ContiguousFile => "txn-member-contiguous-file",
            Self::GnuSparseFile => "txn-member-gnu-sparse-file",
            Self::PaxGlobalHeader => "txn-member-pax-global-header",
            Self::Unknown => "txn-member-unknown",
        })
    }
}

impl Localize for Obstacle {
    fn message(&self) -> Message {
        Message::new(match self {
            Self::Symlink => "txn-obstacle-symlink",
            Self::NotADirectory => "txn-obstacle-not-a-directory",
            Self::Unexaminable => "txn-obstacle-unexaminable",
        })
    }
}

impl Localize for PackageLimit {
    fn message(&self) -> Message {
        Message::new(match self {
            Self::CompressedSize => "txn-limit-compressed-size",
            Self::InflatedSize => "txn-limit-inflated-size",
            Self::DeclaredSize => "txn-limit-declared-size",
            Self::MemberCount => "txn-limit-member-count",
            Self::XattrCount => "txn-limit-xattr-count",
            Self::XattrSize => "txn-limit-xattr-size",
            Self::ScriptletSize => "txn-limit-scriptlet-size",
            Self::PkgInfoSize => "txn-limit-pkginfo-size",
            Self::MergeBaseSize => "txn-limit-merge-base-size",
            Self::BackupFileSize => "txn-limit-backup-file-size",
            Self::SignatureSize => "txn-limit-signature-size",
        })
    }
}

impl Localize for SignatureRefusal {
    fn message(&self) -> Message {
        match self {
            Self::Policy(rejection) => rejection.message(),
            Self::NotBase64 { reason } => {
                Message::new("txn-refusal-not-base64").arg("reason", said(reason))
            }
        }
    }
}

impl Localize for Discarded {
    fn message(&self) -> Message {
        match self {
            Self::No => Message::new("txn-discarded-no"),
            Self::Removed => Message::new("txn-discarded-removed"),
            Self::Failed { reason } => {
                Message::new("txn-discarded-failed").arg("reason", said(reason))
            }
        }
    }
}

impl Localize for PartitionSpace {
    fn message(&self) -> Message {
        Message::new("txn-partition-space")
            .arg("mount_point", self.mount_point.display().to_string())
            .arg("needed", self.bytes_needed() / MIB)
            .arg("free", self.bytes_free() / MIB)
    }
}

impl Localize for Unreadable {
    fn message(&self) -> Message {
        match self {
            Self::NotText => Message::new("txn-journal-not-text"),
            Self::NoHeader => Message::new("txn-journal-no-header"),
            Self::UnknownVersion(version) => Message::new("txn-journal-unknown-version")
                .arg("version", format!("{version:?}"))
                .arg("supported", crate::journal::VERSION.to_string()),
            Self::NotARegularFile => Message::new("txn-journal-not-a-regular-file"),
            Self::TooLarge => Message::new("txn-journal-too-large"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use piko_db::compression::Unsupported;
    use piko_db::fs_util::Distrust;
    use piko_i18n::{Catalog, Language, Placeables};

    use super::*;

    fn path() -> PathBuf {
        PathBuf::from("/var/cache/pacman/pkg/foo-1-1-x86_64.pkg.tar.zst")
    }

    fn conflict(index: usize) -> FileConflict {
        FileConflict {
            package: format!("foo{index}"),
            path: PathBuf::from(format!("usr/bin/foo{index}")),
            blocker: Blocker::Filesystem { owner: Some("bar".to_owned()) },
        }
    }

    /// One value of every variant of [`Error`], with arguments distinct from each other, so a
    /// message that swaps two variables renders differently from `Display`.
    ///
    /// [`Error::PlanInconsistent`] has no sample: only `piko_db` can build a `SolvableId`.
    fn every_error() -> Vec<Error> {
        let actions = [
            IoAction::Metadata,
            IoAction::Open,
            IoAction::Read,
            IoAction::CreateDir,
            IoAction::Decompress,
            IoAction::Create,
            IoAction::Write,
            IoAction::Remove,
            IoAction::Rename,
            IoAction::Sync,
            IoAction::Chown,
        ];
        let mut errors: Vec<Error> = actions
            .into_iter()
            .map(|action| Error::io(path(), action, std::io::ErrorKind::NotFound.into()))
            .collect();
        let skipped = [
            SkipReason::NotARegularFile,
            SkipReason::Unreadable,
            SkipReason::SymbolicLink,
            SkipReason::Untrusted { path: path(), distrust: Distrust::ForeignOwner { uid: 1000 } },
        ];
        let rejections = [
            RejectionReason::NotADirectory,
            RejectionReason::NotWritable,
            RejectionReason::NoWriteBits,
            RejectionReason::CreateFailed(std::io::ErrorKind::PermissionDenied),
            RejectionReason::Untrusted {
                path: path(),
                distrust: Distrust::GroupOrOtherWritable { mode: 0o777 },
            },
            RejectionReason::Untestable,
        ];
        let unsafe_paths = [
            UnsafePath::Absolute,
            UnsafePath::ParentTraversal,
            UnsafePath::CurrentDirectory,
            UnsafePath::Empty,
            UnsafePath::Blank,
            UnsafePath::InvalidComponent,
            UnsafePath::NotUtf8,
        ];
        let blockers = [
            Blocker::Target { other: "baz".to_owned() },
            Blocker::Filesystem { owner: Some("bar".to_owned()) },
            Blocker::Filesystem { owner: None },
            Blocker::Unreachable {
                component: PathBuf::from("usr/sbin"),
                reason: Obstacle::Symlink,
            },
            Blocker::Unreachable {
                component: PathBuf::from("usr/sbin"),
                reason: Obstacle::NotADirectory,
            },
            Blocker::Unreachable {
                component: PathBuf::from("usr/sbin"),
                reason: Obstacle::Unexaminable,
            },
        ];
        let journals = [
            Unreadable::NotText,
            Unreadable::NoHeader,
            Unreadable::UnknownVersion("9".to_owned()),
            Unreadable::NotARegularFile,
            Unreadable::TooLarge,
        ];
        errors.extend([
            Error::NotAvailable {
                file_name: "foo-1-1-x86_64.pkg.tar.zst".to_owned(),
                searched: vec![PathBuf::from("/a"), PathBuf::from("/b")],
                skipped: Vec::new(),
            },
            Error::NotAvailable {
                file_name: "foo-1-1-x86_64.pkg.tar.zst".to_owned(),
                searched: vec![PathBuf::from("/a")],
                skipped: skipped
                    .into_iter()
                    .map(|reason| Skipped { path: PathBuf::from("/a/foo"), reason })
                    .collect(),
            },
        ]);
        errors.extend(
            [
                MemberType::CharacterDevice,
                MemberType::BlockDevice,
                MemberType::Fifo,
                MemberType::ContiguousFile,
                MemberType::GnuSparseFile,
                MemberType::PaxGlobalHeader,
                MemberType::Unknown,
            ]
            .map(|kind| Error::UnsupportedMemberType {
                path: path(),
                member: PathBuf::from("dev/x"),
                kind,
            }),
        );
        errors.extend(
            [
                PackageLimit::CompressedSize,
                PackageLimit::InflatedSize,
                PackageLimit::DeclaredSize,
                PackageLimit::MemberCount,
                PackageLimit::XattrCount,
                PackageLimit::XattrSize,
                PackageLimit::ScriptletSize,
                PackageLimit::PkgInfoSize,
                PackageLimit::MergeBaseSize,
                PackageLimit::BackupFileSize,
                PackageLimit::SignatureSize,
            ]
            .map(|limit| Error::PackageLimitExceeded {
                path: path(),
                limit,
                max: 1024,
            }),
        );
        errors.extend([
            Error::PathEscapesRoot {
                path: path(),
                component: PathBuf::from("usr/sbin"),
                reason: Obstacle::Symlink,
            },
            Error::HardLinkOutsidePackage {
                path: path(),
                member: PathBuf::from("usr/a"),
                target: PathBuf::from("etc/shadow"),
            },
            Error::UnusableMemberOwner { member: PathBuf::from("usr/a"), uid: 1 << 40, gid: 7 },
            Error::UnsupportedCompression { path: path(), format: Unsupported::Xz },
            Error::UnsupportedPackageCompression {
                packages: vec![
                    ("a.pkg.tar.xz".to_owned(), Unsupported::Xz),
                    ("b.pkg.tar.bz2".to_owned(), Unsupported::Bzip2),
                ],
            },
            Error::ExtractionRefused { path: path(), reason: RefuseReason::DirectoryInTheWay },
            Error::FileConflicts { conflicts: vec![conflict(1)] },
            Error::FileConflicts {
                conflicts: blockers
                    .into_iter()
                    .map(|blocker| FileConflict { blocker, ..conflict(2) })
                    .collect(),
            },
            Error::FileConflicts { conflicts: (0..MAX_SHOWN + 3).map(conflict).collect() },
            Error::UnreadableEntry { entry: "foo-1-1".to_owned(), reason: "bad".to_owned() },
            Error::HookAborted {
                hook: "a.hook".to_owned(),
                reason: "failed".to_owned(),
                output: vec![],
            },
            Error::HookAborted {
                hook: "a.hook".to_owned(),
                reason: "failed".to_owned(),
                output: vec!["one".to_owned(), "two".to_owned()],
            },
            Error::HooksUnusable { problems: vec!["a".to_owned(), "b".to_owned()] },
            Error::Cancelled { completed: 1, total: 3 },
            Error::SignatureRejected {
                package: path(),
                refusal: SignatureRefusal::Policy(piko_sig::Rejection::MissingRequired),
                discarded: Discarded::No,
                unsigned: true,
            },
            Error::SignatureRejected {
                package: path(),
                refusal: SignatureRefusal::Policy(piko_sig::Rejection::KeyUnknown {
                    fingerprint: Some("ABCD".to_owned()),
                }),
                discarded: Discarded::Removed,
                unsigned: false,
            },
            Error::SignatureRejected {
                package: path(),
                refusal: SignatureRefusal::NotBase64 { reason: "bad byte".to_owned() },
                discarded: Discarded::Failed { reason: "denied".to_owned() },
                unsigned: false,
            },
            Error::SignatureUncheckable {
                package: path(),
                error: piko_sig::Error::KeyringUnusable {
                    home: PathBuf::from("/etc/pacman.d/gnupg"),
                    reason: "absent".to_owned(),
                },
            },
            Error::ChecksumMismatch {
                package: path(),
                found: "ab".to_owned(),
                published: "cd".to_owned(),
                discarded: Discarded::No,
            },
            Error::Database(piko_db_write::Error::Read(piko_db::Error::NotARegularFile {
                path: path(),
            })),
            Error::Download(piko_net::Error::Cancelled),
            Error::local_db(
                "/var/lib/pacman/local",
                piko_db::Error::NotARegularFile { path: path() },
            ),
            Error::DiskSpace {
                too_full: vec![PartitionSpace {
                    mount_point: PathBuf::from("/"),
                    blocks_needed: 3 << 20,
                    blocks_free: 1 << 20,
                    block_size: 4096,
                }],
                read_only: vec![PathBuf::from("/boot")],
            },
            Error::MountTableUnreadable { path: path(), reason: "bad".to_owned() },
            Error::NoWritableCacheDir {
                rejected: rejections
                    .into_iter()
                    .map(|reason| RejectedCacheDir { path: PathBuf::from("/c"), reason })
                    .collect(),
            },
            Error::PlanStale {
                name: "foo".to_owned(),
                planned: Some("foo-1-1".to_owned()),
                installed: Some("foo-2-1".to_owned()),
            },
            Error::PlanStale {
                name: "foo".to_owned(),
                planned: None,
                installed: Some("foo-2-1".to_owned()),
            },
            Error::PlanStale {
                name: "foo".to_owned(),
                planned: Some("foo-1-1".to_owned()),
                installed: None,
            },
            Error::UnusableSource { path: path(), reason: "bad".to_owned() },
            Error::NotARemoval,
            Error::NoRepositoryCandidate { name: "foo".to_owned() },
            Error::RepositoryPackageUnreadable {
                name: "foo".to_owned(),
                source: Arc::new(piko_db::Error::NotARegularFile { path: path() }),
            },
            Error::WrongArchitecture {
                packages: vec!["a (aarch64)".to_owned(), "b (i686)".to_owned()],
                configured: vec!["x86_64".to_owned(), "x86_64_v3".to_owned()],
            },
            Error::DuplicateTarget {
                package: "foo".to_owned(),
                first: PathBuf::from("/a"),
                second: PathBuf::from("/b"),
            },
            Error::InvalidPackageUrl { url: "https://x/".to_owned(), reason: "bad".to_owned() },
            Error::UrlNotLoaded { url: "https://x/foo.pkg.tar.zst".to_owned() },
            Error::KeyringUnusable {
                path: PathBuf::from("/etc/pacman.d/gnupg"),
                source: piko_sig::Error::KeyringUnusable {
                    home: PathBuf::from("/etc/pacman.d/gnupg"),
                    reason: "missing".to_owned(),
                },
            },
            Error::UnconfiguredSource { package: "foo".to_owned(), reason: "none".to_owned() },
            Error::UnfinishedTransaction { path: path() },
            Error::EmptyOwnerTarget,
        ]);
        errors.extend(
            unsafe_paths
                .into_iter()
                .map(|reason| Error::UnsafeArchivePath { path: path(), reason }),
        );
        errors.extend(
            journals.into_iter().map(|reason| Error::JournalUnreadable { path: path(), reason }),
        );
        // A match with no wildcard arm: a new variant fails to compile here until it has a
        // sample above.
        for error in &errors {
            match error {
                Error::Io { .. }
                | Error::NotAvailable { .. }
                | Error::UnsupportedMemberType { .. }
                | Error::HardLinkOutsidePackage { .. }
                | Error::UnusableMemberOwner { .. }
                | Error::UnsafeArchivePath { .. }
                | Error::PathEscapesRoot { .. }
                | Error::PackageLimitExceeded { .. }
                | Error::UnsupportedCompression { .. }
                | Error::UnsupportedPackageCompression { .. }
                | Error::ExtractionRefused { .. }
                | Error::FileConflicts { .. }
                | Error::UnreadableEntry { .. }
                | Error::HookAborted { .. }
                | Error::HooksUnusable { .. }
                | Error::Cancelled { .. }
                | Error::SignatureRejected { .. }
                | Error::SignatureUncheckable { .. }
                | Error::ChecksumMismatch { .. }
                | Error::Database(_)
                | Error::LocalDatabaseUnreadable { .. }
                | Error::DiskSpace { .. }
                | Error::MountTableUnreadable { .. }
                | Error::NoWritableCacheDir { .. }
                | Error::PlanStale { .. }
                | Error::UnusableSource { .. }
                | Error::Download(_)
                | Error::PlanInconsistent { .. }
                | Error::NotARemoval
                | Error::NoRepositoryCandidate { .. }
                | Error::RepositoryPackageUnreadable { .. }
                | Error::WrongArchitecture { .. }
                | Error::DuplicateTarget { .. }
                | Error::InvalidPackageUrl { .. }
                | Error::UrlNotLoaded { .. }
                | Error::KeyringUnusable { .. }
                | Error::JournalUnreadable { .. }
                | Error::UnconfiguredSource { .. }
                | Error::UnfinishedTransaction { .. }
                | Error::EmptyOwnerTarget => {}
            }
        }
        errors
    }

    #[test]
    fn the_english_catalog_renders_each_error_as_display_does() {
        let catalog = Catalog::new(Language::English, Placeables::Plain);
        for error in every_error() {
            assert_eq!(catalog.try_format(&error.message()), Ok(error.to_string()));
        }
    }

    #[test]
    fn every_language_renders_each_error() {
        for language in Language::ALL {
            let catalog = Catalog::new(*language, Placeables::Plain);
            for error in every_error() {
                let rendered = catalog.try_format(&error.message());
                assert!(rendered.is_ok(), "{language:?}: {rendered:?}");
            }
        }
    }
}
