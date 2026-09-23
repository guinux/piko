//! What a refresh learned about how recent a repository database is.
//!
//! A signature proves who produced a database, not that it is current. A mirror can serve an
//! old, correctly signed database, which rolls the client back. It can also keep serving the
//! same one, which freezes the client. The refresh loop in [`mod@crate::refresh`] makes the
//! decisions. This module holds the policy it follows and the notes it returns.
//!
//! # Two levels of protection
//!
//! A database with a verified signature is dated by that signature. Only the key holder can
//! make one, so a malicious mirror cannot pass an old database off as new. A database with no
//! verified signature is dated by its newest archive member, which the mirror chose. That
//! catches a mirror that is merely behind, never one that lies. Arch does not sign its
//! databases, so on Arch only the second level exists.
//!
//! # Why an older database moves on to the next server
//!
//! A signature that fails to verify stops the mirror loop. Trying more mirrors would be
//! shopping for one that says yes, and one yes is all an attacker needs. A database that is
//! older than the installed one is different. The next server is accepted only if it is at
//! least as new as the installed database, so looking further can only improve what is
//! installed. An attacker gains nothing from it.

use std::{
    path::Path,
    time::{Duration, SystemTime},
};

use piko_db::repo::freshness::{self, Comparison, DEFAULT_MAX_AGE, Publication};
use piko_sig::{Checked, Keyring, Policy, signature_path};

use crate::refresh::Outcome;

/// How a refresh judges the age of what it downloads.
#[derive(Clone, Copy, Debug)]
pub struct FreshnessPolicy {
    /// Install a database even when it is older than the installed one.
    ///
    /// This is how a user goes back to an earlier snapshot, such as the Arch Linux Archive.
    /// It is never implied by `force`. A habitual forced refresh must not turn the check off
    /// without anyone noticing.
    pub accept_older: bool,
    /// How old a database may be before the refresh looks at other servers and warns.
    ///
    /// `None` turns the age check off. The rollback check does not depend on it.
    pub max_age: Option<Duration>,
    /// The current time. Taken from the caller, so a test can fix it.
    pub now: SystemTime,
}

impl FreshnessPolicy {
    /// The default policy at `now`: older databases are refused, and the age limit is
    /// [`DEFAULT_MAX_AGE`].
    #[must_use]
    pub const fn new(now: SystemTime) -> Self {
        Self { accept_older: false, max_age: Some(DEFAULT_MAX_AGE), now }
    }
}

impl Default for FreshnessPolicy {
    /// The default policy at the current system time.
    fn default() -> Self {
        Self::new(SystemTime::now())
    }
}

/// Something a refresh learned about freshness that the caller should hear about.
///
/// None of these is a failure. Each one leaves the system with the best database the refresh
/// found. The caller decides how loudly to report it.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FreshnessNote {
    /// A server answered with a `Last-Modified` older than the installed database, so its body
    /// was not read.
    ///
    /// libcurl makes the same judgement for pacman, which then stops and reports the database
    /// as up to date. The refresh tries the next server instead. The header is not signed, so
    /// it can only rule a server out, never vouch for one.
    Behind {
        /// The URL that was passed over.
        server: String,
        /// The `Last-Modified` it sent, in seconds since the Unix epoch.
        last_modified: u64,
    },
    /// A server's database verified, but was older than the installed one, so it was
    /// discarded.
    RefusedOlder {
        /// The URL whose database was discarded.
        server: String,
        /// When the discarded database was published, if it carried a date.
        candidate: Option<Publication>,
        /// When the installed database was published.
        installed: Option<Publication>,
        /// Why it counts as older.
        comparison: Comparison,
    },
    /// An older database was installed because [`FreshnessPolicy::accept_older`] allowed it.
    AcceptedOlder {
        /// The URL the database came from.
        server: String,
        /// When the installed database was published, if it carried a date.
        candidate: Option<Publication>,
        /// When the database it replaced was published.
        replaced: Option<Publication>,
    },
    /// The database is older than [`FreshnessPolicy::max_age`], and the servers that were
    /// asked had nothing newer.
    Stale {
        /// When the database was published.
        publication: Publication,
        /// How long ago that was.
        age: Duration,
        /// The limit it exceeds.
        max_age: Duration,
        /// How many other servers were asked for a newer one.
        probed: usize,
    },
    /// The database is dated further in the future than the tolerance allows.
    ///
    /// Either the local clock is behind or the publisher's is ahead. The database is kept.
    FromTheFuture {
        /// When the database claims to have been published.
        publication: Publication,
        /// How far ahead of the local clock that is.
        ahead: Duration,
    },
}

/// What a refresh did to one repository archive, and what it learned about its age.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Refreshed {
    /// What happened to the file.
    pub outcome: Outcome,
    /// When the database now in place was published, as far as the refresh needed to know.
    ///
    /// Always computed for a `.db` archive, because the age check needs it. For a `.files`
    /// archive it is computed only when a download had to be compared, since dating a large
    /// file list costs a full decompression. `None` also means the database carries no date.
    pub publication: Option<Publication>,
    /// What the caller should hear about, in the order it happened.
    pub notes: Vec<FreshnessNote>,
}

/// The publication date of the installed database, computed at most once per refresh.
///
/// Computing it can mean a signature check or a full decompression, so it waits until a
/// comparison or the age check actually needs it.
pub(crate) struct Baseline<'a> {
    path: &'a Path,
    keyring: Option<&'a Keyring>,
    policy: Policy,
    limits: piko_db::Limits,
    value: Option<Option<Publication>>,
}

impl<'a> Baseline<'a> {
    pub(crate) const fn new(
        path: &'a Path,
        keyring: Option<&'a Keyring>,
        policy: Policy,
        limits: piko_db::Limits,
    ) -> Self {
        Self { path, keyring, policy, limits, value: None }
    }

    /// The installed database's publication, computing it on first use.
    pub(crate) fn get(&mut self) -> Option<Publication> {
        if let Some(value) = self.value {
            return value;
        }
        let value = installed_publication(self.path, self.keyring, self.policy, &self.limits);
        self.value = Some(value);
        value
    }

    /// The installed database's publication, if something already computed it.
    pub(crate) fn peek(&self) -> Option<Publication> {
        self.value.flatten()
    }

    /// Records that `publication` is now the installed database.
    pub(crate) const fn replace(&mut self, publication: Option<Publication>) {
        self.value = Some(publication);
    }
}

/// Dates the database at `path`.
///
/// Its signature is checked first, under the same policy the download is held to. A
/// signature that verifies dates it. Otherwise the newest archive member does. A file that is
/// missing, or unreadable, has no date, and so no rollback check applies to what replaces it.
/// A broken installed database must stay replaceable.
fn installed_publication(
    path: &Path,
    keyring: Option<&Keyring>,
    policy: Policy,
    limits: &piko_db::Limits,
) -> Option<Publication> {
    if !path.is_file() {
        return None;
    }
    let signed_at = match keyring {
        Some(keyring) if policy.check => {
            let signature = signature_path(path);
            if signature.is_file() {
                keyring
                    .verify_detached(path, &signature)
                    .ok()
                    .and_then(|outcomes| Checked::from_outcomes(&outcomes, policy).signed_at)
            } else {
                None
            }
        }
        _ => None,
    };
    let newest_member = if signed_at.is_none() {
        freshness::newest_member_time(path, limits).ok().flatten()
    } else {
        None
    };
    Publication::new(signed_at, newest_member)
}
