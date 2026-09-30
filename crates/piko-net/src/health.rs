//! Which servers a [`crate::Refresher`] stops asking, after too many errors.
//!
//! A mirror that fails every request costs each file a round trip before the next server is
//! asked. libalpm counts the errors of each host, and skips a host for the rest of the
//! transaction once it reaches [`ERROR_LIMIT`] (`server_error_limit`, `dload.c:136`). piko does
//! the same, for the life of one `Refresher`.
//!
//! The count is kept by host, not by URL, because one host serves every repository under a
//! different path, and its errors are usually the host's (`find_server_errors`, `dload.c:143`).
//! A `CacheServer` is never skipped: a cache that does not hold a file answers 404, which says
//! nothing about the next file. libalpm does not count its errors either (`request_errors_ok`,
//! `dload.c:233`).

use std::{collections::HashMap, sync::Mutex};

/// How many failed requests make a host skipped, as libalpm's `server_error_limit`.
pub(crate) const ERROR_LIMIT: u8 = 3;

/// The failed requests of each host, shared by every worker of one `Refresher`.
#[derive(Debug, Default)]
pub(crate) struct Health {
    errors: Mutex<HashMap<String, u8>>,
}

impl Health {
    /// Whether requests to `server` are skipped.
    pub(crate) fn skips(&self, server: &str) -> bool {
        let Some(host) = host(server) else { return false };
        self.errors
            .lock()
            .is_ok_and(|errors| errors.get(host).is_some_and(|count| *count >= ERROR_LIMIT))
    }

    /// Records a failed request to `server`.
    ///
    /// Returns the host when this failure is the one that makes it skipped, so the caller can
    /// report it once, as libalpm warns once (`server_soft_error`, `dload.c:191`).
    pub(crate) fn failed(&self, server: &str) -> Option<String> {
        let host = host(server)?;
        let mut errors = self.errors.lock().ok()?;
        let count = errors.entry(host.to_owned()).or_default();
        *count = count.saturating_add(1);
        (*count == ERROR_LIMIT).then(|| host.to_owned())
    }
}

/// The part of `url` that errors are counted by: the authority, without user information.
///
/// The port stays, as in libalpm's `curl_gethost` (`dload.c:307`). `None` for a URL with no
/// authority, which is never skipped.
fn host(url: &str) -> Option<&str> {
    let (_, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    (!host.is_empty()).then_some(host)
}

/// Why a request to `server` was not made, for [`crate::Error::AllServersFailed`].
pub(crate) fn skipped_reason(server: &str) -> String {
    format!(
        "not asked: {} failed {ERROR_LIMIT} requests earlier in this run",
        host(server).unwrap_or(server)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_is_skipped_at_the_limit_and_not_before() {
        let health = Health::default();
        for _ in 1..ERROR_LIMIT {
            assert_eq!(health.failed("https://mirror.invalid/core/os/x86_64"), None);
            assert!(!health.skips("https://mirror.invalid/core/os/x86_64"));
        }
        // The failure that reaches the limit names the host, once.
        assert_eq!(
            health.failed("https://mirror.invalid/extra/os/x86_64").as_deref(),
            Some("mirror.invalid")
        );
        assert_eq!(health.failed("https://mirror.invalid/extra/os/x86_64"), None);
        // Every path on the host, not only the ones that failed.
        assert!(health.skips("https://mirror.invalid/multilib/os/x86_64"));
        assert!(!health.skips("https://other.invalid/core/os/x86_64"));
    }

    /// The key is libalpm's: user information goes, the port stays.
    #[test]
    fn the_host_is_the_authority_without_user_information() {
        assert_eq!(host("https://user:pass@mirror.invalid:8443/core"), Some("mirror.invalid:8443"));
        assert_eq!(host("https://mirror.invalid"), Some("mirror.invalid"));
        assert_eq!(host("https://mirror.invalid?x#y"), Some("mirror.invalid"));
        assert_eq!(host("file:///srv/repo"), None);
        assert_eq!(host("not a url"), None);
    }
}
