//! What one refresh downloads, decided from `pacman.conf` alone.
//!
//! A frontend that refreshes repository databases makes the same four decisions `piko refresh`
//! makes: which repositories, which of their archives, which signature policy each one is held
//! to, and whether a keyring is needed at all. [`RefreshTargets`] makes them, so a second
//! frontend refreshes what `piko refresh` refreshes and checks what it checks.

use piko_db::config::{PacmanConfig, RepositoryConfig};
use piko_sig::{Keyring, Policy};

use crate::{DatabaseKind, Error, FreshnessPolicy, RepoRefresh, Result};

/// The archives one refresh fetches, the keyring that checks them, and the names it could not
/// find.
#[derive(Debug)]
pub struct RefreshTargets<'a> {
    requests: Vec<RepoRefresh<'a>>,
    keyring: Option<Keyring>,
    unknown: Vec<String>,
}

impl<'a> RefreshTargets<'a> {
    /// Selects what to refresh from `config`.
    ///
    /// `only` empty selects every configured repository, in priority order. Otherwise it
    /// selects the configured repositories it names, still in priority order, and
    /// [`RefreshTargets::unknown`] lists the names no section configures. `files` adds each
    /// selected repository's `<repo>.files` beside its `<repo>.db`. The two sit next to each
    /// other, so a caller's output reads repository by repository.
    ///
    /// Each archive is held to its repository's effective database policy
    /// ([`RepositoryConfig::effective_sig_level`]), never to the raw `sig_level` field, which
    /// can hold the parser's `USE_DEFAULT` sentinel. The keyring at `GPGDir` is opened only when
    /// a *selected* repository's policy asks for a check, as libalpm checks a database only
    /// under that database's own `SigLevel` (`be_sync.c:108`) and initializes GPGME at the
    /// first check (`signing.c:575`). A system with no keyring can still refresh repositories
    /// whose `SigLevel` asks for nothing, and a repository that is not refreshed does not need
    /// the keyring.
    ///
    /// # Errors
    ///
    /// [`Error::KeyringUnusable`] if a policy asks for a check and the keyring cannot be opened.
    pub fn new(
        config: &'a PacmanConfig,
        only: &[String],
        files: bool,
        freshness: FreshnessPolicy,
    ) -> Result<Self> {
        let global = config.options.sig_level;
        let kinds: &[DatabaseKind] =
            if files { &[DatabaseKind::Db, DatabaseKind::Files] } else { &[DatabaseKind::Db] };
        let requests = config
            .repositories
            .iter()
            .filter(|repo| only.is_empty() || only.iter().any(|name| name == repo.name.as_str()))
            .flat_map(|repo| {
                kinds.iter().map(move |kind| RepoRefresh {
                    name: repo.name.as_str(),
                    kind: *kind,
                    servers: &repo.servers,
                    policy: database_policy(repo, global),
                    freshness,
                })
            })
            .collect::<Vec<RepoRefresh<'a>>>();
        let keyring = if requests.iter().any(|request| request.policy.check) {
            Some(
                Keyring::open(&config.options.gpg_dir)
                    .map_err(|source| Error::KeyringUnusable { source })?,
            )
        } else {
            None
        };
        let unknown = only
            .iter()
            .filter(|name| !config.repositories.iter().any(|repo| repo.name.as_str() == *name))
            .cloned()
            .collect();

        Ok(Self { requests, keyring, unknown })
    }

    /// One request per archive, in the order a caller should report them.
    #[must_use]
    pub fn requests(&self) -> &[RepoRefresh<'a>] {
        &self.requests
    }

    /// The keyring that checks the archives, or `None` when no policy asks for a check.
    #[must_use]
    pub const fn keyring(&self) -> Option<&Keyring> {
        self.keyring.as_ref()
    }

    /// The names the caller selected that no repository section configures, in the order
    /// given.
    #[must_use]
    pub fn unknown(&self) -> &[String] {
        &self.unknown
    }
}

/// The policy `repo`'s database archives are held to, with `global` as `[options]`' `SigLevel`.
fn database_policy(repo: &RepositoryConfig, global: piko_db::config::SigLevel) -> Policy {
    Policy::for_database(repo.effective_sig_level(global))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use std::path::Path;

    use super::*;

    /// Parses `text` as a `pacman.conf` written under `dir`.
    fn config(dir: &Path, text: &str) -> PacmanConfig {
        let path = dir.join("pacman.conf");
        std::fs::write(&path, text).unwrap();
        PacmanConfig::open(&path).unwrap()
    }

    /// Three repositories that ask for no signature, and a keyring directory that does not
    /// exist.
    fn unsigned(dir: &Path) -> PacmanConfig {
        let missing = dir.join("no-keyring");
        config(
            dir,
            &format!(
                "[options]\nSigLevel = Never\nGPGDir = {}\n\
                 [core]\nServer = https://example.invalid/core\n\
                 [extra]\nServer = https://example.invalid/extra\n\
                 [multilib]\nServer = https://example.invalid/multilib\n",
                missing.display()
            ),
        )
    }

    fn freshness() -> FreshnessPolicy {
        FreshnessPolicy { accept_older: false, max_age: None, now: std::time::SystemTime::now() }
    }

    fn selected(targets: &RefreshTargets<'_>) -> Vec<String> {
        targets
            .requests()
            .iter()
            .map(|request| request.kind.file_name(request.name))
            .collect::<Vec<_>>()
    }

    #[test]
    fn no_name_selects_every_repository_in_priority_order() {
        let dir = tempfile::tempdir().unwrap();
        let config = unsigned(dir.path());

        let targets = RefreshTargets::new(&config, &[], false, freshness()).unwrap();

        assert_eq!(selected(&targets), ["core.db", "extra.db", "multilib.db"]);
        assert!(targets.unknown().is_empty());
    }

    /// The order is the configuration's, not the order the names were given in.
    #[test]
    fn named_repositories_keep_the_priority_order() {
        let dir = tempfile::tempdir().unwrap();
        let config = unsigned(dir.path());
        let only = ["multilib".to_owned(), "core".to_owned()];

        let targets = RefreshTargets::new(&config, &only, false, freshness()).unwrap();

        assert_eq!(selected(&targets), ["core.db", "multilib.db"]);
    }

    #[test]
    fn a_name_no_section_configures_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let config = unsigned(dir.path());
        let only = ["core".to_owned(), "testing".to_owned()];

        let targets = RefreshTargets::new(&config, &only, false, freshness()).unwrap();

        assert_eq!(selected(&targets), ["core.db"]);
        assert_eq!(targets.unknown(), ["testing"]);
    }

    /// `--files` adds each `.files` beside its `.db`, so the output reads repository by
    /// repository.
    #[test]
    fn files_adds_each_archive_beside_its_database() {
        let dir = tempfile::tempdir().unwrap();
        let config = unsigned(dir.path());
        let only = ["core".to_owned(), "extra".to_owned()];

        let targets = RefreshTargets::new(&config, &only, true, freshness()).unwrap();

        assert_eq!(selected(&targets), ["core.db", "core.files", "extra.db", "extra.files"]);
    }

    /// A system with no keyring can still refresh repositories that ask for nothing.
    #[test]
    fn no_policy_asking_for_a_check_opens_no_keyring() {
        let dir = tempfile::tempdir().unwrap();
        let config = unsigned(dir.path());

        let targets = RefreshTargets::new(&config, &[], false, freshness()).unwrap();

        assert!(targets.keyring().is_none());
        assert!(targets.requests().iter().all(|request| !request.policy.check));
    }

    /// One repository that asks for a signature is enough to need the keyring. A missing one
    /// is then an error, never a silent pass.
    #[test]
    fn a_repository_asking_for_a_check_needs_a_usable_keyring() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-keyring");
        let config = config(
            dir.path(),
            &format!(
                "[options]\nSigLevel = Never\nGPGDir = {}\n\
                 [core]\nSigLevel = DatabaseRequired\nServer = https://example.invalid/core\n",
                missing.display()
            ),
        );

        let error = RefreshTargets::new(&config, &[], false, freshness()).unwrap_err();
        assert!(matches!(error, Error::KeyringUnusable { .. }), "got {error:?}");
    }

    /// A repository that asks for a check but is not selected does not need the keyring. The
    /// same configuration still needs it once that repository is selected.
    #[test]
    fn a_repository_that_is_not_selected_does_not_need_the_keyring() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-keyring");
        let config = config(
            dir.path(),
            &format!(
                "[options]\nSigLevel = Never\nGPGDir = {}\n\
                 [core]\nServer = https://example.invalid/core\n\
                 [extra]\nSigLevel = DatabaseRequired\nServer = https://example.invalid/extra\n",
                missing.display()
            ),
        );

        let core = RefreshTargets::new(&config, &["core".to_owned()], false, freshness()).unwrap();
        assert_eq!(selected(&core), ["core.db"]);
        assert!(core.keyring().is_none());

        let error = RefreshTargets::new(&config, &[], false, freshness()).unwrap_err();
        assert!(matches!(error, Error::KeyringUnusable { .. }), "got {error:?}");
    }

    /// A repository with no `SigLevel` of its own inherits `[options]`', not the parser's
    /// `USE_DEFAULT` sentinel, whose database bit is clear.
    #[test]
    fn a_repository_with_no_sig_level_inherits_the_global_one() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-keyring");
        let config = config(
            dir.path(),
            &format!(
                "[options]\nSigLevel = Required DatabaseRequired\nGPGDir = {}\n\
                 [core]\nServer = https://example.invalid/core\n",
                missing.display()
            ),
        );

        let error = RefreshTargets::new(&config, &[], false, freshness()).unwrap_err();
        assert!(matches!(error, Error::KeyringUnusable { .. }), "got {error:?}");
    }
}
