//! Fetching one repository database and installing it only if it verifies.

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use alpm_types::PackageFileName;
use piko_db_write::AtomicFile;
use piko_sig::{Keyring, Policy, Verdict};

use crate::{
    cancel::Cancel,
    concurrency::Concurrency,
    error::{Error, Result},
    pool,
    progress::{Event, Kind},
};

/// What a refresh did to one repository.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// A new database was downloaded, verified and installed.
    Updated,
    /// The server said the local copy is current, so nothing was downloaded.
    ///
    /// This comes from a `304` answer to a conditional request, not from comparing contents.
    /// Reaching it depends on the download having been stamped with the server's
    /// `Last-Modified`, so the next request offers back the exact value the server issued.
    UpToDate,
}

/// Bounds and behaviour for downloading.
///
/// A mirror is an untrusted party until its signature is checked, so every number here exists
/// to stop one from deciding how long piko runs or how much disk it uses.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Largest database that will be accepted.
    ///
    /// Enforced against bytes actually received, not against `Content-Length`. The header is
    /// the mirror's claim, not a fact.
    pub max_bytes: u64,
    /// Largest package archive that will be accepted.
    ///
    /// Unlike [`Limits::max_bytes`], this is not measured against one real file. A repository
    /// has a database of a known size to benchmark, but packages vary by orders of magnitude.
    /// `texlive-doc` is the largest known real Arch package at roughly 3.3 GB. 8 GB is generous
    /// headroom above that rather than a measurement, enforced the same way: against bytes
    /// actually received.
    pub max_package_bytes: u64,
    /// How long to wait for the whole request.
    pub timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        // `extra.files` is ~50 MB on a current Arch mirror. 512 MB is far above any real
        // database and far below anything that would fill a disk unnoticed.
        Self {
            max_bytes: 512 * 1024 * 1024,
            max_package_bytes: 8 * 1024 * 1024 * 1024,
            timeout: Duration::from_secs(60),
        }
    }
}

/// What is being fetched, and how large it may legitimately be.
///
/// Bundled so `fetch`'s own parameter count stays under clippy's `too_many_arguments`. These
/// two always travel together, one per kind of file this module downloads.
#[derive(Clone, Copy)]
struct Target {
    kind: Kind,
    max_bytes: u64,
}

/// The cancellation flag and progress sink shared by everything a download call does.
///
/// Bundled for the same reason as [`Target`]: `cancel` and `progress` always travel together.
#[derive(Clone, Copy)]
struct Controls<'a> {
    cancel: &'a Cancel,
    progress: &'a (dyn Fn(Event) + Sync),
}

/// What asking a server for a detached signature produced.
///
/// The three cases are kept apart because the caller must treat them differently. An `Option`
/// would conflate the first two: "the policy never asked" says nothing about whether the file
/// is signed, while "the server has none" is positive evidence that it is not.
#[derive(Debug)]
enum Signature {
    /// The policy does not use a signature, so none was requested.
    NotRequested,
    /// The server has no signature for this file.
    ///
    /// This is the norm, not an error. Arch mirrors serve no `.db.sig` at all, which is why
    /// pacman ships `DatabaseOptional`.
    Absent,
    /// Downloaded into a temporary beside its destination.
    Downloaded(AtomicFile),
}

/// The temporaries a refresh has downloaded, and where the signature belongs.
///
/// Bundled for the same reason as [`Target`] and [`Controls`]. `install`'s parameter count
/// would otherwise trip clippy's `too_many_arguments`, and these three always travel together.
#[derive(Debug)]
struct Downloaded {
    database: AtomicFile,
    signature: Signature,
    /// Where a signature lands, and so where a stale one from a previous refresh is found.
    sig_destination: PathBuf,
}

/// How long a connection may take to establish, separately from [`Limits::timeout`].
///
/// Cancellation is observable between requests and between 64 KiB chunks, never inside a
/// connect, so this is the longest a worker can ignore a Ctrl+C. Bounding it tightly keeps a
/// cancellation prompt when one mirror in a batch has gone dark. The transfer itself still
/// gets the far more generous [`Limits::timeout`].
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// One repository in a batch refresh.
#[derive(Clone, Copy, Debug)]
pub struct RepoRefresh<'a> {
    /// The repository's name — `core` for `core.db`.
    pub name: &'a str,
    /// `Server`, tried in order from wherever this transfer's worker starts.
    pub servers: &'a [String],
    /// The repository's effective database policy.
    pub policy: Policy,
}

/// One package in a batch fetch.
#[derive(Clone, Copy, Debug)]
pub struct PackageFetch<'a> {
    /// The package file to download.
    pub file_name: &'a PackageFileName,
    /// The repository it belongs to, for naming it in an error.
    pub repo_name: &'a str,
    /// `Server`/`CacheServer`, tried in order from wherever this transfer's worker starts.
    pub servers: &'a [String],
    /// Whether a detached `.sig` is worth fetching alongside it.
    pub policy: Policy,
    /// `%CSIZE%`, used only to schedule the largest downloads first.
    ///
    /// Never a bound. What a repository database claims about a package's size is a claim, and
    /// [`Limits::max_package_bytes`] is still enforced against the bytes that arrive. A wrong
    /// value here costs nothing but a worse schedule.
    pub size: u64,
}

/// The first name that appears twice, if any.
fn first_duplicate(names: impl Iterator<Item = String>) -> Option<String> {
    let mut seen = std::collections::HashSet::new();
    names.into_iter().find(|name| !seen.insert(name.clone()))
}

/// Downloads and installs repository databases.
#[derive(Debug)]
pub struct Refresher {
    agent: ureq::Agent,
    limits: Limits,
}

impl Default for Refresher {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}

impl Refresher {
    /// Builds a refresher with the given bounds.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        // The provider must be named explicitly, or ureq's default provider selection and
        // this workspace's enabled features can silently disagree.
        let tls = ureq::tls::TlsConfig::builder()
            .provider(ureq::tls::TlsProvider::Rustls)
            // The system CA store, matching what libcurl and therefore pacman use, rather
            // than a Mozilla root bundle compiled into the binary and aging independently of
            // it.
            .root_certs(ureq::tls::RootCerts::PlatformVerifier)
            .build();
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(limits.timeout))
            // Much shorter than the global one, and separate from it on purpose.
            // Cancellation is only observable between requests and between chunks, so a
            // worker parked in DNS/connect/TLS ignores a Ctrl+C for as long as this allows,
            // once per worker. That is why it is worth bounding tightly while the transfer
            // itself keeps the generous `timeout_global`.
            .timeout_connect(Some(CONNECT_TIMEOUT))
            // A mirror that redirects forever is a mirror that hangs the update.
            .max_redirects(5)
            .user_agent(concat!("piko/", env!("CARGO_PKG_VERSION")))
            .tls_config(tls)
            .build();
        Self { agent: ureq::Agent::new_with_config(config), limits }
    }

    /// Refreshes `repo`'s database into `sync_dir`, verifying before it lands.
    ///
    /// `servers` are tried in order, as pacman tries mirrors. The first that answers wins, and
    /// a failure moves to the next rather than aborting. Every failure is collected so that
    /// [`Error::AllServersFailed`] can name them all.
    ///
    /// `keyring` and `policy` decide what the download must satisfy. When `policy.check` is
    /// false, nothing is verified — the same `SigLevel = Never` escape the rest of piko honors.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if no server could supply the database, if it exceeded
    /// [`Limits::max_bytes`], or if it failed verification. In every case the existing
    /// database is left in place.
    #[allow(
        clippy::too_many_arguments,
        reason = "each parameter names one concern a caller must decide, as \
                  `refresh_with_progress` documents — this is that signature with the \
                  progress sink defaulted away, not a separate design"
    )]
    pub fn refresh(
        &self,
        sync_dir: &Path,
        repo: &str,
        servers: &[String],
        keyring: Option<&Keyring>,
        policy: Policy,
        force: bool,
        cancel: &Cancel,
    ) -> Result<Outcome> {
        self.refresh_with_progress(sync_dir, repo, servers, keyring, policy, force, cancel, &|_| {})
    }

    /// As [`Refresher::refresh`], reporting progress through `progress` as it happens.
    ///
    /// `progress` is a narrow, deliberate exception to the rule that diagnostics are returned,
    /// not logged. See [`crate::progress`]'s documentation before treating this as license to
    /// add another one. It is called synchronously and may be called many times per file. It
    /// duplicates no information the returned `Result<Outcome>` does not already carry.
    ///
    /// # Errors
    ///
    /// As [`Refresher::refresh`].
    #[allow(
        clippy::too_many_arguments,
        reason = "each parameter names one concern a caller must decide (where, which \
                  repository, which servers, how to authenticate, under what policy, whether \
                  to force, how to cancel, how to observe) — bundling any of them would only \
                  hide that from the signature, not reduce it"
    )]
    pub fn refresh_with_progress(
        &self,
        sync_dir: &Path,
        repo: &str,
        servers: &[String],
        keyring: Option<&Keyring>,
        policy: Policy,
        force: bool,
        cancel: &Cancel,
        progress: &(dyn Fn(Event) + Sync),
    ) -> Result<Outcome> {
        self.refresh_one(
            sync_dir,
            RepoRefresh { name: repo, servers, policy },
            keyring,
            Concurrency::default(),
            force,
            0,
            cancel,
            progress,
        )
    }

    /// One repository's refresh, as worker `worker` of a batch.
    ///
    /// `worker` decides only which mirror this attempt starts on
    /// ([`Concurrency::servers_for`]). Every one is still tried in turn, so the failover of a
    /// single serial refresh is unchanged.
    #[allow(
        clippy::too_many_arguments,
        reason = "the public `refresh_with_progress` this backs already documents why each                   concern is named separately; this adds the two the batch decides"
    )]
    fn refresh_one(
        &self,
        sync_dir: &Path,
        repo: RepoRefresh<'_>,
        keyring: Option<&Keyring>,
        concurrency: Concurrency,
        force: bool,
        worker: usize,
        cancel: &Cancel,
        progress: &(dyn Fn(Event) + Sync),
    ) -> Result<Outcome> {
        let RepoRefresh { name: repo, servers, policy } = repo;
        if servers.is_empty() {
            return Err(Error::NoServers { repo: repo.to_owned() });
        }
        std::fs::create_dir_all(sync_dir).map_err(|source| Error::Io {
            path: sync_dir.to_path_buf(),
            action: "create",
            source,
        })?;

        let name = format!("{repo}.db");
        let destination = sync_dir.join(&name);

        // A conditional request uses the local file's mtime, which `fetch` stamped with the
        // server's own `Last-Modified` when it downloaded the file. Sending back the exact
        // value the server issued is not merely tidy: measured against mirror.thekinrar.fr, a
        // date later than its `Last-Modified` gets a full 200 even though RFC 7232 §3.3 asks
        // for 304, while the exact value gets 304 (3/3, at -1h/exact/+1h/+1d). An earlier
        // version of this sent our own download time instead, and that never saved a
        // transfer.
        let since = if force { None } else { last_modified(&destination) };

        let mut attempts = Vec::new();
        for server in concurrency.servers_for(servers, worker) {
            let url = format!("{}/{name}", server.trim_end_matches('/'));
            match self.fetch(
                &url,
                &destination,
                since.as_deref(),
                &name,
                Target { kind: Kind::Database, max_bytes: self.limits.max_bytes },
                Controls { cancel, progress },
            ) {
                Ok(None) => return Ok(Outcome::UpToDate),
                Ok(Some(database)) => {
                    // The signature comes from the same server as the database. Taking it
                    // from another would let a well-behaved mirror vouch for a hostile one.
                    let sig_destination = sync_dir.join(format!("{name}.sig"));
                    let signature = self.fetch_signature(
                        &url,
                        &sig_destination,
                        &name,
                        policy,
                        cancel,
                        progress,
                    )?;
                    self.install(
                        Downloaded { database, signature, sig_destination },
                        &name,
                        keyring,
                        policy,
                        progress,
                    )?;
                    return Ok(Outcome::Updated);
                }
                Err(Error::Cancelled) => return Err(Error::Cancelled),
                Err(error) => attempts.push((url, error.to_string())),
            }
        }
        Err(Error::AllServersFailed { file: name, attempts })
    }

    /// Downloads `url` into a temporary beside `destination`.
    ///
    /// `Ok(None)` means the server answered "not modified".
    fn fetch(
        &self,
        url: &str,
        destination: &Path,
        since: Option<&str>,
        name: &str,
        target: Target,
        controls: Controls<'_>,
    ) -> Result<Option<AtomicFile>> {
        let Target { kind, max_bytes } = target;
        let Controls { cancel, progress } = controls;
        // Checked before the request, not only inside the stream. A worker that was just
        // told to stop should not open one more connection first.
        if cancel.is_requested() {
            return Err(Error::Cancelled);
        }
        let mut request = self.agent.get(url);
        if let Some(value) = since {
            request = request.header("If-Modified-Since", value);
        }

        let response = match request.call() {
            Ok(response) => response,
            Err(error) => {
                return Err(Error::Io {
                    path: PathBuf::from(url),
                    action: "download",
                    source: std::io::Error::other(error.to_string()),
                });
            }
        };

        // The status is inspected explicitly, and only 200 yields a body to install.
        //
        // This was a data-destroying bug. ureq returns 304 as `Ok` with an empty body, not as
        // `Err(StatusCode(304))`, which an earlier version of this code assumed. A successful
        // conditional request therefore looked like a successful download of nothing, and
        // committing it truncated the live database to zero bytes. This was observed against
        // a real mirror. Nothing downstream could have caught it: with no signature to
        // contradict it, an empty file verifies fine under `DatabaseOptional`.
        match response.status().as_u16() {
            200 => {}
            304 => return Ok(None),
            other => {
                return Err(Error::Io {
                    path: PathBuf::from(url),
                    action: "download",
                    source: std::io::Error::other(format!("unexpected HTTP status {other}")),
                });
            }
        }

        // Read before the body is consumed: `into_body` takes the response.
        let stamp = response
            .headers()
            .get("last-modified")
            .and_then(|value| value.to_str().ok())
            .and_then(parse_http_date);
        // Display-only, per this module's documentation. Never fed into `max_bytes`.
        let total = response
            .headers()
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());

        progress(Event::Started { file: name.to_owned(), kind, total });

        let mut file = AtomicFile::create(destination)?;
        let mut reader = response.into_body().into_reader();
        let written = stream_bounded(&mut reader, &mut file, max_bytes, name, cancel, |bytes| {
            progress(Event::Progress { kind, bytes });
        })?;

        // A repository database or a package archive is a compressed tarball, so it is never
        // legitimately empty. Even an empty tarball carries a gzip header. This is defense in
        // depth behind the status check above, kept because what it guards against was a
        // silently truncated live database, not a visible error.
        if written == 0 {
            return Err(Error::EmptyDownload { file: name.to_owned() });
        }
        progress(Event::Downloaded { file: name.to_owned(), kind });

        // Stamping the server's own timestamp onto the file is what makes the next
        // conditional request effective. See the note at the `If-Modified-Since` call site.
        if let Some(time) =
            stamp.and_then(|secs| std::time::UNIX_EPOCH.checked_add(Duration::from_secs(secs)))
        {
            file.set_modified(time);
        }
        Ok(Some(file))
    }

    /// Downloads the detached signature for a database or package, when the policy will use
    /// one, into `destination`.
    ///
    /// A missing signature is not an error here. It becomes zero signatures, which
    /// `piko_sig::decide` treats as "unsigned" and resolves through `Required` vs `Optional`.
    /// That keeps one rule in one place, the same reasoning `Keyring::check` uses.
    fn fetch_signature(
        &self,
        file_url: &str,
        destination: &Path,
        name: &str,
        policy: Policy,
        cancel: &Cancel,
        progress: &(dyn Fn(Event) + Sync),
    ) -> Result<Signature> {
        if !policy.check {
            return Ok(Signature::NotRequested);
        }
        let url = format!("{file_url}.sig");
        if cancel.is_requested() {
            return Err(Error::Cancelled);
        }

        let response = match self.agent.get(&url).call() {
            Ok(response) => response,
            // A 404 means this repository is simply not signed, which is the norm. Arch
            // mirrors serve no `.db.sig` at all (measured: `core.db` is 200, `core.db.sig` is
            // 404), which is why pacman ships `DatabaseOptional`. That is the policy's
            // business, so it becomes "no signatures" and `decide` resolves it.
            Err(ureq::Error::StatusCode(404 | 410)) => return Ok(Signature::Absent),
            // Anything else — a timeout, a TLS failure, a 500 — is not evidence of absence.
            // Reporting it as "it is not signed" would send the user looking for the wrong
            // problem.
            Err(error) => {
                return Err(Error::SignatureUncheckable {
                    file: name.to_owned(),
                    reason: format!("could not fetch {url}: {error}"),
                });
            }
        };
        // Only 200 carries a signature, and the status must be checked rather than assumed.
        // `http_status_as_error` turns 4xx and 5xx into `Err`, which the arms above rely on,
        // but not 3xx: ureq returns those as `Ok` with an empty body. That is the exact shape
        // of the bug that once truncated a live database (§66a), and this path never had the
        // guard `fetch` gained then. Without this check, an empty file reaches GPGME, which
        // reports "No data (gpg error 58)" and names the wrong culprit.
        let status = response.status().as_u16();
        if status != 200 {
            return Err(Error::SignatureUncheckable {
                file: name.to_owned(),
                reason: format!("{url} answered HTTP {status} rather than 200"),
            });
        }

        let total = response
            .headers()
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        progress(Event::Started { file: name.to_owned(), kind: Kind::Signature, total });

        let mut file = AtomicFile::create(destination)?;
        let mut reader = response.into_body().into_reader();
        // A signature is a few hundred bytes. Anything larger is not one.
        let written = stream_bounded(&mut reader, &mut file, 1024 * 1024, name, cancel, |bytes| {
            progress(Event::Progress { kind: Kind::Signature, bytes });
        })?;
        // An empty body is not "unsigned": the server said it had one. Reporting it here,
        // rather than letting the verifier fail on nothing, keeps the two apart.
        if written == 0 {
            return Err(Error::SignatureUncheckable {
                file: name.to_owned(),
                reason: format!("{url} returned an empty signature"),
            });
        }
        progress(Event::Downloaded { file: name.to_owned(), kind: Kind::Signature });
        Ok(Signature::Downloaded(file))
    }

    /// Verifies the downloaded temporaries and, only then, renames them into place.
    ///
    /// The order here is the whole point of the module; see its documentation.
    fn install(
        &self,
        downloaded: Downloaded,
        name: &str,
        keyring: Option<&Keyring>,
        policy: Policy,
        progress: &(dyn Fn(Event) + Sync),
    ) -> Result<()> {
        let Downloaded { database, signature, sig_destination } = downloaded;
        if policy.check {
            let Some(keyring) = keyring else {
                return Err(Error::SignatureUncheckable {
                    file: name.to_owned(),
                    reason: "the policy requires a signature but no keyring was given".to_owned(),
                });
            };

            // Verified at the temporary path, while the live database is still the old one.
            let outcomes = match &signature {
                Signature::Downloaded(signature) => keyring
                    .verify_detached(database.path(), signature.path())
                    .map_err(|source| Error::SignatureUncheckable {
                        file: name.to_owned(),
                        reason: source.to_string(),
                    })?,
                Signature::NotRequested | Signature::Absent => Vec::new(),
            };

            if let Verdict::Rejected(rejection) = piko_sig::decide(&outcomes, policy) {
                // Both temporaries drop here, unlinked, and the destination never changed.
                return Err(Error::SignatureRejected {
                    file: name.to_owned(),
                    reason: rejection.to_string(),
                });
            }
        }

        // The database lands first. A crash between the two leaves a database with a stale
        // signature, which the next open rejects. The reverse order would leave a signature
        // that vouches for a file that is not there yet.
        database.commit()?;
        match signature {
            Signature::Downloaded(signature) => signature.commit()?,
            // The server says there is none, and a database changes content under a fixed
            // name, so any `.sig` still sitting there vouches for bytes that have just been
            // replaced. Nothing in piko reads it (signatures are checked at download, §62),
            // but pacman verifies at open and shares this directory, so leaving it behind
            // makes the next `pacman -Sy` reject a database piko installed correctly.
            //
            // Failure is ignored on purpose. The database is already in place and correct.
            // Refusing the whole refresh because a stale file could not be unlinked would turn
            // a tidying step into an outage.
            Signature::Absent => {
                let _ = std::fs::remove_file(&sig_destination);
            }
            // Never asked, so nothing was learned about whether the database is signed.
            // Removing a signature on a `SigLevel = Never` refresh would destroy data on the
            // strength of a question that was not put.
            Signature::NotRequested => {}
        }
        progress(Event::Installed);
        Ok(())
    }

    /// Downloads `file_name` into `cache_dir`, with default bounds and no progress reporting.
    ///
    /// # Errors
    ///
    /// As [`Refresher::fetch_package_with_progress`].
    pub fn fetch_package(
        &self,
        cache_dir: &Path,
        file_name: &PackageFileName,
        repo_name: &str,
        servers: &[String],
        policy: Policy,
        cancel: &Cancel,
    ) -> Result<PathBuf> {
        self.fetch_package_with_progress(
            cache_dir,
            file_name,
            repo_name,
            servers,
            policy,
            cancel,
            &|_| {},
        )
    }

    /// Downloads `file_name` into `cache_dir`, reporting progress through `progress`.
    ///
    /// Unlike [`Refresher::refresh`], there is no conditional request. A package archive's
    /// name encodes its version, so if it is not already at the destination there is nothing
    /// to compare against.
    ///
    /// `servers` are tried in order, as in [`Refresher::refresh_with_progress`]. When `policy`
    /// asks for a signature, the package's own detached `.sig` is downloaded alongside it into
    /// `<cache_dir>/<file_name>.sig`, the path `piko_sig::Keyring::check` already looks for
    /// beside a package it is asked to verify. Nothing is verified here: this crate only
    /// fetches bytes. The check that matters happens later, against the policy that actually
    /// applies to this package (which can differ per repository, unlike a database's single
    /// `SigLevel`), by whoever calls `Keyring::check`.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if no server could supply the package, if it exceeded
    /// [`Limits::max_package_bytes`], or if the download was cancelled. In every case nothing
    /// is left in `cache_dir`.
    #[allow(
        clippy::too_many_arguments,
        reason = "each parameter names one concern a caller must decide, matching \
                  `refresh_with_progress`'s own justification"
    )]
    pub fn fetch_package_with_progress(
        &self,
        cache_dir: &Path,
        file_name: &PackageFileName,
        repo_name: &str,
        servers: &[String],
        policy: Policy,
        cancel: &Cancel,
        progress: &(dyn Fn(Event) + Sync),
    ) -> Result<PathBuf> {
        self.fetch_one(
            cache_dir,
            PackageFetch { file_name, repo_name, servers, policy, size: 0 },
            Concurrency::default(),
            0,
            cancel,
            progress,
        )
    }

    /// One package's download, as worker `worker` of a batch — see [`Self::refresh_one`] for
    /// what `worker` decides.
    fn fetch_one(
        &self,
        cache_dir: &Path,
        wanted: PackageFetch<'_>,
        concurrency: Concurrency,
        worker: usize,
        cancel: &Cancel,
        progress: &(dyn Fn(Event) + Sync),
    ) -> Result<PathBuf> {
        let PackageFetch { file_name, repo_name, servers, policy, size: _ } = wanted;
        if servers.is_empty() {
            return Err(Error::NoServers { repo: repo_name.to_owned() });
        }
        std::fs::create_dir_all(cache_dir).map_err(|source| Error::Io {
            path: cache_dir.to_path_buf(),
            action: "create",
            source,
        })?;

        let name = file_name.to_string();
        let destination = cache_dir.join(&name);
        let controls = Controls { cancel, progress };

        let mut attempts = Vec::new();
        for server in concurrency.servers_for(servers, worker) {
            let url = format!("{}/{name}", server.trim_end_matches('/'));
            match self.fetch(
                &url,
                &destination,
                None,
                &name,
                Target { kind: Kind::Package, max_bytes: self.limits.max_package_bytes },
                controls,
            ) {
                // A server answering "not modified" to a request that carried no
                // `If-Modified-Since` is not behaving like HTTP. Treat it as a failure of
                // this server rather than silently reporting success with nothing
                // downloaded.
                Ok(None) => {
                    attempts.push((
                        url,
                        "the server answered \"not modified\" to an unconditional request"
                            .to_owned(),
                    ));
                }
                Ok(Some(file)) => {
                    let sig_destination = cache_dir.join(format!("{name}.sig"));
                    let signature = self.fetch_signature(
                        &url,
                        &sig_destination,
                        &name,
                        policy,
                        cancel,
                        progress,
                    )?;
                    file.commit()?;
                    // Unlike a database, a package archive's name encodes its version, so the
                    // bytes under a given file name never change. A `.sig` left from an
                    // earlier download still vouches for exactly this file, so there is
                    // nothing stale to clear away.
                    if let Signature::Downloaded(signature) = signature {
                        signature.commit()?;
                    }
                    progress(Event::Installed);
                    return Ok(destination);
                }
                Err(Error::Cancelled) => return Err(Error::Cancelled),
                Err(error) => attempts.push((url, error.to_string())),
            }
        }
        Err(Error::AllServersFailed { file: name, attempts })
    }

    /// Refreshes every repository in `repos`, `concurrency.downloads()` at a time.
    ///
    /// Returns one result per entry, in `repos` order, regardless of the order the transfers
    /// actually finished in. A caller reports failures in configuration order, and its output
    /// does not depend on which mirror happened to be quick. A repository that fails does not
    /// stop the others, matching the serial loop this replaces.
    ///
    /// Nothing is reported from a worker. Results come back as data for the caller to print
    /// once the batch has joined, which is why parallelism cannot interleave one repository's
    /// error into another's.
    ///
    /// `progress` is called with the repository's index into `repos`, from whichever worker
    /// owns that transfer. See [`crate::progress`] for what an event may and may not be used
    /// for.
    ///
    /// # Errors
    ///
    /// Per entry, as [`Refresher::refresh`]. A `repos` naming the same repository twice fails
    /// every entry with [`Error::DuplicateTarget`] before any I/O, since two workers would
    /// otherwise race for one atomic-write temporary.
    #[allow(
        clippy::too_many_arguments,
        reason = "the same concerns `refresh_with_progress` names, minus the repository (now a \
                  list) and plus how many at a time"
    )]
    pub fn refresh_all(
        &self,
        sync_dir: &Path,
        repos: &[RepoRefresh<'_>],
        keyring: Option<&Keyring>,
        concurrency: Concurrency,
        force: bool,
        cancel: &Cancel,
        progress: &(dyn Fn(usize, Event) + Sync),
    ) -> Vec<Result<Outcome>> {
        if let Some(duplicate) = first_duplicate(repos.iter().map(|repo| repo.name.to_owned())) {
            return repos
                .iter()
                .map(|_| Err(Error::DuplicateTarget { file: format!("{duplicate}.db") }))
                .collect();
        }
        // Input order. Unlike packages, databases carry no size to schedule on, and a
        // `mirrorlist` is already sorted by how fast its mirrors are.
        let schedule: Vec<usize> = (0..repos.len()).collect();
        pool::run(
            repos,
            &schedule,
            concurrency.downloads().min(repos.len()),
            cancel,
            |job| {
                let sink = |event: Event| progress(job.index, event);
                self.refresh_one(
                    sync_dir,
                    *job.item,
                    keyring,
                    concurrency,
                    force,
                    job.worker,
                    cancel,
                    &sink,
                )
            },
            || Err(Error::Cancelled),
        )
    }

    /// Downloads every package in `wanted` into `cache_dir`, `concurrency.downloads()` at a
    /// time, largest first.
    ///
    /// Returns one result per entry, in `wanted` order, for the same reason
    /// [`Refresher::refresh_all`] does. Verifies nothing — see
    /// [`Refresher::fetch_package_with_progress`] for why that stays with the caller.
    ///
    /// Largest-first is [`PackageFetch::size`]'s only job. It measured as no gain on a link
    /// the downloads already saturate. It is kept because it costs nothing, and it is the
    /// difference between a good and a bad schedule on a link they do not: a 3 GiB package
    /// started last is a run that ends when it ends.
    ///
    /// # Errors
    ///
    /// Per entry, as [`Refresher::fetch_package`]. A `wanted` naming the same file twice fails
    /// every entry with [`Error::DuplicateTarget`], as [`Refresher::refresh_all`] does.
    pub fn fetch_packages(
        &self,
        cache_dir: &Path,
        wanted: &[PackageFetch<'_>],
        concurrency: Concurrency,
        cancel: &Cancel,
        progress: &(dyn Fn(Event) + Sync),
    ) -> Vec<Result<PathBuf>> {
        if let Some(duplicate) =
            first_duplicate(wanted.iter().map(|fetch| fetch.file_name.to_string()))
        {
            return wanted
                .iter()
                .map(|_| Err(Error::DuplicateTarget { file: duplicate.clone() }))
                .collect();
        }
        let mut schedule: Vec<usize> = (0..wanted.len()).collect();
        schedule.sort_by_key(|index| {
            std::cmp::Reverse(wanted.get(*index).map_or(0, |fetch| fetch.size))
        });
        pool::run(
            wanted,
            &schedule,
            concurrency.downloads().min(wanted.len()),
            cancel,
            |job| self.fetch_one(cache_dir, *job.item, concurrency, job.worker, cancel, progress),
            || Err(Error::Cancelled),
        )
    }
}

/// Copies `reader` into `writer`, refusing to exceed `max`.
///
/// Bounded as it goes rather than checked afterwards: a bound that
/// fires only after the work is done has not prevented anything. Cancellation is checked the
/// same way, once per chunk, for the same reason.
///
/// `on_chunk` receives the size of the chunk just written, not the running total. See
/// [`Event::Progress`] for why a total is unusable once more than one file is in flight. The
/// total is still kept here, because that is what `max` is checked against.
fn stream_bounded(
    reader: &mut impl Read,
    writer: &mut impl Write,
    max: u64,
    name: &str,
    cancel: &Cancel,
    mut on_chunk: impl FnMut(u64),
) -> Result<u64> {
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        if cancel.is_requested() {
            return Err(Error::Cancelled);
        }
        let read = reader.read(&mut buffer).map_err(|source| Error::Io {
            path: PathBuf::from(name),
            action: "read the download of",
            source,
        })?;
        if read == 0 {
            return Ok(total);
        }
        total = total.saturating_add(read as u64);
        if total > max {
            return Err(Error::TooLarge { file: name.to_owned(), max });
        }
        let chunk = buffer.get(..read).unwrap_or_default();
        writer.write_all(chunk).map_err(|source| Error::Io {
            path: PathBuf::from(name),
            action: "write the download of",
            source,
        })?;
        on_chunk(read as u64);
    }
}

/// The existing database's mtime as an HTTP date, for a conditional request.
///
/// `None` when there is nothing to be conditional about, which makes the first refresh an
/// unconditional download.
fn last_modified(path: &Path) -> Option<String> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    let seconds = modified.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    Some(http_date(seconds))
}

/// Formats seconds-since-epoch as an RFC 7231 IMF-fixdate.
///
/// Hand-rolled rather than pulling in a date library for one format string. This is the only
/// date piko ever renders for the wire, the format is fixed and fully specified, and the
/// nearest well-known formatter (`Rfc2822`) emits `+0000` where HTTP wants `GMT`.
///
/// The input is a file mtime, so it is disk-derived and therefore attacker-influenced. It is
/// clamped to \[1970, 9999\] before any arithmetic. This clamp lets the civil-from-days
/// algorithm below use plain operators without risking overflow: every intermediate is then
/// bounded by roughly 3 million, against an `i64`. A clamped date makes the conditional
/// request wrong at worst, never unsound, and a mtime outside that range is already nonsense.
fn http_date(seconds: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] =
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    /// 9999-12-31T23:59:59Z, past which the four-digit year would not fit anyway.
    const MAX: u64 = 253_402_300_799;

    let seconds = seconds.min(MAX);
    let days_total = seconds / 86_400;
    let time = seconds % 86_400;
    let (hour, minute, second) = (time / 3600, (time % 3600) / 60, time % 60);
    let weekday = DAYS.get((days_total % 7) as usize).copied().unwrap_or("Thu");

    // Civil-from-days (Howard Hinnant's algorithm), shifted so the era starts at 0000-03-01.
    // Every value here is bounded by the clamp above, so the plain operators cannot overflow.
    // Operators are spelled as saturating to satisfy the workspace's `arithmetic_side_effects`
    // wall. Given the clamp above, none of them can actually saturate. The tests against
    // `date -u` demonstrate the arithmetic is still the algorithm, not a mangling of it.
    let z = days_total.saturating_add(719_468) as i64;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe =
        doe.saturating_sub(doe / 1460).saturating_add(doe / 36_524).saturating_sub(doe / 146_096)
            / 365;
    let doy = doe.saturating_sub(
        365_i64.saturating_mul(yoe).saturating_add(yoe / 4).saturating_sub(yoe / 100),
    );
    let mp = 5_i64.saturating_mul(doy).saturating_add(2) / 153;
    let day =
        doy.saturating_sub(153_i64.saturating_mul(mp).saturating_add(2) / 5).saturating_add(1);
    let month = if mp < 10 { mp.saturating_add(3) } else { mp.saturating_sub(9) };
    let year = yoe.saturating_add(era.saturating_mul(400)).saturating_add(i64::from(month <= 2));
    let name = MONTHS.get(month.saturating_sub(1) as usize).copied().unwrap_or("Jan");

    format!("{weekday}, {day:02} {name} {year:04} {hour:02}:{minute:02}:{second:02} GMT")
}

/// Parses an RFC 7231 IMF-fixdate into seconds since the epoch.
///
/// The inverse of [`http_date`], and only that format. The obsolete RFC 850 and asctime forms
/// a recipient is meant to accept do not appear on `Last-Modified` from any real mirror.
/// Failing to parse simply means the file is not stamped, so the next refresh re-downloads
/// rather than misbehaving.
fn parse_http_date(value: &str) -> Option<u64> {
    const MONTHS: [&str; 12] =
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    // "Wed, 19 Aug 2026 09:57:55 GMT"
    let rest = value.split_once(", ")?.1;
    let mut parts = rest.split(' ');
    let day: i64 = parts.next()?.parse().ok()?;
    let month_name = parts.next()?;
    let year: i64 = parts.next()?.parse().ok()?;
    let clock = parts.next()?;
    if parts.next() != Some("GMT") {
        return None;
    }
    let month = MONTHS.iter().position(|name| *name == month_name)? as i64;
    let month = month.saturating_add(1);

    let mut clock = clock.split(':');
    let hour: u64 = clock.next()?.parse().ok()?;
    let minute: u64 = clock.next()?.parse().ok()?;
    let second: u64 = clock.next()?.parse().ok()?;
    // `second == 60` is a leap second. Rejected rather than accepted, because this function is
    // documented as the inverse of `http_date`, and `http_date` cannot produce it. Accepting
    // it would parse to the next minute and render back differently, quietly breaking the
    // round trip the conditional request depends on. This is theoretical either way —
    // `Last-Modified` comes from a file mtime, which is POSIX time and has no leap seconds —
    // and the consequence of refusing is only that the file is not stamped, exactly as for
    // any date that fails to parse.
    if clock.next().is_some() || hour > 23 || minute > 59 || second >= 60 {
        return None;
    }
    if !(1970..=9999).contains(&year) || !(1..=31).contains(&day) {
        return None;
    }

    // days-from-civil, the inverse of the era arithmetic in `http_date`. Bounded by the range
    // check above, so the saturating operators never actually saturate.
    let shifted = year.saturating_sub(i64::from(month <= 2));
    let era = shifted / 400;
    let yoe = shifted.saturating_sub(era.saturating_mul(400));
    let mp = if month > 2 { month.saturating_sub(3) } else { month.saturating_add(9) };
    let doy =
        (153_i64.saturating_mul(mp).saturating_add(2) / 5).saturating_add(day.saturating_sub(1));
    let doe = yoe
        .saturating_mul(365)
        .saturating_add(yoe / 4)
        .saturating_sub(yoe / 100)
        .saturating_add(doy);
    let days = era.saturating_mul(146_097).saturating_add(doe).saturating_sub(719_468);
    if days < 0 {
        return None;
    }

    let seconds = (days as u64)
        .saturating_mul(86_400)
        .saturating_add(hour.saturating_mul(3600))
        .saturating_add(minute.saturating_mul(60))
        .saturating_add(second);
    Some(seconds)
}

/// Refreshes one repository with default bounds.
///
/// # Errors
///
/// As [`Refresher::refresh`].
pub fn refresh(
    sync_dir: &Path,
    repo: &str,
    servers: &[String],
    keyring: Option<&Keyring>,
    policy: Policy,
    force: bool,
    cancel: &Cancel,
) -> Result<Outcome> {
    Refresher::default().refresh(sync_dir, repo, servers, keyring, policy, force, cancel)
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

    /// Checked against `date -u -d @<n> '+%a, %d %b %Y %H:%M:%S GMT'`. A hand-rolled date is
    /// exactly the kind of code that is confidently wrong.
    #[test]
    fn http_dates_match_the_reference_format() {
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(1_000_000_000), "Sun, 09 Sep 2001 01:46:40 GMT");
        assert_eq!(http_date(1_755_000_000), "Tue, 12 Aug 2025 12:00:00 GMT");
        // A leap day: where civil-from-days goes wrong if it is going to.
        assert_eq!(http_date(1_709_164_800), "Thu, 29 Feb 2024 00:00:00 GMT");
    }

    /// The two halves must be exact inverses, or a stamped file sends back a value the
    /// server does not recognize. That is precisely the bug this pairing exists to fix.
    #[test]
    fn parsing_and_formatting_round_trip() {
        for seconds in [0_u64, 1_000_000_000, 1_755_000_000, 1_709_164_800, 1_787_133_475] {
            let rendered = http_date(seconds);
            assert_eq!(parse_http_date(&rendered), Some(seconds), "{rendered}");
        }
    }

    /// The exact string this machine's mirror serves.
    #[test]
    fn a_real_last_modified_header_parses() {
        let parsed = parse_http_date("Tue, 18 Aug 2026 18:18:06 GMT").expect("a valid date");
        assert_eq!(http_date(parsed), "Tue, 18 Aug 2026 18:18:06 GMT");
    }

    #[test]
    fn malformed_dates_are_rejected_rather_than_guessed() {
        for bad in [
            "",
            "not a date",
            // A locale-translated date. This made an earlier measurement of this behavior
            // meaningless.
            "mar., 18 aout 2026 18:18:06 GMT",
            // Obsolete formats: valid HTTP, deliberately unsupported, must not misparse.
            "Tuesday, 18-Aug-26 18:18:06 GMT",
            "Tue Aug 18 18:18:06 2026",
            // Right shape, wrong zone.
            "Tue, 18 Aug 2026 18:18:06 UTC",
            "Tue, 18 Aug 2026 25:00:00 GMT",
            "Tue, 18 Xxx 2026 18:18:06 GMT",
            // A leap second. `http_date` cannot produce one, so accepting it would break the
            // round trip this pair is documented to be. It would parse to the next minute and
            // render back differently, so the conditional request would stop matching.
            "Tue, 18 Aug 2026 23:59:60 GMT",
        ] {
            assert_eq!(parse_http_date(bad), None, "{bad} was accepted");
        }
    }

    #[test]
    fn a_repository_with_no_servers_is_refused_before_any_io() {
        let dir = tempfile::tempdir().unwrap();
        let error = Refresher::default()
            .refresh(
                dir.path(),
                "core",
                &[],
                None,
                Policy::for_database(Default::default()),
                false,
                &Cancel::new(),
            )
            .unwrap_err();
        assert!(matches!(error, Error::NoServers { .. }), "{error:?}");
    }

    #[test]
    fn the_size_bound_fires_during_the_stream_not_after() {
        let mut source = std::io::repeat(0_u8).take(1024 * 1024);
        let mut sink = Vec::new();
        let error = stream_bounded(&mut source, &mut sink, 4096, "core.db", &Cancel::new(), |_| {})
            .unwrap_err();
        assert!(matches!(error, Error::TooLarge { .. }), "{error:?}");
        // The bound stopped the copy rather than letting it finish and complaining.
        assert!(sink.len() <= 64 * 1024 + 4096, "wrote {} bytes past the bound", sink.len());
    }

    #[test]
    fn a_stream_within_the_bound_is_copied_whole() {
        let mut source = std::io::Cursor::new(b"core.db contents".to_vec());
        let mut sink = Vec::new();
        stream_bounded(&mut source, &mut sink, 1024, "core.db", &Cancel::new(), |_| {}).unwrap();
        assert_eq!(sink, b"core.db contents");
    }

    #[test]
    fn a_cancelled_stream_stops_and_reports_it() {
        let mut source = std::io::repeat(0_u8).take(1024 * 1024);
        let mut sink = Vec::new();
        let cancel = Cancel::new();
        cancel.request();
        let error = stream_bounded(&mut source, &mut sink, 1024 * 1024, "core.db", &cancel, |_| {})
            .unwrap_err();
        assert!(matches!(error, Error::Cancelled), "{error:?}");
        assert!(sink.is_empty(), "nothing should have been written once already cancelled");
    }

    /// No previous database means an unconditional request.
    #[test]
    fn a_missing_database_has_no_conditional_header() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(last_modified(&dir.path().join("core.db")), None);
    }

    #[test]
    fn an_existing_database_yields_a_conditional_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("core.db");
        std::fs::write(&path, b"x").unwrap();
        let header = last_modified(&path).expect("an existing file has an mtime");
        assert!(header.ends_with(" GMT"), "{header}");
    }
}
