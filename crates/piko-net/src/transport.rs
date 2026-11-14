//! One HTTP request, made in this process or in the download sandbox's helper.
//!
//! `refresh` sees one shape either way: a status, two headers, and a body to read. That is what
//! keeps the size bound, the atomic write and the `Last-Modified` checks in one place, in the
//! parent, whichever way the bytes arrive.

use std::io::Read;

use crate::{
    cancel::Cancel,
    error::{printable, without_credentials},
    sandbox::{Failure, Fetch, Sandbox, Timeouts, protocol::Header},
};

/// How [`crate::Refresher`] reaches a server.
#[derive(Debug)]
pub(crate) enum Transport {
    /// In this process.
    Direct(ureq::Agent),
    /// In a helper process, one per request.
    Sandboxed { sandbox: Sandbox, timeouts: Timeouts },
}

/// A response whose body is still to be read.
pub(crate) struct Response {
    pub(crate) status: u16,
    pub(crate) last_modified: Option<String>,
    pub(crate) content_length: Option<u64>,
    pub(crate) body: Body,
}

/// A response body.
pub(crate) enum Body {
    Direct(ureq::BodyReader<'static>),
    Sandboxed(Fetch),
}

impl Read for Body {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            // ureq's own messages can quote a header the server sent.
            Self::Direct(reader) => reader.read(buffer).map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    printable(&without_credentials(&error.to_string())),
                )
            }),
            Self::Sandboxed(fetch) => fetch.read(buffer),
        }
    }
}

impl Transport {
    /// Reaches servers in this process, with these timeouts.
    pub(crate) fn direct(timeouts: Timeouts) -> Self {
        Self::Direct(agent(timeouts))
    }

    /// Sends one `GET`. Every status is a response, so the caller decides what each one means.
    pub(crate) fn get(
        &self,
        url: &str,
        if_modified_since: Option<&str>,
        cancel: &Cancel,
    ) -> Result<Response, Failure> {
        if !is_permitted(url) {
            return Err(Failure::Request(format!(
                "refusing {}: piko downloads over https only, or over http from this machine's \
                 loopback",
                printable(&without_credentials(url))
            )));
        }
        match self {
            Self::Direct(agent) => {
                let response = request(agent, url, if_modified_since).call().map_err(|error| {
                    Failure::Request(printable(&without_credentials(&error.to_string())))
                })?;
                let Header { status, last_modified, content_length } = header(&response);
                let body = Body::Direct(response.into_body().into_reader());
                Ok(Response { status, last_modified, content_length, body })
            }
            Self::Sandboxed { sandbox, timeouts } => {
                let fetched = sandbox
                    .fetch(url, if_modified_since, *timeouts, cancel)
                    .ok_or_else(|| Failure::Sandbox("the sandbox is disabled".to_owned()))?;
                // The helper's own messages lose their credentials where they are read, in
                // `protocol`. This covers what the parent says about the helper.
                let (header, fetch) = fetched.map_err(|failure| match failure {
                    Failure::Request(reason) => {
                        Failure::Request(without_credentials(&reason).into_owned())
                    }
                    other @ Failure::Sandbox(_) => other,
                })?;
                let Header { status, last_modified, content_length } = header;
                Ok(Response { status, last_modified, content_length, body: Body::Sandboxed(fetch) })
            }
        }
    }
}

/// The `GET` for `url`, in this process or in the helper.
///
/// A URL configured as `https` is followed only to other `https` URLs, at every redirect. A
/// redirect to `http` would hand the transfer to anyone on the path of that second connection.
/// A repository database is usually unsigned, and then TLS is all that authenticates it. An
/// `http` URL, which [`is_permitted`] allows only on the loopback, follows no redirect at all:
/// one could lead off the machine, and ureq cannot limit it to the loopback.
pub(crate) fn request(
    agent: &ureq::Agent,
    url: &str,
    if_modified_since: Option<&str>,
) -> ureq::RequestBuilder<ureq::typestate::WithoutBody> {
    let mut request = agent.get(url);
    if is_https(url) {
        request = request.config().https_only(true).build();
    } else {
        request = request.config().max_redirects(0).build();
    }
    if let Some(value) = if_modified_since {
        request = request.header("If-Modified-Since", value);
    }
    request
}

/// Whether `url`'s scheme is `https`.
pub(crate) fn is_https(url: &str) -> bool {
    url.split_once("://").is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("https"))
}

/// Whether `url` may be requested at all: `https`, or `http` to this machine's loopback.
///
/// Arch publishes its databases unsigned, so for a database TLS is the only thing between a
/// mirror and the network: over `http`, anyone on the path can hold a database back or serve
/// one of their choosing that is not older (the rollback check refuses only an older one), and
/// see every package this machine installs. libalpm accepts an `http` server; piko refuses it
/// before any connection, and the mirror loop moves on to the next server.
///
/// The loopback is kept, spelled `localhost`, `127.0.0.0/8` or `[::1]`: a caching proxy on this
/// machine is common, and no one else is on that path. The host is read after the last `@` of
/// the authority, so a user name cannot pass for the host.
pub(crate) fn is_permitted(url: &str) -> bool {
    if is_https(url) {
        return true;
    }
    let Some((scheme, rest)) = url.split_once("://") else { return false };
    if !scheme.eq_ignore_ascii_case("http") {
        return false;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host_and_port = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    let host = match host_and_port.strip_prefix('[') {
        Some(bracketed) => bracketed.split_once(']').map_or("", |(host, _)| host),
        None => host_and_port.split(':').next().unwrap_or_default(),
    };
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<std::net::IpAddr>().is_ok_and(|address| address.is_loopback())
}

/// The agent every request uses, in this process or in the helper.
pub(crate) fn agent(timeouts: Timeouts) -> ureq::Agent {
    // The provider must be named explicitly, or ureq's default provider selection and this
    // workspace's enabled features can silently disagree.
    let tls = ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::Rustls)
        // The system CA store, matching what libcurl and therefore pacman use. The alternative is
        // a Mozilla root bundle compiled into the binary, which then ages independently of it.
        .root_certs(ureq::tls::RootCerts::PlatformVerifier)
        .build();
    let config = ureq::Agent::config_builder()
        // No timeout covers the whole request. A total would refuse every transfer that takes
        // longer than it, however steadily the bytes arrive: at 1 MiB/s, a bound of 60 s refuses
        // every package above 60 MiB, on every server. Each wait is bounded instead.
        //
        // Cancellation is only observable between requests and between chunks. So a worker
        // parked in DNS/connect/TLS ignores a Ctrl+C for as long as this allows, once per
        // worker. That is why it is bounded tightly.
        // A local name lookup is not part of ureq's connect phase, so it gets the same bound.
        .timeout_resolve(Some(timeouts.connect))
        .timeout_connect(Some(timeouts.connect))
        .timeout_recv_response(Some(timeouts.response))
        // The bound restarts at each read, so it refuses a transfer that stopped and never one
        // that is slow. libcurl's low-speed limit does the same for pacman.
        .timeout_per_read(timeouts.stall)
        // A mirror that redirects forever is a mirror that hangs the update.
        .max_redirects(5)
        // Every status is returned as a response, and `refresh` reads each one itself. A `304`
        // is not an error, and a `404` on a `.sig` is an answer, not a failure.
        .http_status_as_error(false)
        .user_agent(concat!("piko/", env!("CARGO_PKG_VERSION")))
        .tls_config(tls)
        .build();
    ureq::Agent::new_with_config(config)
}

/// The status and the two headers `refresh` reads.
pub(crate) fn header(response: &ureq::http::Response<ureq::Body>) -> Header {
    let headers = response.headers();
    let text = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
    Header {
        status: response.status().as_u16(),
        last_modified: text("last-modified").map(str::to_owned),
        content_length: text("content-length").and_then(|value| value.parse::<u64>().ok()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_and_the_loopback_are_permitted() {
        for url in [
            "https://geo.mirror.pkgbuild.com/core/os/x86_64",
            "HTTPS://example.org/",
            "http://127.0.0.1:8080/core",
            "http://127.1.2.3/core",
            "http://localhost:9129/repo/archlinux/core",
            "http://LOCALHOST/core",
            "http://[::1]:8080/core",
        ] {
            assert!(is_permitted(url), "{url} was refused");
        }
    }

    /// Plain `http` to anything but the loopback is refused, however the host is dressed up.
    #[test]
    fn http_off_the_loopback_is_refused() {
        for url in [
            "http://mirror.example.org/core",
            "http://192.168.1.10/core",
            "http://[2001:db8::1]/core",
            "http://127.0.0.1@evil.example/core",
            "http://localhost.evil.example/core",
            "http://evil.example#@127.0.0.1/core",
            "http://127.0.0.1\\@evil.example/core",
            "ftp://127.0.0.1/core",
            "file:///var/cache/pacman/pkg",
            "127.0.0.1/core",
        ] {
            assert!(!is_permitted(url), "{url} was permitted");
        }
    }
}
