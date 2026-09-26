//! One HTTP request, made in this process or in the download sandbox's helper.
//!
//! `refresh` sees one shape either way: a status, two headers, and a body to read. That is what
//! keeps the size bound, the atomic write and the `Last-Modified` checks in one place, in the
//! parent, whichever way the bytes arrive.

use std::io::Read;

use crate::{
    cancel::Cancel,
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
            Self::Direct(reader) => reader.read(buffer),
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
        match self {
            Self::Direct(agent) => {
                let mut request = agent.get(url);
                if let Some(value) = if_modified_since {
                    request = request.header("If-Modified-Since", value);
                }
                let response =
                    request.call().map_err(|error| Failure::Request(error.to_string()))?;
                let Header { status, last_modified, content_length } = header(&response);
                let body = Body::Direct(response.into_body().into_reader());
                Ok(Response { status, last_modified, content_length, body })
            }
            Self::Sandboxed { sandbox, timeouts } => {
                let fetched = sandbox
                    .fetch(url, if_modified_since, *timeouts, cancel)
                    .ok_or_else(|| Failure::Sandbox("the sandbox is disabled".to_owned()))?;
                let (header, fetch) = fetched?;
                let Header { status, last_modified, content_length } = header;
                Ok(Response { status, last_modified, content_length, body: Body::Sandboxed(fetch) })
            }
        }
    }
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
        .timeout_global(Some(timeouts.whole))
        // Much shorter than the global one, and separate from it on purpose. Cancellation is
        // only observable between requests and between chunks. So a worker parked in
        // DNS/connect/TLS ignores a Ctrl+C for as long as this allows, once per worker. That is
        // why it is worth bounding tightly, while the transfer itself keeps the generous
        // `timeout_global`.
        .timeout_connect(Some(timeouts.connect))
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
