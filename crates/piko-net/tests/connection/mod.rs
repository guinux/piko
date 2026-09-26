//! The one rule every test HTTP server here shares: answer once, and say so.

use std::io::Write;

/// Writes `response` with a `Connection: close` header after its status line.
///
/// These servers answer one request per connection. Without the header, HTTP/1.1 lets the
/// client keep the connection for its next request. ureq probes a pooled connection before it
/// uses it, but the server can close the socket after the probe and before the request
/// arrives. Nothing reads that request, and the client gets a reset. That happens only on a
/// loaded machine, so the header is what makes a test with more than one request deterministic.
pub fn write_closing(stream: &mut impl Write, response: &[u8]) {
    let end = response.windows(2).position(|pair| pair == b"\r\n").unwrap_or(response.len());
    let (status, rest) = response.split_at(end);
    let _ = stream.write_all(status);
    let _ = stream.write_all(b"\r\nConnection: close");
    let _ = stream.write_all(rest);
}
