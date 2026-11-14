//! The two messages exchanged with the download helper.
//!
//! The parent writes one [`Request`] on the helper's stdin. The helper answers on its stdout with
//! a sequence of frames. Each frame is one tag byte, a four-byte big-endian length, and that many
//! bytes of payload:
//!
//! ```text
//! answer := Setup | Failure | Header Data* (End | Failure)
//! ```
//!
//! The parent reads the answer as hostile input. The helper runs the code that talks to the
//! mirror, so a helper that a mirror took over writes whatever it likes here. Every length is
//! checked against a bound before a byte of payload is read, and anything out of order ends the
//! transfer as a failure. Nothing the helper writes can make the parent allocate more than
//! [`MAX_DATA`] bytes at once.

use std::io::{self, Read, Write};

use crate::error::{printable, without_credentials};

/// The first line of a request. It changes whenever the format does.
const REQUEST_MAGIC: &str = "piko-fetch 2";

/// The largest request the helper reads. A URL is the only part that can grow.
pub(crate) const MAX_REQUEST: u64 = 16 * 1024;

/// The largest header frame. It carries three short lines.
const MAX_HEADER: u32 = 4096;

/// The largest failure message. A longer one is truncated by the helper.
pub(crate) const MAX_MESSAGE: u32 = 4096;

/// The largest data frame.
pub(crate) const MAX_DATA: u32 = 64 * 1024;

/// A frame's tag byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Tag {
    /// The helper could not confine itself. Nothing was requested.
    Setup,
    /// The request, or the transfer of its body, failed.
    Failure,
    /// The status line and the headers the parent reads.
    Header,
    /// Part of the body.
    Data,
    /// The body is complete.
    End,
}

impl Tag {
    const fn byte(self) -> u8 {
        match self {
            Self::Setup => b'S',
            Self::Failure => b'F',
            Self::Header => b'H',
            Self::Data => b'D',
            Self::End => b'E',
        }
    }

    const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            b'S' => Some(Self::Setup),
            b'F' => Some(Self::Failure),
            b'H' => Some(Self::Header),
            b'D' => Some(Self::Data),
            b'E' => Some(Self::End),
            _ => None,
        }
    }

    /// The largest payload this tag may carry.
    const fn max_len(self) -> u32 {
        match self {
            Self::Setup | Self::Failure => MAX_MESSAGE,
            Self::Header => MAX_HEADER,
            Self::Data => MAX_DATA,
            Self::End => 0,
        }
    }
}

/// One request, as the parent sends it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Request {
    /// The URL to fetch.
    pub(crate) url: String,
    /// The `If-Modified-Since` value, if the request is conditional.
    pub(crate) if_modified_since: Option<String>,
    /// How long the response may take to begin after the connection, in milliseconds.
    pub(crate) response_timeout_millis: u64,
    /// The connect timeout, in milliseconds.
    pub(crate) connect_timeout_millis: u64,
    /// How long the transfer may receive nothing, in milliseconds. `None` is no limit.
    pub(crate) stall_timeout_millis: Option<u64>,
    /// Whether the helper applies Landlock.
    pub(crate) filesystem: bool,
    /// Whether the helper applies the system call filter.
    pub(crate) syscalls: bool,
    /// The TCP ports the helper may connect to.
    pub(crate) ports: Vec<u16>,
}

impl Request {
    /// The request as the bytes written on the helper's stdin.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let ports: Vec<String> = self.ports.iter().map(u16::to_string).collect();
        let stall = self.stall_timeout_millis.map(|millis| millis.to_string()).unwrap_or_default();
        format!(
            "{REQUEST_MAGIC}\n{}\n{}\n{}\n{}\n{stall}\n{}\n{}\n{}\n",
            self.url,
            self.if_modified_since.as_deref().unwrap_or_default(),
            self.response_timeout_millis,
            self.connect_timeout_millis,
            u8::from(self.filesystem),
            u8::from(self.syscalls),
            ports.join(","),
        )
        .into_bytes()
    }

    /// Reads a request from `input`, which is the helper's stdin.
    pub(crate) fn decode(input: impl Read) -> Result<Self, String> {
        let mut text = String::new();
        input
            .take(MAX_REQUEST.saturating_add(1))
            .read_to_string(&mut text)
            .map_err(|error| format!("could not read the request: {error}"))?;
        if text.len() as u64 > MAX_REQUEST {
            return Err("the request is too large".to_owned());
        }
        // A line ends at a line feed alone, as `encode` writes it. A carriage return is refused
        // rather than read as part of a line ending: the parent never sends one, and `lines`
        // would remove it from a field, so the field would decode to a value the parent did not
        // encode.
        if text.contains('\r') {
            return Err("the request contains a carriage return".to_owned());
        }

        let mut lines = text.lines();
        let mut next =
            |what: &str| lines.next().ok_or_else(|| format!("the request has no {what}"));
        if next("version")? != REQUEST_MAGIC {
            return Err("the request has an unknown version".to_owned());
        }
        let url = next("URL")?.to_owned();
        if url.is_empty() {
            return Err("the request has an empty URL".to_owned());
        }
        let since = next("If-Modified-Since line")?;
        let if_modified_since = (!since.is_empty()).then(|| since.to_owned());
        let response_timeout_millis = parse_number(next("response timeout")?, "response timeout")?;
        let connect_timeout_millis = parse_number(next("connect timeout")?, "connect timeout")?;
        let stall = next("stall timeout line")?;
        let stall_timeout_millis =
            if stall.is_empty() { None } else { Some(parse_number(stall, "stall timeout")?) };
        let filesystem = parse_flag(next("filesystem flag")?)?;
        let syscalls = parse_flag(next("system call flag")?)?;
        let ports = next("port list")?;
        let ports = if ports.is_empty() {
            Vec::new()
        } else {
            ports
                .split(',')
                .map(|port| port.parse::<u16>().map_err(|_| format!("{port:?} is not a port")))
                .collect::<Result<_, _>>()?
        };

        Ok(Self {
            url,
            if_modified_since,
            response_timeout_millis,
            connect_timeout_millis,
            stall_timeout_millis,
            filesystem,
            syscalls,
            ports,
        })
    }
}

fn parse_number(text: &str, what: &str) -> Result<u64, String> {
    text.parse().map_err(|_| format!("the request's {what} {text:?} is not a number"))
}

fn parse_flag(text: &str) -> Result<bool, String> {
    match text {
        "0" => Ok(false),
        "1" => Ok(true),
        other => Err(format!("{other:?} is not a flag")),
    }
}

/// The status and the headers of a response, as the header frame carries them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Header {
    /// The HTTP status code.
    pub(crate) status: u16,
    /// The `Last-Modified` header, verbatim.
    pub(crate) last_modified: Option<String>,
    /// The `Content-Length` header, parsed.
    pub(crate) content_length: Option<u64>,
}

impl Header {
    fn encode(&self) -> Vec<u8> {
        let length = self.content_length.map(|length| length.to_string()).unwrap_or_default();
        format!(
            "{}\n{}\n{length}\n",
            self.status,
            self.last_modified.as_deref().unwrap_or_default()
        )
        .into_bytes()
    }

    fn decode(payload: &[u8]) -> io::Result<Self> {
        let text =
            std::str::from_utf8(payload).map_err(|_| invalid("a header that is not UTF-8"))?;
        let mut lines = text.split('\n');
        let status = lines
            .next()
            .and_then(|status| status.parse::<u16>().ok())
            .ok_or_else(|| invalid("a header with no status"))?;
        let last_modified = lines.next().filter(|value| !value.is_empty()).map(str::to_owned);
        let content_length = lines.next().and_then(|value| value.parse::<u64>().ok());
        Ok(Self { status, last_modified, content_length })
    }
}

/// Writes the helper's side of the protocol.
#[derive(Debug)]
pub(crate) struct Writer<W: Write> {
    output: W,
}

impl<W: Write> Writer<W> {
    pub(crate) const fn new(output: W) -> Self {
        Self { output }
    }

    fn frame(&mut self, tag: Tag, payload: &[u8]) -> io::Result<()> {
        let len = u32::try_from(payload.len()).map_err(|_| invalid("an oversized frame"))?;
        if len > tag.max_len() {
            return Err(invalid("an oversized frame"));
        }
        self.output.write_all(&[tag.byte()])?;
        self.output.write_all(&len.to_be_bytes())?;
        self.output.write_all(payload)?;
        self.output.flush()
    }

    /// Reports a message under `tag`, truncated to [`MAX_MESSAGE`] bytes.
    pub(crate) fn message(&mut self, tag: Tag, text: &str) -> io::Result<()> {
        let mut end = text.len().min(MAX_MESSAGE as usize);
        while !text.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        self.frame(tag, text.get(..end).unwrap_or_default().as_bytes())
    }

    pub(crate) fn header(&mut self, header: &Header) -> io::Result<()> {
        self.frame(Tag::Header, &header.encode())
    }

    /// Copies `body` in data frames, then writes the end frame.
    ///
    /// A read failure is reported as a failure frame. A write failure means the parent has gone,
    /// and is returned.
    pub(crate) fn body(&mut self, mut body: impl Read) -> io::Result<()> {
        let mut buffer = vec![0_u8; MAX_DATA as usize];
        loop {
            let read = match body.read(&mut buffer) {
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return self.message(Tag::Failure, &error.to_string()),
            };
            if read == 0 {
                return self.frame(Tag::End, &[]);
            }
            self.frame(Tag::Data, buffer.get(..read).unwrap_or_default())?;
        }
    }
}

/// The first frame of an answer, read by the parent.
#[derive(Debug)]
pub(crate) enum Opening {
    /// The helper could not confine itself.
    Setup(String),
    /// The request failed.
    Failure(String),
    /// The response began.
    Header(Header),
}

/// Reads the parent's side of the protocol.
#[derive(Debug)]
pub(crate) struct Reader<R: Read> {
    input: R,
    /// The unread part of the current data frame.
    pending: Vec<u8>,
    /// How much of `pending` is already returned.
    consumed: usize,
    /// Whether the end frame arrived.
    finished: bool,
}

impl<R: Read> Reader<R> {
    pub(crate) const fn new(input: R) -> Self {
        Self { input, pending: Vec::new(), consumed: 0, finished: false }
    }

    /// Reads one frame's tag and payload, checking its length before reading the payload.
    fn frame(&mut self) -> io::Result<(Tag, Vec<u8>)> {
        let mut head = [0_u8; 5];
        self.input.read_exact(&mut head).map_err(|error| {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                io::Error::other("the download helper stopped before it finished")
            } else {
                error
            }
        })?;
        let [tag, a, b, c, d] = head;
        let tag = Tag::from_byte(tag).ok_or_else(|| invalid("an unknown frame"))?;
        let len = u32::from_be_bytes([a, b, c, d]);
        if len > tag.max_len() {
            return Err(invalid("an oversized frame"));
        }
        let mut payload = vec![0_u8; len as usize];
        self.input.read_exact(&mut payload)?;
        Ok((tag, payload))
    }

    /// Reads the first frame.
    pub(crate) fn opening(&mut self) -> io::Result<Opening> {
        let (tag, payload) = self.frame()?;
        let text = || printable(&without_credentials(&String::from_utf8_lossy(&payload)));
        match tag {
            Tag::Setup => Ok(Opening::Setup(text())),
            Tag::Failure => Ok(Opening::Failure(text())),
            Tag::Header => Header::decode(&payload).map(Opening::Header),
            Tag::Data | Tag::End => Err(invalid("a body before its header")),
        }
    }
}

impl<R: Read> Read for Reader<R> {
    /// Returns body bytes. Returns `Ok(0)` only after the end frame, so a helper that stops
    /// half-way is an error rather than a short body.
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        while self.consumed >= self.pending.len() {
            if self.finished {
                return Ok(0);
            }
            let (tag, payload) = self.frame()?;
            match tag {
                Tag::Data if !payload.is_empty() => {
                    self.pending = payload;
                    self.consumed = 0;
                }
                Tag::End => self.finished = true,
                Tag::Failure => {
                    let text = String::from_utf8_lossy(&payload);
                    return Err(io::Error::other(printable(&without_credentials(&text))));
                }
                Tag::Data | Tag::Setup | Tag::Header => {
                    return Err(invalid("a frame out of order"));
                }
            }
        }
        let rest = self.pending.get(self.consumed..).unwrap_or_default();
        let count = rest.len().min(buffer.len());
        let (target, _) = buffer.split_at_mut(count);
        target.copy_from_slice(rest.get(..count).unwrap_or_default());
        self.consumed = self.consumed.saturating_add(count);
        Ok(count)
    }
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("the download helper sent {what}"))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    fn request() -> Request {
        Request {
            url: "https://mirror.example/core/os/x86_64/core.db".to_owned(),
            if_modified_since: Some("Sat, 26 Sep 2026 10:00:00 GMT".to_owned()),
            response_timeout_millis: 60_000,
            connect_timeout_millis: 10_000,
            stall_timeout_millis: Some(10_000),
            filesystem: true,
            syscalls: false,
            ports: vec![53, 443],
        }
    }

    #[test]
    fn a_request_round_trips() {
        let request = request();
        assert_eq!(Request::decode(request.encode().as_slice()).unwrap(), request);

        let bare = Request {
            if_modified_since: None,
            stall_timeout_millis: None,
            ports: Vec::new(),
            ..request
        };
        assert_eq!(Request::decode(bare.encode().as_slice()).unwrap(), bare);
    }

    #[test]
    fn a_malformed_request_is_refused() {
        let text = String::from_utf8(request().encode()).unwrap();
        for bad in [
            text.replace("piko-fetch 2", "piko-fetch 1"),
            text.replace("\n60000\n", "\nsixty\n"),
            text.replace("53,443", "53,70000"),
            text.replace('\n', "\r\n"),
            text.replace("GMT", "GMT\r"),
            "piko-fetch 2\n".to_owned(),
            "x".repeat((MAX_REQUEST as usize).saturating_add(1)),
        ] {
            assert!(Request::decode(bad.as_bytes()).is_err(), "{bad:?}");
        }
    }

    /// Writes a whole answer the way the helper does.
    fn answer(header: &Header, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut writer = Writer::new(&mut out);
        writer.header(header).unwrap();
        writer.body(body).unwrap();
        out
    }

    #[test]
    fn a_body_round_trips_across_frames() {
        let header = Header {
            status: 200,
            last_modified: Some("Sat, 26 Sep 2026 10:00:00 GMT".to_owned()),
            content_length: Some(200_000),
        };
        let body: Vec<u8> = (0..200_000_u32).map(|n| n.to_le_bytes()[0]).collect();

        let bytes = answer(&header, &body);
        let mut reader = Reader::new(bytes.as_slice());
        let Opening::Header(read) = reader.opening().unwrap() else { panic!("no header") };
        let mut received = Vec::new();
        reader.read_to_end(&mut received).unwrap();

        assert_eq!(read, header);
        assert_eq!(received, body);
    }

    /// A helper that dies half-way must not look like a complete, shorter body.
    #[test]
    fn a_body_with_no_end_frame_is_an_error() {
        let header = Header { status: 200, last_modified: None, content_length: None };
        let mut bytes = answer(&header, b"some bytes");
        bytes.truncate(bytes.len().saturating_sub(5));

        let mut reader = Reader::new(bytes.as_slice());
        reader.opening().unwrap();
        let mut received = Vec::new();

        assert!(reader.read_to_end(&mut received).is_err());
    }

    #[test]
    fn an_oversized_frame_is_refused_before_it_is_read() {
        let mut bytes = vec![b'D'];
        bytes.extend_from_slice(&MAX_DATA.saturating_add(1).to_be_bytes());
        let header = Header { status: 200, last_modified: None, content_length: None };
        let mut stream = answer(&header, b"");
        stream.truncate(stream.len().saturating_sub(5));
        stream.extend_from_slice(&bytes);

        let mut reader = Reader::new(stream.as_slice());
        reader.opening().unwrap();
        let error = reader.read(&mut [0; 16]).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_failure_during_the_body_carries_its_message() {
        let mut out = Vec::new();
        let mut writer = Writer::new(&mut out);
        writer.header(&Header { status: 200, last_modified: None, content_length: None }).unwrap();
        writer.message(Tag::Failure, "connection reset").unwrap();

        let mut reader = Reader::new(out.as_slice());
        reader.opening().unwrap();
        let error = reader.read(&mut [0; 16]).unwrap_err();

        assert_eq!(error.to_string(), "connection reset");
    }

    #[test]
    fn data_before_a_header_is_refused() {
        let mut out = Vec::new();
        Writer::new(&mut out).body(&b"early"[..]).unwrap();

        assert!(Reader::new(out.as_slice()).opening().is_err());
    }

    /// A helper that a mirror took over writes whatever it likes in a message. The parent
    /// prints it, so what could drive a terminal is escaped on the way in.
    #[test]
    fn a_message_cannot_drive_the_terminal() {
        let mut out = Vec::new();
        let mut writer = Writer::new(&mut out);
        writer.message(Tag::Failure, "reset\u{1b}[2J").unwrap();

        let mut reader = Reader::new(out.as_slice());
        let Opening::Failure(text) = reader.opening().unwrap() else { panic!("no failure") };
        assert_eq!(text, "reset\\u{1b}[2J");

        let mut header = Vec::new();
        let mut writer = Writer::new(&mut header);
        writer.header(&Header { status: 200, last_modified: None, content_length: None }).unwrap();
        writer.message(Tag::Failure, "late\u{1b}[2J").unwrap();
        let mut reader = Reader::new(header.as_slice());
        reader.opening().unwrap();
        let error = reader.read(&mut [0; 16]).unwrap_err();
        assert_eq!(error.to_string(), "late\\u{1b}[2J");
    }

    #[test]
    fn a_long_message_is_truncated_on_a_character_boundary() {
        let mut out = Vec::new();
        Writer::new(&mut out).message(Tag::Failure, &"é".repeat(5000)).unwrap();

        let Opening::Failure(text) = Reader::new(out.as_slice()).opening().unwrap() else {
            panic!("no failure");
        };
        assert!(text.len() <= MAX_MESSAGE as usize);
        assert!(text.chars().all(|c| c == 'é'));
    }
}
