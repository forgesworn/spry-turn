//! A bounded HTTP/1.1 client for UPnP on the local network only.
//!
//! URLs must be `http://` with an IPv4 literal host, so no name is ever
//! resolved. Each request uses a fresh connection with `Connection: close`,
//! a total deadline and a response size limit. Redirects are never followed.

use crate::Error;
use std::fmt;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::{Duration, Instant};

/// Largest response head accepted.
pub const MAX_HEAD: usize = 8192;
/// Most header lines accepted.
pub const MAX_HEADERS: usize = 64;
/// Longest URL accepted.
pub const MAX_URL: usize = 512;

/// An `http://` URL with an IPv4 literal host.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Url {
    pub host: Ipv4Addr,
    pub port: u16,
    /// Absolute path with any query.
    pub path: String,
}

fn valid_path(path: &str) -> bool {
    path.starts_with('/') && path.bytes().all(|b| b.is_ascii_graphic() && b != b'#')
}

impl Url {
    /// Parse an absolute `http://a.b.c.d[:port][/path]` URL.
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        if value.len() > MAX_URL {
            return Err("URL too long");
        }
        let scheme = value.get(..7).ok_or("not an http URL")?;
        if !scheme.eq_ignore_ascii_case("http://") {
            return Err("not an http URL");
        }
        let rest = &value[7..];
        let (authority, path) = match rest.find('/') {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, "/"),
        };
        if authority.contains('@') {
            return Err("URL carries credentials");
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => {
                let port: u16 = port.parse().map_err(|_| "bad port")?;
                (host, port)
            }
            None => (authority, 80),
        };
        if port == 0 {
            return Err("bad port");
        }
        let host: Ipv4Addr = host.parse().map_err(|_| "host is not an IPv4 literal")?;
        if !valid_path(path) {
            return Err("bad path");
        }
        Ok(Self {
            host,
            port,
            path: path.to_owned(),
        })
    }

    /// Resolve `reference` against this URL: an absolute `http://` URL, an
    /// absolute path, or a path relative to this URL's directory.
    pub fn join(&self, reference: &str) -> Result<Self, &'static str> {
        let reference = reference.trim();
        if reference.len() > MAX_URL {
            return Err("URL too long");
        }
        if reference.starts_with("//") {
            return Err("network-path reference");
        }
        if reference
            .get(..7)
            .is_some_and(|s| s.eq_ignore_ascii_case("http://"))
        {
            return Self::parse(reference);
        }
        let scheme_like = reference
            .find([':', '/'])
            .is_some_and(|at| reference.as_bytes()[at] == b':');
        if scheme_like {
            return Err("not an http URL");
        }
        let path = if reference.starts_with('/') {
            reference.to_owned()
        } else {
            let base = self.path.split(['?']).next().unwrap_or("/");
            let directory = &base[..=base.rfind('/').unwrap_or(0)];
            format!("{directory}{reference}")
        };
        if path.len() > MAX_URL || !valid_path(&path) {
            return Err("bad path");
        }
        Ok(Self {
            host: self.host,
            port: self.port,
            path,
        })
    }

    pub fn socket(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.host, self.port)
    }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "http://{}:{}{}", self.host, self.port, self.path)
    }
}

/// Header lines as (lower-case name, value) pairs.
pub(crate) type Headers = Vec<(String, String)>;

/// A complete response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Parse a status line and header lines. Returns the status and the headers
/// with lower-case names.
pub(crate) fn parse_head(head: &str) -> Result<(u16, Headers), &'static str> {
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or("empty response")?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err("not an HTTP response");
    }
    let code = parts.next().unwrap_or("");
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err("bad status");
    }
    let status = code.parse().map_err(|_| "bad status")?;
    let mut headers = Vec::new();
    for line in lines {
        if headers.len() >= MAX_HEADERS {
            return Err("too many headers");
        }
        let (name, value) = line.split_once(':').ok_or("bad header")?;
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_graphic()) {
            return Err("bad header");
        }
        headers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
    }
    Ok((status, headers))
}

/// Decode a chunked body. `Ok(None)` means more bytes are needed.
fn dechunk(mut data: &[u8], limit: usize) -> Result<Option<Vec<u8>>, &'static str> {
    let mut body = Vec::new();
    loop {
        let Some(line_end) = data.windows(2).position(|w| w == b"\r\n") else {
            return if data.len() > 64 {
                Err("bad chunk size")
            } else {
                Ok(None)
            };
        };
        if line_end > 64 {
            return Err("bad chunk size");
        }
        let line = std::str::from_utf8(&data[..line_end]).map_err(|_| "bad chunk size")?;
        let digits = line.split(';').next().unwrap_or("").trim();
        if digits.is_empty() || digits.len() > 8 {
            return Err("bad chunk size");
        }
        let size = usize::from_str_radix(digits, 16).map_err(|_| "bad chunk size")?;
        data = &data[line_end + 2..];
        if size == 0 {
            // Trailers, if any, are ignored.
            return Ok(Some(body));
        }
        if body.len() + size > limit {
            return Err("response too large");
        }
        if data.len() < size + 2 {
            return Ok(None);
        }
        if &data[size..size + 2] != b"\r\n" {
            return Err("bad chunk");
        }
        body.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

/// Try to parse a response from the bytes read so far. `Ok(None)` means more
/// bytes are needed; `eof` says the peer has closed.
pub(crate) fn parse_response(
    buffer: &[u8],
    eof: bool,
    limit: usize,
) -> Result<Option<Response>, &'static str> {
    let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") else {
        if buffer.len() > MAX_HEAD {
            return Err("response head too large");
        }
        return if eof { Err("truncated") } else { Ok(None) };
    };
    if end > MAX_HEAD {
        return Err("response head too large");
    }
    let head = std::str::from_utf8(&buffer[..end]).map_err(|_| "bad header")?;
    let (status, headers) = parse_head(head)?;
    let rest = &buffer[end + 4..];
    let mut length: Option<usize> = None;
    let mut chunked = false;
    for (name, value) in &headers {
        match name.as_str() {
            "content-length" => {
                let parsed: usize = value.parse().map_err(|_| "bad content length")?;
                if length.is_some_and(|known| known != parsed) {
                    return Err("bad content length");
                }
                length = Some(parsed);
            }
            "transfer-encoding" => {
                if !value.eq_ignore_ascii_case("chunked") {
                    return Err("unsupported transfer encoding");
                }
                chunked = true;
            }
            _ => {}
        }
    }
    let body = if chunked {
        match dechunk(rest, limit)? {
            Some(body) => body,
            None if eof => return Err("truncated"),
            None => return Ok(None),
        }
    } else if let Some(length) = length {
        if length > limit {
            return Err("response too large");
        }
        if rest.len() < length {
            return if eof { Err("truncated") } else { Ok(None) };
        }
        rest[..length].to_vec()
    } else {
        if rest.len() > limit {
            return Err("response too large");
        }
        if !eof {
            return Ok(None);
        }
        rest.to_vec()
    };
    Ok(Some(Response { status, body }))
}

/// Send one request and read one response within `timeout` in total.
pub fn request(
    url: &Url,
    method: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    limit: usize,
    timeout: Duration,
) -> Result<Response, Error> {
    let deadline = Instant::now() + timeout;
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or(Error::NoAnswer)
    };
    let mut stream = TcpStream::connect_timeout(&SocketAddr::V4(url.socket()), remaining()?)?;
    let mut message = format!(
        "{method} {} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\nUser-Agent: spry-portmap UPnP/1.1\r\n",
        url.path, url.host, url.port
    );
    for (name, value) in headers {
        message.push_str(&format!("{name}: {value}\r\n"));
    }
    if !body.is_empty() || method == "POST" {
        message.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    message.push_str("\r\n");
    let mut out = message.into_bytes();
    out.extend_from_slice(body);
    stream.set_write_timeout(Some(remaining()?))?;
    stream.write_all(&out)?;
    // Chunk framing may add to the body, so the raw cap leaves room for it.
    let cap = MAX_HEAD + limit + limit / 4 + 1024;
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        stream.set_read_timeout(Some(remaining()?))?;
        let read = match stream.read(&mut chunk) {
            Ok(read) => read,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > cap {
            return Err(Error::Malformed("response too large"));
        }
        match parse_response(&buffer, read == 0, limit).map_err(Error::Malformed)? {
            Some(response) => return Ok(response),
            None if read == 0 => return Err(Error::Malformed("truncated")),
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_lan_literal_http_urls() {
        let url = Url::parse("http://192.168.1.1:5000/rootDesc.xml").unwrap();
        assert_eq!(
            (url.host, url.port, url.path.as_str()),
            (Ipv4Addr::new(192, 168, 1, 1), 5000, "/rootDesc.xml")
        );
        assert_eq!(Url::parse("HTTP://10.0.0.1").unwrap().path, "/");
        assert_eq!(Url::parse("http://10.0.0.1").unwrap().port, 80);
        for bad in [
            "https://10.0.0.1/",
            "http://router.local/",
            "http://user@10.0.0.1/",
            "http://10.0.0.1:0/",
            "http://10.0.0.1:99999/",
            "http://10.0.0.1/a b",
            "http://10.0.0.1/a#b",
            "http://[::1]/",
            "ftp://10.0.0.1/",
        ] {
            assert!(Url::parse(bad).is_err(), "{bad}");
        }
        assert!(Url::parse(&format!("http://10.0.0.1/{}", "a".repeat(MAX_URL))).is_err());
    }

    #[test]
    fn joins_references() {
        let base = Url::parse("http://192.168.1.1:5000/dev/root.xml?x=1").unwrap();
        assert_eq!(
            base.join("/ctl/IPConn").unwrap().to_string(),
            "http://192.168.1.1:5000/ctl/IPConn"
        );
        assert_eq!(
            base.join("ctl").unwrap().to_string(),
            "http://192.168.1.1:5000/dev/ctl"
        );
        assert_eq!(base.join("http://192.168.1.1:49000/c").unwrap().port, 49000);
        assert_eq!(base.join("//evil.example/c"), Err("network-path reference"));
        assert_eq!(base.join("javascript:alert(1)"), Err("not an http URL"));
        assert_eq!(base.join("https://192.168.1.1/c"), Err("not an http URL"));
    }

    #[test]
    fn reads_length_chunked_and_close_delimited_bodies() {
        let fixed = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
        assert_eq!(
            parse_response(fixed, false, 100).unwrap().unwrap().body,
            b"hello"
        );
        assert_eq!(parse_response(&fixed[..40], false, 100), Ok(None));
        assert_eq!(parse_response(&fixed[..40], true, 100), Err("truncated"));
        let chunked = b"HTTP/1.1 500 Internal\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        let response = parse_response(chunked, false, 100).unwrap().unwrap();
        assert_eq!(
            (response.status, response.body.as_slice()),
            (500, b"abcde".as_slice())
        );
        let closed = b"HTTP/1.0 200 OK\r\n\r\nall of it";
        assert_eq!(parse_response(closed, false, 100), Ok(None));
        assert_eq!(
            parse_response(closed, true, 100).unwrap().unwrap().body,
            b"all of it"
        );
    }

    #[test]
    fn refuses_oversized_and_malformed_responses() {
        assert_eq!(
            parse_response(
                b"HTTP/1.1 200 OK\r\nContent-Length: 101\r\n\r\n",
                false,
                100
            ),
            Err("response too large")
        );
        assert_eq!(
            parse_response(
                b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
                false,
                100
            ),
            Err("bad content length")
        );
        assert_eq!(
            parse_response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
                false,
                100
            ),
            Err("unsupported transfer encoding")
        );
        assert_eq!(
            parse_response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFF\r\n",
                false,
                100
            ),
            Err("response too large")
        );
        assert_eq!(
            parse_response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
                false,
                100
            ),
            Err("bad chunk size")
        );
        assert_eq!(
            parse_response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nabX\r\n",
                false,
                100
            ),
            Err("bad chunk")
        );
        assert_eq!(
            parse_response(b"SSH-2.0 x\r\n\r\n", false, 100),
            Err("not an HTTP response")
        );
        assert_eq!(
            parse_response(b"HTTP/1.1 2000 OK\r\n\r\n", false, 100),
            Err("bad status")
        );
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nno colon\r\n\r\n", false, 100),
            Err("bad header")
        );
        let many = format!(
            "HTTP/1.1 200 OK\r\n{}\r\n",
            "A: b\r\n".repeat(MAX_HEADERS + 1)
        );
        assert_eq!(
            parse_response(many.as_bytes(), false, 100),
            Err("too many headers")
        );
        assert_eq!(
            parse_response(&vec![b'a'; MAX_HEAD + 1], false, 100),
            Err("response head too large")
        );
    }
}
