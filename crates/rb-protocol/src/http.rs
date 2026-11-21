//! HTTP proxy server side, mirroring sing `protocol/http`
//! (`HandleConnectionEx`): CONNECT (RFC 9110 section 9.3.6), `Upgrade`
//! requests, and plain requests in absolute form, several on one client
//! connection.
//!
//! As in sing-box, every plain request is a routed connection of its own:
//! the request is rewritten to origin form without hop-by-hop headers and
//! sent over a fresh connection through the router, the response is passed
//! back without its hop-by-hop headers, and the client connection stays
//! open for the next request when the client asked for it (`HTTP/1.1` with
//! `Proxy-Connection: keep-alive`).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};

use async_trait::async_trait;
use base64::Engine;
use rb_adapter::{BoxStream, PrefixedStream, Socksaddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_HEAD: usize = 64 * 1024;

/// Where the HTTP server hands the connections it opens (sing
/// `N.TCPConnectionHandlerEx`).
#[async_trait]
pub trait ConnectionHandler: Send + Sync {
    /// Routes `stream` to `destination`; returns when the connection ends.
    async fn new_connection(&self, source: SocketAddr, destination: Socksaddr, user: Option<String>, stream: BoxStream);
}

fn protocol_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// A reader with a buffer of bytes read ahead (Go's `bufio.Reader`).
pub struct Wire<R> {
    inner: R,
    buffer: Vec<u8>,
}

impl<R: AsyncRead + Unpin> Wire<R> {
    pub fn new(inner: R) -> Self {
        Wire { inner, buffer: Vec::new() }
    }

    async fn fill(&mut self) -> io::Result<usize> {
        let mut chunk = [0u8; 8192];
        let read = self.inner.read(&mut chunk).await?;
        self.buffer.extend_from_slice(&chunk[..read]);
        Ok(read)
    }

    /// Reads up to and including the blank line ending a message head;
    /// `None` when the stream ends before any byte of it.
    async fn read_head(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(end) = self.buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                let rest = self.buffer.split_off(end + 4);
                return Ok(Some(std::mem::replace(&mut self.buffer, rest)));
            }
            if self.buffer.len() > MAX_HEAD {
                return Err(protocol_error("http: message head too large"));
            }
            if self.fill().await? == 0 {
                if self.buffer.is_empty() {
                    return Ok(None);
                }
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "http: connection closed in message head"));
            }
        }
    }

    async fn read_line(&mut self) -> io::Result<Vec<u8>> {
        loop {
            if let Some(end) = self.buffer.windows(2).position(|window| window == b"\r\n") {
                let rest = self.buffer.split_off(end + 2);
                return Ok(std::mem::replace(&mut self.buffer, rest));
            }
            if self.buffer.len() > MAX_HEAD {
                return Err(protocol_error("http: line too long"));
            }
            if self.fill().await? == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "http: connection closed in chunk header"));
            }
        }
    }

    /// Some bytes, at most `max`: buffered ones first. Empty at the end.
    async fn read_some(&mut self, max: usize) -> io::Result<Vec<u8>> {
        if self.buffer.is_empty() && self.fill().await? == 0 {
            return Ok(Vec::new());
        }
        let count = self.buffer.len().min(max);
        let rest = self.buffer.split_off(count);
        Ok(std::mem::replace(&mut self.buffer, rest))
    }

    pub fn into_parts(self) -> (R, Vec<u8>) {
        (self.inner, self.buffer)
    }
}

/// How a message body is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    None,
    Length(u64),
    Chunked,
    /// Until the sender closes (responses only).
    Close,
}

/// Copies one body as it is on the wire, chunked framing included.
/// Returns the number of payload bytes.
async fn copy_body<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    from: &mut Wire<R>,
    framing: Framing,
    to: &mut W,
) -> io::Result<u64> {
    let mut total = 0u64;
    match framing {
        Framing::None => {}
        Framing::Length(length) => {
            let mut remaining = length;
            while remaining > 0 {
                let data = from.read_some(remaining.min(65536) as usize).await?;
                if data.is_empty() {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "http: body ended early"));
                }
                remaining -= data.len() as u64;
                total += data.len() as u64;
                to.write_all(&data).await?;
            }
        }
        Framing::Chunked => loop {
            let line = from.read_line().await?;
            to.write_all(&line).await?;
            let text = std::str::from_utf8(&line).map_err(|_| protocol_error("http: bad chunk size"))?;
            let size_text = text.trim_end_matches("\r\n").split(';').next().unwrap_or_default().trim();
            let size = u64::from_str_radix(size_text, 16).map_err(|_| protocol_error("http: bad chunk size"))?;
            if size == 0 {
                // Trailers, up to the blank line.
                loop {
                    let line = from.read_line().await?;
                    to.write_all(&line).await?;
                    if line == b"\r\n" {
                        return Ok(total);
                    }
                }
            }
            let mut remaining = size + 2;
            while remaining > 0 {
                let data = from.read_some(remaining.min(65536) as usize).await?;
                if data.is_empty() {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "http: chunk ended early"));
                }
                remaining -= data.len() as u64;
                to.write_all(&data).await?;
            }
            total += size;
        },
        Framing::Close => loop {
            let data = from.read_some(65536).await?;
            if data.is_empty() {
                return Ok(total);
            }
            total += data.len() as u64;
            to.write_all(&data).await?;
        },
    }
    to.flush().await?;
    Ok(total)
}

/// A parsed request head.
struct Request {
    method: String,
    target: String,
    minor: u8,
    headers: Vec<(String, String)>,
}

impl Request {
    fn parse(head: &[u8]) -> io::Result<Self> {
        let mut headers = [httparse::EMPTY_HEADER; 128];
        let mut request = httparse::Request::new(&mut headers);
        match request.parse(head) {
            Ok(httparse::Status::Complete(_)) => {}
            Ok(httparse::Status::Partial) => return Err(protocol_error("http: incomplete request head")),
            Err(error) => return Err(protocol_error(format!("http: read request: {error}"))),
        }
        Ok(Request {
            method: request.method.unwrap_or_default().to_string(),
            target: request.path.unwrap_or_default().to_string(),
            minor: request.version.unwrap_or(1),
            headers: request
                .headers
                .iter()
                .map(|header| (header.name.to_string(), String::from_utf8_lossy(header.value).trim().to_string()))
                .collect(),
        })
    }

    fn header(&self, name: &str) -> Option<&str> {
        header(&self.headers, name)
    }

    fn proto(&self) -> String {
        format!("HTTP/1.{}", self.minor)
    }

    /// Go's `request.ContentLength`: -1 for chunked, else the length or 0.
    fn framing(&self) -> io::Result<Framing> {
        if let Some(encoding) = self.header("transfer-encoding") {
            if encoding.to_ascii_lowercase().split(',').next_back().map(str::trim) == Some("chunked") {
                return Ok(Framing::Chunked);
            }
            return Err(protocol_error(format!("http: unsupported transfer encoding {encoding:?}")));
        }
        match self.header("content-length") {
            Some(length) => match length.parse::<u64>() {
                Ok(0) => Ok(Framing::None),
                Ok(length) => Ok(Framing::Length(length)),
                Err(_) => Err(protocol_error(format!("http: bad Content-Length {length:?}"))),
            },
            None => Ok(Framing::None),
        }
    }

    /// `HTTP/1.1` with `Proxy-Connection: keep-alive` (sing's condition).
    fn keep_alive(&self) -> bool {
        self.minor != 0
            && self.header("proxy-connection").is_some_and(|value| value.trim().eq_ignore_ascii_case("keep-alive"))
    }
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
}

fn check_auth(request: &Request, users: &HashMap<String, String>) -> Result<Option<String>, String> {
    if users.is_empty() {
        return Ok(None);
    }
    let Some(value) = request.header("proxy-authorization") else {
        return Err("no Proxy-Authorization header".into());
    };
    let decoded = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))
        .and_then(|encoded| base64::engine::general_purpose::STANDARD.decode(encoded.trim()).ok())
        .and_then(|decoded| String::from_utf8(decoded).ok());
    let Some((username, password)) = decoded.as_deref().and_then(|text| text.split_once(':')) else {
        return Err(format!("Proxy-Authorization={value}"));
    };
    if users.get(username).map(String::as_str) == Some(password) {
        Ok(Some(username.to_string()))
    } else {
        Err(format!("username={username}"))
    }
}

/// `host[:port]` of a request target (Go's `url.URL.Hostname` / `Port`),
/// brackets removed from IPv6 literals.
fn split_authority(authority: &str) -> Option<(String, Option<u16>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        return match after.strip_prefix(':') {
            Some(port) => Some((host.to_string(), Some(port.parse().ok()?))),
            None if after.is_empty() => Some((host.to_string(), None)),
            None => None,
        };
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            Some((host.to_string(), if port.is_empty() { None } else { Some(port.parse().ok()?) }))
        }
        Some(_) => None,
        None => Some((authority.to_string(), None)),
    }
}

/// An absolute-form target: (scheme, authority without user info, path and query).
fn split_absolute(target: &str) -> Option<(String, String, String)> {
    let (scheme, rest) = target.split_once("://")?;
    let (authority, path) = match rest.find(['/', '?']) {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    };
    let authority = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    let path = if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('?') {
        format!("/{path}")
    } else {
        path.to_string()
    };
    Some((scheme.to_ascii_lowercase(), authority.to_string(), path))
}

/// sing `removeHopByHopHeaders`, plus what Go's request and response
/// writers replace themselves (`Host`, `Content-Length`).
fn end_to_end_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    let mut named = Vec::new();
    for (key, value) in headers {
        if key.eq_ignore_ascii_case("connection") {
            named.extend(value.split(',').map(|name| name.trim().to_ascii_lowercase()));
        }
    }
    headers
        .iter()
        .filter(|(key, _)| {
            let lower = key.to_ascii_lowercase();
            !matches!(
                lower.as_str(),
                "proxy-connection"
                    | "proxy-authenticate"
                    | "proxy-authorization"
                    | "te"
                    | "trailers"
                    | "transfer-encoding"
                    | "upgrade"
                    | "connection"
                    | "host"
                    | "content-length"
            ) && !named.contains(&lower)
        })
        .cloned()
        .collect()
}

/// A response with no body (sing `responseWith`, written by Go's
/// `Response.Write`).
fn simple_response(proto: &str, code: u16, reason: &str, headers: &[(&str, &str)]) -> Vec<u8> {
    let mut text = format!("{proto} {code} {reason}\r\n");
    for (name, value) in headers {
        text.push_str(&format!("{name}: {value}\r\n"));
    }
    text.push_str("Content-Length: 0\r\n\r\n");
    text.into_bytes()
}

/// sing `SourceAddress`: the first valid address of `X-Forwarded-For`
/// replaces the client's (with port 0).
fn forwarded_source(request: &Request) -> Option<SocketAddr> {
    let forwarded = request.header("x-forwarded-for")?;
    forwarded
        .split(',')
        .find_map(|from| from.trim().parse::<IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip.to_canonical(), 0))
}

/// Serves an HTTP proxy connection until it closes (sing
/// `http.HandleConnectionEx`). `users` empty means no authentication.
pub async fn serve(
    stream: BoxStream,
    users: &HashMap<String, String>,
    handler: &dyn ConnectionHandler,
    mut source: SocketAddr,
) -> io::Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = Wire::new(reader);
    loop {
        let Some(head) = reader.read_head().await? else { return Ok(()) };
        let request = Request::parse(&head)?;
        let user = match check_auth(&request, users) {
            Ok(user) => user,
            Err(reason) => {
                let keep_alive = request.keep_alive() && request.framing()? == Framing::None;
                let mut headers = vec![("Proxy-Authenticate", "Basic realm=\"rust-box\" charset=\"UTF-8\"")];
                if !keep_alive {
                    headers.push(("Connection", "close"));
                }
                writer
                    .write_all(&simple_response(&request.proto(), 407, "Proxy Authentication Required", &headers))
                    .await?;
                if keep_alive {
                    continue;
                }
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("http: authentication failed, {reason}"),
                ));
            }
        };
        if let Some(forwarded) = forwarded_source(&request) {
            source = forwarded;
        }
        if request.method.eq_ignore_ascii_case("CONNECT") {
            // Go parses the authority as "http://" + target with the scheme
            // then dropped, so a missing port is 80.
            let Some((host, port)) = split_authority(&request.target) else {
                return Err(protocol_error(format!("http: bad CONNECT target {:?}", request.target)));
            };
            let destination = Socksaddr::from_host_port(&host, port.unwrap_or(80));
            writer.write_all(format!("{} 200 Connection established\r\n\r\n", request.proto()).as_bytes()).await?;
            let (reader, buffered) = reader.into_parts();
            let client = reader.unsplit(writer);
            let client: BoxStream =
                if buffered.is_empty() { Box::new(client) } else { Box::new(PrefixedStream::new(buffered, client)) };
            handler.new_connection(source, destination, user, client).await;
            return Ok(());
        }
        let absolute = split_absolute(&request.target);
        if request.header("connection").is_some_and(|value| value.eq_ignore_ascii_case("upgrade")) {
            // Upgrade (WebSocket and the like): the request goes out as it
            // is, in origin form, and the connection becomes a tunnel.
            let Some((scheme, authority, path)) = absolute else {
                writer.write_all(&simple_response(&request.proto(), 400, "Bad Request", &[])).await?;
                continue;
            };
            let Some((host, port)) = split_authority(&authority) else {
                writer.write_all(&simple_response(&request.proto(), 400, "Bad Request", &[])).await?;
                continue;
            };
            let default_port = if scheme == "https" || scheme == "wss" { 443 } else { 80 };
            let destination = Socksaddr::from_host_port(&host, port.unwrap_or(default_port));
            let mut initial = format!("{} {path} HTTP/1.1\r\nHost: {authority}\r\n", request.method);
            for (key, value) in &request.headers {
                if !key.eq_ignore_ascii_case("host") {
                    initial.push_str(&format!("{key}: {value}\r\n"));
                }
            }
            initial.push_str("\r\n");
            let (reader, buffered) = reader.into_parts();
            let mut initial = initial.into_bytes();
            initial.extend_from_slice(&buffered);
            let client: BoxStream = Box::new(PrefixedStream::new(initial, reader.unsplit(writer)));
            handler.new_connection(source, destination, user, client).await;
            return Ok(());
        }
        let keep_alive = plain_request(&request, absolute, &mut reader, &mut writer, handler, source, user).await?;
        if !keep_alive {
            let _ = writer.shutdown().await;
            return Ok(());
        }
    }
}

/// One plain request (sing `handleHTTPConnection`); returns whether the
/// client connection stays open.
async fn plain_request<R, W>(
    request: &Request,
    absolute: Option<(String, String, String)>,
    reader: &mut Wire<R>,
    writer: &mut W,
    handler: &dyn ConnectionHandler,
    source: SocketAddr,
    user: Option<String>,
) -> io::Result<bool>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut keep_alive = request.keep_alive();
    let proto = request.proto();
    let Some((scheme, authority, path)) = absolute.filter(|(_, authority, _)| !authority.is_empty()) else {
        // sing answers 400 and goes on with the next request.
        writer.write_all(&simple_response(&proto, 400, "Bad Request", &[])).await?;
        return Ok(true);
    };
    let bad_gateway = simple_response(&proto, 502, "Bad Gateway", &[]);
    if scheme != "http" {
        // An `https://` target would need the proxy to speak TLS itself,
        // which rust-box cannot do yet.
        writer.write_all(&bad_gateway).await?;
        return Err(protocol_error(format!("http: unsupported scheme {scheme:?} in {:?}", request.target)));
    }
    let Some((host, port)) = split_authority(&authority) else {
        writer.write_all(&simple_response(&proto, 400, "Bad Request", &[])).await?;
        return Ok(true);
    };
    // sing `removeExtraHTTPHostPort`: an explicit port 80 is dropped.
    let host_header = match port {
        Some(80) | None if host.contains(':') => format!("[{host}]"),
        Some(80) | None => host.clone(),
        Some(port) if host.contains(':') => format!("[{host}]:{port}"),
        Some(port) => format!("{host}:{port}"),
    };
    let destination = Socksaddr::from_host_port(&host, port.unwrap_or(80));
    let body_framing = request.framing()?;

    let mut head = format!("{} {path} HTTP/1.1\r\nHost: {host_header}\r\n", request.method);
    for (key, value) in end_to_end_headers(&request.headers) {
        head.push_str(&format!("{key}: {value}\r\n"));
    }
    match body_framing {
        Framing::Length(length) => head.push_str(&format!("Content-Length: {length}\r\n")),
        Framing::Chunked => head.push_str("Transfer-Encoding: chunked\r\n"),
        _ => {}
    }
    head.push_str("\r\n");

    // A fresh routed connection for this request (sing dials one per
    // request through a pipe).
    let (upstream, routed) = tokio::io::duplex(64 * 1024);
    let route = handler.new_connection(source, destination, user, Box::new(routed));
    tokio::pin!(route);
    let (upstream_reader, mut upstream_writer) = tokio::io::split(upstream);
    let mut upstream_reader = Wire::new(upstream_reader);

    let forward = async {
        upstream_writer.write_all(head.as_bytes()).await?;
        copy_body(reader, body_framing, &mut upstream_writer).await?;
        upstream_writer.flush().await
    };
    let respond = respond(&mut upstream_reader, writer, request, keep_alive, &bad_gateway);
    tokio::pin!(forward);
    tokio::pin!(respond);
    let mut forwarded: Option<io::Result<()>> = None;
    let mut routed_done = false;
    let response = loop {
        tokio::select! {
            result = &mut forward, if forwarded.is_none() => forwarded = Some(result),
            result = &mut respond => break result,
            _ = &mut route, if !routed_done => routed_done = true,
        }
    };
    let response = response?;
    keep_alive &= response;
    // The request body must have been read to its end for the next
    // request to start at the right byte. sing discards up to 256KiB of an
    // unread body; rust-box closes the connection instead.
    if !matches!(forwarded, Some(Ok(()))) && body_framing != Framing::None {
        keep_alive = false;
    }
    Ok(keep_alive)
}

/// Reads the response from the routed connection and writes it to the
/// client; returns whether the client connection can stay open.
async fn respond<R, W>(
    upstream: &mut Wire<R>,
    writer: &mut W,
    request: &Request,
    keep_alive: bool,
    bad_gateway: &[u8],
) -> io::Result<bool>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (head, status) = loop {
        let head = match upstream.read_head().await {
            Ok(Some(head)) => head,
            Ok(None) => {
                writer.write_all(bad_gateway).await?;
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "http: no response from upstream"));
            }
            Err(error) => {
                writer.write_all(bad_gateway).await?;
                return Err(error);
            }
        };
        let mut headers = [httparse::EMPTY_HEADER; 128];
        let mut response = httparse::Response::new(&mut headers);
        if let Err(error) = response.parse(&head) {
            writer.write_all(bad_gateway).await?;
            return Err(protocol_error(format!("http: read response: {error}")));
        }
        let status = response.code.unwrap_or(0);
        // Interim responses are consumed, as Go's transport does.
        if (100..200).contains(&status) && status != 101 {
            continue;
        }
        break (head, status);
    };
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut response = httparse::Response::new(&mut headers);
    response.parse(&head).map_err(|error| protocol_error(error.to_string()))?;
    let minor = response.version.unwrap_or(1);
    let reason = response.reason.unwrap_or("").to_string();
    let headers: Vec<(String, String)> = response
        .headers
        .iter()
        .map(|header| (header.name.to_string(), String::from_utf8_lossy(header.value).trim().to_string()))
        .collect();
    let chunked = header(&headers, "transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().split(',').next_back().map(str::trim) == Some("chunked"));
    let length = header(&headers, "content-length").and_then(|value| value.parse::<u64>().ok());
    let no_body = request.method.eq_ignore_ascii_case("HEAD") || status == 204 || status == 304 || status < 200;
    let framing = if no_body {
        Framing::None
    } else if chunked {
        Framing::Chunked
    } else if let Some(length) = length {
        Framing::Length(length)
    } else {
        Framing::Close
    };
    // A body that ends with the connection cannot be followed by another
    // response (Go's `Response.Write` closes then).
    let keep_alive = keep_alive && framing != Framing::Close;
    let mut out = format!("HTTP/1.{minor} {status} {reason}\r\n");
    for (key, value) in end_to_end_headers(&headers) {
        if keep_alive && (key.eq_ignore_ascii_case("keep-alive")) {
            continue;
        }
        out.push_str(&format!("{key}: {value}\r\n"));
    }
    match framing {
        Framing::Chunked => out.push_str("Transfer-Encoding: chunked\r\n"),
        Framing::Length(length) => out.push_str(&format!("Content-Length: {length}\r\n")),
        Framing::None if request.method.eq_ignore_ascii_case("HEAD") => {
            if let Some(length) = length {
                out.push_str(&format!("Content-Length: {length}\r\n"));
            }
        }
        _ => {}
    }
    if keep_alive {
        out.push_str("Proxy-Connection: keep-alive\r\nConnection: keep-alive\r\nKeep-Alive: timeout=4\r\n");
    } else {
        out.push_str("Connection: close\r\n");
    }
    out.push_str("\r\n");
    writer.write_all(out.as_bytes()).await?;
    copy_body(upstream, framing, writer).await?;
    writer.flush().await?;
    Ok(keep_alive)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Answers every routed request with a fixed response and records the
    /// request heads and destinations it saw.
    struct Upstream {
        seen: Arc<Mutex<Vec<(Socksaddr, SocketAddr, String)>>>,
        response: &'static [u8],
    }

    #[async_trait]
    impl ConnectionHandler for Upstream {
        async fn new_connection(
            &self,
            source: SocketAddr,
            destination: Socksaddr,
            _user: Option<String>,
            stream: BoxStream,
        ) {
            if destination.domain() == Some("refused.test") {
                return;
            }
            let (reader, mut writer) = tokio::io::split(stream);
            let mut wire = Wire::new(reader);
            let Ok(Some(head)) = wire.read_head().await else { return };
            let text = String::from_utf8_lossy(&head).into_owned();
            let request = Request::parse(&head).unwrap();
            let mut body = Vec::new();
            copy_body(&mut wire, request.framing().unwrap(), &mut body).await.unwrap();
            self.seen.lock().unwrap().push((destination, source, text + &String::from_utf8_lossy(&body)));
            writer.write_all(self.response).await.unwrap();
            // Done writing, as a server that closes after its response.
            writer.shutdown().await.unwrap();
            // Keep reading until the proxy drops the connection.
            let _ = wire.read_some(1).await;
        }
    }

    async fn exchange(
        input: &[u8],
        users: &[(&str, &str)],
        response: &'static [u8],
    ) -> (io::Result<()>, String, Vec<(Socksaddr, SocketAddr, String)>) {
        let users: HashMap<String, String> = users.iter().map(|(u, p)| (u.to_string(), p.to_string())).collect();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let handler = Upstream { seen: seen.clone(), response };
        let (mut client, server) = tokio::io::duplex(65536);
        client.write_all(input).await.unwrap();
        client.shutdown().await.unwrap();
        let source: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let result = serve(Box::new(server), &users, &handler, source).await;
        let mut output = Vec::new();
        client.read_to_end(&mut output).await.unwrap();
        let seen = seen.lock().unwrap().clone();
        (result, String::from_utf8(output).unwrap(), seen)
    }

    const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nKeep-Alive: timeout=60\r\nX-Up: 1\r\n\r\nhi";

    #[tokio::test]
    async fn keep_alive_requests_share_the_connection() {
        let input = b"GET http://a.test/one HTTP/1.1\r\nHost: a.test\r\nProxy-Connection: keep-alive\r\n\r\n\
                      POST http://b.test:8080/two?x=1 HTTP/1.1\r\nProxy-Connection: keep-alive\r\nContent-Length: 3\r\n\r\nabc\
                      GET http://c.test/three HTTP/1.1\r\nConnection: close\r\n\r\n";
        let (result, output, seen) = exchange(input, &[], OK).await;
        result.unwrap();
        // Three responses on one client connection, the last one closing it.
        assert_eq!(output.matches("HTTP/1.1 200 OK").count(), 3, "{output}");
        assert_eq!(output.matches("Proxy-Connection: keep-alive").count(), 2, "{output}");
        assert!(output.ends_with("Connection: close\r\n\r\nhi"), "{output}");
        // The upstream's Keep-Alive is replaced on kept-alive responses only (Go's Header.Set).
        assert_eq!(output.matches("timeout=60").count(), 1, "{output}");
        assert!(output.contains("X-Up: 1"));
        // Each request was routed on its own, rewritten to origin form.
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[0].0.to_string(), "a.test:80");
        assert!(seen[0].2.starts_with("GET /one HTTP/1.1\r\nHost: a.test\r\n"), "{}", seen[0].2);
        assert!(!seen[0].2.to_ascii_lowercase().contains("proxy-connection"));
        assert_eq!(seen[1].0.to_string(), "b.test:8080");
        assert!(seen[1].2.starts_with("POST /two?x=1 HTTP/1.1\r\nHost: b.test:8080\r\n"), "{}", seen[1].2);
        assert!(seen[1].2.ends_with("Content-Length: 3\r\n\r\nabc"), "{}", seen[1].2);
        assert!(!seen[2].2.to_ascii_lowercase().contains("connection:"), "{}", seen[2].2);
    }

    #[tokio::test]
    async fn chunked_bodies_and_close_delimited_responses() {
        let input =
            b"PUT http://a.test/ HTTP/1.1\r\nProxy-Connection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n\
                      3\r\nabc\r\n0\r\n\r\n\
                      GET http://a.test/again HTTP/1.1\r\nProxy-Connection: keep-alive\r\n\r\n";
        let (result, output, seen) =
            exchange(input, &[], b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n").await;
        result.unwrap();
        assert_eq!(seen.len(), 2);
        assert!(seen[0].2.contains("Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"), "{}", seen[0].2);
        assert_eq!(output.matches("Transfer-Encoding: chunked\r\n").count(), 2, "{output}");
        // A response that ends with its connection closes the client's too.
        let input = b"GET http://a.test/ HTTP/1.1\r\nProxy-Connection: keep-alive\r\n\r\n\
                      GET http://a.test/never HTTP/1.1\r\nProxy-Connection: keep-alive\r\n\r\n";
        let (result, output, seen) = exchange(input, &[], b"HTTP/1.0 200 OK\r\n\r\nstream").await;
        result.unwrap();
        assert_eq!(seen.len(), 1);
        assert!(output.contains("Connection: close") && output.ends_with("stream"), "{output}");
    }

    #[tokio::test]
    async fn http10_and_errors() {
        // HTTP/1.0 never stays open.
        let (_, output, seen) = exchange(
            b"GET http://a.test/ HTTP/1.0\r\nProxy-Connection: keep-alive\r\n\r\nGET http://a.test/ HTTP/1.0\r\n\r\n",
            &[],
            OK,
        )
        .await;
        assert_eq!(seen.len(), 1);
        assert!(output.starts_with("HTTP/1.1 200 OK") && output.contains("Connection: close"), "{output}");
        // Origin form is answered with 400 and the connection goes on.
        let (_, output, seen) =
            exchange(b"GET /local HTTP/1.1\r\n\r\nGET http://a.test/ HTTP/1.1\r\n\r\n", &[], OK).await;
        assert!(output.starts_with("HTTP/1.1 400 Bad Request\r\n"), "{output}");
        assert_eq!(seen.len(), 1);
        // A request the router drops gets 502.
        let (result, output, _) = exchange(b"GET http://refused.test/ HTTP/1.1\r\n\r\n", &[], OK).await;
        assert!(result.is_err());
        assert!(output.starts_with("HTTP/1.1 502 Bad Gateway"), "{output}");
        // A malformed request closes the connection without an answer.
        let (result, output, _) = exchange(b"NOT HTTP\r\n\r\n", &[], OK).await;
        assert!(result.is_err());
        assert!(output.is_empty());
    }

    #[tokio::test]
    async fn authentication() {
        let token = base64::engine::general_purpose::STANDARD.encode("u:p");
        // A failed keep-alive request is answered and the client may retry.
        let input = format!(
            "GET http://a.test/ HTTP/1.1\r\nProxy-Connection: keep-alive\r\n\r\n\
             GET http://a.test/ HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n"
        );
        let (result, output, seen) = exchange(input.as_bytes(), &[("u", "p")], OK).await;
        result.unwrap();
        assert!(output.starts_with("HTTP/1.1 407 Proxy Authentication Required\r\n"), "{output}");
        assert!(output.contains("realm=\"rust-box\""));
        assert_eq!(seen.len(), 1);
        assert!(!seen[0].2.to_ascii_lowercase().contains("proxy-authorization"));
        // Without keep-alive the failure ends the connection.
        let (result, output, _) = exchange(b"CONNECT a.test:443 HTTP/1.1\r\n\r\n", &[("u", "p")], OK).await;
        assert!(result.is_err());
        assert!(output.contains("Connection: close"));
    }

    #[tokio::test]
    async fn connect_and_forwarded_source() {
        let (result, output, seen) = exchange(
            b"CONNECT example.com HTTP/1.1\r\nX-Forwarded-For: bogus, 10.1.2.3\r\n\r\nGET / HTTP/1.1\r\n\r\n",
            &[],
            b"HTTP/1.1 204 No Content\r\n\r\n",
        )
        .await;
        result.unwrap();
        assert!(output.starts_with("HTTP/1.1 200 Connection established\r\n\r\nHTTP/1.1 204"), "{output}");
        // Port 80 when the CONNECT target has none, as Go parses it.
        assert_eq!(seen[0].0.to_string(), "example.com:80");
        assert_eq!(seen[0].1, "10.1.2.3:0".parse().unwrap());
        assert!(seen[0].2.starts_with("GET / HTTP/1.1"));
    }

    #[test]
    fn targets() {
        assert_eq!(
            split_absolute("http://user@[::1]:8080?q"),
            Some(("http".into(), "[::1]:8080".into(), "/?q".into()))
        );
        assert_eq!(split_authority("[::1]:8080"), Some(("::1".into(), Some(8080))));
        assert_eq!(split_authority("a.test"), Some(("a.test".into(), None)));
        assert_eq!(split_authority("::1"), None);
        let headers = vec![
            ("Connection".to_string(), "X-Hop, keep-alive".to_string()),
            ("X-Hop".to_string(), "1".to_string()),
            ("X-Keep".to_string(), "2".to_string()),
            ("TE".to_string(), "trailers".to_string()),
        ];
        assert_eq!(end_to_end_headers(&headers), vec![("X-Keep".to_string(), "2".to_string())]);
    }
}
