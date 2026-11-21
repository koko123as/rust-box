//! DNS over HTTPS (sing-box `dns/transport/https.go` and
//! `dns/transport/https_transport.go`).
//!
//! Connections are established through the configured project dialer and
//! TLS client. Negotiated HTTP/2 connections multiplex requests; any other
//! negotiated ALPN uses HTTP/1.1. HTTP/1.1 requests are serialized on a
//! persistent connection and reconnect after an error or non-reusable reply.

use std::collections::BTreeMap;
use std::io;
use std::io::Read as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use flate2::read::GzDecoder;
use h2::client::ResponseFuture;
use http::header::{ACCEPT, ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HOST, USER_AGENT};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri};
use rb_adapter::{BoxStream, Socksaddr};
use rb_config::Listable;
use rb_dialer::Dialer;
use rb_tls::{TlsClient, TlsClientStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex as AsyncMutex;

use super::invalid;

const DEFAULT_PATH: &str = "/dns-query";
const MAX_HTTP_BODY: usize = 1024 * 1024;
const MAX_DNS_MESSAGE: usize = u16::MAX as usize;
const MAX_HTTP_HEADERS: usize = 64 * 1024;

fn invalid_display(error: impl std::fmt::Display) -> io::Error {
    invalid(error.to_string())
}

/// One HTTPS DNS upstream, using the project's dialer and TLS implementation.
pub struct DohTransport {
    server: Socksaddr,
    dialer: Arc<dyn Dialer>,
    tls: TlsClient,
    authority: String,
    path: String,
    headers: HeaderMap,
    auto_gzip: bool,
    connection: AsyncMutex<Option<Arc<DohConnection>>>,
}

enum DohConnection {
    Http2(Arc<Http2Connection>),
    Http1(Arc<Http1Connection>),
}

impl DohConnection {
    fn is_alive(&self) -> bool {
        match self {
            DohConnection::Http2(connection) => !connection.closed.load(Ordering::Acquire),
            DohConnection::Http1(connection) => connection.alive.load(Ordering::Acquire),
        }
    }
}

struct Http2Connection {
    sender: AsyncMutex<h2::client::SendRequest<Bytes>>,
    closed: Arc<AtomicBool>,
    driver: tokio::task::JoinHandle<()>,
}

impl Drop for Http2Connection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

struct Http1Connection {
    stream: AsyncMutex<BoxStream>,
    alive: Arc<AtomicBool>,
}

struct InFlight<'a> {
    alive: &'a AtomicBool,
    reusable: bool,
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        if !self.reusable {
            self.alive.store(false, Ordering::Release);
        }
    }
}

struct HttpResponse {
    status: u16,
    reason: String,
    headers: HeaderMap,
    body: Vec<u8>,
    reusable: bool,
}

impl DohTransport {
    /// `server_port` is the configured value (zero is distinct from 443 for
    /// the URL authority, as in sing-box); `server.port` is the dial port.
    pub fn new(
        server: Socksaddr,
        dialer: Arc<dyn Dialer>,
        tls: TlsClient,
        server_port: u16,
        path: &str,
        configured_headers: &BTreeMap<String, Listable<String>>,
    ) -> io::Result<Self> {
        let mut headers = HeaderMap::new();
        let mut host_header = None;
        for (name, values) in configured_headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|error| invalid(format!("invalid DNS over HTTPS header name: {error}")))?;
            if name == HOST {
                host_header = values.0.first().cloned();
                continue;
            }
            for value in values.iter() {
                let value = HeaderValue::from_str(value)
                    .map_err(|error| invalid(format!("invalid DNS over HTTPS header value: {error}")))?;
                headers.append(name.clone(), value);
            }
        }

        let url_host = host_header.filter(|host| !host.is_empty()).unwrap_or_else(|| tls.server_name().to_string());
        let authority = make_authority(&url_host, server_port)?;
        let path = normalize_path(path)?;
        let auto_gzip = !headers.contains_key(ACCEPT_ENCODING);
        if auto_gzip {
            headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        }
        if !headers.contains_key(USER_AGENT) {
            headers.insert(USER_AGENT, HeaderValue::from_static("Go-http-client/1.1"));
        }
        // sing-box sets these after cloning user headers, overriding any
        // configured values.
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/dns-message"));
        headers.insert(ACCEPT, HeaderValue::from_static("application/dns-message"));

        Ok(DohTransport { server, dialer, tls, authority, path, headers, auto_gzip, connection: AsyncMutex::new(None) })
    }

    pub fn server(&self) -> &Socksaddr {
        &self.server
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn tls_server_name(&self) -> &str {
        self.tls.server_name()
    }

    pub fn tls_alpn(&self) -> Vec<String> {
        self.tls.alpn()
    }

    /// Sends one DNS message with ID zero and restores the caller's ID in the
    /// decoded response, matching the DNS transport's raw Exchange contract.
    pub async fn exchange(&self, query: &[u8], timeout: Duration) -> io::Result<Vec<u8>> {
        if query.len() < 12 {
            return Err(invalid("DNS query too short"));
        }
        if query.len() > MAX_DNS_MESSAGE {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "DNS query exceeds the message limit"));
        }
        tokio::time::timeout(timeout, self.exchange_inner(query))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS over HTTPS: exchange timed out"))?
    }

    async fn exchange_inner(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let mut message =
            hickory_proto::op::Message::from_vec(query).map_err(|error| invalid(format!("DNS over HTTPS: {error}")))?;
        let original_id = message.id();
        // Message::to_vec uses hickory's compressing encoder, equivalent to
        // sing-box's `dns.Msg.Compress = true`.
        message.set_id(0);
        let body = message.to_vec().map_err(|error| invalid(format!("DNS over HTTPS: {error}")))?;

        let connection = self.connection().await?;
        let response = match connection.as_ref() {
            DohConnection::Http2(connection) => {
                connection.request(&self.authority, &self.path, &self.headers, &body).await?
            }
            DohConnection::Http1(connection) => {
                connection.request(&self.authority, &self.path, &self.headers, &body).await?
            }
        };
        if response.status != StatusCode::OK.as_u16() {
            let status = if response.reason.is_empty() {
                StatusCode::from_u16(response.status)
                    .ok()
                    .and_then(|status| status.canonical_reason())
                    .map_or_else(|| response.status.to_string(), |reason| format!("{} {reason}", response.status))
            } else {
                format!("{} {}", response.status, response.reason)
            };
            return Err(io::Error::other(format!("unexpected status: {status}")));
        }
        let mut body = response.body;
        if self.auto_gzip
            && response
                .headers
                .get(CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|encoding| encoding.eq_ignore_ascii_case("gzip"))
        {
            let mut decoded = Vec::new();
            GzDecoder::new(body.as_slice())
                .take((MAX_DNS_MESSAGE + 1) as u64)
                .read_to_end(&mut decoded)
                .map_err(|error| invalid(format!("DNS over HTTPS: gzip response: {error}")))?;
            if decoded.len() > MAX_DNS_MESSAGE {
                return Err(invalid("DNS over HTTPS: response exceeds the DNS message limit"));
            }
            body = decoded;
        }
        if body.len() < 12 || body.len() > MAX_DNS_MESSAGE {
            return Err(invalid("DNS over HTTPS: invalid DNS response length"));
        }
        hickory_proto::op::Message::from_vec(&body).map_err(|error| invalid(format!("DNS over HTTPS: {error}")))?;
        body[..2].copy_from_slice(&original_id.to_be_bytes());
        Ok(body)
    }

    async fn connection(&self) -> io::Result<Arc<DohConnection>> {
        let mut current = self.connection.lock().await;
        if let Some(connection) = current.as_ref().filter(|connection| connection.is_alive()) {
            return Ok(connection.clone());
        }
        let stream = self.dialer.dial_tcp(&self.server).await?;
        let stream: TlsClientStream = self.tls.handshake(stream).await?;
        let negotiated = stream.get_ref().1.alpn_protocol().map(ToOwned::to_owned);
        let stream: BoxStream = Box::new(stream);
        let connection = if negotiated.as_deref() == Some(b"h2") {
            DohConnection::Http2(Arc::new(Http2Connection::new(stream).await?))
        } else {
            DohConnection::Http1(Arc::new(Http1Connection::new(stream)))
        };
        let connection = Arc::new(connection);
        *current = Some(connection.clone());
        Ok(connection)
    }
}

impl Http2Connection {
    async fn new(stream: BoxStream) -> io::Result<Self> {
        let (sender, driver) = h2::client::Builder::new().handshake::<_, Bytes>(stream).await.map_err(h2_error)?;
        let closed = Arc::new(AtomicBool::new(false));
        let flag = closed.clone();
        let driver = tokio::spawn(async move {
            let _ = driver.await;
            flag.store(true, Ordering::Release);
        });
        Ok(Http2Connection { sender: AsyncMutex::new(sender), closed, driver })
    }

    async fn request(&self, authority: &str, path: &str, headers: &HeaderMap, body: &[u8]) -> io::Result<HttpResponse> {
        if self.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "DNS over HTTPS: HTTP/2 connection closed"));
        }
        let uri = make_uri(authority, path)?;
        let mut request = Request::builder().method(Method::POST).uri(uri).body(()).map_err(invalid_display)?;
        for (name, values) in headers.iter() {
            if is_h2_forbidden_header(name) {
                continue;
            }
            request.headers_mut().append(name.clone(), values.clone());
        }
        request
            .headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from_str(&body.len().to_string()).map_err(invalid_display)?);

        let sender = self.sender.lock().await.clone();
        let mut sender = sender.ready().await.map_err(h2_error)?;
        let (response, mut send) = sender.send_request(request, false).map_err(h2_error)?;
        send.send_data(Bytes::copy_from_slice(body), true).map_err(h2_error)?;
        read_h2_response(response).await
    }
}

impl Http1Connection {
    fn new(stream: BoxStream) -> Self {
        Http1Connection { stream: AsyncMutex::new(stream), alive: Arc::new(AtomicBool::new(true)) }
    }

    async fn request(&self, authority: &str, path: &str, headers: &HeaderMap, body: &[u8]) -> io::Result<HttpResponse> {
        if !self.alive.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "DNS over HTTPS: HTTP/1.1 connection closed"));
        }
        let mut flight = InFlight { alive: &self.alive, reusable: false };
        let mut stream = self.stream.lock().await;
        let request_path = if path.starts_with('/') { path.to_string() } else { format!("/{path}") };
        let mut request = format!("POST {request_path} HTTP/1.1\r\nHost: {authority}\r\n");
        for name in headers.keys() {
            for value in headers.get_all(name).iter() {
                request.push_str(name.as_str());
                request.push_str(": ");
                request.push_str(value.to_str().map_err(invalid_display)?);
                request.push_str("\r\n");
            }
        }
        request.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
        stream.write_all(request.as_bytes()).await?;
        stream.write_all(body).await?;
        stream.flush().await?;
        let response = read_http1_response(&mut stream).await?;
        flight.reusable = response.reusable;
        Ok(response)
    }
}

fn make_authority(host: &str, configured_port: u16) -> io::Result<String> {
    let parsed: http::uri::Authority =
        host.parse().map_err(|error| invalid(format!("invalid DNS over HTTPS authority `{host}`: {error}")))?;
    let hostname = parsed.host();
    if hostname.is_empty() {
        return Err(invalid("DNS over HTTPS authority must not be empty"));
    }
    if configured_port != 0 && configured_port != 443 {
        let port = parsed.port_u16().unwrap_or(configured_port);
        return Ok(format_authority_with_port(hostname, port));
    }
    Ok(hostname.to_string())
}

fn format_authority_with_port(host: &str, port: u16) -> String {
    if host.starts_with('[') {
        format!("{host}:{port}")
    } else if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn normalize_path(path: &str) -> io::Result<String> {
    let path = if path.is_empty() { DEFAULT_PATH } else { path };
    let path = if path.starts_with('/') { path.to_string() } else { format!("/{path}") };
    let _: http::uri::PathAndQuery =
        path.parse().map_err(|error| invalid(format!("invalid DNS over HTTPS path `{path}`: {error}")))?;
    Ok(path)
}

fn make_uri(authority: &str, path: &str) -> io::Result<Uri> {
    Uri::builder()
        .scheme("https")
        .authority(authority)
        .path_and_query(path)
        .build()
        .map_err(|error| invalid(format!("invalid DNS over HTTPS URI: {error}")))
}

fn is_h2_forbidden_header(name: &HeaderName) -> bool {
    matches!(name.as_str(), "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade")
}

fn h2_error(error: h2::Error) -> io::Error {
    if error.is_io() {
        error.into_io().unwrap_or_else(|| io::Error::other("HTTP/2 I/O error"))
    } else {
        io::Error::other(error.to_string())
    }
}

async fn read_h2_response(response: ResponseFuture) -> io::Result<HttpResponse> {
    let response = response.await.map_err(h2_error)?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    if status != 200 {
        return Ok(HttpResponse { status, reason: String::new(), headers, body: Vec::new(), reusable: true });
    }
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(h2_error)?;
        if bytes.len().saturating_add(chunk.len()) > MAX_HTTP_BODY {
            return Err(invalid("DNS over HTTPS: HTTP response body too large"));
        }
        bytes.extend_from_slice(&chunk);
        body.flow_control().release_capacity(chunk.len()).map_err(h2_error)?;
    }
    Ok(HttpResponse {
        status,
        reason: String::new(),
        headers,
        body: bytes,
        // HTTP/2 connection reuse is handled by the session driver.
        reusable: true,
    })
}

async fn read_http1_response(stream: &mut BoxStream) -> io::Result<HttpResponse> {
    let mut wire = Vec::new();
    let (header_len, status, version, reason, parsed_headers) = loop {
        if wire.len() > MAX_HTTP_HEADERS {
            return Err(invalid("DNS over HTTPS: HTTP response headers too large"));
        }
        let mut headers = [httparse::EMPTY_HEADER; 128];
        let mut parsed = httparse::Response::new(&mut headers);
        match parsed.parse(&wire).map_err(|error| invalid(format!("DNS over HTTPS: HTTP response: {error}")))? {
            httparse::Status::Complete(header_len) => {
                let status = parsed.code.ok_or_else(|| invalid("DNS over HTTPS: HTTP response has no status"))?;
                let version = parsed.version.unwrap_or(1);
                let reason = parsed.reason.unwrap_or_default().to_string();
                let parsed_headers = parsed
                    .headers
                    .iter()
                    .map(|header| {
                        let name = HeaderName::from_bytes(header.name.as_bytes()).map_err(invalid_display)?;
                        let value = HeaderValue::from_bytes(header.value).map_err(invalid_display)?;
                        Ok((name, value))
                    })
                    .collect::<io::Result<Vec<_>>>()?;
                break (header_len, status, version, reason, parsed_headers);
            }
            httparse::Status::Partial => {
                if wire.len() >= MAX_HTTP_HEADERS {
                    return Err(invalid("DNS over HTTPS: HTTP response headers too large"));
                }
                let mut chunk = [0u8; 4096];
                let size = stream.read(&mut chunk).await?;
                if size == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "DNS over HTTPS: incomplete HTTP headers",
                    ));
                }
                wire.extend_from_slice(&chunk[..size]);
            }
        }
    };

    let mut headers = HeaderMap::new();
    for (name, value) in parsed_headers {
        headers.append(name, value);
    }
    if status != 200 {
        return Ok(HttpResponse { status, reason, headers, body: Vec::new(), reusable: false });
    }
    let initial_body = wire[header_len..].to_vec();
    let transfer_encoding = headers
        .get_all(http::header::TRANSFER_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join(",");
    let chunked = transfer_encoding.split(',').any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"));
    let content_length = parse_content_length(&headers)?;
    let connection_header = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join(",");
    let close = connection_header.split(',').any(|token| token.trim().eq_ignore_ascii_case("close"));
    let keep_alive = connection_header.split(',').any(|token| token.trim().eq_ignore_ascii_case("keep-alive"));
    let mut reader = Http1BodyReader::new(stream, initial_body);

    let no_body = (100..200).contains(&status) || status == 204 || status == 304;
    let (body, body_reusable) = if no_body {
        (Vec::new(), true)
    } else if chunked {
        if transfer_encoding
            .split(',')
            .filter(|encoding| !encoding.trim().is_empty())
            .any(|encoding| !encoding.trim().eq_ignore_ascii_case("chunked"))
        {
            return Err(invalid("DNS over HTTPS: unsupported HTTP transfer encoding"));
        }
        let body = reader.read_chunked().await?;
        let reusable = !reader.has_buffered_data();
        (body, reusable)
    } else if let Some(length) = content_length {
        if length > MAX_HTTP_BODY {
            return Err(invalid("DNS over HTTPS: HTTP response body too large"));
        }
        let body = reader.read_exact(length).await?;
        let reusable = !reader.has_buffered_data();
        (body, reusable)
    } else {
        let body = reader.read_until_eof().await?;
        (body, false)
    };
    let reusable = body_reusable && !close && (version == 1 || keep_alive);
    Ok(HttpResponse { status, reason, headers, body, reusable })
}

fn parse_content_length(headers: &HeaderMap) -> io::Result<Option<usize>> {
    let values = headers
        .get_all(CONTENT_LENGTH)
        .iter()
        .map(|value| {
            value
                .to_str()
                .map_err(invalid_display)?
                .parse::<usize>()
                .map_err(|error| invalid(format!("DNS over HTTPS: invalid Content-Length: {error}")))
        })
        .collect::<io::Result<Vec<_>>>()?;
    if values.iter().any(|value| *value != values[0]) {
        return Err(invalid("DNS over HTTPS: conflicting Content-Length headers"));
    }
    Ok(values.first().copied())
}

struct Http1BodyReader<'a> {
    stream: &'a mut BoxStream,
    buffer: Vec<u8>,
    offset: usize,
}

impl<'a> Http1BodyReader<'a> {
    fn new(stream: &'a mut BoxStream, buffer: Vec<u8>) -> Self {
        Http1BodyReader { stream, buffer, offset: 0 }
    }

    async fn fill(&mut self) -> io::Result<bool> {
        let mut chunk = [0u8; 4096];
        let size = self.stream.read(&mut chunk).await?;
        if size == 0 {
            return Ok(false);
        }
        self.buffer.extend_from_slice(&chunk[..size]);
        Ok(true)
    }

    async fn read_exact(&mut self, length: usize) -> io::Result<Vec<u8>> {
        let mut output = Vec::with_capacity(length);
        while output.len() < length {
            if self.offset == self.buffer.len() && !self.fill().await? {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "DNS over HTTPS: incomplete HTTP body"));
            }
            let available = self.buffer.len() - self.offset;
            let count = available.min(length - output.len());
            output.extend_from_slice(&self.buffer[self.offset..self.offset + count]);
            self.offset += count;
        }
        Ok(output)
    }

    async fn read_line(&mut self) -> io::Result<Vec<u8>> {
        loop {
            if let Some(position) = self.buffer[self.offset..].windows(2).position(|window| window == b"\r\n") {
                let end = self.offset + position;
                let line = self.buffer[self.offset..end].to_vec();
                self.offset = end + 2;
                return Ok(line);
            }
            if self.buffer.len().saturating_sub(self.offset) > MAX_HTTP_HEADERS || !self.fill().await? {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "DNS over HTTPS: incomplete chunked body"));
            }
        }
    }

    async fn read_chunked(&mut self) -> io::Result<Vec<u8>> {
        let mut output = Vec::new();
        loop {
            let line = self.read_line().await?;
            let size = line.split(|byte| *byte == b';').next().unwrap_or_default();
            let size = std::str::from_utf8(size)
                .ok()
                .and_then(|size| usize::from_str_radix(size.trim(), 16).ok())
                .ok_or_else(|| invalid("DNS over HTTPS: invalid HTTP chunk size"))?;
            if size == 0 {
                loop {
                    if self.read_line().await?.is_empty() {
                        break;
                    }
                }
                return Ok(output);
            }
            if output.len().saturating_add(size) > MAX_HTTP_BODY {
                return Err(invalid("DNS over HTTPS: HTTP response body too large"));
            }
            output.extend_from_slice(&self.read_exact(size).await?);
            if self.read_exact(2).await? != b"\r\n" {
                return Err(invalid("DNS over HTTPS: invalid HTTP chunk delimiter"));
            }
        }
    }

    async fn read_until_eof(&mut self) -> io::Result<Vec<u8>> {
        let mut output = self.buffer[self.offset..].to_vec();
        if output.len() > MAX_HTTP_BODY {
            return Err(invalid("DNS over HTTPS: HTTP response body too large"));
        }
        self.offset = self.buffer.len();
        let mut chunk = [0u8; 4096];
        loop {
            let size = self.stream.read(&mut chunk).await?;
            if size == 0 {
                return Ok(output);
            }
            if output.len().saturating_add(size) > MAX_HTTP_BODY {
                return Err(invalid("DNS over HTTPS: HTTP response body too large"));
            }
            output.extend_from_slice(&chunk[..size]);
        }
    }

    fn has_buffered_data(&self) -> bool {
        self.offset != self.buffer.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_uses_host_header_without_changing_tls_name() {
        assert_eq!(make_authority("resolver.example", 8443).unwrap(), "resolver.example:8443");
        assert_eq!(make_authority("resolver.example:9443", 8443).unwrap(), "resolver.example:9443");
        assert_eq!(make_authority("resolver.example:9443", 443).unwrap(), "resolver.example");
        assert_eq!(make_authority("[2001:db8::1]", 0).unwrap(), "[2001:db8::1]");
        assert_eq!(normalize_path("").unwrap(), "/dns-query");
        assert_eq!(normalize_path("dns-query?x=1").unwrap(), "/dns-query?x=1");
    }

    #[tokio::test]
    async fn parses_http1_content_length_response() {
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            server.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody").await.unwrap();
        });
        let mut stream: BoxStream = Box::new(client);
        let response = read_http1_response(&mut stream).await.unwrap();
        assert_eq!(response.body, b"body");
        assert!(response.reusable);
    }

    #[tokio::test]
    async fn parses_http1_chunked_response() {
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            server
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndata\r\n0\r\n\r\n")
                .await
                .unwrap();
        });
        let mut stream: BoxStream = Box::new(client);
        let response = read_http1_response(&mut stream).await.unwrap();
        assert_eq!(response.body, b"data");
        assert!(response.reusable);
    }

    #[tokio::test]
    async fn returns_non_200_before_reading_http1_body() {
        let (client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            server.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 100\r\n\r\n").await.unwrap();
            std::future::pending::<()>().await;
        });
        let mut stream: BoxStream = Box::new(client);
        let response = read_http1_response(&mut stream).await.unwrap();
        server_task.abort();
        assert_eq!(response.status, 404);
        assert!(response.body.is_empty());
        assert!(!response.reusable);
    }
}
