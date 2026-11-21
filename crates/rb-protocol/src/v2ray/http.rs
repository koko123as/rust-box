//! The V2Ray HTTP transport (sing-box `transport/v2rayhttp`).
//!
//! Cleartext clients use one HTTP/1.1 request per TCP connection. TLS clients
//! use an HTTP/2 stream; inbound HTTP/2 requests are accepted independently
//! on a shared H2 session.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode, Uri};
use rb_adapter::{BoxStream, Host, PrefixedStream, Socksaddr};
use rb_config::{V2RayHeaders, V2RayHttpOptions};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::h2::{H2Client, H2Server};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_HEADER_COUNT: usize = 128;
const READ_CHUNK_SIZE: usize = 4096;
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

fn protocol_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("v2ray-http: {}", message.into()))
}

fn path_and_query(path: &str) -> io::Result<String> {
    let path = if path.is_empty() {
        "/".to_owned()
    } else if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    let uri = path.parse::<Uri>().map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    Ok(uri.path_and_query().map_or_else(|| "/".to_owned(), |value| value.as_str().to_owned()))
}

fn server_host(server: &Socksaddr) -> String {
    match &server.host {
        Host::Ip(std::net::IpAddr::V6(address)) => format!("[{address}]"),
        Host::Ip(address) => address.to_string(),
        Host::Domain(domain) => domain.clone(),
    }
}

fn select_host(options: &V2RayHttpOptions, server: &Socksaddr, tls: bool) -> String {
    if !options.host.is_empty() {
        let index = (rand::random::<u64>() as usize) % options.host.0.len();
        return options.host.0[index].clone();
    }
    if tls {
        "www.example.com".to_owned()
    } else {
        server_host(server)
    }
}

fn method(options: &V2RayHttpOptions) -> io::Result<Method> {
    let value = if options.method.is_empty() { "PUT" } else { &options.method };
    Method::from_bytes(value.as_bytes()).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

fn headers(options: &V2RayHeaders) -> io::Result<HeaderMap> {
    let mut result = HeaderMap::new();
    for (name, values) in options {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let value = values.iter().cloned().collect::<Vec<_>>().join(", ");
        let value = HeaderValue::from_bytes(value.as_bytes())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        result.insert(name, value);
    }
    Ok(result)
}

fn response_headers(options: &V2RayHeaders) -> io::Result<HeaderMap> {
    let mut result = HeaderMap::new();
    result.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    for (name, values) in options {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        for value in values.iter() {
            let value = HeaderValue::from_bytes(value.as_bytes())
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            result.insert(name.clone(), value);
        }
    }
    Ok(result)
}

fn request_target(options: &V2RayHttpOptions) -> io::Result<String> {
    path_and_query(&options.path)
}

/// Create a V2Ray HTTP client stream over an already-dialed connection.
/// `tls` is explicit: it selects H2 only for a connection that has completed
/// TLS; cleartext always uses HTTP/1.1, never h2c.
pub(crate) async fn client(
    mut stream: BoxStream,
    server: &Socksaddr,
    options: &V2RayHttpOptions,
    tls: bool,
) -> io::Result<BoxStream> {
    let method = method(options)?;
    let path = request_target(options)?;
    let mut headers = headers(&options.headers)?;
    let authority = select_host(options, server, tls);
    if tls {
        let uri = format!("https://{authority}{path}")
            .parse::<Uri>()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        // In HTTP/2 the virtual host belongs in :authority; a configured
        // ordinary Host header is not emitted as a second authority.
        headers.remove(header::HOST);
        let mut request = Request::builder()
            .method(method)
            .version(http::Version::HTTP_2)
            .uri(uri)
            .body(())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        *request.headers_mut() = headers;
        let client = H2Client::new(stream).await?;
        let (response, body) = client.open(request).await?;
        if response.status() != StatusCode::OK {
            return Err(io::Error::other(format!("v2ray-http: unexpected status: {}", response.status())));
        }
        Ok(Box::new(body))
    } else {
        let host = if headers.contains_key(header::HOST) { None } else { Some(authority) };
        let request = request_head(&method, &path, &headers, host.as_deref())?;
        stream.write_all(&request).await?;
        stream.flush().await?;
        let (reader, writer) = tokio::io::split(stream);
        Ok(Box::new(Http1ClientStream {
            reader,
            writer,
            response_header: Vec::with_capacity(READ_CHUNK_SIZE),
            response_prefix: Vec::new(),
            response_prefix_offset: 0,
            response_read: false,
            response_error: None,
        }))
    }
}

fn request_head(method: &Method, target: &str, headers: &HeaderMap, host: Option<&str>) -> io::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(1024);
    output.extend_from_slice(method.as_str().as_bytes());
    output.extend_from_slice(b" ");
    output.extend_from_slice(target.as_bytes());
    output.extend_from_slice(b" HTTP/1.1\r\n");
    for (name, value) in headers {
        output.extend_from_slice(name.as_str().as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    if let Some(host) = host {
        let host = HeaderValue::from_str(host).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        output.extend_from_slice(b"Host: ");
        output.extend_from_slice(host.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"\r\n");
    Ok(output)
}

struct Http1ClientStream {
    reader: tokio::io::ReadHalf<BoxStream>,
    writer: tokio::io::WriteHalf<BoxStream>,
    response_header: Vec<u8>,
    response_prefix: Vec<u8>,
    response_prefix_offset: usize,
    response_read: bool,
    response_error: Option<String>,
}

impl Http1ClientStream {
    fn read_response_head(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut chunk = [0u8; READ_CHUNK_SIZE];
        let mut read_buf = ReadBuf::new(&mut chunk);
        match Pin::new(&mut self.reader).poll_read(cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                let read = read_buf.filled().len();
                if read == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "v2ray-http: connection closed before response",
                    )));
                }
                self.response_header.extend_from_slice(&chunk[..read]);
                if let Some(end) = header_end(&self.response_header) {
                    let prefix = self.response_header.split_off(end);
                    let head = std::mem::take(&mut self.response_header);
                    match parse_response_status(&head) {
                        Ok(StatusCode::OK) => {
                            self.response_prefix = prefix;
                            self.response_read = true;
                            Poll::Ready(Ok(()))
                        }
                        Ok(status) => {
                            let error = format!("v2ray-http: unexpected status: {status}");
                            self.response_error = Some(error.clone());
                            self.response_read = true;
                            Poll::Ready(Err(io::Error::other(error)))
                        }
                        Err(error) => {
                            let message = error.to_string();
                            self.response_error = Some(message.clone());
                            self.response_read = true;
                            Poll::Ready(Err(io::Error::new(error.kind(), message)))
                        }
                    }
                } else if self.response_header.len() > MAX_HEADER_BYTES {
                    let error = "v2ray-http: response headers too large".to_owned();
                    self.response_error = Some(error.clone());
                    self.response_read = true;
                    Poll::Ready(Err(protocol_error(error)))
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }
    }
}

impl AsyncRead for Http1ClientStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if !this.response_read {
            ready!(this.read_response_head(cx))?;
        }
        if let Some(error) = &this.response_error {
            return Poll::Ready(Err(io::Error::other(error.clone())));
        }
        if this.response_prefix_offset < this.response_prefix.len() {
            let remaining = &this.response_prefix[this.response_prefix_offset..];
            let count = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..count]);
            this.response_prefix_offset += count;
            if this.response_prefix_offset == this.response_prefix.len() {
                this.response_prefix.clear();
                this.response_prefix_offset = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for Http1ClientStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

fn parse_response_status(head: &[u8]) -> io::Result<StatusCode> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADER_COUNT];
    let mut response = httparse::Response::new(&mut headers);
    match response.parse(head).map_err(|error| protocol_error(format!("parse response: {error}")))? {
        httparse::Status::Complete(length) if length == head.len() => {}
        _ => return Err(protocol_error("incomplete HTTP response")),
    }
    let code = response.code.ok_or_else(|| protocol_error("missing response status"))?;
    StatusCode::from_u16(code).map_err(|error| protocol_error(format!("invalid response status: {error}")))
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n").map(|position| position + 4)
}

async fn read_head(mut stream: BoxStream) -> io::Result<(Vec<u8>, Vec<u8>, BoxStream)> {
    let mut buffer = Vec::with_capacity(READ_CHUNK_SIZE);
    let mut chunk = [0u8; READ_CHUNK_SIZE];
    loop {
        let length = stream.read(&mut chunk).await?;
        if length == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "v2ray-http: connection closed during request"));
        }
        buffer.extend_from_slice(&chunk[..length]);
        if let Some(end) = header_end(&buffer) {
            if end > MAX_HEADER_BYTES {
                return Err(protocol_error("request headers too large"));
            }
            let prefix = buffer.split_off(end);
            return Ok((buffer, prefix, stream));
        }
        if buffer.len() > MAX_HEADER_BYTES {
            return Err(protocol_error("request headers too large"));
        }
    }
}

struct ParsedRequest {
    method: String,
    target: String,
    host: Option<String>,
    upgrade: Option<String>,
}

fn parse_request(head: &[u8]) -> io::Result<ParsedRequest> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADER_COUNT];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(head).map_err(|error| protocol_error(format!("parse request: {error}")))? {
        httparse::Status::Complete(length) if length == head.len() => {}
        _ => return Err(protocol_error("incomplete HTTP request")),
    }
    let method = request.method.ok_or_else(|| protocol_error("missing request method"))?.to_owned();
    let target = request.path.ok_or_else(|| protocol_error("missing request target"))?.to_owned();
    let host = request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("host"))
        .map(|header| String::from_utf8_lossy(trim_ows(header.value)).into_owned());
    let has_h2c_upgrade = request.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("upgrade") && trim_ows(header.value).eq_ignore_ascii_case(b"h2c")
    });
    Ok(ParsedRequest { method, target, host, upgrade: has_h2c_upgrade.then(|| "h2c".into()) })
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn decoded_path(target: &str) -> io::Result<Vec<u8>> {
    let path = if let Some((_, after_scheme)) = target.split_once("://") {
        after_scheme.find('/').map_or("/", |index| &after_scheme[index..])
    } else {
        target
    };
    let path = path.split(['?', '#']).next().unwrap_or_default();
    let path = if path.is_empty() { "/" } else { path };
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(protocol_error("invalid percent-encoded path"));
            }
            let high = hex(bytes[index + 1]).ok_or_else(|| protocol_error("invalid percent-encoded path"))?;
            let low = hex(bytes[index + 2]).ok_or_else(|| protocol_error("invalid percent-encoded path"))?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    Ok(decoded)
}

fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn normalized_path_prefix(path: &str) -> String {
    if path.is_empty() {
        "/".to_owned()
    } else if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    }
}

fn request_status(request: &ParsedRequest, options: &V2RayHttpOptions) -> StatusCode {
    if !options.host.is_empty()
        && !request.host.as_ref().is_some_and(|host| options.host.iter().any(|item| item == host))
    {
        return StatusCode::BAD_REQUEST;
    }
    if request.upgrade.as_deref() == Some("h2c") {
        return StatusCode::NOT_IMPLEMENTED;
    }
    if !options.method.is_empty() && request.method != options.method {
        return StatusCode::NOT_FOUND;
    }
    match decoded_path(&request.target) {
        Ok(path) if path.starts_with(normalized_path_prefix(&options.path).as_bytes()) => StatusCode::OK,
        _ => StatusCode::NOT_FOUND,
    }
}

fn response_head(status: StatusCode, headers: &HeaderMap) -> Vec<u8> {
    let reason = match status {
        StatusCode::OK => "OK",
        StatusCode::BAD_REQUEST => "Bad Request",
        StatusCode::NOT_FOUND => "Not Found",
        StatusCode::NOT_IMPLEMENTED => "Not Implemented",
        _ => "Error",
    };
    let mut output = format!("HTTP/1.1 {} {}\r\n", status.as_u16(), reason).into_bytes();
    for (name, value) in headers {
        output.extend_from_slice(name.as_str().as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    if status != StatusCode::OK {
        output.extend_from_slice(b"Connection: close\r\nContent-Length: 0\r\n");
    }
    output.extend_from_slice(b"\r\n");
    output
}

/// Accept and validate an HTTP/1.1 request on one connection, return its
/// request/response bodies as a single bidirectional byte stream.
pub(crate) async fn server(stream: BoxStream, options: &V2RayHttpOptions) -> io::Result<BoxStream> {
    let (head, prefix, mut stream) = read_head(stream).await?;
    let request = parse_request(&head)?;
    let status = request_status(&request, options);
    let headers = if status == StatusCode::OK { response_headers(&options.headers)? } else { HeaderMap::new() };
    stream.write_all(&response_head(status, &headers)).await?;
    stream.flush().await?;
    if status != StatusCode::OK {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("v2ray-http: rejected request with status {status}"),
        ));
    }
    Ok(Box::new(PrefixedStream::new(prefix, stream)))
}

/// HTTP/2 request-stream acceptor for one negotiated TLS H2 connection (or
/// cleartext prior-knowledge session). Each accepted request maps to a
/// distinct bidirectional body stream.
pub(crate) struct Http2Server {
    h2: H2Server,
    options: V2RayHttpOptions,
}

impl Http2Server {
    pub(crate) fn new(stream: BoxStream, options: &V2RayHttpOptions) -> Self {
        Self { h2: H2Server::new(stream), options: options.clone() }
    }

    pub(crate) async fn accept(&self) -> io::Result<Option<BoxStream>> {
        loop {
            let Some(incoming) = self.h2.accept().await? else { return Ok(None) };
            let request = ParsedRequest {
                method: incoming.request.method().as_str().to_owned(),
                target: incoming.request.uri().path_and_query().map_or("/", |value| value.as_str()).to_owned(),
                host: incoming.request.uri().authority().map(|authority| authority.as_str().to_owned()).or_else(|| {
                    incoming
                        .request
                        .headers()
                        .get(header::HOST)
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned)
                }),
                upgrade: None,
            };
            let status = request_status(&request, &self.options);
            let mut response = Response::builder().status(status);
            if status == StatusCode::OK {
                for (name, value) in response_headers(&self.options.headers)?.iter() {
                    response = response.header(name, value);
                }
            }
            let response = response.body(()).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            let mut stream = incoming.respond(response)?;
            if status == StatusCode::OK {
                return Ok(Some(Box::new(stream)));
            }
            stream.shutdown().await?;
        }
    }
}

pub(crate) enum ServerSession {
    Http1(BoxStream),
    Http2(Http2Server),
}

/// Select HTTP/1.1 or a multiplexed H2 session using the negotiated TLS ALPN,
/// or sniff the H2 prior-knowledge preface on cleartext connections.
pub(crate) async fn server_session(
    stream: BoxStream,
    options: &V2RayHttpOptions,
    tls: bool,
    alpn: Option<&str>,
) -> io::Result<ServerSession> {
    if tls {
        if alpn == Some("h2") {
            return Ok(ServerSession::Http2(Http2Server::new(stream, options)));
        }
        return server(stream, options).await.map(ServerSession::Http1);
    }
    match sniff_h2c(stream).await? {
        Ok(stream) => Ok(ServerSession::Http2(Http2Server::new(stream, options))),
        Err(stream) => server(stream, options).await.map(ServerSession::Http1),
    }
}

/// Check whether a cleartext connection begins with the H2 prior-knowledge
/// preface. An HTTP/1.1 request is returned with every sniffed byte restored.
pub(crate) async fn sniff_h2c(stream: BoxStream) -> io::Result<Result<BoxStream, BoxStream>> {
    let mut stream = stream;
    let mut prefix = Vec::with_capacity(H2_PREFACE.len());
    let mut byte = [0u8; 1];
    while prefix.len() < H2_PREFACE.len() {
        let count = stream.read(&mut byte).await?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "v2ray-http: connection closed during protocol sniff",
            ));
        }
        prefix.push(byte[0]);
        if prefix.last() != H2_PREFACE.get(prefix.len() - 1) {
            return Ok(Err(Box::new(PrefixedStream::new(prefix, stream))));
        }
    }
    Ok(Ok(Box::new(PrefixedStream::new(prefix, stream))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    fn options() -> V2RayHttpOptions {
        V2RayHttpOptions { path: "/proxy".into(), ..Default::default() }
    }

    #[tokio::test]
    async fn cleartext_client_and_server_bridge_raw_http11_bodies() {
        let (client_io, server_io) = duplex(1 << 16);
        let server_options = options();
        let server = tokio::spawn(async move {
            let mut stream = server(Box::new(server_io), &server_options).await.unwrap();
            let mut request = [0u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.unwrap();
            stream.flush().await.unwrap();
        });
        let mut client =
            client(Box::new(client_io), &Socksaddr::from_host_port("127.0.0.1", 80), &options(), false).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut response = [0u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn http1_server_checks_path_host_and_method() {
        let (client, server_io) = duplex(1 << 16);
        let mut options = options();
        options.host = rb_config::Listable(vec!["edge.example".into()]);
        options.method = "POST".into();
        let task = tokio::spawn(async move { server(Box::new(server_io), &options).await });
        let mut client: BoxStream = Box::new(client);
        client.write_all(b"GET /proxy/x HTTP/1.1\r\nHost: edge.example\r\n\r\n").await.unwrap();
        let mut response = [0u8; 128];
        let count = client.read(&mut response).await.unwrap();
        assert!(String::from_utf8_lossy(&response[..count]).starts_with("HTTP/1.1 404"));
        assert!(task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn http2_server_multiplexes_independent_streams() {
        let (client_io, server_io) = duplex(1 << 18);
        let server = Http2Server::new(Box::new(server_io), &options());
        let client = H2Client::new(Box::new(client_io)).await.unwrap();
        let server_task = tokio::spawn(async move {
            let mut workers = Vec::new();
            for _ in 0..2 {
                let mut stream = server.accept().await.unwrap().unwrap();
                workers.push(tokio::spawn(async move {
                    let mut request = Vec::new();
                    stream.read_to_end(&mut request).await.unwrap();
                    stream.write_all(&request).await.unwrap();
                    stream.shutdown().await.unwrap();
                }));
            }
            for worker in workers {
                worker.await.unwrap();
            }
        });
        let request = |target: &str| {
            Request::builder().method("PUT").uri(format!("https://edge.example{target}")).body(()).unwrap()
        };
        let (response_a, mut stream_a) = client.open(request("/proxy/a")).await.unwrap();
        let (response_b, mut stream_b) = client.open(request("/proxy/b")).await.unwrap();
        assert_eq!(response_a.status(), StatusCode::OK);
        assert_eq!(response_b.status(), StatusCode::OK);
        stream_a.write_all(b"one").await.unwrap();
        stream_a.shutdown().await.unwrap();
        stream_b.write_all(b"two").await.unwrap();
        stream_b.shutdown().await.unwrap();
        let mut a = Vec::new();
        let mut b = Vec::new();
        stream_a.read_to_end(&mut a).await.unwrap();
        stream_b.read_to_end(&mut b).await.unwrap();
        assert_eq!(a, b"one");
        assert_eq!(b, b"two");
        server_task.await.unwrap();
    }
}
