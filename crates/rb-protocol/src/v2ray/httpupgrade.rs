//! V2Ray HTTPUpgrade transport (sing-box `transport/v2rayhttpupgrade`).
//!
//! This is an HTTP/1.1 upgrade followed by an unframed TCP byte stream. It is
//! deliberately separate from WebSocket: no WebSocket key, frames, or masking
//! are used. Bytes read beyond the HTTP headers are put back in front of the
//! stream, as sing-box does with its cached connection wrapper.

use std::io;
use std::net::Ipv6Addr;
use std::time::Duration;

use http::header::{CONNECTION, HOST, UPGRADE, USER_AGENT};
use http::{HeaderName, HeaderValue};
use rb_adapter::{BoxStream, PrefixedStream, Socksaddr};
use rb_config::{V2RayHeaders, V2RayHttpUpgradeOptions};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const HANDSHAKE_TIMEOUT: Duration = rb_tls::DEFAULT_HANDSHAKE_TIMEOUT;
const MAX_HEADER_BYTES: usize = 1024 * 1024;
const READ_CHUNK_SIZE: usize = 8 * 1024;
const MAX_HEADER_COUNT: usize = 256;

/// Performs the HTTPUpgrade client handshake on an already-dialed stream.
/// `tls_server_name` is the effective TLS server name, when TLS is enabled.
pub async fn client(
    stream: BoxStream,
    server: &Socksaddr,
    options: &V2RayHttpUpgradeOptions,
    tls_server_name: Option<&str>,
) -> io::Result<BoxStream> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, client_inner(stream, server, options, tls_server_name))
        .await
        .map_err(|_| handshake_timeout())?
}

async fn client_inner(
    mut stream: BoxStream,
    server: &Socksaddr,
    options: &V2RayHttpUpgradeOptions,
    tls_server_name: Option<&str>,
) -> io::Result<BoxStream> {
    let request = client_request(server, options, tls_server_name)?;
    stream.write_all(&request).await?;
    stream.flush().await?;

    let (head, prefix, stream) = read_http_head(stream).await?;
    let response = parse_response(&head)?;
    if response.status != 101
        || !response.connection.as_deref().is_some_and(|value| value.eq_ignore_ascii_case(b"upgrade"))
        || !response.upgrade.as_deref().is_some_and(|value| value.eq_ignore_ascii_case(b"websocket"))
    {
        let status = if response.reason.is_empty() {
            response.status.to_string()
        } else {
            format!("{} {}", response.status, response.reason)
        };
        return Err(protocol_error(format!("unexpected status: {status}")));
    }

    Ok(Box::new(PrefixedStream::new(prefix, stream)))
}

/// Performs an HTTPUpgrade client handshake without replacing the stream
/// object. Reading one byte at a time leaves following TLS plaintext in the
/// TLS stream, which VLESS Vision must continue to access as a TLS stream.
pub async fn client_in_place<S>(
    stream: &mut S,
    server: &Socksaddr,
    options: &V2RayHttpUpgradeOptions,
    tls_server_name: Option<&str>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    tokio::time::timeout(HANDSHAKE_TIMEOUT, client_in_place_inner(stream, server, options, tls_server_name))
        .await
        .map_err(|_| handshake_timeout())?
}

async fn client_in_place_inner<S>(
    stream: &mut S,
    server: &Socksaddr,
    options: &V2RayHttpUpgradeOptions,
    tls_server_name: Option<&str>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let request = client_request(server, options, tls_server_name)?;
    stream.write_all(&request).await?;
    stream.flush().await?;
    let head = read_http_head_in_place(stream).await?;
    let response = parse_response(&head)?;
    if response.status != 101
        || !response.connection.as_deref().is_some_and(|value| value.eq_ignore_ascii_case(b"upgrade"))
        || !response.upgrade.as_deref().is_some_and(|value| value.eq_ignore_ascii_case(b"websocket"))
    {
        let status = if response.reason.is_empty() {
            response.status.to_string()
        } else {
            format!("{} {}", response.status, response.reason)
        };
        return Err(protocol_error(format!("unexpected status: {status}")));
    }
    Ok(())
}

/// Accepts a V2Ray HTTPUpgrade request and returns the unframed TCP stream.
pub async fn server(stream: BoxStream, options: &V2RayHttpUpgradeOptions) -> io::Result<BoxStream> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, server_inner(stream, options)).await.map_err(|_| handshake_timeout())?
}

async fn server_inner(stream: BoxStream, options: &V2RayHttpUpgradeOptions) -> io::Result<BoxStream> {
    let (head, prefix, mut stream) = read_http_head(stream).await?;
    let request = match parse_request(&head) {
        Ok(request) => request,
        Err(error) => return reject(stream, 400, format!("invalid request: {error}")).await,
    };

    let path = match decoded_path(&request.target) {
        Ok(path) => path,
        Err(error) => return reject(stream, 400, format!("invalid request path: {error}")).await,
    };
    if !options.host.is_empty() && request.host.as_deref() != Some(options.host.as_bytes()) {
        return reject(stream, 400, format!("bad host: {}", display_header(request.host.as_deref()))).await;
    }
    if path != normalized_path(&options.path) {
        return reject(stream, 404, format!("bad path: {path}")).await;
    }
    if request.method != "GET" {
        return reject(stream, 404, format!("bad method: {}", request.method)).await;
    }
    if !request.connection.as_deref().is_some_and(|value| value.eq_ignore_ascii_case(b"upgrade")) {
        return reject(stream, 404, "not an upgrade request".into()).await;
    }
    if !request.upgrade.as_deref().is_some_and(|value| value.eq_ignore_ascii_case(b"websocket")) {
        return reject(stream, 404, "not a websocket request".into()).await;
    }
    if request.websocket_key.as_deref().is_some_and(|value| !value.is_empty()) {
        return reject(stream, 404, "real websocket request received".into()).await;
    }

    // sing-box v1.14.4 stores the configured response headers but does not
    // emit them in this server implementation; match the source behavior.
    let _configured_headers = &options.headers;
    stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n").await?;
    stream.flush().await?;
    Ok(Box::new(PrefixedStream::new(prefix, stream)))
}

/// Accepts an HTTPUpgrade request without replacing the stream object.
pub async fn server_in_place<S>(stream: &mut S, options: &V2RayHttpUpgradeOptions) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    tokio::time::timeout(HANDSHAKE_TIMEOUT, server_in_place_inner(stream, options))
        .await
        .map_err(|_| handshake_timeout())?
}

async fn server_in_place_inner<S>(stream: &mut S, options: &V2RayHttpUpgradeOptions) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let head = read_http_head_in_place(stream).await?;
    let request = match parse_request(&head) {
        Ok(request) => request,
        Err(error) => return reject_in_place(stream, 400, format!("invalid request: {error}")).await,
    };
    let path = match decoded_path(&request.target) {
        Ok(path) => path,
        Err(error) => return reject_in_place(stream, 400, format!("invalid request path: {error}")).await,
    };
    if !options.host.is_empty() && request.host.as_deref() != Some(options.host.as_bytes()) {
        return reject_in_place(stream, 400, format!("bad host: {}", display_header(request.host.as_deref()))).await;
    }
    if path != normalized_path(&options.path) {
        return reject_in_place(stream, 404, format!("bad path: {path}")).await;
    }
    if request.method != "GET" {
        return reject_in_place(stream, 404, format!("bad method: {}", request.method)).await;
    }
    if !request.connection.as_deref().is_some_and(|value| value.eq_ignore_ascii_case(b"upgrade")) {
        return reject_in_place(stream, 404, "not an upgrade request".into()).await;
    }
    if !request.upgrade.as_deref().is_some_and(|value| value.eq_ignore_ascii_case(b"websocket")) {
        return reject_in_place(stream, 404, "not a websocket request".into()).await;
    }
    if request.websocket_key.as_deref().is_some_and(|value| !value.is_empty()) {
        return reject_in_place(stream, 404, "real websocket request received".into()).await;
    }

    let _configured_headers = &options.headers;
    stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n").await?;
    stream.flush().await
}

async fn reject(mut stream: BoxStream, status: u16, message: String) -> io::Result<BoxStream> {
    let reason = match status {
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Internal Server Error",
    };
    let response = format!("HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
    Err(protocol_error(message))
}

async fn reject_in_place<S>(stream: &mut S, status: u16, message: String) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let reason = match status {
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Internal Server Error",
    };
    let response = format!("HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
    Err(protocol_error(message))
}

fn client_request(
    server: &Socksaddr,
    options: &V2RayHttpUpgradeOptions,
    tls_server_name: Option<&str>,
) -> io::Result<Vec<u8>> {
    let host = if !options.host.is_empty() {
        options.host.clone()
    } else if let Some(server_name) = tls_server_name.filter(|name| !name.is_empty()) {
        tls_host_authority(server_name)
    } else {
        server.to_string()
    };
    let host = HeaderValue::from_bytes(host.as_bytes())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid HTTPUpgrade Host: {error}")))?;

    let mut headers = request_headers(&options.headers)?;
    headers.retain(|(name, _)| name != HOST && name != CONNECTION && name != UPGRADE);
    if !headers.iter().any(|(name, value)| name == USER_AGENT && !value.as_bytes().is_empty()) {
        headers.push((USER_AGENT, HeaderValue::from_static("Go-http-client/1.1")));
    }
    headers.sort_by(|(left, _), (right, _)| left.as_str().cmp(right.as_str()));

    let target = escaped_path(&options.path);
    let mut request = Vec::with_capacity(256);
    request.extend_from_slice(b"GET ");
    request.extend_from_slice(target.as_bytes());
    request.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(b"\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n");
    for (name, value) in headers {
        request.extend_from_slice(name.as_str().as_bytes());
        request.extend_from_slice(b": ");
        request.extend_from_slice(value.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    Ok(request)
}

fn request_headers(headers: &V2RayHeaders) -> io::Result<Vec<(HeaderName, HeaderValue)>> {
    let mut result = Vec::new();
    for (name, values) in headers {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("invalid HTTPUpgrade header name: {error}"))
        })?;
        for value in values.iter() {
            let value = HeaderValue::from_bytes(value.as_bytes()).map_err(|error| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("invalid HTTPUpgrade header value: {error}"))
            })?;
            result.push((name.clone(), value));
        }
    }
    Ok(result)
}

fn tls_host_authority(server_name: &str) -> String {
    let unbracketed = server_name.strip_prefix('[').and_then(|name| name.strip_suffix(']')).unwrap_or(server_name);
    if unbracketed.parse::<Ipv6Addr>().is_ok() {
        format!("[{unbracketed}]")
    } else {
        server_name.to_owned()
    }
}

fn normalized_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_owned()
    } else if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    }
}

fn escaped_path(path: &str) -> String {
    let path = normalized_path(path);
    let bytes = path.as_bytes();
    let mut result = String::with_capacity(path.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' && index + 2 < bytes.len() && is_hex(bytes[index + 1]) && is_hex(bytes[index + 2]) {
            result.push('%');
            result.push(bytes[index + 1] as char);
            result.push(bytes[index + 2] as char);
            index += 3;
        } else if is_path_byte(byte) {
            result.push(byte as char);
            index += 1;
        } else {
            result.push('%');
            result.push(hex(byte >> 4));
            result.push(hex(byte & 0x0f));
            index += 1;
        }
    }
    result
}

fn decoded_path(target: &str) -> io::Result<String> {
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    let bytes = path.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() || !is_hex(bytes[index + 1]) || !is_hex(bytes[index + 2]) {
                return Err(protocol_error("invalid percent escape"));
            }
            result.push((from_hex(bytes[index + 1]) << 4) | from_hex(bytes[index + 2]));
            index += 3;
        } else {
            result.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(result).map_err(|error| protocol_error(format!("invalid UTF-8 path: {error}")))
}

fn is_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
                | b'/'
        )
}

fn is_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

fn from_hex(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

fn hex(value: u8) -> char {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    DIGITS[value as usize] as char
}

async fn read_http_head(mut stream: BoxStream) -> io::Result<(Vec<u8>, Vec<u8>, BoxStream)> {
    let mut buffer = Vec::with_capacity(READ_CHUNK_SIZE);
    let mut chunk = [0u8; READ_CHUNK_SIZE];
    loop {
        let length = stream.read(&mut chunk).await?;
        if length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTPUpgrade: connection closed during handshake",
            ));
        }
        buffer.extend_from_slice(&chunk[..length]);
        if let Some(end) = header_end(&buffer) {
            if end > MAX_HEADER_BYTES {
                return Err(protocol_error("HTTP headers too large"));
            }
            let prefix = buffer.split_off(end);
            return Ok((buffer, prefix, stream));
        }
        if buffer.len() > MAX_HEADER_BYTES {
            return Err(protocol_error("HTTP headers too large"));
        }
    }
}

async fn read_http_head_in_place<S>(stream: &mut S) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut buffer = Vec::with_capacity(READ_CHUNK_SIZE);
    let mut byte = [0u8; 1];
    loop {
        if stream.read(&mut byte).await? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTPUpgrade: connection closed during handshake",
            ));
        }
        buffer.push(byte[0]);
        if buffer.len() > MAX_HEADER_BYTES {
            return Err(protocol_error("HTTP headers too large"));
        }
        if buffer.ends_with(b"\r\n\r\n") {
            return Ok(buffer);
        }
    }
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n").map(|position| position + 4)
}

struct ParsedRequest {
    method: String,
    target: String,
    host: Option<Vec<u8>>,
    connection: Option<Vec<u8>>,
    upgrade: Option<Vec<u8>>,
    websocket_key: Option<Vec<u8>>,
}

fn parse_request(head: &[u8]) -> io::Result<ParsedRequest> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADER_COUNT];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(head).map_err(|error| protocol_error(format!("parse request: {error}")))? {
        httparse::Status::Complete(length) if length == head.len() => {}
        _ => return Err(protocol_error("incomplete HTTPUpgrade request")),
    }
    let method = request.method.ok_or_else(|| protocol_error("missing request method"))?.to_owned();
    let target = request.path.ok_or_else(|| protocol_error("missing request path"))?.to_owned();
    Ok(ParsedRequest {
        method,
        target,
        host: header_value(request.headers, "host").map(trim_ows).map(<[u8]>::to_vec),
        connection: header_value(request.headers, "connection").map(trim_ows).map(<[u8]>::to_vec),
        upgrade: header_value(request.headers, "upgrade").map(trim_ows).map(<[u8]>::to_vec),
        websocket_key: header_value(request.headers, "sec-websocket-key").map(trim_ows).map(<[u8]>::to_vec),
    })
}

struct ParsedResponse {
    status: u16,
    reason: String,
    connection: Option<Vec<u8>>,
    upgrade: Option<Vec<u8>>,
}

fn parse_response(head: &[u8]) -> io::Result<ParsedResponse> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADER_COUNT];
    let mut response = httparse::Response::new(&mut headers);
    match response.parse(head).map_err(|error| protocol_error(format!("parse response: {error}")))? {
        httparse::Status::Complete(length) if length == head.len() => {}
        _ => return Err(protocol_error("incomplete HTTPUpgrade response")),
    }
    let status = response.code.ok_or_else(|| protocol_error("missing HTTP status"))?;
    Ok(ParsedResponse {
        status,
        reason: response.reason.unwrap_or_default().to_owned(),
        connection: header_value(response.headers, "connection").map(trim_ows).map(<[u8]>::to_vec),
        upgrade: header_value(response.headers, "upgrade").map(trim_ows).map(<[u8]>::to_vec),
    })
}

fn header_value<'a>(headers: &'a [httparse::Header<'a>], name: &str) -> Option<&'a [u8]> {
    headers.iter().find(|header| header.name.eq_ignore_ascii_case(name)).map(|header| header.value)
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

fn display_header(value: Option<&[u8]>) -> String {
    value.map_or_else(String::new, |value| String::from_utf8_lossy(value).into_owned())
}

fn protocol_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("v2ray-http-upgrade: {}", message.into()))
}

fn handshake_timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "v2ray-http-upgrade: handshake: context deadline exceeded")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn client_upgrades_to_raw_stream_and_keeps_response_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let stream: BoxStream = Box::new(stream);
            let (head, _, mut stream) = read_http_head(stream).await.unwrap();
            let request = parse_request(&head).unwrap();
            assert_eq!(request.method, "GET");
            assert_eq!(request.target, "/proxy");
            assert_eq!(request.host.as_deref(), Some(b"cdn.example".as_slice()));
            assert_eq!(request.connection.as_deref(), Some(b"Upgrade".as_slice()));
            assert_eq!(request.upgrade.as_deref(), Some(b"websocket".as_slice()));
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n\x81\x03hey",
                )
                .await
                .unwrap();
        });

        let options =
            V2RayHttpUpgradeOptions { host: "cdn.example".into(), path: "proxy".into(), ..Default::default() };
        let stream = TcpStream::connect(address).await.unwrap();
        let mut stream = client(Box::new(stream), &Socksaddr::from(address), &options, None).await.unwrap();
        let mut payload = [0u8; 5];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"\x81\x03hey");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn server_upgrades_raw_tcp_and_preserves_request_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let options = V2RayHttpUpgradeOptions { path: "/proxy".into(), ..Default::default() };
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = server(Box::new(stream), &options).await.unwrap();
            let mut payload = [0u8; 5];
            stream.read_exact(&mut payload).await.unwrap();
            payload
        });

        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"GET /proxy HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n\x81\x03hey")
            .await
            .unwrap();
        let stream: BoxStream = Box::new(stream);
        let (head, _, _) = read_http_head(stream).await.unwrap();
        let response = parse_response(&head).unwrap();
        assert_eq!(response.status, 101);
        assert_eq!(response.connection.as_deref(), Some(b"upgrade".as_slice()));
        assert_eq!(response.upgrade.as_deref(), Some(b"websocket".as_slice()));
        assert_eq!(&server_task.await.unwrap(), b"\x81\x03hey");
    }

    #[tokio::test]
    async fn in_place_handshakes_keep_the_stream_usable_in_both_directions() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let options = V2RayHttpUpgradeOptions { path: "/proxy".into(), ..Default::default() };
        let server_options = options.clone();
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            server_in_place(&mut stream, &server_options).await.unwrap();
            stream.write_all(b"server").await.unwrap();
            let mut payload = [0u8; 6];
            stream.read_exact(&mut payload).await.unwrap();
            payload
        });

        let mut stream = TcpStream::connect(address).await.unwrap();
        client_in_place(&mut stream, &Socksaddr::from(address), &options, None).await.unwrap();
        stream.write_all(b"client").await.unwrap();
        let mut payload = [0u8; 6];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"server");
        assert_eq!(&server_task.await.unwrap(), b"client");
    }

    #[test]
    fn path_escaping_round_trips_like_url_set_path() {
        let path = "/proxy path?x=1";
        assert_eq!(escaped_path(path), "/proxy%20path%3Fx=1");
        assert_eq!(decoded_path(&escaped_path(path)).unwrap(), path);
    }
}
