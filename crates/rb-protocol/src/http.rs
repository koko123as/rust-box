//! HTTP proxy server side (RFC 9110 section 9.3.6 CONNECT, and plain
//! requests in absolute form), mirroring sing-box `sing/protocol/http`.

use std::collections::HashMap;
use std::io;

use base64::Engine;
use rb_adapter::Socksaddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_HEAD: usize = 64 * 1024;

/// A request the proxy accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub destination: Socksaddr,
    pub user: Option<String>,
    /// Bytes to send to the destination before the client's own: the
    /// rewritten request for plain HTTP, and for both kinds whatever the
    /// client sent after the request head.
    pub initial: Vec<u8>,
}

fn protocol_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut data = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        if let Some(end) = data.windows(4).position(|window| window == b"\r\n\r\n") {
            let rest = data.split_off(end + 4);
            return Ok((data, rest));
        }
        if data.len() > MAX_HEAD {
            return Err(protocol_error("http: request head too large"));
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "http: connection closed in request head"));
        }
        data.extend_from_slice(&chunk[..read]);
    }
}

fn split_host_port(authority: &str, default_port: u16) -> Option<Socksaddr> {
    if authority.is_empty() {
        return None;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(port) => port.parse().ok()?,
            None if after.is_empty() => default_port,
            None => return None,
        };
        return Some(Socksaddr::from_host_port(host, port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Some(Socksaddr::from_host_port(host, port.parse().ok()?)),
        Some(_) => None,
        None => Some(Socksaddr::from_host_port(authority, default_port)),
    }
}

fn check_auth(headers: &[(String, String)], users: &HashMap<String, String>) -> Result<Option<String>, ()> {
    if users.is_empty() {
        return Ok(None);
    }
    let value = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("proxy-authorization"))
        .map(|(_, value)| value.as_str())
        .ok_or(())?;
    let encoded = value.strip_prefix("Basic ").or_else(|| value.strip_prefix("basic ")).ok_or(())?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(encoded.trim()).map_err(|_| ())?;
    let decoded = String::from_utf8(decoded).map_err(|_| ())?;
    let (username, password) = decoded.split_once(':').ok_or(())?;
    if users.get(username).map(String::as_str) == Some(password) {
        Ok(Some(username.to_string()))
    } else {
        Err(())
    }
}

/// Reads one proxy request and answers what the proxy itself answers:
/// `200 Connection established` for CONNECT, `407` without valid
/// credentials, `400` for a request it cannot route.
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    users: &HashMap<String, String>,
) -> io::Result<Request> {
    let (head, rest) = read_head(stream).await?;
    let text = std::str::from_utf8(&head).map_err(|_| protocol_error("http: request head is not UTF-8"))?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next()) else {
        stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n").await?;
        return Err(protocol_error(format!("http: bad request line {request_line:?}")));
    };
    let headers: Vec<(String, String)> = lines
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            line.split_once(':').map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        })
        .collect();
    let user = match check_auth(&headers, users) {
        Ok(user) => user,
        Err(()) => {
            stream
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nConnection: close\r\n\r\n")
                .await?;
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "http: authentication failed"));
        }
    };
    if method.eq_ignore_ascii_case("CONNECT") {
        let Some(destination) = split_host_port(target, 443) else {
            stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n").await?;
            return Err(protocol_error(format!("http: bad CONNECT target {target:?}")));
        };
        stream.write_all(format!("{version} 200 Connection established\r\n\r\n").as_bytes()).await?;
        return Ok(Request { destination, user, initial: rest });
    }
    // A plain request: `GET http://host[:port]/path HTTP/1.1`.
    let Some(after_scheme) = target.strip_prefix("http://").or_else(|| target.strip_prefix("HTTP://")) else {
        stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n").await?;
        return Err(protocol_error(format!("http: not a proxy request: {target:?}")));
    };
    let (authority, path) = match after_scheme.find('/') {
        Some(index) => (&after_scheme[..index], &after_scheme[index..]),
        None => (after_scheme, "/"),
    };
    let authority = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    let Some(destination) = split_host_port(authority, 80) else {
        stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n").await?;
        return Err(protocol_error(format!("http: bad request target {target:?}")));
    };
    // Rewrite to origin form, drop the proxy's own headers, and end the
    // connection after this exchange: one connection carries one
    // destination, so a keep-alive client opens a new one per request.
    let mut initial = format!("{method} {path} {version}\r\n");
    let mut has_host = false;
    for (name, value) in &headers {
        let lower = name.to_ascii_lowercase();
        if lower == "proxy-authorization"
            || lower == "proxy-connection"
            || lower == "connection"
            || lower == "keep-alive"
        {
            continue;
        }
        has_host |= lower == "host";
        initial.push_str(&format!("{name}: {value}\r\n"));
    }
    if !has_host {
        initial.push_str(&format!("Host: {authority}\r\n"));
    }
    initial.push_str("Connection: close\r\n\r\n");
    let mut initial = initial.into_bytes();
    initial.extend_from_slice(&rest);
    Ok(Request { destination, user, initial })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn run(request: &[u8], users: &[(&str, &str)]) -> (io::Result<Request>, String) {
        let users: HashMap<String, String> = users.iter().map(|(u, p)| (u.to_string(), p.to_string())).collect();
        let (mut client, mut server) = tokio::io::duplex(65536);
        client.write_all(request).await.unwrap();
        let result = handshake(&mut server, &users).await;
        drop(server);
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        (result, String::from_utf8(reply).unwrap())
    }

    #[tokio::test]
    async fn connect() {
        let (result, reply) = run(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nEARLY", &[]).await;
        let request = result.unwrap();
        assert_eq!(request.destination.to_string(), "example.com:443");
        assert_eq!(request.initial, b"EARLY");
        assert_eq!(reply, "HTTP/1.1 200 Connection established\r\n\r\n");
    }

    #[tokio::test]
    async fn plain_request_rewritten() {
        let (result, reply) = run(
            b"GET http://example.com:8080/a?b=1 HTTP/1.1\r\nHost: example.com:8080\r\nProxy-Connection: keep-alive\r\n\r\n",
            &[],
        )
        .await;
        let request = result.unwrap();
        assert_eq!(request.destination.to_string(), "example.com:8080");
        let initial = String::from_utf8(request.initial).unwrap();
        assert!(initial.starts_with("GET /a?b=1 HTTP/1.1\r\n"), "{initial}");
        assert!(!initial.to_lowercase().contains("proxy-connection"));
        assert!(initial.ends_with("Connection: close\r\n\r\n"));
        assert!(reply.is_empty());
    }

    #[tokio::test]
    async fn authentication() {
        let token = base64::engine::general_purpose::STANDARD.encode("u:p");
        let good = format!("CONNECT [::1]:22 HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n");
        let (result, _) = run(good.as_bytes(), &[("u", "p")]).await;
        let request = result.unwrap();
        assert_eq!(request.user.as_deref(), Some("u"));
        assert_eq!(request.destination.to_string(), "[::1]:22");
        let (result, reply) = run(b"CONNECT a.com:443 HTTP/1.1\r\n\r\n", &[("u", "p")]).await;
        assert!(result.is_err());
        assert!(reply.starts_with("HTTP/1.1 407"));
    }

    #[tokio::test]
    async fn bad_requests() {
        let (result, reply) = run(b"GET /local HTTP/1.1\r\n\r\n", &[]).await;
        assert!(result.is_err());
        assert!(reply.starts_with("HTTP/1.1 400"));
    }
}
