//! A small HTTP/1.1 client for downloading rule-sets, standing in for the
//! Go `http.Client` sing-box uses: GET over a rust-box dialer, TLS with the
//! certificate store's roots, `Accept-Encoding: gzip` with transparent
//! decompression, `If-None-Match`, and up to 10 redirects.

use std::io::{self, Read};
use std::sync::Arc;
use std::time::Duration;

use rb_adapter::Socksaddr;
use rb_dialer::Dialer;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The parts of a URL a GET needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub https: bool,
    pub host: String,
    pub port: u16,
    /// Path and query, starting with `/`.
    pub request_target: String,
}

impl Url {
    pub fn parse(text: &str) -> Result<Url, String> {
        let (scheme, rest) = text.split_once("://").ok_or_else(|| format!("parse {text:?}: missing scheme"))?;
        let https = match scheme.to_ascii_lowercase().as_str() {
            "https" => true,
            "http" => false,
            other => return Err(format!("Get {text:?}: unsupported protocol scheme {other:?}")),
        };
        let rest = rest.split('#').next().unwrap_or("");
        let (authority, target) = match rest.find(['/', '?']) {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, ""),
        };
        let authority = authority.rsplit('@').next().unwrap_or(authority);
        let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
            let (host, after) = stripped.split_once(']').ok_or_else(|| format!("parse {text:?}: bad host"))?;
            (host.to_string(), after.strip_prefix(':'))
        } else {
            match authority.rsplit_once(':') {
                Some((host, port)) => (host.to_string(), Some(port)),
                None => (authority.to_string(), None),
            }
        };
        if host.is_empty() {
            return Err(format!("Get {text:?}: http: no Host in request URL"));
        }
        let port = match port {
            Some(port) if !port.is_empty() => port.parse().map_err(|_| format!("parse {text:?}: invalid port"))?,
            _ => {
                if https {
                    443
                } else {
                    80
                }
            }
        };
        let mut request_target = target.to_string();
        if !request_target.starts_with('/') {
            request_target.insert(0, '/');
        }
        Ok(Url { https, host, port, request_target })
    }

    fn host_header(&self) -> String {
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        let default = if self.https { 443 } else { 80 };
        if self.port == default {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// Resolves a `Location` header against this URL.
    fn join(&self, location: &str) -> Result<Url, String> {
        if location.contains("://") {
            return Url::parse(location);
        }
        let scheme = if self.https { "https" } else { "http" };
        if let Some(rest) = location.strip_prefix("//") {
            return Url::parse(&format!("{scheme}://{rest}"));
        }
        let target = if location.starts_with('/') {
            location.to_string()
        } else {
            let base = self.request_target.split('?').next().unwrap_or("/");
            let directory = &base[..base.rfind('/').map(|index| index + 1).unwrap_or(1)];
            format!("{directory}{location}")
        };
        Ok(Url { request_target: target, ..self.clone() })
    }
}

/// A response: status, the headers that matter, the decoded body.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub etag: Option<String>,
    pub body: Vec<u8>,
}

impl Response {
    /// Go's `Response.Status`: "200 OK".
    pub fn status_text(&self) -> String {
        format!("{} {}", self.status, self.reason)
    }
}

/// What a GET goes through.
#[derive(Clone)]
pub struct Client {
    pub dialer: Arc<dyn Dialer>,
    pub roots: Arc<rustls::RootCertStore>,
    pub timeout: Duration,
}

trait Connection: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Connection for T {}

const MAX_REDIRECTS: usize = 10;
const MAX_HEADER: usize = 64 * 1024;

impl Client {
    /// `GET url`, with `If-None-Match: etag` when there is one.
    pub async fn get(&self, url: &str, etag: Option<&str>) -> io::Result<Response> {
        let mut url = Url::parse(url).map_err(io::Error::other)?;
        let original = url.clone();
        for _ in 0..=MAX_REDIRECTS {
            let response = tokio::time::timeout(self.timeout, self.request(&url, etag))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "context deadline exceeded"))??;
            match response.0.status {
                301 | 302 | 303 | 307 | 308 => {
                    let location = response.1.ok_or_else(|| {
                        io::Error::other(format!("{} response missing Location header", response.0.status))
                    })?;
                    url = url.join(&location).map_err(io::Error::other)?;
                }
                _ => return Ok(response.0),
            }
        }
        Err(io::Error::other(format!("Get {:?}: stopped after 10 redirects", original.host)))
    }

    async fn request(&self, url: &Url, etag: Option<&str>) -> io::Result<(Response, Option<String>)> {
        let destination = Socksaddr::from_host_port(&url.host, url.port);
        let stream = self.dialer.dial_tcp(&destination).await?;
        let mut stream: Box<dyn Connection> = if url.https {
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(io::Error::other)?
                .with_root_certificates(self.roots.clone())
                .with_no_client_auth();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let name = rustls_pki_types::ServerName::try_from(url.host.clone())
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
            Box::new(connector.connect(name, stream).await?)
        } else {
            Box::new(stream)
        };
        let mut request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Go-http-client/1.1\r\n",
            url.request_target,
            url.host_header()
        );
        if let Some(etag) = etag {
            request.push_str(&format!("If-None-Match: {etag}\r\n"));
        }
        request.push_str("Accept-Encoding: gzip\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        read_response(&mut stream).await
    }
}

async fn read_response(stream: &mut Box<dyn Connection>) -> io::Result<(Response, Option<String>)> {
    let mut buffer = Vec::with_capacity(8192);
    let header_end = loop {
        if let Some(index) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
        if buffer.len() > MAX_HEADER {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP response header too long"));
        }
        let mut chunk = [0u8; 4096];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF reading HTTP response"));
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut headers);
    parsed
        .parse(&buffer[..header_end])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("malformed HTTP response: {error}")))?;
    let status = parsed.code.unwrap_or(0);
    let reason = parsed.reason.unwrap_or("").to_string();
    let header = |name: &str| {
        parsed
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| String::from_utf8_lossy(header.value).trim().to_string())
    };
    let etag = header("ETag");
    let location = header("Location");
    let gzip = header("Content-Encoding").is_some_and(|value| value.eq_ignore_ascii_case("gzip"));
    let chunked = header("Transfer-Encoding").is_some_and(|value| value.to_ascii_lowercase().contains("chunked"));
    let length: Option<usize> = header("Content-Length").and_then(|value| value.parse().ok());
    let mut body = buffer[header_end..].to_vec();
    let no_body = status == 304 || status == 204 || (100..200).contains(&status);
    if no_body {
        body.clear();
    } else if chunked {
        body = read_chunked(stream, body).await?;
    } else if let Some(length) = length {
        while body.len() < length {
            let mut chunk = vec![0u8; (length - body.len()).min(65536)];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF"));
            }
            body.extend_from_slice(&chunk[..read]);
        }
        body.truncate(length);
    } else {
        stream.read_to_end(&mut body).await?;
    }
    if gzip && !body.is_empty() {
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(&body[..])
            .read_to_end(&mut decoded)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("gzip: {error}")))?;
        body = decoded;
    }
    Ok((Response { status, reason, etag, body }, location))
}

async fn read_chunked(stream: &mut Box<dyn Connection>, mut pending: Vec<u8>) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        // the size line
        let line_end = loop {
            if let Some(index) = pending.windows(2).position(|window| window == b"\r\n") {
                break index;
            }
            fill(stream, &mut pending).await?;
        };
        let line = String::from_utf8_lossy(&pending[..line_end]).to_string();
        let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk length"))?;
        pending.drain(..line_end + 2);
        if size == 0 {
            return Ok(body);
        }
        while pending.len() < size + 2 {
            fill(stream, &mut pending).await?;
        }
        body.extend_from_slice(&pending[..size]);
        pending.drain(..size + 2);
    }
}

async fn fill(stream: &mut Box<dyn Connection>, pending: &mut Vec<u8>) -> io::Result<()> {
    let mut chunk = [0u8; 16384];
    let read = stream.read(&mut chunk).await?;
    if read == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF"));
    }
    pending.extend_from_slice(&chunk[..read]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let url = Url::parse("https://example.com/a/b.srs?x=1#f").unwrap();
        assert_eq!(url, Url { https: true, host: "example.com".into(), port: 443, request_target: "/a/b.srs?x=1".into() });
        let url = Url::parse("http://[::1]:8080").unwrap();
        assert_eq!((url.host.as_str(), url.port, url.request_target.as_str()), ("::1", 8080, "/"));
        assert_eq!(url.host_header(), "[::1]:8080");
        assert!(Url::parse("ftp://x/y").is_err());
        let base = Url::parse("https://h/dir/file.srs").unwrap();
        assert_eq!(base.join("other.srs").unwrap().request_target, "/dir/other.srs");
        assert_eq!(base.join("/root.srs").unwrap().request_target, "/root.srs");
        assert_eq!(base.join("http://x:81/y").unwrap().port, 81);
    }
}
