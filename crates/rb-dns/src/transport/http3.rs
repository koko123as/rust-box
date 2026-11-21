//! DNS over HTTP/3 transport (sing-box `dns/transport/quic/http3.go`).
//!
//! The configured dialer supplies the routed UDP socket; Quinn and h3 then
//! maintain one reusable HTTP/3 connection with one request stream per query.

use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use h3::client::SendRequest;
use http::header::{ACCEPT, CONTENT_TYPE, HOST};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri};
use rb_adapter::Socksaddr;
use rb_config::Listable;
use rb_dialer::Dialer;
use rb_tls::TlsClient;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

use super::invalid;
use super::quic_socket;

const DEFAULT_PATH: &str = "/dns-query";
const MAX_DNS_MESSAGE: usize = u16::MAX as usize;

/// A DNS-over-HTTP/3 upstream.
pub struct H3Transport {
    server: Socksaddr,
    dialer: Arc<dyn Dialer>,
    tls: TlsClient,
    authority: String,
    path: String,
    uri: Uri,
    headers: HeaderMap,
    connection: AsyncMutex<Option<Arc<H3Connection>>>,
}

struct H3Connection {
    // The endpoint owns Quinn's UDP socket and its routed packet tasks.
    _endpoint: quinn::Endpoint,
    quic: quinn::Connection,
    sender: AsyncMutex<SendRequest<h3_quinn::OpenStreams, Bytes>>,
    driver: JoinHandle<()>,
}

impl Drop for H3Connection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl H3Transport {
    /// `server_port` is the configured URL port (zero remains distinct from
    /// 443 when building the HTTP authority); `server.port` is the dial port.
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
                .map_err(|error| invalid(format!("DNS over HTTP/3: invalid header name: {error}")))?;
            if name == HOST {
                host_header = values.0.first().cloned();
                continue;
            }
            for value in values.iter() {
                let value = HeaderValue::from_str(value)
                    .map_err(|error| invalid(format!("DNS over HTTP/3: invalid header value: {error}")))?;
                headers.append(name.clone(), value);
            }
        }

        // Host controls the HTTP authority only; TLS SNI and verification use
        // the configured TLS server name (defaulting to the DNS server).
        let url_host = host_header.filter(|host| !host.is_empty()).unwrap_or_else(|| tls.server_name().to_string());
        let authority = make_authority(&url_host, server_port)?;
        let path = normalize_path(path)?;
        let uri = Uri::builder()
            .scheme("https")
            .authority(authority.as_str())
            .path_and_query(path.as_str())
            .build()
            .map_err(|error| invalid(format!("DNS over HTTP/3: invalid URI: {error}")))?;
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/dns-message"));
        headers.insert(ACCEPT, HeaderValue::from_static("application/dns-message"));

        Ok(Self { server, dialer, tls, authority, path, uri, headers, connection: AsyncMutex::new(None) })
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

    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    pub fn tls_server_name(&self) -> &str {
        self.tls.server_name()
    }

    pub fn tls_alpn(&self) -> Vec<String> {
        self.tls.alpn()
    }

    /// Sends one compressed DNS message over an HTTP/3 POST and restores its
    /// original DNS ID in the response, matching sing-box's raw Exchange.
    pub async fn exchange(&self, query: &[u8], timeout: Duration) -> io::Result<Vec<u8>> {
        if query.len() < 12 {
            return Err(invalid("DNS query too short"));
        }
        if query.len() > MAX_DNS_MESSAGE {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "DNS query exceeds the message limit"));
        }
        tokio::time::timeout(timeout, self.exchange_inner(query))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS over HTTP/3: exchange timed out"))?
    }

    async fn exchange_inner(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let mut message = hickory_proto::op::Message::from_vec(query)
            .map_err(|error| invalid(format!("DNS over HTTP/3: {error}")))?;
        let original_id = message.id();
        message.set_id(0);
        // Hickory's wire encoder applies DNS name compression, as sing-box does.
        let request_body = message.to_vec().map_err(|error| invalid(format!("DNS over HTTP/3: {error}")))?;

        let connection = self.connection().await?;
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(self.uri.clone())
            .body(())
            .map_err(|error| invalid(format!("DNS over HTTP/3: invalid request: {error}")))?;
        *request.headers_mut() = self.headers.clone();

        let mut sender = connection.sender.lock().await.clone();
        let mut stream = sender
            .send_request(request)
            .await
            .map_err(|error| io::Error::other(format!("DNS over HTTP/3: send request: {error}")))?;
        stream
            .send_data(Bytes::from(request_body))
            .await
            .map_err(|error| io::Error::other(format!("DNS over HTTP/3: write request: {error}")))?;
        stream.finish().await.map_err(|error| io::Error::other(format!("DNS over HTTP/3: finish request: {error}")))?;

        let response = stream
            .recv_response()
            .await
            .map_err(|error| io::Error::other(format!("DNS over HTTP/3: read response: {error}")))?;
        let status = response.status();
        if status != StatusCode::OK {
            return Err(io::Error::other(format!("unexpected status: {status}")));
        }

        let mut body = Vec::new();
        while let Some(mut data) = stream
            .recv_data()
            .await
            .map_err(|error| io::Error::other(format!("DNS over HTTP/3: read response body: {error}")))?
        {
            while data.has_remaining() {
                let chunk = data.chunk();
                if body.len().saturating_add(chunk.len()) > MAX_DNS_MESSAGE {
                    return Err(invalid("DNS over HTTP/3: response exceeds the DNS message limit"));
                }
                body.extend_from_slice(chunk);
                let length = chunk.len();
                data.advance(length);
            }
        }
        if body.len() < 12 {
            return Err(invalid("DNS over HTTP/3: invalid DNS response length"));
        }
        hickory_proto::op::Message::from_vec(&body).map_err(|error| invalid(format!("DNS over HTTP/3: {error}")))?;
        body[..2].copy_from_slice(&original_id.to_be_bytes());
        Ok(body)
    }

    async fn connection(&self) -> io::Result<Arc<H3Connection>> {
        let mut current = self.connection.lock().await;
        if let Some(connection) = current
            .as_ref()
            .filter(|connection| connection.quic.close_reason().is_none() && !connection.driver.is_finished())
        {
            return Ok(connection.clone());
        }
        *current = None;

        let packet_conn = self.dialer.dial_udp(&self.server).await?;
        let (endpoint, quic) = quic_socket::connect(packet_conn, self.server.clone(), &self.tls).await?;
        let h3_quic = h3_quinn::Connection::new(quic.clone());
        let (mut driver, sender) = h3::client::new(h3_quic)
            .await
            .map_err(|error| io::Error::other(format!("DNS over HTTP/3: establish HTTP/3 connection: {error}")))?;
        let driver = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let connection = Arc::new(H3Connection { _endpoint: endpoint, quic, sender: AsyncMutex::new(sender), driver });
        *current = Some(connection.clone());
        Ok(connection)
    }
}

fn make_authority(host: &str, configured_port: u16) -> io::Result<String> {
    let parsed: http::uri::Authority =
        host.parse().map_err(|error| invalid(format!("DNS over HTTP/3: invalid authority `{host}`: {error}")))?;
    let hostname = parsed.host();
    if hostname.is_empty() {
        return Err(invalid("DNS over HTTP/3 authority must not be empty"));
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
        path.parse().map_err(|error| invalid(format!("DNS over HTTP/3: invalid path `{path}`: {error}")))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::{make_authority, normalize_path};

    #[test]
    fn uses_http3_defaults_for_authority_and_path() {
        assert_eq!(make_authority("dns.example", 0).unwrap(), "dns.example");
        assert_eq!(normalize_path("").unwrap(), "/dns-query");
    }

    #[test]
    fn preserves_custom_port_and_normalizes_path() {
        assert_eq!(make_authority("resolver.example", 8443).unwrap(), "resolver.example:8443");
        assert_eq!(normalize_path("custom-query").unwrap(), "/custom-query");
    }
}
