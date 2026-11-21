//! DNS over QUIC transport (sing-box `dns/transport/quic/quic.go`).
//!
//! One QUIC connection is reused; every DNS exchange uses its own bidirectional
//! stream and the TCP-compatible two-byte length prefix.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use quinn::{Connection, ConnectionError, Endpoint};
use rb_adapter::Socksaddr;
use rb_dialer::Dialer;
use rb_tls::TlsClient;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex as AsyncMutex;

use super::quic_socket;

/// A DoQ server and the dialer/TLS options used to connect to it.
pub struct DoqTransport {
    server: Socksaddr,
    dialer: Arc<dyn Dialer>,
    tls: TlsClient,
    connection: AsyncMutex<Option<Arc<DoqConnection>>>,
}

struct DoqConnection {
    // Keeping the endpoint alive is required for the connection's UDP I/O.
    _endpoint: Endpoint,
    connection: Connection,
}

impl DoqTransport {
    pub fn new(server: Socksaddr, dialer: Arc<dyn Dialer>, tls: TlsClient) -> Self {
        Self { server, dialer, tls, connection: AsyncMutex::new(None) }
    }

    pub fn server(&self) -> &Socksaddr {
        &self.server
    }

    pub fn tls_server_name(&self) -> &str {
        self.tls.server_name()
    }

    pub fn tls_alpn(&self) -> Vec<String> {
        self.tls.alpn()
    }

    async fn connection(&self) -> io::Result<Arc<DoqConnection>> {
        let mut current = self.connection.lock().await;
        if let Some(connection) = current.as_ref().filter(|connection| connection.connection.close_reason().is_none()) {
            return Ok(connection.clone());
        }

        *current = None;
        let packet_conn = self.dialer.dial_udp(&self.server).await?;
        let (endpoint, connection) = quic_socket::connect(packet_conn, self.server.clone(), &self.tls).await?;
        let session = Arc::new(DoqConnection { _endpoint: endpoint, connection });
        *current = Some(session.clone());
        Ok(session)
    }

    async fn clear_connection(&self, failed: &Arc<DoqConnection>) {
        let mut current = self.connection.lock().await;
        if current.as_ref().is_some_and(|connection| Arc::ptr_eq(connection, failed)) {
            *current = None;
        }
    }

    /// Forwards a DNS message. sing-box uses ID zero on the wire and restores
    /// the caller's ID when returning the response.
    pub async fn exchange(&self, query: &[u8], timeout: Duration) -> io::Result<Vec<u8>> {
        if query.len() < 12 {
            return Err(invalid("DNS query too short"));
        }
        if query.len() > u16::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "DNS query exceeds the TCP message limit"));
        }
        tokio::time::timeout(timeout, self.exchange_inner(query))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS over QUIC: exchange timed out"))?
    }

    async fn exchange_inner(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let frame = encode_request(query)?;
        for attempt in 0..2 {
            let session = self.connection().await?;
            match exchange_stream(&session.connection, &frame).await {
                Ok(mut response) => {
                    response[..2].copy_from_slice(&query[..2]);
                    return Ok(response);
                }
                Err(error) => {
                    let retryable = session.connection.close_reason().is_some_and(|error| is_retryable_close(&error));
                    if retryable {
                        self.clear_connection(&session).await;
                        if attempt == 0 {
                            continue;
                        }
                    }
                    return Err(error);
                }
            }
        }
        unreachable!("DoQ exchange loop returns or retries at most once")
    }
}

async fn exchange_stream(connection: &Connection, frame: &[u8]) -> io::Result<Vec<u8>> {
    let (mut send, mut receive) =
        connection.open_bi().await.map_err(|error| io::Error::other(format!("DNS over QUIC: open stream: {error}")))?;
    send.write_all(frame).await.map_err(|error| io::Error::other(format!("DNS over QUIC: write query: {error}")))?;
    send.finish().map_err(|error| io::Error::other(format!("DNS over QUIC: finish query: {error}")))?;

    let length = receive
        .read_u16()
        .await
        .map_err(|error| io::Error::other(format!("DNS over QUIC: read response length: {error}")))?;
    if length < 12 {
        return Err(invalid(format!("DNS over QUIC: invalid message length {length}")));
    }
    let mut response = vec![0; length as usize];
    receive
        .read_exact(&mut response)
        .await
        .map_err(|error| io::Error::other(format!("DNS over QUIC: read response: {error}")))?;
    Ok(response)
}

fn encode_request(query: &[u8]) -> io::Result<Vec<u8>> {
    if query.len() < 12 {
        return Err(invalid("DNS query too short"));
    }
    let length = u16::try_from(query.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DNS query exceeds the TCP message limit"))?;
    let mut frame = Vec::with_capacity(query.len() + 2);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(query);
    frame[2..4].fill(0);
    Ok(frame)
}

fn is_retryable_close(error: &ConnectionError) -> bool {
    match error {
        ConnectionError::TimedOut | ConnectionError::Reset | ConnectionError::LocallyClosed => true,
        ConnectionError::ApplicationClosed(close) => close.error_code.into_inner() == 0,
        ConnectionError::ConnectionClosed(close) => u64::from(close.error_code) == 0,
        ConnectionError::TransportError(error) => u64::from(error.code) == 0,
        ConnectionError::VersionMismatch | ConnectionError::CidsExhausted => false,
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::{encode_request, is_retryable_close};
    use quinn::ConnectionError;

    #[test]
    fn frames_request_with_big_endian_length_and_zero_id() {
        let mut query = vec![0; 12];
        query[..2].copy_from_slice(&0x1234u16.to_be_bytes());
        let frame = encode_request(&query).unwrap();

        assert_eq!(&frame[..2], &12u16.to_be_bytes());
        assert_eq!(&frame[2..4], &[0, 0]);
        assert_eq!(&frame[4..], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn rejects_short_dns_message() {
        let error = encode_request(&[0; 11]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn retries_only_upstream_connection_close_categories() {
        assert!(is_retryable_close(&ConnectionError::TimedOut));
        assert!(is_retryable_close(&ConnectionError::Reset));
        assert!(!is_retryable_close(&ConnectionError::VersionMismatch));
        assert!(!is_retryable_close(&ConnectionError::CidsExhausted));
    }
}
