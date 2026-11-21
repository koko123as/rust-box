//! DNS over TLS transport (sing-box `dns/transport/tls.go`).
//!
//! A TLS connection carries multiple concurrent two-byte-length-prefixed DNS
//! messages. Responses are correlated by their DNS IDs, so the server may
//! answer queries out of order just as sing-box's query multiplexer allows.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rb_adapter::{BoxStream, Socksaddr};
use rb_dialer::Dialer;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{oneshot, Mutex as AsyncMutex};

use super::next_id;

/// A DoT server and its TLS dialer.
pub struct DotTransport {
    server: Socksaddr,
    dialer: Arc<dyn Dialer>,
    connection: AsyncMutex<Option<Arc<DotConnection>>>,
}

struct DotConnection {
    writer: AsyncMutex<WriteHalf<BoxStream>>,
    pending: Mutex<HashMap<u16, oneshot::Sender<io::Result<Vec<u8>>>>>,
    alive: AtomicBool,
}

struct PendingGuard {
    connection: Arc<DotConnection>,
    id: u16,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.connection.pending.lock().unwrap().remove(&self.id);
    }
}

impl DotConnection {
    fn fail(&self, kind: io::ErrorKind, message: &str) {
        self.alive.store(false, Ordering::Release);
        let pending = std::mem::take(&mut *self.pending.lock().unwrap());
        for (_, sender) in pending {
            let _ = sender.send(Err(io::Error::new(kind, message.to_string())));
        }
    }

    async fn read_loop(self: Arc<Self>, mut reader: ReadHalf<BoxStream>) {
        loop {
            let length = match reader.read_u16().await {
                Ok(length) if length >= 12 => length as usize,
                Ok(length) => {
                    self.fail(io::ErrorKind::InvalidData, &format!("DNS over TLS: invalid message length {length}"));
                    return;
                }
                Err(error) => {
                    self.fail(error.kind(), &format!("DNS over TLS: {error}"));
                    return;
                }
            };
            let mut response = vec![0; length];
            if let Err(error) = reader.read_exact(&mut response).await {
                self.fail(error.kind(), &format!("DNS over TLS: {error}"));
                return;
            }
            let id = u16::from_be_bytes([response[0], response[1]]);
            if let Some(sender) = self.pending.lock().unwrap().remove(&id) {
                let _ = sender.send(Ok(response));
            }
        }
    }
}

impl DotTransport {
    pub fn new(server: Socksaddr, dialer: Arc<dyn Dialer>) -> Self {
        DotTransport { server, dialer, connection: AsyncMutex::new(None) }
    }

    pub fn server(&self) -> &Socksaddr {
        &self.server
    }

    async fn connection(&self) -> io::Result<Arc<DotConnection>> {
        let mut current = self.connection.lock().await;
        if let Some(connection) = current.as_ref().filter(|connection| connection.alive.load(Ordering::Acquire)) {
            return Ok(connection.clone());
        }

        let stream = self.dialer.dial_tcp(&self.server).await?;
        let (reader, writer) = tokio::io::split(stream);
        let connection = Arc::new(DotConnection {
            writer: AsyncMutex::new(writer),
            pending: Mutex::new(HashMap::new()),
            alive: AtomicBool::new(true),
        });
        *current = Some(connection.clone());
        tokio::spawn(connection.clone().read_loop(reader));
        Ok(connection)
    }

    /// Forwards one DNS message. The caller's ID is restored in the response;
    /// on the wire this transport assigns a unique ID for correlation.
    pub async fn exchange(&self, query: &[u8], timeout: Duration) -> io::Result<Vec<u8>> {
        if query.len() < 12 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "DNS query too short"));
        }
        if query.len() > u16::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "DNS query exceeds the TCP message limit"));
        }
        tokio::time::timeout(timeout, self.exchange_inner(query))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS over TLS: exchange timed out"))?
    }

    async fn exchange_inner(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let connection = self.connection().await?;
        let (id, receiver) = {
            let mut pending = connection.pending.lock().unwrap();
            let mut selected = None;
            for _ in 0..=u16::MAX {
                let id = next_id();
                if let std::collections::hash_map::Entry::Vacant(entry) = pending.entry(id) {
                    let (sender, receiver) = oneshot::channel();
                    entry.insert(sender);
                    selected = Some((id, receiver));
                    break;
                }
            }
            selected
                .ok_or_else(|| io::Error::new(io::ErrorKind::WouldBlock, "DNS over TLS: all query IDs are in use"))?
        };
        let _pending = PendingGuard { connection: connection.clone(), id };

        let mut message = query.to_vec();
        message[..2].copy_from_slice(&id.to_be_bytes());
        let mut frame = Vec::with_capacity(message.len() + 2);
        frame.extend_from_slice(&(message.len() as u16).to_be_bytes());
        frame.extend_from_slice(&message);
        if let Err(error) = connection.writer.lock().await.write_all(&frame).await {
            connection.fail(error.kind(), &format!("DNS over TLS: {error}"));
            return Err(error);
        }

        let mut response = receiver
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "DNS over TLS: connection closed"))??;
        if response.len() < 12 || response[..2] != id.to_be_bytes() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "DNS over TLS: response ID mismatch"));
        }
        response[..2].copy_from_slice(&query[..2]);
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    use async_trait::async_trait;
    use hickory_proto::op::{Message, MessageType};
    use rb_adapter::SharedPacketConn;

    struct MultiplexTestDialer {
        connections: AtomicUsize,
    }

    #[async_trait]
    impl Dialer for MultiplexTestDialer {
        async fn dial_tcp(&self, _destination: &Socksaddr) -> io::Result<BoxStream> {
            self.connections.fetch_add(1, Ordering::SeqCst);
            let (client, mut server) = tokio::io::duplex(8192);
            tokio::spawn(async move {
                let mut queries = Vec::new();
                for _ in 0..2 {
                    let Ok(length) = server.read_u16().await else { return };
                    let mut query = vec![0; length as usize];
                    if server.read_exact(&mut query).await.is_err() {
                        return;
                    }
                    queries.push(query);
                }
                for query in queries.into_iter().rev() {
                    let Ok(mut response) = Message::from_vec(&query) else { return };
                    response.set_message_type(MessageType::Response).set_recursion_available(true);
                    let Ok(response) = response.to_vec() else { return };
                    if server.write_u16(response.len() as u16).await.is_err()
                        || server.write_all(&response).await.is_err()
                    {
                        return;
                    }
                }
                std::future::pending::<()>().await;
            });
            Ok(Box::new(client))
        }

        async fn dial_udp(&self, _destination: &Socksaddr) -> io::Result<SharedPacketConn> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }

        async fn listen_packet(&self, _destination: &Socksaddr) -> io::Result<SharedPacketConn> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    #[tokio::test]
    async fn multiplexes_parallel_queries_and_restores_ids() {
        let dialer = Arc::new(MultiplexTestDialer { connections: AtomicUsize::new(0) });
        let transport = Arc::new(DotTransport::new(Socksaddr::from_host_port("dns.example", 853), dialer.clone()));
        let first = super::super::build_query("first.test", super::super::QTYPE_A, 0x1111).unwrap();
        let second = super::super::build_query("second.test", super::super::QTYPE_AAAA, 0x2222).unwrap();
        let (first, second) = tokio::join!(
            transport.exchange(&first, Duration::from_secs(1)),
            transport.exchange(&second, Duration::from_secs(1))
        );
        let first = first.unwrap();
        let second = second.unwrap();
        assert_eq!(&first[..2], &[0x11, 0x11]);
        assert_eq!(&second[..2], &[0x22, 0x22]);
        assert_eq!(dialer.connections.load(Ordering::SeqCst), 1);
    }
}
