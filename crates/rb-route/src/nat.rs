//! The UDP NAT table, mirroring sing-box `sing/common/udpnat2`
//! (`udpnat.Service`): an inbound that receives the packets of many clients
//! on one socket turns each client (source address) into its own packet
//! connection, routes it once, and sends replies back through a
//! [`PacketWriter`]. A session ends when its routed connection ends, which
//! the router does after the session's UDP timeout of idleness
//! (`udp_timeout`, carried as [`InboundContext::inbound_udp_timeout`]).
//!
//! The SOCKS5 inbound does not need it (each UDP ASSOCIATE has its own
//! socket and is one session, as in sing-box); inbounds that share one UDP
//! socket between clients (`direct`, `shadowsocks`, `tun`) will.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rb_adapter::{ConnectionRouter, InboundContext, PacketConn, SharedPacketConn, Socksaddr};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::debug;

/// Packets queued for one session before new ones are dropped.
const SESSION_QUEUE: usize = 128;

/// Where the replies of a session go: the inbound's own socket.
#[async_trait]
pub trait PacketWriter: Send + Sync {
    /// Sends `data` to the client at `to`, as if it came from `from`.
    async fn write_back(&self, data: &[u8], from: &Socksaddr, to: SocketAddr) -> io::Result<()>;
}

type Packet = (Vec<u8>, Socksaddr);
type Sessions = Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Packet>>>>;

pub struct UdpNat {
    router: Arc<dyn ConnectionRouter>,
    writer: Arc<dyn PacketWriter>,
    sessions: Sessions,
    tasks: Mutex<JoinSet<()>>,
}

impl UdpNat {
    pub fn new(router: Arc<dyn ConnectionRouter>, writer: Arc<dyn PacketWriter>) -> Self {
        UdpNat { router, writer, sessions: Arc::default(), tasks: Mutex::new(JoinSet::new()) }
    }

    /// Number of open sessions.
    pub fn len(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Hands one packet from `context.source` to `context.destination` to
    /// its session, opening and routing a new session for a new source.
    /// A packet for a session whose queue is full is dropped, as UDP may.
    pub fn new_packet(&self, context: InboundContext, data: Vec<u8>) {
        let source = context.source;
        let packet = (data, context.destination.clone());
        let mut sessions = self.sessions.lock().unwrap();
        let packet = match sessions.get(&source) {
            Some(sender) => match sender.try_send(packet) {
                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => return,
                // The session just ended: start a new one.
                Err(mpsc::error::TrySendError::Closed(packet)) => packet,
            },
            None => packet,
        };
        let (sender, receiver) = mpsc::channel(SESSION_QUEUE);
        let _ = sender.try_send(packet);
        sessions.insert(source, sender.clone());
        drop(sessions);
        let conn: SharedPacketConn =
            Arc::new(NatConn { receiver: tokio::sync::Mutex::new(receiver), writer: self.writer.clone(), source });
        let router = self.router.clone();
        let sessions = self.sessions.clone();
        let mut tasks = self.tasks.lock().unwrap();
        while tasks.try_join_next().is_some() {}
        tasks.spawn(async move {
            if let Err(error) = router.route_packet_connection(context, conn).await {
                debug!(%source, %error, "udp nat session closed");
            }
            let mut sessions = sessions.lock().unwrap();
            if sessions.get(&source).is_some_and(|current| current.same_channel(&sender)) {
                sessions.remove(&source);
            }
        });
    }
}

/// One session: packets of one source, replies back to it.
struct NatConn {
    receiver: tokio::sync::Mutex<mpsc::Receiver<Packet>>,
    writer: Arc<dyn PacketWriter>,
    source: SocketAddr,
}

#[async_trait]
impl PacketConn for NatConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let mut receiver = self.receiver.lock().await;
        let (data, destination) =
            receiver.recv().await.ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "udp nat closed"))?;
        let length = data.len().min(buffer.len());
        buffer[..length].copy_from_slice(&data[..length]);
        Ok((length, destination))
    }

    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        self.writer.write_back(data, address, self.source).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rb_adapter::{BoxStream, Network, RouteError};
    use std::time::Duration;

    /// Answers each packet with its payload uppercased, from where it was
    /// sent, until the session is idle for 100ms.
    struct EchoRouter;

    #[async_trait]
    impl ConnectionRouter for EchoRouter {
        async fn route_connection(&self, _context: InboundContext, _client: BoxStream) -> Result<(), RouteError> {
            Err(RouteError::Rejected)
        }
        async fn route_packet_connection(
            &self,
            context: InboundContext,
            client: SharedPacketConn,
        ) -> Result<(), RouteError> {
            assert_eq!(context.network, Network::Udp);
            let mut buffer = [0u8; 64];
            while let Ok(Ok((length, destination))) =
                tokio::time::timeout(Duration::from_millis(100), client.read_packet(&mut buffer)).await
            {
                let reply = buffer[..length].to_ascii_uppercase();
                client.write_packet(&reply, &destination).await.map_err(RouteError::Io)?;
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct Collect(Mutex<Vec<(Vec<u8>, String, SocketAddr)>>);

    #[async_trait]
    impl PacketWriter for Collect {
        async fn write_back(&self, data: &[u8], from: &Socksaddr, to: SocketAddr) -> io::Result<()> {
            self.0.lock().unwrap().push((data.to_vec(), from.to_string(), to));
            Ok(())
        }
    }

    fn context(source: &str, destination: &str) -> InboundContext {
        let destination: SocketAddr = destination.parse().unwrap();
        InboundContext::new("in", "direct", Network::Udp, source.parse().unwrap(), destination.into())
    }

    #[tokio::test]
    async fn one_session_per_source() {
        let writer = Arc::new(Collect::default());
        let nat = UdpNat::new(Arc::new(EchoRouter), writer.clone());
        nat.new_packet(context("10.0.0.1:1000", "1.1.1.1:53"), b"a".to_vec());
        nat.new_packet(context("10.0.0.1:1000", "8.8.8.8:53"), b"b".to_vec());
        nat.new_packet(context("10.0.0.2:2000", "1.1.1.1:53"), b"c".to_vec());
        assert_eq!(nat.len(), 2);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut replies = writer.0.lock().unwrap().clone();
        replies.sort();
        assert_eq!(
            replies,
            vec![
                (b"A".to_vec(), "1.1.1.1:53".into(), "10.0.0.1:1000".parse().unwrap()),
                (b"B".to_vec(), "8.8.8.8:53".into(), "10.0.0.1:1000".parse().unwrap()),
                (b"C".to_vec(), "1.1.1.1:53".into(), "10.0.0.2:2000".parse().unwrap()),
            ]
        );
        // Idle sessions end and leave the table; a new packet opens a new one.
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(nat.is_empty());
        nat.new_packet(context("10.0.0.1:1000", "1.1.1.1:53"), b"d".to_vec());
        assert_eq!(nat.len(), 1);
    }
}
