//! UDP sessions: the stack's NAT table (sing-tun `udpnat`), keyed by the
//! client endpoint and, for the dependent mappings, the destination.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

use tokio::sync::{mpsc, Mutex as AsyncMutex, Notify};

use crate::{packet, Command};

/// sing-box `udp_mapping` / `udp_filtering` (RFC 4787 behaviors).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NatBehavior {
    #[default]
    EndpointIndependent,
    AddressDependent,
    AddressAndPortDependent,
}

/// Packets a session queues before it drops new ones.
const SESSION_QUEUE: usize = 256;

/// A UDP client socket opened through the user-space IP stack.
pub struct ClientUdpConn {
    source: SocketAddr,
    commands: mpsc::Sender<Command>,
    packets: AsyncMutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
}

impl ClientUdpConn {
    pub(crate) fn new(
        source: SocketAddr,
        commands: mpsc::Sender<Command>,
        packets: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    ) -> Self {
        ClientUdpConn { source, commands, packets: AsyncMutex::new(packets) }
    }

    /// The virtual local address assigned by the stack.
    pub fn local_addr(&self) -> SocketAddr {
        self.source
    }

    /// Sends one UDP datagram through the stack.
    pub async fn send_to(&self, data: &[u8], destination: SocketAddr) -> io::Result<()> {
        if data.len() > 65507 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "UDP payload is too large"));
        }
        if self.source.is_ipv4() != destination.is_ipv4() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "UDP address family mismatch"));
        }
        self.commands
            .send(Command::SendUdp { source: self.source, destination, data: data.to_vec() })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "network stack stopped"))
    }

    /// Reads the next datagram and its source address. The payload is
    /// truncated to the supplied buffer, like a UDP socket.
    pub async fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut packets = self.packets.lock().await;
        let (data, source) = packets
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "UDP stack connection closed"))?;
        let length = data.len().min(buffer.len());
        buffer[..length].copy_from_slice(&data[..length]);
        Ok((length, source))
    }
}

impl Drop for ClientUdpConn {
    fn drop(&mut self) {
        let _ = self.commands.try_send(Command::CloseUdp { source: self.source });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct NatKey {
    source: SocketAddr,
    address: Option<IpAddr>,
    port: Option<u16>,
}

impl NatKey {
    pub fn new(mapping: NatBehavior, source: SocketAddr, destination: SocketAddr) -> Self {
        let (address, port) = match mapping {
            NatBehavior::EndpointIndependent => (None, None),
            NatBehavior::AddressDependent => (Some(destination.ip()), None),
            NatBehavior::AddressAndPortDependent => (Some(destination.ip()), Some(destination.port())),
        };
        NatKey { source, address, port }
    }
}

pub(crate) struct Session {
    key: NatKey,
    source: SocketAddr,
    queue: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
    notify: Notify,
    closed: AtomicBool,
    /// Destinations the client sent to (for the dependent filterings).
    contacted: Mutex<HashSet<SocketAddr>>,
    filtering: NatBehavior,
    out: mpsc::Sender<Vec<u8>>,
    last_active: Mutex<Instant>,
}

impl Session {
    /// Queues a packet from the client to `destination`.
    pub fn push(&self, data: &[u8], destination: SocketAddr) {
        *self.last_active.lock().unwrap() = Instant::now();
        if self.filtering != NatBehavior::EndpointIndependent {
            self.contacted.lock().unwrap().insert(destination);
        }
        let mut queue = self.queue.lock().unwrap();
        if queue.len() < SESSION_QUEUE {
            queue.push_back((data.to_vec(), destination));
            drop(queue);
            self.notify.notify_one();
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.notify.notify_one();
    }
}

#[derive(Default)]
pub(crate) struct Table {
    sessions: Mutex<HashMap<NatKey, Arc<Session>>>,
}

impl Table {
    pub fn get(&self, key: &NatKey) -> Option<Arc<Session>> {
        self.sessions.lock().unwrap().get(key).cloned()
    }

    /// Adds a session, first closing the least recently active one when
    /// `max` sessions exist already (sing-box `udp_nat_max`, 0 = no limit).
    pub fn insert(
        self: &Arc<Self>,
        key: NatKey,
        source: SocketAddr,
        filtering: NatBehavior,
        out: mpsc::Sender<Vec<u8>>,
        max: usize,
    ) -> UdpSession {
        let session = Arc::new(Session {
            key,
            source,
            queue: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
            closed: AtomicBool::new(false),
            contacted: Mutex::new(HashSet::new()),
            filtering,
            out,
            last_active: Mutex::new(Instant::now()),
        });
        let mut sessions = self.sessions.lock().unwrap();
        if max > 0 && sessions.len() >= max {
            let oldest = sessions.values().min_by_key(|session| *session.last_active.lock().unwrap()).map(|s| s.key);
            if let Some(oldest) = oldest {
                if let Some(evicted) = sessions.remove(&oldest) {
                    evicted.close();
                }
            }
        }
        if let Some(previous) = sessions.insert(key, session.clone()) {
            previous.close();
        }
        UdpSession { session, table: Arc::downgrade(self) }
    }

    pub fn len(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    pub fn close_all(&self) {
        for (_, session) in self.sessions.lock().unwrap().drain() {
            session.close();
        }
    }
}

/// A UDP session of one client (one NAT mapping).
pub struct UdpSession {
    session: Arc<Session>,
    table: Weak<Table>,
}

impl UdpSession {
    /// The client's address.
    pub fn source(&self) -> SocketAddr {
        self.session.source
    }

    /// Reads the next packet the client sent, with the address it sent it
    /// to. Cancel safe. Fails once the session is closed (evicted, or the
    /// stack stopped).
    pub async fn recv(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            let notified = self.session.notify.notified();
            if let Some((data, destination)) = self.session.queue.lock().unwrap().pop_front() {
                let length = data.len().min(buffer.len());
                buffer[..length].copy_from_slice(&data[..length]);
                return Ok((length, destination));
            }
            if self.session.closed.load(Ordering::Acquire) {
                return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "UDP session closed"));
            }
            notified.await;
        }
    }

    /// Sends `data` to the client as if from `from`. Packets the filtering
    /// does not let through, and packets for a full TUN queue, are dropped.
    pub fn send(&self, data: &[u8], from: SocketAddr) -> io::Result<()> {
        if self.session.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "UDP session closed"));
        }
        let source = self.session.source;
        let from = match (source, from) {
            (SocketAddr::V4(_), SocketAddr::V6(v6)) => match v6.ip().to_ipv4_mapped() {
                Some(v4) => SocketAddr::new(v4.into(), v6.port()),
                None => return Err(io::Error::new(io::ErrorKind::InvalidInput, "send IPv6 packet to IPv4 connection")),
            },
            _ => from,
        };
        let allowed = match self.session.filtering {
            NatBehavior::EndpointIndependent => true,
            NatBehavior::AddressDependent => {
                self.session.contacted.lock().unwrap().iter().any(|contacted| contacted.ip() == from.ip())
            }
            NatBehavior::AddressAndPortDependent => self.session.contacted.lock().unwrap().contains(&from),
        };
        if !allowed {
            return Ok(());
        }
        let _ = self.session.out.try_send(packet::build_udp(from, source, data));
        Ok(())
    }
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        self.session.close();
        if let Some(table) = self.table.upgrade() {
            let mut sessions = table.sessions.lock().unwrap();
            if sessions.get(&self.session.key).is_some_and(|current| Arc::ptr_eq(current, &self.session)) {
                sessions.remove(&self.session.key);
            }
        }
    }
}

/// Sends DNS answers for a hijacked query back to the client (sing-tun
/// `dnsResponseWriter`).
#[derive(Clone)]
pub struct UdpReply {
    pub(crate) client: SocketAddr,
    pub(crate) out: mpsc::Sender<Vec<u8>>,
}

impl UdpReply {
    pub fn send(&self, data: &[u8], from: SocketAddr) -> io::Result<()> {
        if from.is_ipv6() && self.client.is_ipv4() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "send IPv6 packet to IPv4 connection"));
        }
        if 8 + data.len() + 40 > usize::from(u16::MAX) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("DNS response too large: {}", data.len())));
        }
        let _ = self.out.try_send(packet::build_udp(from, self.client, data));
        Ok(())
    }
}
