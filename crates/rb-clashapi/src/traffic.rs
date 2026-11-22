//! sing-box `common/trafficcontrol.Manager`: the routed connections with
//! their byte counts, and the totals including closed ones.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::time::SystemTime;

use async_trait::async_trait;
use rb_adapter::{
    BoxStream, ConnectionTracker, Host, InboundContext, Interrupt, PacketConn, RoutedConnection, SharedPacketConn,
    Socksaddr,
};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// `closedConnectionsLimit`.
const CLOSED_LIMIT: usize = 1000;

/// sing-box `TrackerMetadata`.
pub struct TrackerMetadata {
    pub id: String,
    pub context: InboundContext,
    pub created_at: SystemTime,
    pub upload: AtomicI64,
    pub download: AtomicI64,
    /// The selected outbound first, then the groups (sing-box reverses
    /// `OutboundChain`).
    pub chain: Vec<String>,
    /// `rule => action`, or `None` for the final outbound.
    pub rule: Option<String>,
    pub outbound: String,
    pub outbound_type: &'static str,
    interrupt: Arc<Interrupt>,
}

impl TrackerMetadata {
    /// Closes the connection (`Tracker.Close`).
    pub fn close(&self) {
        self.interrupt.close();
    }

    /// The connection as `GET /connections` lists it.
    pub fn to_json(&self) -> Value {
        let context = &self.context;
        let inbound = if !context.inbound.is_empty() {
            format!("{}/{}", context.inbound_type, context.inbound)
        } else {
            context.inbound_type.to_string()
        };
        let host = context.sniff_host.clone().or_else(|| context.destination.domain().map(str::to_string));
        let destination_ip = match &context.destination.host {
            Host::Ip(address) => address.to_string(),
            Host::Domain(_) => String::new(),
        };
        json!({
            "id": self.id,
            "metadata": {
                "network": context.network.as_str(),
                "type": inbound,
                "sourceIP": source_ip(&context.source),
                "destinationIP": destination_ip,
                "sourcePort": context.source.port().to_string(),
                "destinationPort": context.destination.port.to_string(),
                "host": host.unwrap_or_default(),
                "dnsMode": "normal",
                "processPath": "",
            },
            "upload": self.upload.load(Ordering::Relaxed),
            "download": self.download.load(Ordering::Relaxed),
            "start": crate::util::rfc3339_nano(self.created_at),
            "chains": self.chain,
            "rule": self.rule.clone().unwrap_or_else(|| "final".into()),
            "rulePayload": "",
        })
    }
}

/// A connection with no inbound behind it has an unspecified source, which
/// sing-box leaves as the zero address (marshalled empty).
fn source_ip(source: &SocketAddr) -> String {
    if source.ip().is_unspecified() && source.port() == 0 {
        String::new()
    } else {
        source.ip().to_canonical().to_string()
    }
}

#[derive(Default)]
struct Closed {
    list: VecDeque<Arc<TrackerMetadata>>,
    upload_total: i64,
    download_total: i64,
}

/// Open connections by id, with their ids in insertion order for listing.
type Active = (Vec<String>, HashMap<String, Arc<TrackerMetadata>>);

#[derive(Default)]
struct Inner {
    connections: Mutex<Active>,
    closed: Mutex<Closed>,
}

/// The traffic manager, the router's connection tracker for the Clash API.
#[derive(Default, Clone)]
pub struct TrafficManager {
    inner: Arc<Inner>,
}

fn new_id() -> String {
    let mut bytes: [u8; 16] = rand::random();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32])
}

impl TrafficManager {
    pub fn new() -> Self {
        TrafficManager::default()
    }

    fn join(&self, routed: &RoutedConnection<'_>) -> Arc<TrackerMetadata> {
        let mut chain: Vec<String> = routed.chain.iter().map(|(tag, _)| tag.clone()).collect();
        chain.reverse();
        let (outbound, outbound_type) = routed.chain.last().cloned().unwrap_or_default();
        let metadata = Arc::new(TrackerMetadata {
            id: new_id(),
            context: routed.context.clone(),
            created_at: SystemTime::now(),
            upload: AtomicI64::new(0),
            download: AtomicI64::new(0),
            chain,
            rule: routed.rule.clone(),
            outbound,
            outbound_type,
            interrupt: routed.interrupt.clone(),
        });
        let mut connections = self.inner.connections.lock().unwrap();
        connections.0.push(metadata.id.clone());
        connections.1.insert(metadata.id.clone(), metadata.clone());
        metadata
    }

    fn leave(inner: &Inner, metadata: &Arc<TrackerMetadata>) {
        let mut closed = inner.closed.lock().unwrap();
        {
            let mut connections = inner.connections.lock().unwrap();
            if connections.1.remove(&metadata.id).is_none() {
                return;
            }
            connections.0.retain(|id| *id != metadata.id);
        }
        if closed.list.len() >= CLOSED_LIMIT {
            if let Some(evicted) = closed.list.pop_front() {
                closed.upload_total += evicted.upload.load(Ordering::Relaxed);
                closed.download_total += evicted.download.load(Ordering::Relaxed);
            }
        }
        closed.list.push_back(metadata.clone());
    }

    /// `Total`: uploaded and downloaded bytes of all connections, closed
    /// ones included.
    pub fn total(&self) -> (i64, i64) {
        let closed = self.inner.closed.lock().unwrap();
        let mut upload = closed.upload_total;
        let mut download = closed.download_total;
        for metadata in &closed.list {
            upload += metadata.upload.load(Ordering::Relaxed);
            download += metadata.download.load(Ordering::Relaxed);
        }
        for metadata in self.inner.connections.lock().unwrap().1.values() {
            upload += metadata.upload.load(Ordering::Relaxed);
            download += metadata.download.load(Ordering::Relaxed);
        }
        (upload, download)
    }

    /// The open connections, oldest first.
    pub fn connections(&self) -> Vec<Arc<TrackerMetadata>> {
        let connections = self.inner.connections.lock().unwrap();
        connections.0.iter().filter_map(|id| connections.1.get(id).cloned()).collect()
    }

    pub fn connection(&self, id: &str) -> Option<Arc<TrackerMetadata>> {
        self.inner.connections.lock().unwrap().1.get(id).cloned()
    }

    pub fn close_all(&self) {
        for metadata in self.connections() {
            metadata.close();
        }
    }
}

/// Removes the connection from the manager when the wrapper is dropped.
struct Leave {
    inner: Weak<Inner>,
    metadata: Arc<TrackerMetadata>,
}

impl Drop for Leave {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.upgrade() {
            TrafficManager::leave(&inner, &self.metadata);
        }
    }
}

struct CountedStream {
    inner: BoxStream,
    leave: Leave,
}

impl AsyncRead for CountedStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        let read = buf.filled().len() - before;
        if read > 0 {
            self.leave.metadata.upload.fetch_add(read as i64, Ordering::Relaxed);
        }
        result
    }
}

impl AsyncWrite for CountedStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(written)) = &result {
            self.leave.metadata.download.fetch_add(*written as i64, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct CountedPacketConn {
    inner: SharedPacketConn,
    _leave: Mutex<Leave>,
    metadata: Arc<TrackerMetadata>,
}

#[async_trait]
impl PacketConn for CountedPacketConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let (read, address) = self.inner.read_packet(buffer).await?;
        self.metadata.upload.fetch_add(read as i64, Ordering::Relaxed);
        Ok((read, address))
    }

    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        self.inner.write_packet(data, address).await?;
        self.metadata.download.fetch_add(data.len() as i64, Ordering::Relaxed);
        Ok(())
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.inner.peer_addr()
    }
}

impl ConnectionTracker for TrafficManager {
    fn routed_connection(&self, routed: &RoutedConnection<'_>, stream: BoxStream) -> BoxStream {
        let metadata = self.join(routed);
        Box::new(CountedStream { inner: stream, leave: Leave { inner: Arc::downgrade(&self.inner), metadata } })
    }

    fn routed_packet_connection(&self, routed: &RoutedConnection<'_>, conn: SharedPacketConn) -> SharedPacketConn {
        let metadata = self.join(routed);
        Arc::new(CountedPacketConn {
            inner: conn,
            _leave: Mutex::new(Leave { inner: Arc::downgrade(&self.inner), metadata: metadata.clone() }),
            metadata,
        })
    }
}
