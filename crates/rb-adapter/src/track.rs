//! Outbound groups and connection tracking: sing-box `adapter.OutboundGroup`,
//! `adapter.ConnectionTracker` and `common/interrupt`.
//!
//! A routed connection that goes through a group, or that a tracker
//! watches, carries an [`Interrupt`]: closing it makes the connection's
//! client side fail its pending and later reads and writes, which ends the
//! relay (sing-box closes the connection instead).

use std::any::Any;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{BoxStream, InboundContext, Network, Outbound, PacketConn, SharedPacketConn, Socksaddr};

/// Closes one routed connection from outside (a group changing its
/// selection, `DELETE /connections/{id}`).
#[derive(Debug, Default)]
pub struct Interrupt {
    closed: AtomicBool,
    /// Whether the connection came from an inbound (sing-box
    /// `interrupt.IsExternalConnectionFromContext`), not from rust-box itself.
    pub external: bool,
    wakers: Mutex<Vec<Waker>>,
    notify: tokio::sync::Notify,
}

impl Interrupt {
    pub fn new(external: bool) -> Arc<Self> {
        Arc::new(Interrupt { external, ..Default::default() })
    }

    pub fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        for waker in self.wakers.lock().unwrap().drain(..) {
            waker.wake();
        }
        self.notify.notify_waiters();
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Resolves once the connection is closed.
    pub async fn closed(&self) {
        loop {
            let notified = self.notify.notified();
            if self.is_closed() {
                return;
            }
            notified.await;
        }
    }

    fn register(&self, waker: &Waker) {
        let mut wakers = self.wakers.lock().unwrap();
        if !wakers.iter().any(|known| known.will_wake(waker)) {
            wakers.push(waker.clone());
        }
    }

    fn check(&self, cx: &Context<'_>) -> Result<(), io::Error> {
        self.register(cx.waker());
        if self.is_closed() {
            Err(io::Error::new(io::ErrorKind::ConnectionAborted, "connection interrupted"))
        } else {
            Ok(())
        }
    }
}

/// A stream that fails once its [`Interrupt`] closes.
pub struct InterruptStream {
    inner: BoxStream,
    interrupt: Arc<Interrupt>,
}

impl InterruptStream {
    pub fn new(inner: BoxStream, interrupt: Arc<Interrupt>) -> Self {
        InterruptStream { inner, interrupt }
    }
}

impl AsyncRead for InterruptStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.interrupt.check(cx)?;
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for InterruptStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        self.interrupt.check(cx)?;
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.interrupt.check(cx)?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A packet connection that fails once its [`Interrupt`] closes.
pub struct InterruptPacketConn {
    inner: SharedPacketConn,
    interrupt: Arc<Interrupt>,
}

impl InterruptPacketConn {
    pub fn new(inner: SharedPacketConn, interrupt: Arc<Interrupt>) -> Self {
        InterruptPacketConn { inner, interrupt }
    }

    fn error() -> io::Error {
        io::Error::new(io::ErrorKind::ConnectionAborted, "connection interrupted")
    }
}

#[async_trait]
impl PacketConn for InterruptPacketConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        if self.interrupt.is_closed() {
            return Err(Self::error());
        }
        tokio::select! {
            result = self.inner.read_packet(buffer) => result,
            _ = self.interrupt.closed() => Err(Self::error()),
        }
    }

    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        if self.interrupt.is_closed() {
            return Err(Self::error());
        }
        self.inner.write_packet(data, address).await
    }

    fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.peer_addr()
    }
}

/// Keeps a connection attached to a group until dropped.
pub type Attachment = Box<dyn Any + Send>;

/// An outbound that picks one of its members (sing-box
/// `adapter.OutboundGroup`).
pub trait OutboundGroup: Send + Sync {
    /// The member tags, in configuration order.
    fn all(&self) -> Vec<String>;
    /// The member a connection of `network` goes through now.
    fn selected(&self, network: Network) -> Option<Arc<dyn Outbound>>;
    /// Attaches a routed connection so a selection change can interrupt it
    /// (`AttachConnection`); it stays attached until the returned value is
    /// dropped.
    fn attach(&self, interrupt: Arc<Interrupt>) -> Attachment;
    /// Whether this is a URL test group (`adapter.URLTestGroup`).
    fn is_url_test(&self) -> bool {
        false
    }
    /// The concrete group, for what only the Clash API does with it.
    fn as_any(&self) -> &dyn Any;
}

/// The route of one connection as the trackers see it (the parts of
/// sing-box `RoutedConnection`'s arguments they read).
pub struct RoutedConnection<'a> {
    pub context: &'a InboundContext,
    /// The matched rule and its action (`rule => action`), or `None` for
    /// the final outbound.
    pub rule: Option<String>,
    /// The outbound the rule chose, then each group's selection: `(tag,
    /// type)` (sing-box `metadata.OutboundChain`).
    pub chain: Vec<(String, &'static str)>,
    pub interrupt: Arc<Interrupt>,
}

/// Watches routed connections (sing-box `adapter.ConnectionTracker`).
pub trait ConnectionTracker: Send + Sync {
    fn routed_connection(&self, routed: &RoutedConnection<'_>, stream: BoxStream) -> BoxStream;
    fn routed_packet_connection(&self, routed: &RoutedConnection<'_>, conn: SharedPacketConn) -> SharedPacketConn;
}

/// One URL test result (sing-box `adapter.URLTestHistory`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UrlTestHistory {
    pub time: std::time::SystemTime,
    /// Milliseconds.
    pub delay: u16,
}

/// The latest URL test result of each outbound (sing-box
/// `urltest.HistoryStorage`), shared by the groups, the router and the
/// Clash API.
#[derive(Debug, Default)]
pub struct HistoryStorage {
    history: Mutex<std::collections::HashMap<String, UrlTestHistory>>,
}

impl HistoryStorage {
    pub fn new() -> Arc<Self> {
        Arc::new(HistoryStorage::default())
    }

    pub fn load(&self, tag: &str) -> Option<UrlTestHistory> {
        self.history.lock().unwrap().get(tag).copied()
    }

    pub fn store(&self, tag: &str, history: UrlTestHistory) {
        self.history.lock().unwrap().insert(tag.to_string(), history);
    }

    pub fn delete(&self, tag: &str) {
        self.history.lock().unwrap().remove(tag);
    }
}

/// `group.RealTag`: the outbound a group resolves to for `network`, through
/// nested groups (empty when a group has no member for it).
pub fn real_tag(outbound: &Arc<dyn Outbound>, network: Network) -> String {
    let mut current = outbound.clone();
    for _ in 0..64 {
        let next = match current.group() {
            None => return current.tag().to_string(),
            Some(group) => group.selected(network),
        };
        match next {
            Some(next) => current = next,
            None => return String::new(),
        }
    }
    String::new()
}
