//! sing-box `common/interrupt.Group`: the connections attached to a group,
//! closed together when its selection changes.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};

use async_trait::async_trait;
use rb_adapter::{
    Attachment, BoxStream, Interrupt, InterruptPacketConn, InterruptStream, PacketConn, SharedPacketConn, Socksaddr,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
struct Entries {
    next: u64,
    list: Vec<(u64, Weak<Interrupt>)>,
}

/// The attached connections of one group.
#[derive(Default, Clone)]
pub struct InterruptGroup {
    entries: Arc<Mutex<Entries>>,
}

struct Detach {
    entries: Weak<Mutex<Entries>>,
    id: u64,
}

impl Drop for Detach {
    fn drop(&mut self) {
        if let Some(entries) = self.entries.upgrade() {
            entries.lock().unwrap().list.retain(|(id, _)| *id != self.id);
        }
    }
}

impl InterruptGroup {
    pub fn new() -> Self {
        InterruptGroup::default()
    }

    /// Attaches a connection until the returned value is dropped
    /// (`Group.Add`).
    pub fn add(&self, interrupt: &Arc<Interrupt>) -> Attachment {
        let mut entries = self.entries.lock().unwrap();
        entries.next += 1;
        let id = entries.next;
        entries.list.push((id, Arc::downgrade(interrupt)));
        Box::new(Detach { entries: Arc::downgrade(&self.entries), id })
    }

    /// Closes the attached connections rust-box opened itself, and those
    /// from inbounds too when `interrupt_external` (`Group.Interrupt`).
    pub fn interrupt(&self, interrupt_external: bool) {
        let mut entries = self.entries.lock().unwrap();
        entries.list.retain(|(_, interrupt)| {
            let Some(interrupt) = interrupt.upgrade() else { return false };
            if interrupt.external && !interrupt_external {
                return true;
            }
            interrupt.close();
            false
        });
    }

    /// The number of attached connections still open.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().list.iter().filter(|(_, interrupt)| interrupt.strong_count() > 0).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A stream a group opened itself (as some outbound's detour), which a
    /// selection change closes (`Group.NewConn` with an internal context).
    pub fn wrap_stream(&self, stream: BoxStream) -> BoxStream {
        let interrupt = Interrupt::new(false);
        let attachment = self.add(&interrupt);
        Box::new(AttachedStream { inner: InterruptStream::new(stream, interrupt), _attachment: attachment })
    }

    /// The packet connection counterpart of [`InterruptGroup::wrap_stream`].
    pub fn wrap_packet_conn(&self, conn: SharedPacketConn) -> SharedPacketConn {
        let interrupt = Interrupt::new(false);
        let attachment = self.add(&interrupt);
        Arc::new(AttachedPacketConn {
            inner: InterruptPacketConn::new(conn, interrupt),
            _attachment: Mutex::new(attachment),
        })
    }
}

struct AttachedStream {
    inner: InterruptStream,
    _attachment: Attachment,
}

impl AsyncRead for AttachedStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for AttachedStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct AttachedPacketConn {
    inner: InterruptPacketConn,
    /// `Mutex` only to make the attachment `Sync`.
    _attachment: Mutex<Attachment>,
}

#[async_trait]
impl PacketConn for AttachedPacketConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        self.inner.read_packet(buffer).await
    }

    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        self.inner.write_packet(data, address).await
    }

    fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.peer_addr()
    }
}
