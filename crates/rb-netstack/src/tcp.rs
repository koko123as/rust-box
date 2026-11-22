//! A TCP connection accepted by the stack, as an async byte stream.
//!
//! The stack task owns the smoltcp socket; this side and the stack share a
//! small state with two bounded byte queues. The stack moves bytes between
//! the queues and the socket and wakes this side; this side wakes the stack
//! through a [`Notify`].

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

/// How many bytes each direction queues outside the socket buffers.
pub(crate) const QUEUE_LIMIT: usize = 64 * 1024;

#[derive(Default)]
pub(crate) struct State {
    /// Received from the client, not yet read by the application.
    pub rx: VecDeque<u8>,
    /// The client finished sending (FIN), or the connection is gone.
    pub rx_closed: bool,
    /// Written by the application, not yet in the socket.
    pub tx: VecDeque<u8>,
    /// The application shut down its write side.
    pub tx_shutdown: bool,
    /// The application dropped its handle.
    pub dropped: bool,
    /// The connection was reset or timed out.
    pub reset: bool,
    pub read_waker: Option<Waker>,
    pub write_waker: Option<Waker>,
}

pub(crate) struct Shared {
    pub state: Mutex<State>,
    pub stack: Arc<Notify>,
}

impl Shared {
    pub fn new(stack: Arc<Notify>) -> Arc<Self> {
        Arc::new(Shared { state: Mutex::new(State::default()), stack })
    }
}

/// A TCP connection from a client behind the TUN interface. Reading gives
/// what the client sent, writing sends to the client; dropping it closes
/// the connection after the written data is sent.
pub struct TcpConn {
    shared: Arc<Shared>,
    source: SocketAddr,
    destination: SocketAddr,
}

impl TcpConn {
    pub(crate) fn new(shared: Arc<Shared>, source: SocketAddr, destination: SocketAddr) -> Self {
        TcpConn { shared, source, destination }
    }

    /// The client's address.
    pub fn source(&self) -> SocketAddr {
        self.source
    }

    /// The address the client connected to.
    pub fn destination(&self) -> SocketAddr {
        self.destination
    }
}

impl AsyncRead for TcpConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut state = self.shared.state.lock().unwrap();
        if !state.rx.is_empty() {
            let was_full = state.rx.len() >= QUEUE_LIMIT;
            let count = buf.remaining().min(state.rx.len());
            let (front, back) = state.rx.as_slices();
            let first = count.min(front.len());
            buf.put_slice(&front[..first]);
            if count > first {
                buf.put_slice(&back[..count - first]);
            }
            state.rx.drain(..count);
            drop(state);
            if was_full {
                self.shared.stack.notify_one();
            }
            return Poll::Ready(Ok(()));
        }
        if state.reset {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        if state.rx_closed {
            return Poll::Ready(Ok(()));
        }
        state.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for TcpConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let mut state = self.shared.state.lock().unwrap();
        if state.reset {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        if state.tx_shutdown {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let space = QUEUE_LIMIT.saturating_sub(state.tx.len());
        if space == 0 {
            state.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let count = space.min(data.len());
        state.tx.extend(&data[..count]);
        drop(state);
        self.shared.stack.notify_one();
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.shared.state.lock().unwrap();
        if state.tx.is_empty() || state.reset {
            return Poll::Ready(Ok(()));
        }
        state.write_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shared.state.lock().unwrap().tx_shutdown = true;
        self.shared.stack.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpConn {
    fn drop(&mut self) {
        self.shared.state.lock().unwrap().dropped = true;
        self.shared.stack.notify_one();
    }
}
