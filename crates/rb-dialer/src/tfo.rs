//! TCP Fast Open for outgoing connections (sing-box
//! `common/dialer/tfo.go` with tfo-go).
//!
//! As in sing-box, the connection is opened lazily: nothing is sent until
//! the first write, whose data goes out in the SYN (`sendto` with
//! `MSG_FASTOPEN`). Reads wait for that first write. A kernel that refuses
//! Fast Open gets an ordinary connect.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

type ConnectFuture = Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>>;

enum State {
    /// Not connected yet: the first write opens the connection.
    Pending {
        socket: Option<socket2::Socket>,
        read_waker: Option<Waker>,
    },
    /// A plain connect after Fast Open was refused, then the data is written.
    Connecting {
        future: ConnectFuture,
        read_waker: Option<Waker>,
    },
    Connected(TcpStream),
    Closed,
}

pub struct TfoStream {
    address: SocketAddr,
    connect_timeout: Duration,
    state: State,
}

impl TfoStream {
    /// `socket` is configured (options, local address) and not connected.
    pub fn new(socket: socket2::Socket, address: SocketAddr, connect_timeout: Duration) -> Self {
        TfoStream { address, connect_timeout, state: State::Pending { socket: Some(socket), read_waker: None } }
    }

    /// The connected stream, once the first write has opened it.
    pub fn stream(&self) -> Option<&TcpStream> {
        match &self.state {
            State::Connected(stream) => Some(stream),
            _ => None,
        }
    }

    fn wake_reader(waker: Option<Waker>) {
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// `sendto(MSG_FASTOPEN)`: `Ok(Some(n))` when `n` bytes went out with the
/// SYN, `Ok(None)` when the SYN went out without them (no cookie yet),
/// `Err` when Fast Open is refused.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn send_fast_open(socket: &socket2::Socket, address: SocketAddr, data: &[u8]) -> io::Result<Option<usize>> {
    use std::os::fd::AsRawFd;
    let address = socket2::SockAddr::from(address);
    // SAFETY: a valid buffer and socket address with their lengths.
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            data.as_ptr() as *const libc::c_void,
            data.len(),
            libc::MSG_FASTOPEN | libc::MSG_NOSIGNAL,
            address.as_ptr() as *const libc::sockaddr,
            address.len(),
        )
    };
    if sent >= 0 {
        return Ok(Some(sent as usize));
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::EINPROGRESS) | Some(libc::EAGAIN) => Ok(None),
        _ => Err(error),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn send_fast_open(_socket: &socket2::Socket, _address: SocketAddr, _data: &[u8]) -> io::Result<Option<usize>> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "TCP Fast Open is not supported by rust-box on this platform"))
}

impl AsyncWrite for TfoStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            let address = self.address;
            let connect_timeout = self.connect_timeout;
            match &mut self.state {
                State::Pending { socket, read_waker } => {
                    if data.is_empty() {
                        return Poll::Ready(Ok(0));
                    }
                    let socket = socket.take().expect("pending socket");
                    let read_waker = read_waker.take();
                    match send_fast_open(&socket, address, data) {
                        Ok(sent) => {
                            let stream = TcpStream::from_std(std::net::TcpStream::from(socket))?;
                            let _ = stream.set_nodelay(true);
                            self.state = State::Connected(stream);
                            Self::wake_reader(read_waker);
                            if let Some(sent) = sent {
                                return Poll::Ready(Ok(sent));
                            }
                            // The SYN went without data: write once connected.
                        }
                        Err(error) => {
                            tracing::debug!(%address, %error, "TCP Fast Open refused, connecting normally");
                            let socket = tokio::net::TcpSocket::from_std_stream(std::net::TcpStream::from(socket));
                            let future: ConnectFuture = Box::pin(async move {
                                let stream = tokio::time::timeout(connect_timeout, socket.connect(address))
                                    .await
                                    .map_err(|_| {
                                        io::Error::new(io::ErrorKind::TimedOut, format!("{address}: connect timed out"))
                                    })??;
                                let _ = stream.set_nodelay(true);
                                Ok(stream)
                            });
                            self.state = State::Connecting { future, read_waker };
                        }
                    }
                }
                State::Connecting { future, read_waker } => match future.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(stream)) => {
                        let read_waker = read_waker.take();
                        self.state = State::Connected(stream);
                        Self::wake_reader(read_waker);
                    }
                    Poll::Ready(Err(error)) => {
                        let read_waker = read_waker.take();
                        self.state = State::Closed;
                        Self::wake_reader(read_waker);
                        return Poll::Ready(Err(error));
                    }
                },
                State::Connected(stream) => return Pin::new(stream).poll_write(cx, data),
                State::Closed => return Poll::Ready(Err(io::Error::from(io::ErrorKind::NotConnected))),
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.state {
            State::Connected(stream) => Pin::new(stream).poll_flush(cx),
            _ => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.state {
            State::Connected(stream) => Pin::new(stream).poll_shutdown(cx),
            State::Pending { read_waker, .. } | State::Connecting { read_waker, .. } => {
                // Nothing was sent: there is no connection to shut down.
                let read_waker = read_waker.take();
                self.state = State::Closed;
                Self::wake_reader(read_waker);
                Poll::Ready(Ok(()))
            }
            State::Closed => Poll::Ready(Ok(())),
        }
    }
}

impl AsyncRead for TfoStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match &mut self.state {
            State::Connected(stream) => Pin::new(stream).poll_read(cx, buf),
            State::Pending { read_waker, .. } | State::Connecting { read_waker, .. } => {
                *read_waker = Some(cx.waker().clone());
                Poll::Pending
            }
            State::Closed => Poll::Ready(Err(io::Error::from(io::ErrorKind::NotConnected))),
        }
    }
}
