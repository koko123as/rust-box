//! h2mux (sing-mux `h2mux.go`): each stream is an HTTP/2 CONNECT request
//! to `localhost` whose request and response bodies carry the data.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use bytes::Bytes;
use h2::client::ResponseFuture;
use h2::{RecvStream, SendStream};
use rb_adapter::BoxStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

/// `MaxReadFrameSize: buf.BufferSize`.
const MAX_FRAME_SIZE: u32 = 32 * 1024;

fn h2_error(error: h2::Error) -> io::Error {
    if error.is_io() {
        error.into_io().unwrap_or_else(|| io::Error::other("http2: io error"))
    } else {
        io::Error::other(error.to_string())
    }
}

/// One h2mux stream.
pub struct H2Stream {
    response: Option<ResponseFuture>,
    send: SendStream<Bytes>,
    recv: Option<RecvStream>,
    buffered: Bytes,
    /// Whether the end of the stream was sent.
    ended: bool,
}

impl AsyncRead for H2Stream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if let Some(response) = &mut this.response {
            let response = ready!(Pin::new(response).poll(cx)).map_err(h2_error)?;
            this.response = None;
            let status = response.status();
            if status != http::StatusCode::OK {
                return Poll::Ready(Err(io::Error::other(format!(
                    "unexpected status: {} {}",
                    status.as_u16(),
                    status
                ))));
            }
            this.recv = Some(response.into_body());
        }
        loop {
            if !this.buffered.is_empty() {
                let count = this.buffered.len().min(buf.remaining());
                buf.put_slice(&this.buffered.split_to(count));
                return Poll::Ready(Ok(()));
            }
            let Some(recv) = &mut this.recv else { return Poll::Ready(Ok(())) };
            match ready!(recv.poll_data(cx)) {
                Some(Ok(data)) => {
                    let _ = recv.flow_control().release_capacity(data.len());
                    this.buffered = data;
                }
                Some(Err(error)) => {
                    if error.reason() == Some(h2::Reason::NO_ERROR) {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(h2_error(error)));
                }
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let send = &mut self.send;
        send.reserve_capacity(data.len());
        let capacity = match ready!(send.poll_capacity(cx)) {
            Some(Ok(capacity)) => capacity,
            Some(Err(error)) => return Poll::Ready(Err(h2_error(error))),
            None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        };
        let count = capacity.min(data.len());
        send.send_data(Bytes::copy_from_slice(&data[..count]), false).map_err(h2_error)?;
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.ended {
            self.ended = true;
            let _ = self.send.send_data(Bytes::new(), true);
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for H2Stream {
    /// Closing ends the body, as Go's pipe `Close` does; h2 resets the
    /// stream once every handle is gone and the queued data went out.
    fn drop(&mut self) {
        if !self.ended {
            let _ = self.send.send_data(Bytes::new(), true);
        }
    }
}

/// The client side of an h2mux session.
pub struct H2Client {
    send_request: tokio::sync::Mutex<h2::client::SendRequest<Bytes>>,
    closed: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for H2Client {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl H2Client {
    pub async fn new(conn: BoxStream) -> io::Result<Self> {
        let (send_request, connection) = h2::client::Builder::new()
            .max_frame_size(MAX_FRAME_SIZE)
            .handshake::<_, Bytes>(conn)
            .await
            .map_err(h2_error)?;
        let closed = Arc::new(AtomicBool::new(false));
        let flag = closed.clone();
        let task = tokio::spawn(async move {
            let _ = connection.await;
            flag.store(true, Ordering::SeqCst);
        });
        Ok(H2Client { send_request: tokio::sync::Mutex::new(send_request), closed, task })
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.task.abort();
    }

    /// A CONNECT request to `localhost` (Go's http2 sends `:method` and
    /// `:authority` only); the response is read before the first data.
    pub async fn open(&self) -> io::Result<H2Stream> {
        let mut send_request = self.send_request.lock().await.clone();
        send_request = send_request.ready().await.map_err(h2_error)?;
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("localhost")
            .body(())
            .map_err(io::Error::other)?;
        let (response, send) = send_request.send_request(request, false).map_err(h2_error)?;
        Ok(H2Stream { response: Some(response), send, recv: None, buffered: Bytes::new(), ended: false })
    }
}

/// The server side of an h2mux session: each request becomes a stream
/// with a 200 response.
pub struct H2Server {
    accept: tokio::sync::Mutex<mpsc::Receiver<H2Stream>>,
    closed: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for H2Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl H2Server {
    pub fn new(conn: BoxStream) -> Self {
        let (streams, accept) = mpsc::channel(16);
        let closed = Arc::new(AtomicBool::new(false));
        let flag = closed.clone();
        let task = tokio::spawn(async move {
            let mut connection = match h2::server::Builder::new().max_frame_size(MAX_FRAME_SIZE).handshake(conn).await {
                Ok(connection) => connection,
                Err(_) => {
                    flag.store(true, Ordering::SeqCst);
                    return;
                }
            };
            while let Some(Ok((request, mut respond))) = connection.accept().await {
                let response = http::Response::builder().status(http::StatusCode::OK).body(()).unwrap();
                let Ok(send) = respond.send_response(response, false) else { continue };
                let stream = H2Stream {
                    response: None,
                    send,
                    recv: Some(request.into_body()),
                    buffered: Bytes::new(),
                    ended: false,
                };
                if streams.send(stream).await.is_err() {
                    break;
                }
            }
            flag.store(true, Ordering::SeqCst);
        });
        H2Server { accept: tokio::sync::Mutex::new(accept), closed, task }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    pub async fn accept(&self) -> io::Result<H2Stream> {
        self.accept
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "use of closed network connection"))
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.task.abort();
    }
}
