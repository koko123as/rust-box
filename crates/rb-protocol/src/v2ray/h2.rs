//! HTTP/2 stream sessions over an already-established byte stream (TLS or h2c).
use std::future::{poll_fn, Future};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use bytes::Bytes;
use h2::{RecvStream, SendStream};
use http::{Request, Response, StatusCode};
use rb_adapter::BoxStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex};

const MAX_FRAME_SIZE: u32 = 32 * 1024;
type PendingResponse = Pin<Box<dyn Future<Output = Result<Response<RecvStream>, h2::Error>> + Send>>;

struct ConnectionDriver(tokio::task::JoinHandle<()>);

impl Drop for ConnectionDriver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct H2IncomingRaw {
    request: Request<()>,
    responder: h2::server::SendResponse<Bytes>,
    recv: RecvStream,
}

fn h2_error(error: h2::Error) -> io::Error {
    if error.is_io() {
        error.into_io().unwrap_or_else(|| io::Error::other("HTTP/2 I/O error"))
    } else {
        io::Error::other(error.to_string())
    }
}

/// A bidirectional HTTP/2 DATA body exposed as an ordinary byte stream.
pub struct H2Stream {
    send: SendStream<Bytes>,
    recv: Option<RecvStream>,
    response: Option<PendingResponse>,
    expected_status: Option<StatusCode>,
    buffered: Bytes,
    ended: bool,
    read_finished: bool,
    _driver: Arc<ConnectionDriver>,
}

impl AsyncRead for H2Stream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.read_finished {
            return Poll::Ready(Ok(()));
        }
        if this.recv.is_none() {
            let result = ready!(this.response.as_mut().expect("pending H2 response").as_mut().poll(cx));
            this.response = None;
            let response = match result {
                Ok(response) => response,
                Err(error) => {
                    this.read_finished = true;
                    return Poll::Ready(Err(h2_error(error)));
                }
            };
            if let Some(expected) = this.expected_status.take() {
                if response.status() != expected {
                    let status = response.status();
                    this.read_finished = true;
                    return Poll::Ready(Err(io::Error::other(format!(
                        "HTTP/2 server returned unexpected status {status}"
                    ))));
                }
            }
            this.recv = Some(response.into_body());
        }
        loop {
            if !this.buffered.is_empty() {
                let n = this.buffered.len().min(buf.remaining());
                buf.put_slice(&this.buffered.split_to(n));
                return Poll::Ready(Ok(()));
            }
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            match ready!(this.recv.as_mut().expect("H2 response body").poll_data(cx)) {
                Some(Ok(data)) => {
                    if let Err(error) =
                        this.recv.as_mut().expect("H2 response body").flow_control().release_capacity(data.len())
                    {
                        return Poll::Ready(Err(h2_error(error)));
                    }
                    this.buffered = data;
                }
                Some(Err(error)) if error.reason() == Some(h2::Reason::NO_ERROR) => {
                    this.read_finished = true;
                    return Poll::Ready(Ok(()));
                }
                Some(Err(error)) => return Poll::Ready(Err(h2_error(error))),
                None => {
                    this.read_finished = true;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        if self.ended {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "HTTP/2 stream write side is closed")));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let send = &mut self.send;
        send.reserve_capacity(data.len());
        let capacity = match ready!(send.poll_capacity(cx)) {
            Some(Ok(capacity)) => capacity,
            Some(Err(error)) => return Poll::Ready(Err(h2_error(error))),
            None => return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "HTTP/2 stream closed"))),
        };
        if capacity == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let n = capacity.min(data.len());
        match send.send_data(Bytes::copy_from_slice(&data[..n]), false) {
            Ok(()) => Poll::Ready(Ok(n)),
            Err(error) => Poll::Ready(Err(h2_error(error))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.ended {
            self.send.send_data(Bytes::new(), true).map_err(h2_error)?;
            self.ended = true;
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for H2Stream {
    fn drop(&mut self) {
        if !self.ended {
            let _ = self.send.send_data(Bytes::new(), true);
        }
    }
}

/// Client session; each `open` sends an independent request on the same connection.
pub struct H2Client {
    sender: Arc<Mutex<h2::client::SendRequest<Bytes>>>,
    driver: Arc<ConnectionDriver>,
}

impl H2Client {
    /// Perform an H2 client handshake on an established TLS or cleartext stream.
    pub async fn new(stream: BoxStream) -> io::Result<Self> {
        let (sender, connection) = h2::client::Builder::new()
            .max_frame_size(MAX_FRAME_SIZE)
            .handshake::<_, Bytes>(stream)
            .await
            .map_err(h2_error)?;
        let task = tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Self { sender: Arc::new(Mutex::new(sender)), driver: Arc::new(ConnectionDriver(task)) })
    }

    /// Send a custom request and return its response body as a byte stream.
    pub async fn open(&self, request: Request<()>) -> io::Result<(Response<()>, H2Stream)> {
        let (response, send) = {
            let mut sender = self.sender.lock().await;
            poll_fn(|cx| Pin::new(&mut *sender).poll_ready(cx)).await.map_err(h2_error)?;
            sender.send_request(request, false).map_err(h2_error)?
        };
        let response = response.await.map_err(h2_error)?;
        let (parts, recv) = response.into_parts();
        Ok((
            Response::from_parts(parts, ()),
            H2Stream {
                send,
                recv: Some(recv),
                response: None,
                expected_status: None,
                buffered: Bytes::new(),
                ended: false,
                read_finished: false,
                _driver: self.driver.clone(),
            },
        ))
    }

    /// Submit request headers and return a bidirectional stream before its response headers arrive.
    /// This is required by streaming RPC servers that wait for request DATA before responding.
    pub async fn open_stream(&self, request: Request<()>) -> io::Result<H2Stream> {
        let (response, send) = {
            let mut sender = self.sender.lock().await;
            poll_fn(|cx| Pin::new(&mut *sender).poll_ready(cx)).await.map_err(h2_error)?;
            sender.send_request(request, false).map_err(h2_error)?
        };
        Ok(H2Stream {
            send,
            recv: None,
            response: Some(Box::pin(response)),
            expected_status: Some(StatusCode::OK),
            buffered: Bytes::new(),
            ended: false,
            read_finished: false,
            _driver: self.driver.clone(),
        })
    }
}

/// Metadata and response capability for an accepted request.
pub struct H2Incoming {
    /// Original request method, URI, headers and extensions, without the body.
    pub request: Request<()>,
    responder: h2::server::SendResponse<Bytes>,
    recv: RecvStream,
    driver: Arc<ConnectionDriver>,
}

impl H2Incoming {
    /// Send the chosen response headers/status and obtain the request body stream.
    pub fn respond(mut self, response: Response<()>) -> io::Result<H2Stream> {
        let (parts, ()) = response.into_parts();
        let response = Response::from_parts(parts, ());
        let send = self.responder.send_response(response, false).map_err(h2_error)?;
        Ok(H2Stream {
            send,
            recv: Some(self.recv),
            response: None,
            expected_status: None,
            buffered: Bytes::new(),
            ended: false,
            read_finished: false,
            _driver: self.driver,
        })
    }
}

/// Server session continuously accepting concurrent request streams.
pub struct H2Server {
    accepted: Mutex<mpsc::UnboundedReceiver<io::Result<H2IncomingRaw>>>,
    driver: Arc<ConnectionDriver>,
}

impl H2Server {
    /// Start the server-side H2 handshake and background accept loop.
    pub fn new(stream: BoxStream) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let mut connection = match h2::server::Builder::new().max_frame_size(MAX_FRAME_SIZE).handshake(stream).await
            {
                Ok(connection) => connection,
                Err(error) => {
                    let _ = tx.send(Err(h2_error(error)));
                    return;
                }
            };
            while let Some(result) = connection.accept().await {
                match result {
                    Ok((request, responder)) => {
                        let (parts, recv) = request.into_parts();
                        let request = Request::from_parts(parts, ());
                        let incoming = H2IncomingRaw { request, responder, recv };
                        if let Err(error) = tx.send(Ok(incoming)) {
                            if let Ok(mut incoming) = error.0 {
                                let response = Response::builder().status(503).body(()).expect("valid response");
                                let _ = incoming.responder.send_response(response, true);
                            }
                        }
                    }
                    Err(error) => {
                        let _ = tx.send(Err(h2_error(error)));
                        break;
                    }
                }
            }
        });
        Self { accepted: Mutex::new(rx), driver: Arc::new(ConnectionDriver(task)) }
    }

    /// Accept the next request stream; call `respond` to accept or reject it.
    pub async fn accept(&self) -> io::Result<Option<H2Incoming>> {
        let Some(result) = self.accepted.lock().await.recv().await else { return Ok(None) };
        result.map(|incoming| {
            Some(H2Incoming {
                request: incoming.request,
                responder: incoming.responder,
                recv: incoming.recv,
                driver: self.driver.clone(),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    // Exercise both directions and multiple simultaneous streams using an in-memory transport.
    #[tokio::test]
    async fn bidirectional_multiple_streams() {
        let (a, b) = duplex(1 << 20);
        let client_io: BoxStream = Box::new(a);
        let server_io: BoxStream = Box::new(b);
        let server = H2Server::new(server_io);
        let client = H2Client::new(client_io).await.unwrap();
        let server_task = tokio::spawn(async move {
            let mut workers = Vec::new();
            for _ in 0..2 {
                let incoming = server.accept().await.unwrap().unwrap();
                assert_eq!(incoming.request.uri().path(), "/echo");
                workers.push(tokio::spawn(async move {
                    let mut stream = incoming.respond(Response::builder().status(200).body(()).unwrap()).unwrap();
                    let mut body = Vec::new();
                    stream.read_to_end(&mut body).await.unwrap();
                    stream.write_all(&body).await.unwrap();
                    stream.shutdown().await.unwrap();
                }));
            }
            for worker in workers {
                worker.await.unwrap();
            }
        });
        let mut tasks = Vec::new();
        for payload in [b"first".as_slice(), b"second".as_slice()] {
            let request = Request::builder().method("POST").uri("/echo").header("x-test", "yes").body(()).unwrap();
            let (response, mut stream) = client.open(request).await.unwrap();
            assert_eq!(response.status(), 200);
            stream.write_all(payload).await.unwrap();
            stream.shutdown().await.unwrap();
            tasks.push(tokio::spawn(async move {
                let mut result = Vec::new();
                stream.read_to_end(&mut result).await.unwrap();
                result
            }));
        }
        for (task, expected) in tasks.into_iter().zip([b"first".as_slice(), b"second".as_slice()]) {
            assert_eq!(task.await.unwrap(), expected);
        }
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn client_stream_can_send_before_server_response_headers() {
        let (client_io, server_io) = duplex(1 << 20);
        let server = H2Server::new(Box::new(server_io));
        let client = H2Client::new(Box::new(client_io)).await.unwrap();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            let mut incoming = server.accept().await.unwrap().unwrap();
            assert_eq!(incoming.request.uri().path(), "/stream");
            let mut request_body = Vec::new();
            while let Some(result) = poll_fn(|cx| incoming.recv.poll_data(cx)).await {
                let data = result.unwrap();
                incoming.recv.flow_control().release_capacity(data.len()).unwrap();
                request_body.extend_from_slice(&data);
            }
            assert_eq!(request_body, b"request body");

            let response = Response::builder().status(StatusCode::OK).body(()).unwrap();
            let mut response_stream = incoming.respond(response).unwrap();
            response_stream.write_all(b"response body").await.unwrap();
            response_stream.shutdown().await.unwrap();
            finished_rx.await.unwrap();
        });

        let request = Request::builder().method("POST").uri("https://example.test/stream").body(()).unwrap();
        let mut stream = client.open_stream(request).await.unwrap();
        stream.write_all(b"request body").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response_body = Vec::new();
        stream.read_to_end(&mut response_body).await.unwrap();
        assert_eq!(response_body, b"response body");
        finished_tx.send(()).unwrap();
        server_task.await.unwrap();
    }
}
