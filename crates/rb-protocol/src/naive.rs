//! sing-box v1.14.4 Naive outbound over TLS + HTTP/2 CONNECT.

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use base64::Engine as _;
use bytes::Bytes;
use h2::client::{self, SendRequest};
use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Method, Request, StatusCode, Uri, Version};
use rand::Rng as _;
use rb_adapter::{BoxStream, InboundContext, Network, Outbound, Socksaddr};
use rb_config::NaiveOutbound as NaiveOutboundOptions;
use rb_dialer::{new_outbound_dialer, Dialer, DialerEnv};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::{watch, Mutex};

const PADDING_FRAMES: u8 = 8;
const MAX_PADDING_CHUNK: usize = u16::MAX as usize;
const DEFAULT_RECEIVE_WINDOW: u64 = 128 * 1024 * 1024;
const BRIDGE_BUFFER: usize = 64 * 1024;

struct SessionPool {
    session: Mutex<Option<Arc<H2Session>>>,
}

struct H2Session {
    sender: Mutex<SendRequest<Bytes>>,
    healthy: AtomicBool,
}

/// A Naive TCP outbound. Each pool entry owns one reusable HTTP/2 connection;
/// CONNECT tunnels within that entry are multiplexed as HTTP/2 streams.
pub struct NaiveOutbound {
    tag: String,
    server: Socksaddr,
    dialer: Arc<dyn Dialer>,
    tls: rb_tls::TlsClient,
    pools: Vec<SessionPool>,
    next_pool: AtomicUsize,
    headers: HeaderMap,
    receive_window: u32,
    stream_window: u32,
}

impl NaiveOutbound {
    pub fn new(
        options: &NaiveOutboundOptions,
        tag: String,
        env: &DialerEnv,
        certificates: &Arc<rb_certificate::Store>,
    ) -> Result<Self, String> {
        if options.server.is_empty() {
            return Err("server is required".into());
        }
        if options.server_port == 0 {
            return Err("server_port is required".into());
        }
        let server = Socksaddr::from_host_port(&options.server, options.server_port);
        let dialer = new_outbound_dialer(
            &options.dialer_options(),
            server.domain().is_some(),
            env,
            &format!("outbound/naive[{tag}]"),
        )?;
        let tls_options = options.tls.as_ref().ok_or_else(|| "TLS is required".to_string())?;
        let tls = rb_tls::TlsClient::new(tls_options, &options.server, certificates)?.with_alpn(&["h2"]);
        let pool_count = if options.insecure_concurrency == 0 {
            1
        } else {
            usize::try_from(options.insecure_concurrency)
                .map_err(|_| "insecure_concurrency must not be negative".to_string())?
        };
        let mut pools = Vec::new();
        pools.try_reserve_exact(pool_count).map_err(|error| format!("insecure_concurrency: {error}"))?;
        pools.extend((0..pool_count).map(|_| SessionPool { session: Mutex::new(None) }));

        let mut headers = HeaderMap::new();
        if !options.username.is_empty() {
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", options.username, options.password));
            let value = HeaderValue::from_str(&format!("Basic {encoded}"))
                .map_err(|error| format!("username/password: invalid proxy authorization: {error}"))?;
            headers.insert(http::header::PROXY_AUTHORIZATION, value);
        }
        if let Some(extra_headers) = &options.extra_headers {
            for (name, values) in extra_headers {
                let Some(value) = values.0.first() else { continue };
                let name = HeaderName::from_bytes(name.as_bytes())
                    .map_err(|error| format!("extra_headers.{name}: invalid header name: {error}"))?;
                let value = HeaderValue::from_str(value)
                    .map_err(|error| format!("extra_headers.{name}: invalid header value: {error}"))?;
                headers.insert(name, value);
            }
        }

        let receive_window = options.stream_receive_window.map_or(DEFAULT_RECEIVE_WINDOW, |window| window.0);
        if receive_window < 2 || receive_window > i32::MAX as u64 {
            return Err("stream_receive_window must be between 2 bytes and 2147483647 bytes".into());
        }
        Ok(NaiveOutbound {
            tag,
            server,
            dialer,
            tls,
            pools,
            next_pool: AtomicUsize::new(0),
            headers,
            receive_window: receive_window as u32,
            stream_window: (receive_window / 2) as u32,
        })
    }

    async fn session(&self, index: usize) -> io::Result<Arc<H2Session>> {
        let pool = &self.pools[index];
        let mut slot = pool.session.lock().await;
        if let Some(session) = slot.as_ref().filter(|session| session.healthy.load(Ordering::Acquire)) {
            return Ok(session.clone());
        }

        let stream = self.dialer.dial_tcp(&self.server).await?;
        let tls = self.tls.handshake(stream).await?;
        if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "naive: server did not negotiate HTTP/2"));
        }
        let mut builder = client::Builder::new();
        builder.initial_connection_window_size(self.receive_window);
        builder.initial_window_size(self.stream_window);
        let (sender, connection) = builder
            .handshake(tls)
            .await
            .map_err(|error| io::Error::other(format!("naive: HTTP/2 handshake: {error}")))?;
        let session = Arc::new(H2Session { sender: Mutex::new(sender), healthy: AtomicBool::new(true) });
        let weak = Arc::downgrade(&session);
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!("Naive HTTP/2 connection closed: {error}");
            }
            if let Some(session) = weak.upgrade() {
                session.healthy.store(false, Ordering::Release);
            }
        });
        *slot = Some(session.clone());
        Ok(session)
    }

    fn request(&self, destination: &Socksaddr) -> io::Result<Request<()>> {
        let authority: http::uri::Authority = destination.to_string().parse().map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("naive: invalid CONNECT authority: {error}"))
        })?;
        let uri = Uri::builder()
            .authority(authority)
            .build()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, format!("naive: CONNECT URI: {error}")))?;
        let mut headers = HeaderMap::new();
        let padding = padding_header();
        headers.insert(
            http::header::HeaderName::from_static("padding"),
            HeaderValue::from_str(&padding).expect("padding header is valid ASCII"),
        );
        for (name, value) in &self.headers {
            headers.insert(name, value.clone());
        }
        let mut builder = Request::builder().method(Method::CONNECT).version(Version::HTTP_2).uri(uri);
        *builder.headers_mut().expect("request builder has headers") = headers;
        builder
            .body(())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, format!("naive: request: {error}")))
    }
}

#[async_trait]
impl Outbound for NaiveOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "naive"
    }

    fn networks(&self) -> &[Network] {
        &[Network::Tcp]
    }

    async fn dial_tcp(&self, context: &InboundContext) -> io::Result<BoxStream> {
        let index = self.next_pool.fetch_add(1, Ordering::Relaxed) % self.pools.len();
        let session = self.session(index).await?;
        let request = self.request(&context.destination)?;
        let (response, send_stream) = {
            let mut sender = session.sender.lock().await;
            poll_fn(|cx| sender.poll_ready(cx))
                .await
                .map_err(|error| io::Error::other(format!("naive: HTTP/2 request: {error}")))?;
            sender
                .send_request(request, false)
                .map_err(|error| io::Error::other(format!("naive: HTTP/2 CONNECT: {error}")))?
        };
        let response = response.await.map_err(|error| io::Error::other(format!("naive: CONNECT response: {error}")))?;
        if response.status() != StatusCode::OK {
            let kind = if response.status() == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                io::ErrorKind::PermissionDenied
            } else {
                io::ErrorKind::ConnectionRefused
            };
            return Err(io::Error::new(kind, format!("naive: unexpected response status: {}", response.status())));
        }
        Ok(bridge_tunnel(send_stream, response.into_body()))
    }
}

fn padding_header() -> String {
    const CHARSET: &[u8] = b"!#$()+<>?@[]^`{}";
    let length = rand::rng().random_range(30..62);
    let mut bits = rand::random::<u64>();
    let mut result = vec![b'~'; length];
    for byte in result.iter_mut().take(16) {
        *byte = CHARSET[(bits & 15) as usize];
        bits >>= 4;
    }
    String::from_utf8(result).expect("padding header is ASCII")
}

async fn send_h2_data(stream: &mut h2::SendStream<Bytes>, data: Bytes, end: bool) -> io::Result<()> {
    let mut offset = 0;
    while offset < data.len() {
        let remaining = data.len() - offset;
        stream.reserve_capacity(remaining);
        let capacity = poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionReset, "naive: HTTP/2 stream closed"))?
            .map_err(|error| io::Error::other(format!("naive: HTTP/2 send capacity: {error}")))?;
        if capacity == 0 {
            return Err(io::Error::new(io::ErrorKind::ConnectionReset, "naive: HTTP/2 send capacity is zero"));
        }
        let count = capacity.min(remaining);
        let chunk = data.slice(offset..offset + count);
        offset += count;
        stream
            .send_data(chunk, end && offset == data.len())
            .map_err(|error| io::Error::other(format!("naive: HTTP/2 send: {error}")))?;
    }
    if end && data.is_empty() {
        stream
            .send_data(Bytes::new(), true)
            .map_err(|error| io::Error::other(format!("naive: HTTP/2 end stream: {error}")))?;
    }
    Ok(())
}

fn bridge_tunnel(send_stream: h2::SendStream<Bytes>, recv_stream: h2::RecvStream) -> BoxStream {
    let (local, bridge) = tokio::io::duplex(BRIDGE_BUFFER);
    let (mut reader, mut writer) = tokio::io::split(bridge);
    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    let mut send_cancel = cancel_rx.clone();
    let send_failed = cancel_tx.clone();
    tokio::spawn(async move {
        let result = async {
            let mut stream = send_stream;
            let mut buffer = [0u8; 16 * 1024];
            loop {
                let count = tokio::select! {
                    _ = send_cancel.changed() => return Ok(()),
                    result = reader.read(&mut buffer) => result?,
                };
                if count == 0 {
                    tokio::select! {
                        _ = send_cancel.changed() => return Ok(()),
                        result = send_h2_data(&mut stream, Bytes::new(), true) => result?,
                    }
                    return Ok::<(), io::Error>(());
                }
                tokio::select! {
                    _ = send_cancel.changed() => return Ok(()),
                    result = send_h2_data(&mut stream, Bytes::copy_from_slice(&buffer[..count]), false) => result?,
                }
            }
        }
        .await;
        if let Err(error) = result {
            tracing::debug!("Naive upload tunnel closed: {error}");
            let _ = send_failed.send(true);
        }
    });

    tokio::spawn(async move {
        let result = async {
            let mut stream = recv_stream;
            loop {
                let item = tokio::select! {
                    _ = cancel_rx.changed() => return Ok(()),
                    item = stream.data() => item,
                };
                let Some(data) = item else {
                    writer.shutdown().await?;
                    return Ok::<(), io::Error>(());
                };
                let data = data.map_err(|error| io::Error::other(format!("naive: HTTP/2 receive: {error}")))?;
                let length = data.len();
                tokio::select! {
                    _ = cancel_rx.changed() => return Ok(()),
                    result = writer.write_all(&data) => result?,
                }
                stream
                    .flow_control()
                    .release_capacity(length)
                    .map_err(|error| io::Error::other(format!("naive: release HTTP/2 capacity: {error}")))?;
            }
        }
        .await;
        if let Err(error) = result {
            tracing::debug!("Naive download tunnel closed: {error}");
            let _ = cancel_tx.send(true);
        }
    });
    Box::new(NaivePaddedStream::new(local))
}

struct NaivePaddedStream {
    inner: DuplexStream,
    read_frames: u8,
    write_frames: u8,
    header: [u8; 3],
    header_filled: usize,
    payload_remaining: usize,
    padding_remaining: usize,
    pending_write: Vec<u8>,
    pending_offset: usize,
    pending_original_len: usize,
}

impl NaivePaddedStream {
    fn new(inner: DuplexStream) -> Self {
        Self {
            inner,
            read_frames: 0,
            write_frames: 0,
            header: [0; 3],
            header_filled: 0,
            payload_remaining: 0,
            padding_remaining: 0,
            pending_write: Vec::new(),
            pending_offset: 0,
            pending_original_len: 0,
        }
    }

    fn poll_pending_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        while self.pending_offset < self.pending_write.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending_write[self.pending_offset..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "naive: tunnel write zero")))
                }
                Poll::Ready(Ok(count)) => self.pending_offset += count,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        let original_len = self.pending_original_len;
        self.pending_write.clear();
        self.pending_offset = 0;
        self.pending_original_len = 0;
        Poll::Ready(Ok(original_len))
    }
}

impl AsyncRead for NaivePaddedStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.payload_remaining > 0 {
                let count = buffer.remaining().min(this.payload_remaining);
                let read = {
                    let mut inner_buffer = ReadBuf::new(&mut buffer.initialize_unfilled()[..count]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut inner_buffer) {
                        Poll::Ready(Ok(())) => inner_buffer.filled().len(),
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                };
                if read == 0 {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "naive: truncated payload")));
                }
                buffer.advance(read);
                this.payload_remaining -= read;
                return Poll::Ready(Ok(()));
            }
            if this.padding_remaining > 0 {
                let mut scratch = [0u8; 255];
                let count = this.padding_remaining.min(scratch.len());
                let read = {
                    let mut inner_buffer = ReadBuf::new(&mut scratch[..count]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut inner_buffer) {
                        Poll::Ready(Ok(())) => inner_buffer.filled().len(),
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                };
                if read == 0 {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "naive: truncated padding")));
                }
                this.padding_remaining -= read;
                continue;
            }
            if this.read_frames >= PADDING_FRAMES {
                return Pin::new(&mut this.inner).poll_read(cx, buffer);
            }
            while this.header_filled < this.header.len() {
                let read = {
                    let mut inner_buffer = ReadBuf::new(&mut this.header[this.header_filled..]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut inner_buffer) {
                        Poll::Ready(Ok(())) => inner_buffer.filled().len(),
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                };
                if read == 0 {
                    if this.header_filled == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "naive: truncated padding header",
                    )));
                }
                this.header_filled += read;
            }
            this.payload_remaining = u16::from_be_bytes([this.header[0], this.header[1]]) as usize;
            this.padding_remaining = this.header[2] as usize;
            this.header_filled = 0;
            this.read_frames += 1;
        }
    }
}

impl AsyncWrite for NaivePaddedStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buffer: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !this.pending_write.is_empty() {
            return this.poll_pending_write(cx);
        }
        if this.write_frames >= PADDING_FRAMES {
            return Pin::new(&mut this.inner).poll_write(cx, buffer);
        }
        let original_len = buffer.len().min(MAX_PADDING_CHUNK);
        let padding_len = rand::random::<u8>() as usize;
        this.pending_write.reserve(3 + original_len + padding_len);
        this.pending_write.extend_from_slice(&(original_len as u16).to_be_bytes());
        this.pending_write.push(padding_len as u8);
        this.pending_write.extend_from_slice(&buffer[..original_len]);
        this.pending_write.resize(this.pending_write.len() + padding_len, 0);
        this.pending_original_len = original_len;
        this.write_frames += 1;
        this.poll_pending_write(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if !this.pending_write.is_empty() {
            match this.poll_pending_write(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if !this.pending_write.is_empty() {
            match this.poll_pending_write(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rb_adapter::SharedPacketConn;
    use rb_config::{CertificateOptions, Listable, OutboundTlsOptions};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;

    struct FixedDialer(std::net::SocketAddr);

    #[async_trait]
    impl Dialer for FixedDialer {
        async fn dial_tcp(&self, _destination: &Socksaddr) -> io::Result<BoxStream> {
            Ok(Box::new(TcpStream::connect(self.0).await?))
        }

        async fn dial_udp(&self, _destination: &Socksaddr) -> io::Result<SharedPacketConn> {
            Err(io::ErrorKind::Unsupported.into())
        }

        async fn listen_packet(&self, _destination: &Socksaddr) -> io::Result<SharedPacketConn> {
            Err(io::ErrorKind::Unsupported.into())
        }
    }

    #[derive(Debug)]
    struct RequestSnapshot {
        method: Method,
        authority: Option<String>,
        scheme: Option<String>,
        path: Option<String>,
        authorization: Option<String>,
        custom_header: Option<String>,
        padding_len: usize,
    }

    #[tokio::test]
    async fn h2_connect_auth_padding_and_bidirectional_tunnel_interoperate() {
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate =
            rcgen::CertificateParams::new(vec!["naive.test".to_string()]).unwrap().self_signed(&key).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server_config = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
        let (observed_tx, observed_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.unwrap();
            let mut connection = h2::server::Builder::new().handshake(tls).await.unwrap();
            let mut observed_tx = Some(observed_tx);
            loop {
                tokio::select! {
                    _ = &mut stop_rx => break,
                    request = connection.accept() => {
                        let Some(Ok((request, mut response_sender))) = request else { break };
                        let denied = request.uri().authority().is_some_and(|authority| authority.as_str() == "denied.example:443");
                        if let Some(tx) = observed_tx.take() {
                            let snapshot = RequestSnapshot {
                                method: request.method().clone(),
                                authority: request.uri().authority().map(ToString::to_string),
                                scheme: request.uri().scheme_str().map(str::to_string),
                                path: request.uri().path_and_query().map(ToString::to_string),
                                authorization: request.headers().get("proxy-authorization").and_then(|v| v.to_str().ok()).map(str::to_string),
                                custom_header: request.headers().get("x-test").and_then(|v| v.to_str().ok()).map(str::to_string),
                                padding_len: request.headers().get("padding").and_then(|v| v.to_str().ok()).map_or(0, str::len),
                            };
                            let _ = tx.send(snapshot);
                        }
                        let body = request.into_body();
                        let status = if denied { StatusCode::PROXY_AUTHENTICATION_REQUIRED } else { StatusCode::OK };
                        let response = http::Response::builder().status(status).body(()).unwrap();
                        let mut send = response_sender.send_response(response, denied).unwrap();
                        if denied {
                            drop(body);
                            continue;
                        }
                        tokio::spawn(async move {
                            let mut body = body;
                            while let Some(Ok(data)) = body.data().await {
                                let length = data.len();
                                if send_h2_data(&mut send, data, false).await.is_err() {
                                    return;
                                }
                                if body.flow_control().release_capacity(length).is_err() {
                                    return;
                                }
                            }
                            let _ = send_h2_data(&mut send, Bytes::new(), true).await;
                        });
                    }
                }
            }
        });

        let store =
            rb_certificate::Store::new(Some(&CertificateOptions { store: "none".into(), ..Default::default() }))
                .unwrap();
        let tls_options = OutboundTlsOptions {
            enabled: true,
            server_name: "naive.test".into(),
            certificate: Listable(certificate.pem().lines().map(str::to_string).collect()),
            ..Default::default()
        };
        let tls = rb_tls::TlsClient::new(&tls_options, "127.0.0.1", &store).unwrap().with_alpn(&["h2"]);
        let mut headers = HeaderMap::new();
        headers.insert(http::header::PROXY_AUTHORIZATION, HeaderValue::from_static("Basic dXNlcjpwYXNz"));
        headers.insert(HeaderName::from_static("x-test"), HeaderValue::from_static("works"));
        let outbound = NaiveOutbound {
            tag: "naive-test".into(),
            server: Socksaddr::from(address),
            dialer: Arc::new(FixedDialer(address)),
            tls,
            pools: vec![SessionPool { session: Mutex::new(None) }],
            next_pool: AtomicUsize::new(0),
            headers,
            receive_window: 1024 * 1024,
            stream_window: 512 * 1024,
        };
        let destination = Socksaddr::from_host_port("destination.example", 443);
        let mut tunnel = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            outbound.dial_tcp(&InboundContext::internal(Network::Tcp, destination)),
        )
        .await
        .unwrap()
        .unwrap();
        let observed = tokio::time::timeout(std::time::Duration::from_secs(5), observed_rx).await.unwrap().unwrap();
        assert_eq!(observed.method, Method::CONNECT);
        assert_eq!(observed.authority.as_deref(), Some("destination.example:443"));
        assert_eq!(observed.scheme, None);
        assert_eq!(observed.path, None);
        assert_eq!(observed.authorization.as_deref(), Some("Basic dXNlcjpwYXNz"));
        assert_eq!(observed.custom_header.as_deref(), Some("works"));
        assert!((30..=61).contains(&observed.padding_len));

        let mut expected = Vec::new();
        for index in 0..10 {
            let payload = format!("frame-{index};");
            expected.extend_from_slice(payload.as_bytes());
            tunnel.write_all(payload.as_bytes()).await.unwrap();
        }
        tunnel.shutdown().await.unwrap();
        let mut echoed = vec![0; expected.len()];
        tokio::time::timeout(std::time::Duration::from_secs(5), tunnel.read_exact(&mut echoed)).await.unwrap().unwrap();
        assert_eq!(echoed, expected);
        let mut byte = [0; 1];
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(5), tunnel.read(&mut byte)).await.unwrap().unwrap(),
            0
        );

        let denied = Socksaddr::from_host_port("denied.example", 443);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            outbound.dial_tcp(&InboundContext::internal(Network::Tcp, denied)),
        )
        .await
        .unwrap();
        assert!(result.is_err(), "non-success CONNECT status must fail");

        let _ = stop_tx.send(());
        server.await.unwrap();
    }

    #[test]
    fn padding_header_has_expected_size_and_alphabet() {
        let value = padding_header();
        assert!((30..=61).contains(&value.len()));
        assert!(value.is_ascii());
        assert!(value.bytes().all(|byte| b"!#$()+<>?@[]^`{}~".contains(&byte)));
    }
}
