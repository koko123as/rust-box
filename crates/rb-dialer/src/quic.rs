//! A Quinn UDP socket backed by the project's routed `PacketConn`.
//!
//! Quinn requires synchronous poll-based UDP I/O, while the project dialer
//! exposes asynchronous packet reads and writes. A pair of Tokio tasks bridges
//! those APIs; packets always use the original `Socksaddr` through the
//! configured dialer, including detours.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, ClientConfig, Connection, Endpoint, EndpointConfig, TransportConfig, UdpPoller, VarInt};
use rb_adapter::{Host, SharedPacketConn, Socksaddr, MAX_PACKET_SIZE};
use rb_config::QuicOptions;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const PACKET_QUEUE_CAPACITY: usize = 256;

/// Connects Quinn over a packet connection already created by the project
/// dialer. The returned endpoint owns the adapter and its I/O tasks.
pub async fn connect(
    packet_conn: SharedPacketConn,
    destination: Socksaddr,
    tls: Arc<rustls::ClientConfig>,
    server_name: &str,
) -> io::Result<(Endpoint, Connection)> {
    connect_with_options(packet_conn, destination, tls, server_name, &QuicOptions::default()).await
}

/// Connects Quinn over the routed packet connection and applies the shared
/// sing-box `HTTP2Options` used by DNS, TUIC, Hysteria2 and V2Ray QUIC.
pub async fn connect_with_options(
    packet_conn: SharedPacketConn,
    destination: Socksaddr,
    tls: Arc<rustls::ClientConfig>,
    server_name: &str,
    options: &QuicOptions,
) -> io::Result<(Endpoint, Connection)> {
    let socket = QuicPacketSocket::new(packet_conn, destination);
    let peer = socket.peer_addr;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|error| io::Error::other(format!("QUIC TLS configuration: {error}")))?;
    let mut endpoint =
        Endpoint::new_with_abstract_socket(EndpointConfig::default(), None, socket, Arc::new(quinn::TokioRuntime))?;
    let mut client = ClientConfig::new(Arc::new(crypto));
    client.transport_config(Arc::new(transport_config(options)?));
    endpoint.set_default_client_config(client);
    let connecting =
        endpoint.connect(peer, server_name).map_err(|error| io::Error::other(format!("QUIC connect: {error}")))?;
    let connection = connecting.await.map_err(|error| io::Error::other(format!("QUIC handshake: {error}")))?;
    Ok((endpoint, connection))
}

/// Builds a Quinn server configuration from the shared TLS and QUIC options.
pub fn server_config(tls: Arc<rustls::ServerConfig>, options: &QuicOptions) -> io::Result<quinn::ServerConfig> {
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|error| io::Error::other(format!("QUIC TLS configuration: {error}")))?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(Arc::new(transport_config(options)?));
    Ok(config)
}

/// Builds the Quinn transport parameters corresponding to sing-box's shared
/// QUIC options. Zero/omitted values retain Quinn's protocol defaults, just as
/// `sing-quic.ApplyQUICOptions` leaves its underlying QUIC config untouched.
pub fn transport_config(options: &QuicOptions) -> io::Result<TransportConfig> {
    let mut config = TransportConfig::default();
    if !options.idle_timeout.0.is_zero() {
        let timeout = options
            .idle_timeout
            .0
            .try_into()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, format!("QUIC idle_timeout: {error}")))?;
        config.max_idle_timeout(Some(timeout));
    }
    if !options.keep_alive_period.0.is_zero() {
        config.keep_alive_interval(Some(options.keep_alive_period.0));
    }
    if let Some(window) = options.stream_receive_window {
        config.stream_receive_window(quic_varint(window.value(), "stream_receive_window")?);
    }
    if let Some(window) = options.connection_receive_window {
        config.receive_window(quic_varint(window.value(), "connection_receive_window")?);
    }
    if options.max_concurrent_streams > 0 {
        let streams = u64::try_from(options.max_concurrent_streams).map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("QUIC max_concurrent_streams: {error}"))
        })?;
        let streams = VarInt::from_u64(streams).map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("QUIC max_concurrent_streams: {error}"))
        })?;
        config.max_concurrent_bidi_streams(streams);
    }
    if options.initial_packet_size > 0 {
        // sing-quic v0.7.2 casts the configured positive int to uint16.
        config.initial_mtu(options.initial_packet_size as u16);
    }
    if options.disable_path_mtu_discovery {
        config.mtu_discovery_config(None);
    }
    Ok(config)
}

fn quic_varint(value: u64, name: &str) -> io::Result<VarInt> {
    VarInt::from_u64(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, format!("QUIC {name}: {error}")))
}

struct QuicPacketSocket {
    incoming: Mutex<mpsc::Receiver<io::Result<Vec<u8>>>>,
    outgoing: mpsc::Sender<Vec<u8>>,
    writable: Arc<WritableRegistry>,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    _reader: JoinHandle<()>,
    _writer: JoinHandle<()>,
}

impl fmt::Debug for QuicPacketSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicPacketSocket")
            .field("peer_addr", &self.peer_addr)
            .field("local_addr", &self.local_addr)
            .finish()
    }
}

impl QuicPacketSocket {
    fn new(packet_conn: SharedPacketConn, destination: Socksaddr) -> Arc<Self> {
        let peer_addr = packet_conn.peer_addr().unwrap_or_else(|| virtual_peer_addr(&destination));
        let local_addr = packet_conn
            .local_addr()
            .filter(|address| address.is_ipv4() == peer_addr.is_ipv4())
            .unwrap_or_else(|| wildcard_addr(peer_addr));
        let (outgoing, mut outgoing_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE_CAPACITY);
        let (incoming_tx, incoming) = mpsc::channel::<io::Result<Vec<u8>>>(PACKET_QUEUE_CAPACITY);
        let writable = Arc::new(WritableRegistry::default());

        let reader_conn = packet_conn.clone();
        let reader_tx = incoming_tx.clone();
        let reader = tokio::spawn(async move {
            let mut buffer = vec![0; MAX_PACKET_SIZE];
            loop {
                let packet = match reader_conn.read_packet(&mut buffer).await {
                    Ok((length, _source)) => Ok(buffer[..length].to_vec()),
                    Err(error) => {
                        let _ = reader_tx.send(Err(copy_error(&error))).await;
                        break;
                    }
                };
                if reader_tx.send(packet).await.is_err() {
                    break;
                }
            }
        });

        let writer_conn = packet_conn;
        let writer_destination = destination;
        let writer_writable = writable.clone();
        let writer_tx = incoming_tx;
        let writer = tokio::spawn(async move {
            while let Some(packet) = outgoing_rx.recv().await {
                writer_writable.wake_waiters();
                if let Err(error) = writer_conn.write_packet(&packet, &writer_destination).await {
                    let _ = writer_tx.send(Err(copy_error(&error))).await;
                    break;
                }
            }
        });

        Arc::new(QuicPacketSocket {
            incoming: Mutex::new(incoming),
            outgoing,
            writable,
            peer_addr,
            local_addr,
            _reader: reader,
            _writer: writer,
        })
    }
}

impl Drop for QuicPacketSocket {
    fn drop(&mut self) {
        self._reader.abort();
        self._writer.abort();
    }
}

impl AsyncUdpSocket for QuicPacketSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        let waiter = Arc::new(Mutex::new(None));
        self.writable.register(&waiter);
        Box::pin(WritablePoller { socket: self, waiter })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if transmit.segment_size.is_some_and(|segment_size| segment_size == 0 || transmit.contents.len() > segment_size)
        {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "QUIC UDP segmentation is not supported"));
        }
        match self.outgoing.try_send(transmit.contents.to_vec()) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(io::Error::from(io::ErrorKind::WouldBlock)),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "QUIC UDP packet writer stopped"))
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut incoming = self.incoming.lock().unwrap();
        match incoming.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "QUIC UDP packet reader stopped")))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(error)),
            Poll::Ready(Some(Ok(packet))) => {
                let length = packet.len().min(bufs[0].len());
                bufs[0][..length].copy_from_slice(&packet[..length]);
                let received = RecvMeta { addr: self.peer_addr, len: length, stride: length, ..RecvMeta::default() };
                meta[0] = received;
                Poll::Ready(Ok(1))
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}

#[derive(Default)]
struct WritableRegistry {
    waiters: Mutex<Vec<Weak<Mutex<Option<Waker>>>>>,
}

impl WritableRegistry {
    fn register(&self, waiter: &Arc<Mutex<Option<Waker>>>) {
        let mut waiters = self.waiters.lock().unwrap();
        waiters.retain(|registered| registered.strong_count() > 0);
        waiters.push(Arc::downgrade(waiter));
    }

    fn wake_waiters(&self) {
        let waiters = {
            let mut registered = self.waiters.lock().unwrap();
            let mut waiters = Vec::with_capacity(registered.len());
            registered.retain(|waiter| {
                if let Some(waiter) = waiter.upgrade() {
                    waiters.push(waiter);
                    true
                } else {
                    false
                }
            });
            waiters
        };
        for waiter in waiters {
            if let Some(waker) = waiter.lock().unwrap().take() {
                waker.wake();
            }
        }
    }
}

struct WritablePoller {
    socket: Arc<QuicPacketSocket>,
    waiter: Arc<Mutex<Option<Waker>>>,
}

impl fmt::Debug for WritablePoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WritablePoller").finish_non_exhaustive()
    }
}

impl UdpPoller for WritablePoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut waiter = this.waiter.lock().unwrap();
        if this.socket.outgoing.capacity() > 0 {
            *waiter = None;
            return Poll::Ready(Ok(()));
        }
        if waiter.as_ref().is_none_or(|waker| !waker.will_wake(cx.waker())) {
            *waiter = Some(cx.waker().clone());
        }
        if this.socket.outgoing.capacity() > 0 {
            *waiter = None;
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

fn virtual_peer_addr(destination: &Socksaddr) -> SocketAddr {
    match destination.host {
        Host::Ip(address) => SocketAddr::new(address, destination.port),
        Host::Domain(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), destination.port),
    }
}

fn wildcard_addr(peer: SocketAddr) -> SocketAddr {
    let address = match peer.ip() {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    SocketAddr::new(address, 0)
}

fn copy_error(error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), error.to_string())
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::io::IoSliceMut;
    use std::sync::Arc;

    use async_trait::async_trait;
    use quinn::udp::Transmit;
    use quinn::AsyncUdpSocket;
    use rb_adapter::{PacketConn, SharedPacketConn, Socksaddr};
    use tokio::sync::mpsc;

    use super::{server_config, transport_config, QuicPacketSocket};
    use rb_config::{MemoryBytes, QuicOptions};

    fn server_tls_config() -> Arc<rustls::ServerConfig> {
        let generated = rcgen::generate_simple_self_signed(vec!["quic.example".into()]).unwrap();
        let certificate = generated.cert.der().clone();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(generated.key_pair.serialize_der().into());
        Arc::new(
            rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![certificate], key).unwrap(),
        )
    }

    #[test]
    fn shared_quic_options_map_and_reject_unrepresentable_windows() {
        let options = QuicOptions {
            stream_receive_window: Some(MemoryBytes(256 * 1024)),
            connection_receive_window: Some(MemoryBytes(4 * 1024 * 1024)),
            max_concurrent_streams: 128,
            initial_packet_size: 1400,
            disable_path_mtu_discovery: true,
            ..Default::default()
        };
        assert!(transport_config(&options).is_ok());

        let options = QuicOptions { stream_receive_window: Some(MemoryBytes(u64::MAX)), ..Default::default() };
        match transport_config(&options) {
            Err(error) => assert!(error.to_string().contains("stream_receive_window")),
            Ok(_) => panic!("window larger than QUIC's varint range must be rejected"),
        }
    }

    #[test]
    fn server_quic_config_uses_shared_transport_options() {
        let options = QuicOptions {
            stream_receive_window: Some(MemoryBytes(256 * 1024)),
            connection_receive_window: Some(MemoryBytes(4 * 1024 * 1024)),
            max_concurrent_streams: 128,
            initial_packet_size: 1400,
            disable_path_mtu_discovery: true,
            ..Default::default()
        };
        assert!(server_config(server_tls_config(), &options).is_ok());

        let invalid = QuicOptions { stream_receive_window: Some(MemoryBytes(u64::MAX)), ..Default::default() };
        let error = server_config(server_tls_config(), &invalid).unwrap_err();
        assert!(error.to_string().contains("stream_receive_window"));
    }

    struct MockPacketConn {
        incoming: tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, Socksaddr)>>,
        outgoing: mpsc::UnboundedSender<(Vec<u8>, Socksaddr)>,
    }

    #[async_trait]
    impl PacketConn for MockPacketConn {
        async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
            let (packet, source) =
                self.incoming.lock().await.recv().await.ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
            let length = packet.len().min(buffer.len());
            buffer[..length].copy_from_slice(&packet[..length]);
            Ok((length, source))
        }

        async fn write_packet(&self, packet: &[u8], destination: &Socksaddr) -> io::Result<()> {
            self.outgoing
                .send((packet.to_vec(), destination.clone()))
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    #[tokio::test]
    async fn routes_outgoing_and_maps_incoming_peer() {
        let destination = Socksaddr::from_host_port("resolver.example", 853);
        let (incoming_tx, incoming_rx) = mpsc::channel(4);
        let (outgoing_tx, mut outgoing_rx) = mpsc::unbounded_channel();
        let packet_conn: SharedPacketConn = std::sync::Arc::new(MockPacketConn {
            incoming: tokio::sync::Mutex::new(incoming_rx),
            outgoing: outgoing_tx,
        });
        let socket = QuicPacketSocket::new(packet_conn, destination.clone());
        let peer = socket.peer_addr;

        let transmit =
            Transmit { destination: peer, ecn: None, contents: b"quic request", segment_size: None, src_ip: None };
        socket.try_send(&transmit).unwrap();
        let (sent, routed_to) =
            tokio::time::timeout(std::time::Duration::from_secs(1), outgoing_rx.recv()).await.unwrap().unwrap();
        assert_eq!(sent, b"quic request");
        assert_eq!(routed_to, destination);

        incoming_tx.send((b"quic reply".to_vec(), Socksaddr::from_host_port("203.0.113.8", 853))).await.unwrap();
        let mut buffer = [0u8; 64];
        let mut bufs = [IoSliceMut::new(&mut buffer)];
        let mut meta = [quinn::udp::RecvMeta::default()];
        let received = std::future::poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta)).await.unwrap();

        assert_eq!(received, 1);
        assert_eq!(&bufs[0][..10], b"quic reply");
        assert_eq!(meta[0].addr, peer);
        assert_eq!(meta[0].len, 10);
    }
}
