//! TUIC v5 QUIC server, compatible with sing-quic `tuic.Service`.
use super::wire;
use async_trait::async_trait;
use quinn::{Connection, RecvStream, SendStream, VarInt};
use rb_adapter::{
    BoxStream, ConnectionRouter, Inbound, InboundContext, Network, PacketConn, Socksaddr, MAX_PACKET_SIZE,
};
use rb_config::{QuicOptions, TuicInbound as Options};
use rb_dialer::listener::Listener;
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc, Mutex, OnceLock,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    sync::{mpsc, watch, Mutex as AsyncMutex},
    task::{JoinHandle, JoinSet},
};
use tracing::debug;

const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(300);
const FRAGMENT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_FRAGMENT_SESSIONS: usize = 256;
const MAX_UDP_SESSIONS: usize = 1024;
const MAX_UNI_STREAM_SIZE: usize = u16::MAX as usize + 512;
const STREAM_UDP_MTU: usize = 1200 - 3;
const UDP_QUEUE_SIZE: usize = 64;
const MAX_UNI_READERS: usize = 64;
const _: () = assert!(MAX_UNI_READERS <= UDP_QUEUE_SIZE);

type UdpSessions = Arc<AsyncMutex<HashMap<u16, Arc<TuicUdpSession>>>>;

enum UniEvent {
    Message(io::Result<Vec<u8>>),
}

pub struct TuicInbound {
    tag: String,
    listener: Listener,
    tls: rb_tls::TlsServer,
    quic: QuicOptions,
    users: HashMap<[u8; 16], (String, String)>,
    router: Arc<dyn ConnectionRouter>,
    auth_timeout: Duration,
    heartbeat: Duration,
    udp_timeout: Duration,
    detour: Option<String>,
    local_addr: OnceLock<SocketAddr>,
    task: Mutex<Option<JoinHandle<()>>>,
    endpoint: Mutex<Option<quinn::Endpoint>>,
    closing: AtomicBool,
}

impl TuicInbound {
    pub fn new(options: &Options, tag: String, router: Arc<dyn ConnectionRouter>) -> Result<Self, String> {
        let tls_options = options.tls.as_ref().filter(|tls| tls.enabled).ok_or("TLS is required")?;
        if options.zero_rtt_handshake {
            return Err("zero_rtt_handshake: unsupported by rust-box TUIC inbound".into());
        }
        if !matches!(options.congestion_control.as_str(), "" | "cubic") {
            return Err(format!("congestion_control: unsupported value {:?}", options.congestion_control));
        }
        let mut users = HashMap::new();
        for (index, user) in options.users.iter().enumerate() {
            let uuid = crate::vless::protocol::parse_uuid_strict(&user.uuid)
                .ok_or_else(|| format!("users[{index}].uuid: invalid uuid"))?;
            users.insert(uuid, (user.name.clone(), user.password.clone()));
        }
        if users.is_empty() {
            return Err("users: at least one user is required".into());
        }
        let quic = QuicOptions {
            idle_timeout: options.idle_timeout,
            keep_alive_period: options.keep_alive_period,
            stream_receive_window: options.stream_receive_window,
            connection_receive_window: options.connection_receive_window,
            max_concurrent_streams: options.max_concurrent_streams,
            initial_packet_size: options.initial_packet_size,
            disable_path_mtu_discovery: options.disable_path_mtu_discovery,
        };
        let listen = options.listen_options();
        let udp_timeout = if listen.udp_timeout.0 .0.is_zero() { DEFAULT_UDP_TIMEOUT } else { listen.udp_timeout.0 .0 };
        Ok(Self {
            tag,
            listener: Listener::new(&listen).map_err(|error| error.to_string())?,
            tls: rb_tls::TlsServer::new(tls_options)?,
            quic,
            users,
            router,
            auth_timeout: if options.auth_timeout.0.is_zero() {
                Duration::from_secs(3)
            } else {
                options.auth_timeout.0
            },
            heartbeat: if options.heartbeat.0.is_zero() { Duration::from_secs(10) } else { options.heartbeat.0 },
            udp_timeout,
            detour: (!listen.detour.is_empty()).then_some(listen.detour),
            local_addr: OnceLock::new(),
            task: Mutex::new(None),
            endpoint: Mutex::new(None),
            closing: AtomicBool::new(false),
        })
    }

    fn prefix(&self) -> String {
        format!("inbound/tuic[{}]", self.tag)
    }

    async fn serve(self: Arc<Self>, connection: Connection, user: Option<String>) {
        let sessions: UdpSessions = Arc::new(AsyncMutex::new(HashMap::new()));
        let (uni_tx, mut uni_rx) = mpsc::channel(UDP_QUEUE_SIZE);
        let uni_readers = Arc::new(tokio::sync::Semaphore::new(MAX_UNI_READERS));
        let mut tasks = JoinSet::new();

        let heartbeat_connection = connection.clone();
        let heartbeat = self.heartbeat;
        tasks.spawn(async move {
            loop {
                tokio::select! {
                    _ = heartbeat_connection.closed() => break,
                    _ = tokio::time::sleep(heartbeat) => {
                        if heartbeat_connection.send_datagram(wire::encode_heartbeat().to_vec().into()).is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let mut expire = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = connection.closed() => break,
                accepted = async {
                    let permit = uni_readers.clone().acquire_owned().await.map_err(other)?;
                    let stream = connection.accept_uni().await.map_err(other)?;
                    Ok::<_, io::Error>((permit, stream))
                } => match accepted {
                    Ok((permit, stream)) => {
                        let tx = uni_tx.clone();
                        tasks.spawn(async move {
                            let _permit = permit;
                            let _ = tx.send(UniEvent::Message(read_uni_stream(stream).await)).await;
                        });
                    }
                    Err(_) => break,
                },
                accepted = connection.accept_bi() => match accepted {
                    Ok((send, recv)) => {
                        let inbound = self.clone();
                        let connection = connection.clone();
                        let user = user.clone();
                        tasks.spawn(async move {
                            if let Err(error) = inbound.handle_connect(connection.clone(), send, recv, user).await {
                                debug!("{}: handle CONNECT: {error}", inbound.prefix());
                            }
                        });
                    }
                    Err(_) => break,
                },
                message = connection.read_datagram() => match message {
                    Ok(message) => {
                        let payload = message.as_ref();
                        let result = if payload.get(1) == Some(&wire::COMMAND_HEARTBEAT) {
                            wire::decode_heartbeat(payload)
                        } else {
                            self.handle_udp_message(
                                &connection,
                                &sessions,
                                user.clone(),
                                payload,
                                false,
                                &mut tasks,
                            )
                            .await
                        };
                        if let Err(error) = result {
                            debug!("{}: handle DATAGRAM: {error}", self.prefix());
                            connection.close(VarInt::from_u32(1), b"invalid TUIC datagram");
                            break;
                        }
                    }
                    Err(error) => {
                        debug!("{}: receive DATAGRAM: {error}", self.prefix());
                        break;
                    }
                },
                Some(UniEvent::Message(message)) = uni_rx.recv() => match message {
                    Ok(message) => {
                        if let Err(error) = self.handle_uni_message(
                            &connection,
                            &sessions,
                            user.clone(),
                            &message,
                            &mut tasks,
                        ).await {
                            debug!("{}: handle uni stream: {error}", self.prefix());
                            connection.close(VarInt::from_u32(1), b"invalid TUIC uni stream");
                            break;
                        }
                    }
                    Err(error) => {
                        debug!("{}: read uni stream: {error}", self.prefix());
                        connection.close(VarInt::from_u32(1), b"invalid TUIC uni stream");
                        break;
                    }
                },
                _ = expire.tick() => expire_incomplete_sessions(&sessions).await,
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = joined {
                        debug!("{}: connection task failed: {error}", self.prefix());
                    }
                }
            }
        }

        close_all_sessions(&sessions).await;
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }

    async fn handle_uni_message(
        &self,
        connection: &Connection,
        sessions: &UdpSessions,
        user: Option<String>,
        message: &[u8],
        tasks: &mut JoinSet<()>,
    ) -> io::Result<()> {
        if message.len() < 2 || message[0] != wire::VERSION {
            return Err(invalid("invalid TUIC uni stream header"));
        }
        match message[1] {
            wire::COMMAND_PACKET => self.handle_udp_message(connection, sessions, user, message, true, tasks).await,
            wire::COMMAND_DISSOCIATE => {
                let session_id = wire::decode_dissociate(message)?;
                dissociate_session(sessions, session_id).await;
                Ok(())
            }
            wire::COMMAND_AUTHENTICATE => Err(invalid("multiple TUIC authentication requests")),
            command => Err(invalid(format!("unknown TUIC uni stream command {command}"))),
        }
    }

    async fn handle_udp_message(
        &self,
        connection: &Connection,
        sessions: &UdpSessions,
        user: Option<String>,
        message: &[u8],
        udp_stream: bool,
        tasks: &mut JoinSet<()>,
    ) -> io::Result<()> {
        let packet = wire::decode_udp(message)?;
        let session = {
            let mut sessions = sessions.lock().await;
            if should_reject_new_session(sessions.len(), sessions.contains_key(&packet.session_id)) {
                // Do not evict or disturb established sessions when capacity is exhausted.
                return Ok(());
            }
            sessions
                .entry(packet.session_id)
                .or_insert_with(|| Arc::new(TuicUdpSession::new(packet.session_id, connection.clone(), udp_stream)))
                .clone()
        };
        if let Some(destination) = session.input(packet).await? {
            let inbound_tag = self.tag.clone();
            let router = self.router.clone();
            let sessions = sessions.clone();
            let session = session.clone();
            let user = user.clone();
            let source = connection.remote_address();
            let mut context = InboundContext::new(&self.tag, "tuic", Network::Udp, source, destination);
            context.user = user;
            context.inbound_udp_timeout = Some(self.udp_timeout);
            context.inbound_detour = self.detour.clone();
            tasks.spawn(async move {
                if let Err(error) = router.route_packet_connection(context, session.packet_conn.clone()).await {
                    debug!("inbound/tuic[{inbound_tag}]: UDP session {}: {error}", session.session_id);
                }
                session.close();
                let mut sessions = sessions.lock().await;
                if sessions.get(&session.session_id).is_some_and(|current| Arc::ptr_eq(current, &session)) {
                    sessions.remove(&session.session_id);
                }
            });
        }
        Ok(())
    }

    async fn handle_connect(
        &self,
        connection: Connection,
        send: SendStream,
        mut recv: RecvStream,
        user: Option<String>,
    ) -> io::Result<()> {
        let mut header = [0; 2];
        recv.read_exact(&mut header).await.map_err(other)?;
        if header != [wire::VERSION, wire::COMMAND_CONNECT] {
            return Err(invalid("invalid TUIC CONNECT header"));
        }
        let destination = read_address(&mut recv).await?;
        let source = connection.remote_address();
        let mut context = InboundContext::new(&self.tag, "tuic", Network::Tcp, source, destination);
        context.user = user;
        context.inbound_detour = self.detour.clone();
        let stream: BoxStream = Box::new(TuicStream { send, recv });
        if let Err(error) = self.router.route_connection(context, stream).await {
            debug!("{}: route CONNECT: {error}", self.prefix());
        }
        Ok(())
    }
}

async fn authenticate(
    connection: &Connection,
    users: &HashMap<[u8; 16], (String, String)>,
) -> io::Result<Option<String>> {
    let mut stream = connection.accept_uni().await.map_err(other)?;
    let mut bytes = [0; wire::AUTH_LEN];
    stream.read_exact(&mut bytes).await.map_err(other)?;
    let (uuid, token) = wire::decode_auth(&bytes)?;
    let Some((name, password)) = users.get(&uuid) else {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "unknown user"));
    };
    let mut expected = [0; 32];
    connection.export_keying_material(&mut expected, &uuid, password.as_bytes()).map_err(other)?;
    if !constant_eq(&token, &expected) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "token mismatch"));
    }
    Ok((!name.is_empty()).then(|| name.clone()))
}

async fn read_uni_stream(mut stream: RecvStream) -> io::Result<Vec<u8>> {
    stream.read_to_end(MAX_UNI_STREAM_SIZE).await.map_err(other)
}

async fn read_address(stream: &mut RecvStream) -> io::Result<Socksaddr> {
    let family = stream.read_u8().await.map_err(other)?;
    let mut encoded = vec![family];
    match family {
        0 => {
            let length = stream.read_u8().await.map_err(other)?;
            encoded.push(length);
            let mut name = vec![0; usize::from(length)];
            stream.read_exact(&mut name).await.map_err(other)?;
            encoded.extend_from_slice(&name);
        }
        1 => {
            let mut address = [0; 4];
            stream.read_exact(&mut address).await.map_err(other)?;
            encoded.extend_from_slice(&address);
        }
        2 => {
            let mut address = [0; 16];
            stream.read_exact(&mut address).await.map_err(other)?;
            encoded.extend_from_slice(&address);
        }
        other => return Err(invalid(format!("unknown TUIC address family 0x{other:02x}"))),
    }
    let mut port = [0; 2];
    stream.read_exact(&mut port).await.map_err(other)?;
    encoded.extend_from_slice(&port);
    match wire::decode_address(&mut encoded.as_slice())? {
        wire::TuicAddress::Socket(destination) => Ok(destination),
        wire::TuicAddress::Empty => Err(invalid("empty TUIC CONNECT destination")),
    }
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |diff, (left, right)| diff | (left ^ right)) == 0
}

fn other(error: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("{error:?}"))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn validate_start_state(closing: bool, started: bool) -> io::Result<()> {
    if closing {
        return Err(io::Error::new(io::ErrorKind::NotConnected, "TUIC inbound is closing"));
    }
    if started {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "TUIC inbound is already started"));
    }
    Ok(())
}

async fn dissociate_session(sessions: &UdpSessions, session_id: u16) {
    if let Some(session) = sessions.lock().await.remove(&session_id) {
        session.close();
    }
}

async fn expire_incomplete_sessions(sessions: &UdpSessions) {
    let stale = {
        let sessions = sessions.lock().await;
        sessions
            .iter()
            .filter(|(_, session)| !session.route_started.load(Ordering::Relaxed) && session.is_idle(FRAGMENT_TIMEOUT))
            .map(|(&session_id, _)| session_id)
            .collect::<Vec<_>>()
    };
    for session_id in stale {
        dissociate_session(sessions, session_id).await;
    }
}

async fn close_all_sessions(sessions: &UdpSessions) {
    let sessions = std::mem::take(&mut *sessions.lock().await);
    for session in sessions.into_values() {
        session.close();
    }
}

fn should_reject_new_session(session_count: usize, exists: bool) -> bool {
    !exists && session_count >= MAX_UDP_SESSIONS
}

struct TuicUdpSession {
    session_id: u16,
    packet_conn: Arc<TuicUdpPacketConn>,
    defragger: Mutex<TuicDefragger>,
    route_started: AtomicBool,
    last_activity: Mutex<Instant>,
}

impl TuicUdpSession {
    fn new(session_id: u16, connection: Connection, udp_stream: bool) -> Self {
        Self {
            session_id,
            packet_conn: Arc::new(TuicUdpPacketConn::new(session_id, connection, udp_stream)),
            defragger: Mutex::new(TuicDefragger::default()),
            route_started: AtomicBool::new(false),
            last_activity: Mutex::new(Instant::now()),
        }
    }

    async fn input(&self, packet: wire::UdpPacket) -> io::Result<Option<Socksaddr>> {
        *self.last_activity.lock().unwrap() = Instant::now();
        let packet = self.defragger.lock().unwrap().feed(packet)?;
        let Some((data, destination)) = packet else { return Ok(None) };
        self.packet_conn.enqueue(data, destination.clone()).await?;
        if self.route_started.swap(true, Ordering::AcqRel) {
            return Ok(None);
        }
        Ok(Some(destination))
    }

    fn is_idle(&self, timeout: Duration) -> bool {
        self.last_activity.lock().unwrap().elapsed() > timeout
    }

    fn close(&self) {
        self.packet_conn.close();
    }
}

struct TuicUdpPacketConn {
    session_id: u16,
    connection: Connection,
    udp_stream: bool,
    packet_id: AtomicU32,
    tx: mpsc::Sender<(Vec<u8>, Socksaddr)>,
    rx: AsyncMutex<mpsc::Receiver<(Vec<u8>, Socksaddr)>>,
    closed_tx: watch::Sender<bool>,
    closed_rx: watch::Receiver<bool>,
}

impl TuicUdpPacketConn {
    fn new(session_id: u16, connection: Connection, udp_stream: bool) -> Self {
        let (tx, rx) = mpsc::channel(UDP_QUEUE_SIZE);
        let (closed_tx, closed_rx) = watch::channel(false);
        Self {
            session_id,
            connection,
            udp_stream,
            packet_id: AtomicU32::new(0),
            tx,
            rx: AsyncMutex::new(rx),
            closed_tx,
            closed_rx,
        }
    }

    async fn enqueue(&self, data: Vec<u8>, destination: Socksaddr) -> io::Result<()> {
        if *self.closed_rx.borrow() {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "TUIC UDP session closed"));
        }
        self.tx
            .send((data, destination))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "TUIC UDP session closed"))
    }

    fn close(&self) {
        self.closed_tx.send_replace(true);
    }

    fn packet_limit(&self) -> io::Result<usize> {
        if self.udp_stream {
            Ok(STREAM_UDP_MTU)
        } else {
            self.connection
                .max_datagram_size()
                .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "TUIC DATAGRAM was not negotiated"))
        }
    }

    async fn send_packet(&self, packet: &wire::UdpPacket) -> io::Result<()> {
        let encoded = wire::encode_udp(packet)?;
        if self.udp_stream {
            let mut stream = self.connection.open_uni().await.map_err(other)?;
            stream.write_all(&encoded).await.map_err(other)?;
            stream.finish().map_err(other)?;
        } else {
            self.connection.send_datagram(encoded.into()).map_err(other)?;
        }
        Ok(())
    }
}

#[async_trait]
impl PacketConn for TuicUdpPacketConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        if *self.closed_rx.borrow() {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "TUIC UDP session closed"));
        }
        let mut rx = self.rx.lock().await;
        let mut closed_rx = self.closed_rx.clone();
        let packet = tokio::select! {
            packet = rx.recv() => packet.ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "TUIC UDP session closed"))?,
            result = closed_rx.changed() => {
                let _ = result;
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "TUIC UDP session closed"));
            }
        };
        let (data, address) = packet;
        let length = data.len().min(buffer.len());
        buffer[..length].copy_from_slice(&data[..length]);
        Ok((length, address))
    }

    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        if *self.closed_rx.borrow() {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "TUIC UDP session closed"));
        }
        if data.len() > u16::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "TUIC UDP packet exceeds u16 length"));
        }
        let mut encoded_address = Vec::new();
        wire::encode_address(&wire::TuicAddress::Socket(address.clone()), &mut encoded_address)?;
        let limit = self.packet_limit()?;
        let first_header = 10 + encoded_address.len();
        let fragment_size = limit
            .checked_sub(first_header)
            .filter(|size| *size > 0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "TUIC packet limit is too small"))?;
        let fragment_count = data.len().max(1).div_ceil(fragment_size);
        if fragment_count > u8::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "TUIC UDP packet requires too many fragments"));
        }
        let packet_id = self.packet_id.fetch_add(1, Ordering::Relaxed).wrapping_add(1) as u16;
        for fragment_id in 0..fragment_count {
            let start = fragment_id * fragment_size;
            let end = data.len().min(start + fragment_size);
            self.send_packet(&wire::UdpPacket {
                session_id: self.session_id,
                packet_id,
                fragment_total: fragment_count as u8,
                fragment_id: fragment_id as u8,
                destination: if fragment_id == 0 {
                    wire::TuicAddress::Socket(address.clone())
                } else {
                    wire::TuicAddress::Empty
                },
                data: data[start..end].to_vec(),
            })
            .await?;
        }
        Ok(())
    }
}

#[derive(Default)]
struct TuicDefragger {
    packets: HashMap<u16, TuicFragments>,
}

struct TuicFragments {
    updated: Instant,
    total: u8,
    parts: Vec<Option<Vec<u8>>>,
    destination: Option<Socksaddr>,
    length: usize,
}

impl TuicDefragger {
    fn feed(&mut self, packet: wire::UdpPacket) -> io::Result<Option<(Vec<u8>, Socksaddr)>> {
        if packet.fragment_total <= 1 {
            return match packet.destination {
                wire::TuicAddress::Socket(destination) => Ok(Some((packet.data, destination))),
                wire::TuicAddress::Empty => Err(invalid("empty TUIC UDP destination")),
            };
        }
        if packet.fragment_id >= packet.fragment_total {
            return Err(invalid("invalid TUIC UDP fragment id"));
        }
        let packet_id = packet.packet_id;
        self.packets.retain(|_, entry| entry.updated.elapsed() <= FRAGMENT_TIMEOUT);
        if self.packets.get(&packet_id).is_some_and(|entry| entry.total != packet.fragment_total) {
            self.packets.remove(&packet_id);
            return Err(invalid("inconsistent TUIC UDP fragment total"));
        }
        self.packets.entry(packet_id).or_insert_with(|| TuicFragments {
            updated: Instant::now(),
            total: packet.fragment_total,
            parts: vec![None; packet.fragment_total as usize],
            destination: None,
            length: 0,
        });
        if self.packets.len() > MAX_FRAGMENT_SESSIONS {
            if let Some(oldest) = self.packets.iter().min_by_key(|(_, entry)| entry.updated).map(|(&id, _)| id) {
                self.packets.remove(&oldest);
            }
        }
        if packet.fragment_id == 0 && matches!(packet.destination, wire::TuicAddress::Empty) {
            self.packets.remove(&packet_id);
            return Err(invalid("first TUIC UDP fragment has no destination"));
        }
        let too_large;
        let complete;
        {
            let entry = self.packets.get_mut(&packet_id).expect("fragment entry inserted");
            entry.updated = Instant::now();
            let part = &mut entry.parts[packet.fragment_id as usize];
            if part.is_none() {
                if packet.fragment_id == 0 {
                    if let wire::TuicAddress::Socket(destination) = packet.destination {
                        entry.destination = Some(destination);
                    }
                }
                entry.length = entry.length.saturating_add(packet.data.len());
                *part = Some(packet.data);
            }
            too_large = entry.length > MAX_PACKET_SIZE;
            complete = entry.destination.is_some() && entry.parts.iter().all(Option::is_some);
        }
        if too_large {
            self.packets.remove(&packet_id);
            return Err(invalid("reassembled TUIC UDP packet is too large"));
        }
        if !complete {
            return Ok(None);
        }
        let entry = self.packets.remove(&packet_id).expect("complete fragment entry exists");
        let mut data = Vec::with_capacity(entry.length);
        for part in entry.parts {
            data.extend_from_slice(&part.expect("all fragments are present"));
        }
        Ok(Some((data, entry.destination.expect("first fragment carries destination"))))
    }
}

struct TuicStream {
    send: SendStream,
    recv: RecvStream,
}

impl AsyncRead for TuicStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buffer)
    }
}

impl AsyncWrite for TuicStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send).poll_write(cx, data).map(|result| result.map_err(other))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx).map(|result| result.map_err(other))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx).map(|result| result.map_err(other))
    }
}

#[async_trait]
impl Inbound for TuicInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "tuic"
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr.get().copied()
    }

    async fn start(self: Arc<Self>) -> io::Result<()> {
        let mut task_slot = self.task.lock().unwrap();
        validate_start_state(self.closing.load(Ordering::Acquire), task_slot.is_some())?;
        self.tls.start().map_err(other)?;
        let socket = self.listener.listen_udp()?;
        let local = socket.local_addr()?;
        let _ = self.local_addr.set(local);
        let tls = (*self.tls.rustls_config()).clone();
        let endpoint = rb_dialer::quic::tuic_server_endpoint(socket, Arc::new(tls), &self.quic)?;
        *self.endpoint.lock().unwrap() = Some(endpoint.clone());
        let inbound = self.clone();
        *task_slot = Some(tokio::spawn(async move {
            let mut connections = JoinSet::new();
            while let Some(connecting) = endpoint.accept().await {
                let inbound = inbound.clone();
                connections.spawn(async move {
                    let Ok(connection) = connecting.await else { return };
                    match tokio::time::timeout(inbound.auth_timeout, authenticate(&connection, &inbound.users)).await {
                        Ok(Ok(user)) => inbound.serve(connection, user).await,
                        Ok(Err(error)) => {
                            debug!("{}: authentication failed: {error}", inbound.prefix());
                            connection.close(VarInt::from_u32(1), b"authentication failed");
                        }
                        Err(_) => connection.close(VarInt::from_u32(1), b"authentication timeout"),
                    }
                });
                while connections.try_join_next().is_some() {}
            }
            endpoint.close(VarInt::from_u32(0), b"TUIC endpoint stopped");
            while connections.join_next().await.is_some() {}
            endpoint.wait_idle().await;
        }));
        Ok(())
    }

    async fn close(&self) {
        self.closing.store(true, Ordering::Release);
        let (endpoint, task) = {
            let mut task_slot = self.task.lock().unwrap();
            let endpoint = self.endpoint.lock().unwrap().take();
            (endpoint, task_slot.take())
        };
        if let Some(endpoint) = endpoint {
            endpoint.close(VarInt::from_u32(0), b"TUIC inbound closed");
        }
        if let Some(task) = task {
            let _ = task.await;
        }
        self.tls.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(fragment_id: u8, destination: wire::TuicAddress, data: &[u8]) -> wire::UdpPacket {
        wire::UdpPacket {
            session_id: 7,
            packet_id: 9,
            fragment_total: 2,
            fragment_id,
            destination,
            data: data.to_vec(),
        }
    }

    #[test]
    fn defragger_reassembles_out_of_order_tuic_fragments() {
        let destination = Socksaddr::from_host_port("192.0.2.7", 5353);
        let mut defragger = TuicDefragger::default();
        assert_eq!(defragger.feed(packet(1, wire::TuicAddress::Empty, b"world")).unwrap(), None);
        assert_eq!(
            defragger.feed(packet(0, wire::TuicAddress::Socket(destination.clone()), b"hello")).unwrap(),
            Some((b"helloworld".to_vec(), destination)),
        );
    }

    #[test]
    fn defragger_rejects_first_fragment_without_destination() {
        let mut defragger = TuicDefragger::default();
        assert!(defragger.feed(packet(0, wire::TuicAddress::Empty, b"first")).is_err());
    }

    #[test]
    fn defragger_rejects_inconsistent_or_excessive_fragments() {
        let mut defragger = TuicDefragger::default();
        let destination = Socksaddr::from_host_port("example.org", 53);
        assert!(defragger.feed(packet(0, wire::TuicAddress::Socket(destination), b"a")).unwrap().is_none());
        let mut inconsistent = packet(1, wire::TuicAddress::Empty, b"b");
        inconsistent.fragment_total = 3;
        assert!(defragger.feed(inconsistent).is_err());
    }

    #[test]
    fn udp_session_limit_rejects_only_new_sessions_when_full() {
        assert_eq!(MAX_UDP_SESSIONS, 1024);
        assert!(!should_reject_new_session(0, false));
        assert!(!should_reject_new_session(MAX_UDP_SESSIONS, true));
        assert!(should_reject_new_session(MAX_UDP_SESSIONS, false));
    }

    #[test]
    fn uni_reader_concurrency_is_bounded_by_configured_permits() {
        let readers = Arc::new(tokio::sync::Semaphore::new(MAX_UNI_READERS));
        let permits = (0..MAX_UNI_READERS).map(|_| readers.clone().try_acquire_owned().unwrap()).collect::<Vec<_>>();

        assert!(readers.clone().try_acquire_owned().is_err());
        drop(permits);
        assert!(readers.clone().try_acquire_owned().is_ok());
    }

    #[test]
    fn start_rejects_duplicate_and_post_close_attempts() {
        assert!(validate_start_state(false, false).is_ok());
        assert_eq!(validate_start_state(false, true).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(validate_start_state(true, false).unwrap_err().kind(), io::ErrorKind::NotConnected);
    }
}
