//! Hysteria2 server runtime for HTTP/3 authentication, raw QUIC TCP streams and DATAGRAM UDP.
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use http::header::HeaderValue;
use http::{Method, Request, Response, StatusCode};
use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use rand::Rng;
use rb_adapter::{
    BoxStream, ConnectionHandshake, ConnectionRouter, Inbound, InboundContext, Network, PacketConn, RouteError,
    Socksaddr,
};
use rb_config::{Hysteria2Inbound as Options, MemoryBytes, QuicOptions};
use rb_dialer::listener::Listener;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot, watch, Mutex as AsyncMutex};
use tokio::task::{JoinHandle, JoinSet};
use tracing::debug;

use super::auth::{hysteria_mbps_to_bps, AUTH_HOST, AUTH_OK_STATUS, AUTH_PATH};
use super::packet::{fragment, Reassembler, UdpMessage, MAX_FQDN_LENGTH, MAX_UDP_SIZE};
use super::tcp::{self, encode_tcp_response_prefix};

const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(300);
const FRAGMENT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_UDP_SESSIONS: usize = 1024;
const UDP_QUEUE_SIZE: usize = 64;
const HYSTERIA2_UDP_MTU: usize = 1200 - 3;
const TCP_RESPONSE_PADDING_MIN: usize = 128;
const TCP_RESPONSE_PADDING_MAX: usize = 1024;
const TCP_RESPONSE_MESSAGE_LIMIT: usize = 2048;
const PADDING_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

type UdpSessions = Arc<AsyncMutex<HashMap<u32, Arc<Hysteria2UdpSession>>>>;

#[derive(Debug)]
enum AuthFailure {
    Rejected,
    DriverStopped,
}

struct H3AuthConfig {
    users: HashMap<String, String>,
    send_bps: u64,
    receive_bps: u64,
    ignore_client_bandwidth: bool,
    controller: Arc<quinn::congestion::Hysteria2NegotiatedConfig>,
    udp_enabled: bool,
}

pub struct Hysteria2Inbound {
    tag: String,
    listener: Listener,
    tls: rb_tls::TlsServer,
    quic: QuicOptions,
    users: HashMap<String, String>,
    send_bps: u64,
    receive_bps: u64,
    ignore_client_bandwidth: bool,
    auth_timeout: Duration,
    udp_timeout: Duration,
    router: Arc<dyn ConnectionRouter>,
    local_addr: OnceLock<SocketAddr>,
    task: Mutex<Option<JoinHandle<()>>>,
    shutdown: Mutex<Option<oneshot::Sender<()>>>,
}

impl Hysteria2Inbound {
    pub fn new(options: &Options, tag: String, router: Arc<dyn ConnectionRouter>) -> Result<Self, String> {
        if options.masquerade.is_some() {
            return Err(unsupported_config_field("masquerade"));
        }
        if options.realm.is_some() {
            return Err(unsupported_config_field("realm"));
        }
        if options.obfs.is_some() {
            return Err(unsupported_config_field("obfs.type"));
        }
        if !options.bbr_profile.is_empty() {
            return Err(unsupported_config_field("bbr_profile"));
        }
        if options.brutal_debug {
            return Err(unsupported_config_field("brutal_debug"));
        }
        let tls_options = options.tls.as_ref().filter(|tls| tls.enabled).ok_or("TLS is required")?;
        let listen = options.listen_options();
        if !listen.detour.is_empty() {
            return Err(unsupported_config_field("detour"));
        }
        let mut users = HashMap::new();
        for user in &options.users {
            // sing-quic UpdateUsers assigns into a password-keyed map, so later
            // entries replace earlier ones when the same password is repeated.
            users.insert(user.password.clone(), user.name.clone());
        }
        let udp_timeout = if listen.udp_timeout.0 .0.is_zero() { DEFAULT_UDP_TIMEOUT } else { listen.udp_timeout.0 .0 };
        Ok(Self {
            tag,
            listener: Listener::new(&listen).map_err(|error| error.to_string())?,
            tls: rb_tls::TlsServer::new(tls_options)?,
            quic: hysteria2_quic_options(options),
            users,
            send_bps: hysteria_mbps_to_bps(options.up_mbps),
            receive_bps: hysteria_mbps_to_bps(options.down_mbps),
            ignore_client_bandwidth: options.ignore_client_bandwidth,
            auth_timeout: Duration::from_secs(3),
            udp_timeout,
            router,
            local_addr: OnceLock::new(),
            task: Mutex::new(None),
            shutdown: Mutex::new(None),
        })
    }

    fn prefix(&self) -> String {
        format!("inbound/hysteria2[{}]", self.tag)
    }

    async fn serve_connection(
        self: Arc<Self>,
        connection: Connection,
        controller: Arc<quinn::congestion::Hysteria2NegotiatedConfig>,
    ) {
        let (raw_tx, raw_rx) = mpsc::unbounded_channel();
        let (auth_tx, auth_rx) = oneshot::channel();
        let udp_enabled = connection.max_datagram_size().is_some();
        let authenticated = Arc::new(AtomicBool::new(false));
        let dispatch_authenticated = authenticated.clone();
        let adapter = h3_quinn::Connection::new_with_bidi_dispatch(connection.clone(), move |stream| {
            if !dispatch_authenticated.load(Ordering::Acquire) {
                let mut stream = stream;
                let error_code = VarInt::from_u32(1);
                let _ = stream.send.reset(error_code);
                let _ = stream.recv.stop(error_code);
            } else {
                let _ = raw_tx.send(stream);
            }
        });
        let inbound = self.clone();
        let h3_driver = tokio::spawn(async move {
            drive_h3(
                adapter,
                auth_tx,
                H3AuthConfig {
                    users: inbound.users.clone(),
                    send_bps: inbound.send_bps,
                    receive_bps: inbound.receive_bps,
                    ignore_client_bandwidth: inbound.ignore_client_bandwidth,
                    controller,
                    udp_enabled,
                },
                authenticated,
            )
            .await;
        });

        let authentication = tokio::time::timeout(self.auth_timeout, auth_rx).await;
        let user = match authentication {
            Ok(Ok(Ok(user))) => user,
            Ok(Ok(Err(AuthFailure::Rejected))) => {
                debug!("{}: authentication rejected", self.prefix());
                connection.close(VarInt::from_u32(1), b"authentication failed");
                h3_driver.abort();
                let _ = h3_driver.await;
                return;
            }
            Ok(Ok(Err(AuthFailure::DriverStopped))) | Ok(Err(_)) => {
                connection.close(VarInt::from_u32(1), b"HTTP/3 authentication failed");
                h3_driver.abort();
                let _ = h3_driver.await;
                return;
            }
            Err(_) => {
                debug!("{}: authentication timed out", self.prefix());
                connection.close(VarInt::from_u32(1), b"authentication timeout");
                h3_driver.abort();
                let _ = h3_driver.await;
                return;
            }
        };
        self.serve_authenticated(connection, user, raw_rx, h3_driver).await;
    }

    async fn serve_authenticated(
        self: Arc<Self>,
        connection: Connection,
        user: Option<String>,
        mut raw_rx: mpsc::UnboundedReceiver<h3_quinn::RawBidiStream>,
        mut h3_driver: JoinHandle<()>,
    ) {
        let udp_enabled = connection.max_datagram_size().is_some();
        let sessions: UdpSessions = Arc::new(AsyncMutex::new(HashMap::new()));
        let mut tasks = JoinSet::new();
        let mut expire = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = connection.closed() => break,
                raw = raw_rx.recv() => match raw {
                    Some(raw) => {
                        let inbound = self.clone();
                        let connection = connection.clone();
                        let user = user.clone();
                        tasks.spawn(async move {
                            if let Err(error) = inbound.handle_tcp(connection, raw, user).await {
                                debug!("{}: TCP stream: {error}", inbound.prefix());
                            }
                        });
                    }
                    None => break,
                },
                datagram = connection.read_datagram(), if udp_enabled => match datagram {
                    Ok(datagram) => {
                        if let Err(error) = self.handle_udp_datagram(&connection, &sessions, user.clone(), datagram.as_ref(), &mut tasks).await {
                            debug!("{}: invalid UDP datagram: {error}", self.prefix());
                            connection.close(VarInt::from_u32(1), b"invalid Hysteria2 UDP datagram");
                            break;
                        }
                    }
                    Err(error) => {
                        debug!("{}: receive UDP datagram: {error}", self.prefix());
                        break;
                    }
                },
                _ = expire.tick() => expire_incomplete_sessions(&sessions).await,
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = joined {
                        debug!("{}: connection task failed: {error}", self.prefix());
                    }
                },
                result = &mut h3_driver => {
                    if let Err(error) = result {
                        debug!("{}: HTTP/3 driver failed: {error}", self.prefix());
                    }
                    break;
                }
            }
        }

        close_all_sessions(&sessions).await;
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        h3_driver.abort();
        let _ = h3_driver.await;
    }

    async fn handle_tcp(
        &self,
        connection: Connection,
        raw: h3_quinn::RawBidiStream,
        user: Option<String>,
    ) -> io::Result<()> {
        let (mut send, mut recv) = (raw.send, raw.recv);
        let destination = match read_tcp_request(&mut recv).await {
            Ok(destination) => destination,
            Err(error) => {
                let message = error.to_string();
                let message = &message.as_bytes()[..message.len().min(TCP_RESPONSE_MESSAGE_LIMIT)];
                let response = encode_tcp_response_prefix(
                    1,
                    message,
                    &random_padding(TCP_RESPONSE_PADDING_MIN, TCP_RESPONSE_PADDING_MAX),
                )?;
                let _ = send.write_all(&response).await;
                let _ = send.finish();
                return Err(error);
            }
        };
        let mut context =
            InboundContext::new(&self.tag, "hysteria2", Network::Tcp, connection.remote_address(), destination);
        context.user = user;
        let stream: BoxStream = Box::new(Hysteria2TcpStream { send, recv });
        self.router.route_connection_with_handshake(context, stream, &Hysteria2TcpHandshake).await.map_err(other)
    }

    async fn handle_udp_datagram(
        &self,
        connection: &Connection,
        sessions: &UdpSessions,
        user: Option<String>,
        datagram: &[u8],
        tasks: &mut JoinSet<()>,
    ) -> io::Result<()> {
        let message = UdpMessage::decode(datagram)?;
        let session = {
            let mut sessions = sessions.lock().await;
            if !sessions.contains_key(&message.session_id) && sessions.len() >= MAX_UDP_SESSIONS {
                return Err(invalid_data("Hysteria2 UDP session limit reached"));
            }
            sessions
                .entry(message.session_id)
                .or_insert_with(|| Arc::new(Hysteria2UdpSession::new(message.session_id, connection.clone())))
                .clone()
        };
        if let Some(destination) = session.input(message).await? {
            let inbound_tag = self.tag.clone();
            let router = self.router.clone();
            let sessions = sessions.clone();
            let session_for_task = session.clone();
            let mut context =
                InboundContext::new(&self.tag, "hysteria2", Network::Udp, connection.remote_address(), destination);
            context.user = user;
            context.inbound_udp_timeout = Some(self.udp_timeout);
            tasks.spawn(async move {
                if let Err(error) = router.route_packet_connection(context, session_for_task.packet_conn.clone()).await
                {
                    debug!("inbound/hysteria2[{inbound_tag}]: UDP session {}: {error}", session_for_task.session_id);
                }
                session_for_task.close();
                let mut sessions = sessions.lock().await;
                if sessions
                    .get(&session_for_task.session_id)
                    .is_some_and(|current| Arc::ptr_eq(current, &session_for_task))
                {
                    sessions.remove(&session_for_task.session_id);
                }
            });
        }
        Ok(())
    }
}

#[async_trait]
impl Inbound for Hysteria2Inbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "hysteria2"
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr.get().copied()
    }

    async fn start(self: Arc<Self>) -> io::Result<()> {
        if self.task.lock().unwrap().is_some() {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "Hysteria2 inbound is already started"));
        }
        self.tls.start().map_err(other)?;
        let socket = self.listener.listen_udp()?;
        let local = socket.local_addr()?;
        let _ = self.local_addr.set(local);
        let mut tls = (*self.tls.rustls_config()).clone();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let tls = Arc::new(tls);
        let endpoint = rb_dialer::quic::hysteria2_server_endpoint(socket, tls.clone(), &self.quic)?;
        let inbound = self.clone();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        *self.shutdown.lock().unwrap() = Some(shutdown_tx);
        *self.task.lock().unwrap() = Some(tokio::spawn(async move {
            inbound.run_endpoint(endpoint, tls, shutdown_rx).await;
        }));
        Ok(())
    }

    async fn close(&self) {
        if let Some(shutdown) = self.shutdown.lock().unwrap().take() {
            let _ = shutdown.send(());
        }
        let task = self.task.lock().unwrap().take();
        if let Some(task) = task {
            let _ = task.await;
        }
        self.tls.close();
    }
}

impl Hysteria2Inbound {
    async fn run_endpoint(
        self: Arc<Self>,
        endpoint: Endpoint,
        tls: Arc<rustls::ServerConfig>,
        mut shutdown: oneshot::Receiver<()>,
    ) {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                incoming = endpoint.accept() => match incoming {
                    Some(incoming) => {
                        let inbound = self.clone();
                        let tls = tls.clone();
                        let options = self.quic.clone();
                        connections.spawn(async move {
                            let controller = Arc::new(quinn::congestion::Hysteria2NegotiatedConfig::default());
                            let server_config = match rb_dialer::quic::hysteria2_server_config(tls, &options, controller.clone()) {
                                Ok(config) => Arc::new(config),
                                Err(error) => {
                                    incoming.refuse();
                                    debug!("{}: server config: {error}", inbound.prefix());
                                    return;
                                }
                            };
                            let connecting = match incoming.accept_with(server_config) {
                                Ok(connecting) => connecting,
                                Err(error) => {
                                    debug!("{}: accept connection: {error}", inbound.prefix());
                                    return;
                                }
                            };
                            match connecting.await {
                                Ok(connection) => inbound.serve_connection(connection, controller).await,
                                Err(error) => debug!("{}: QUIC handshake: {error}", inbound.prefix()),
                            }
                        });
                    }
                    None => break,
                },
                joined = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(error)) = joined {
                        debug!("{}: connection task failed: {error}", self.prefix());
                    }
                }
            }
        }
        endpoint.close(VarInt::from_u32(0), b"Hysteria2 inbound closed");
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        endpoint.wait_idle().await;
    }
}

async fn drive_h3<C>(
    adapter: C,
    auth_tx: oneshot::Sender<Result<Option<String>, AuthFailure>>,
    auth: H3AuthConfig,
    authenticated: Arc<AtomicBool>,
) where
    C: h3::quic::Connection<bytes::Bytes> + Send + 'static,
    C::BidiStream: Send + 'static,
    C::RecvStream: Send + 'static,
    C::SendStream: Send + 'static,
{
    let mut server = match h3::server::builder().build(adapter).await {
        Ok(server) => server,
        Err(error) => {
            let _ = auth_tx.send(Err(AuthFailure::DriverStopped));
            debug!("Hysteria2 establish HTTP/3: {error}");
            return;
        }
    };
    let mut auth_tx = Some(auth_tx);
    loop {
        let resolver = match server.accept().await {
            Ok(Some(resolver)) => resolver,
            Ok(None) => break,
            Err(error) => {
                debug!("Hysteria2 HTTP/3 accept: {error}");
                break;
            }
        };
        let (request, mut stream) = match resolver.resolve_request().await {
            Ok(request) => request,
            Err(error) => {
                debug!("Hysteria2 HTTP/3 request: {error}");
                if let Some(auth_tx) = auth_tx.take() {
                    let _ = auth_tx.send(Err(AuthFailure::DriverStopped));
                    return;
                }
                continue;
            }
        };
        if let Some(auth_tx) = auth_tx.take() {
            let result = authenticate_request(
                &request,
                &auth.users,
                auth.send_bps,
                auth.receive_bps,
                auth.ignore_client_bandwidth,
                &auth.controller,
            );
            match result {
                Ok(user) => {
                    let response = match auth_response(
                        auth.receive_bps,
                        auth.receive_bps == 0 && auth.ignore_client_bandwidth,
                        auth.udp_enabled,
                    ) {
                        Ok(response) => response,
                        Err(_) => {
                            let _ = auth_tx.send(Err(AuthFailure::DriverStopped));
                            return;
                        }
                    };
                    if let Err(error) = stream.send_response(response).await {
                        let _ = auth_tx.send(Err(AuthFailure::DriverStopped));
                        debug!("Hysteria2 send auth response: {error}");
                        return;
                    }
                    if let Err(error) = stream.finish().await {
                        let _ = auth_tx.send(Err(AuthFailure::DriverStopped));
                        debug!("Hysteria2 finish auth response: {error}");
                        return;
                    }
                    authenticated.store(true, Ordering::Release);
                    let _ = auth_tx.send(Ok(user));
                }
                Err(error) => {
                    let response = Response::builder().status(StatusCode::NOT_FOUND).body(());
                    if let Ok(response) = response {
                        let _ = stream.send_response(response).await;
                        let _ = stream.finish().await;
                    }
                    let _ = auth_tx.send(Err(error));
                    return;
                }
            }
        } else {
            let response = authenticated_request_response(
                &request,
                auth.receive_bps,
                auth.receive_bps == 0 && auth.ignore_client_bandwidth,
                auth.udp_enabled,
            );
            if let Ok(response) = response {
                let _ = stream.send_response(response).await;
                let _ = stream.finish().await;
            }
        }
    }
    if let Some(auth_tx) = auth_tx {
        let _ = auth_tx.send(Err(AuthFailure::DriverStopped));
    }
}

fn authenticate_request(
    request: &Request<()>,
    users: &HashMap<String, String>,
    send_bps: u64,
    receive_bps: u64,
    ignore_client_bandwidth: bool,
    controller: &quinn::congestion::Hysteria2NegotiatedConfig,
) -> Result<Option<String>, AuthFailure> {
    if !is_auth_request(request) {
        return Err(AuthFailure::Rejected);
    }
    let password =
        request.headers().get("hysteria-auth").and_then(|value| value.to_str().ok()).ok_or(AuthFailure::Rejected)?;
    let Some(user) = users.get(password) else {
        return Err(AuthFailure::Rejected);
    };
    let client_rx = request
        .headers()
        .get("hysteria-cc-rx")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_default();
    if receive_bps > 0 && ignore_client_bandwidth && client_rx == 0 {
        return Err(AuthFailure::Rejected);
    }
    if !(receive_bps == 0 && ignore_client_bandwidth) && client_rx > 0 {
        let rate = if send_bps > 0 && client_rx > send_bps { send_bps } else { client_rx };
        controller.select_brutal(rate).map_err(|_| AuthFailure::Rejected)?;
    } else {
        controller.select_meta2();
    }
    Ok((!user.is_empty()).then(|| user.clone()))
}

fn is_auth_request(request: &Request<()>) -> bool {
    request.method() == Method::POST
        && request.uri().path() == AUTH_PATH
        && request.uri().authority().map(|authority| authority.as_str()) == Some(AUTH_HOST)
}

fn auth_response(receive_bps: u64, receive_auto: bool, udp_enabled: bool) -> io::Result<Response<()>> {
    let mut response = Response::builder()
        .status(StatusCode::from_u16(AUTH_OK_STATUS).expect("Hysteria2 auth status is valid"))
        .body(())
        .map_err(other)?;
    let rx = if receive_auto { "auto".to_string() } else { receive_bps.to_string() };
    let padding = HeaderValue::from_bytes(&random_padding(256, 2048)).map_err(other)?;
    response.headers_mut().insert("hysteria-udp", HeaderValue::from_static(if udp_enabled { "true" } else { "false" }));
    response.headers_mut().insert("hysteria-cc-rx", HeaderValue::from_str(&rx).map_err(other)?);
    response.headers_mut().insert("hysteria-padding", padding);
    Ok(response)
}

fn authenticated_request_response(
    request: &Request<()>,
    receive_bps: u64,
    receive_auto: bool,
    udp_enabled: bool,
) -> io::Result<Response<()>> {
    if is_auth_request(request) {
        // sing-quic accepts repeated auth requests on an already authenticated
        // connection without checking the password again.
        auth_response(receive_bps, receive_auto, udp_enabled)
    } else {
        Response::builder().status(StatusCode::NOT_FOUND).body(()).map_err(other)
    }
}

async fn read_tcp_request(stream: &mut RecvStream) -> io::Result<Socksaddr> {
    // h3-quinn consumed the initial 0x401 varint for dispatch; reconstruct it
    // so the shared codec validates the complete request prefix.
    let mut prefix = vec![0x44, 0x01];
    let (address_length, encoded) = read_quic_varint(stream).await?;
    prefix.extend_from_slice(&encoded);
    let address_length =
        usize::try_from(address_length).map_err(|_| invalid_data("Hysteria2 TCP address length overflow"))?;
    if address_length == 0 || address_length > 2048 {
        return Err(invalid_data("invalid Hysteria2 TCP destination length"));
    }
    let mut address = vec![0; address_length];
    stream.read_exact(&mut address).await.map_err(other)?;
    prefix.extend_from_slice(&address);
    let (padding_length, encoded) = read_quic_varint(stream).await?;
    prefix.extend_from_slice(&encoded);
    let padding_length =
        usize::try_from(padding_length).map_err(|_| invalid_data("Hysteria2 TCP padding length overflow"))?;
    if padding_length > 4096 {
        return Err(invalid_data("Hysteria2 TCP padding exceeds the limit"));
    }
    let mut padding = vec![0; padding_length];
    stream.read_exact(&mut padding).await.map_err(other)?;
    prefix.extend_from_slice(&padding);
    let request = tcp::decode_tcp_request_prefix(&prefix)?;
    parse_destination(&request.destination)
}

async fn read_quic_varint(stream: &mut RecvStream) -> io::Result<(u64, Vec<u8>)> {
    let mut encoded = [0; 8];
    stream.read_exact(&mut encoded[..1]).await.map_err(other)?;
    let length = 1usize << (encoded[0] >> 6);
    if length > 1 {
        stream.read_exact(&mut encoded[1..length]).await.map_err(other)?;
    }
    let mut value = u64::from(encoded[0] & 0x3f);
    for byte in &encoded[1..length] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok((value, encoded[..length].to_vec()))
}

fn parse_destination(destination: &str) -> io::Result<Socksaddr> {
    let (host, port) = if let Some(bracketed) = destination.strip_prefix('[') {
        let end = bracketed.find(']').ok_or_else(|| invalid_data("invalid Hysteria2 destination"))?;
        let remainder = &bracketed[end + 1..];
        let port = remainder.strip_prefix(':').ok_or_else(|| invalid_data("invalid Hysteria2 destination port"))?;
        let host = &bracketed[..end];
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(invalid_data("invalid Hysteria2 IPv6 destination"));
        }
        (host, port)
    } else {
        destination.rsplit_once(':').ok_or_else(|| invalid_data("invalid Hysteria2 destination"))?
    };
    let port = port.parse::<u16>().map_err(|_| invalid_data("invalid Hysteria2 destination port"))?;
    if host.is_empty() || (host.contains(':') && host.parse::<std::net::IpAddr>().is_err()) {
        return Err(invalid_data("invalid Hysteria2 destination host"));
    }
    if host.len() > MAX_FQDN_LENGTH && host.parse::<std::net::IpAddr>().is_err() {
        return Err(invalid_data("Hysteria2 destination FQDN exceeds 255 bytes"));
    }
    Ok(Socksaddr::from_host_port(host, port))
}

fn hysteria2_quic_options(options: &Options) -> QuicOptions {
    let duration_or_default = |duration: rb_config::Duration, seconds| {
        if duration.0.is_zero() {
            rb_config::Duration(Duration::from_secs(seconds))
        } else {
            duration
        }
    };
    let window_or_default = |window: Option<MemoryBytes>, default| {
        window.filter(|window| window.value() != 0).unwrap_or(MemoryBytes(default))
    };
    QuicOptions {
        idle_timeout: duration_or_default(options.idle_timeout, 30),
        keep_alive_period: duration_or_default(options.keep_alive_period, 10),
        stream_receive_window: Some(window_or_default(options.stream_receive_window, 8 << 20)),
        connection_receive_window: Some(window_or_default(options.connection_receive_window, 20 << 20)),
        max_concurrent_streams: options.max_concurrent_streams,
        initial_packet_size: options.initial_packet_size,
        disable_path_mtu_discovery: options.disable_path_mtu_discovery,
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
        if let Some(session) = sessions.lock().await.remove(&session_id) {
            session.close();
        }
    }
}

async fn close_all_sessions(sessions: &UdpSessions) {
    let sessions = std::mem::take(&mut *sessions.lock().await);
    for session in sessions.into_values() {
        session.close();
    }
}

struct Hysteria2UdpSession {
    session_id: u32,
    packet_conn: Arc<Hysteria2PacketConn>,
    reassembler: Mutex<Reassembler>,
    route_started: AtomicBool,
    last_activity: Mutex<Instant>,
}

impl Hysteria2UdpSession {
    fn new(session_id: u32, connection: Connection) -> Self {
        Self {
            session_id,
            packet_conn: Arc::new(Hysteria2PacketConn::new(session_id, connection)),
            reassembler: Mutex::new(Reassembler::new(256, MAX_UDP_SIZE)),
            route_started: AtomicBool::new(false),
            last_activity: Mutex::new(Instant::now()),
        }
    }

    async fn input(&self, message: UdpMessage) -> io::Result<Option<Socksaddr>> {
        *self.last_activity.lock().unwrap() = Instant::now();
        let complete = self.reassembler.lock().unwrap().push(message)?;
        let Some(message) = complete else { return Ok(None) };
        if message.payload.len() > MAX_UDP_SIZE {
            return Err(invalid_data("Hysteria2 UDP payload exceeds 4096 bytes"));
        }
        let destination = parse_destination(&message.destination)?;
        self.packet_conn.enqueue(message.payload, destination.clone()).await?;
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

struct Hysteria2PacketConn {
    session_id: u32,
    connection: Connection,
    packet_id: AtomicU32,
    tx: mpsc::Sender<(Vec<u8>, Socksaddr)>,
    rx: AsyncMutex<mpsc::Receiver<(Vec<u8>, Socksaddr)>>,
    closed_tx: watch::Sender<bool>,
    closed_rx: watch::Receiver<bool>,
}

impl Hysteria2PacketConn {
    fn new(session_id: u32, connection: Connection) -> Self {
        let (tx, rx) = mpsc::channel(UDP_QUEUE_SIZE);
        let (closed_tx, closed_rx) = watch::channel(false);
        Self { session_id, connection, packet_id: AtomicU32::new(0), tx, rx: AsyncMutex::new(rx), closed_tx, closed_rx }
    }

    async fn enqueue(&self, data: Vec<u8>, destination: Socksaddr) -> io::Result<()> {
        if *self.closed_rx.borrow() {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "Hysteria2 UDP session closed"));
        }
        self.tx
            .send((data, destination))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Hysteria2 UDP session closed"))
    }

    fn close(&self) {
        self.closed_tx.send_replace(true);
    }
}

#[async_trait]
impl PacketConn for Hysteria2PacketConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        if *self.closed_rx.borrow() {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "Hysteria2 UDP session closed"));
        }
        let mut rx = self.rx.lock().await;
        let mut closed_rx = self.closed_rx.clone();
        let packet = tokio::select! {
            packet = rx.recv() => packet.ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "Hysteria2 UDP session closed"))?,
            _ = closed_rx.changed() => return Err(io::Error::new(io::ErrorKind::BrokenPipe, "Hysteria2 UDP session closed")),
        };
        let (data, address) = packet;
        let length = data.len().min(buffer.len());
        buffer[..length].copy_from_slice(&data[..length]);
        Ok((length, address))
    }

    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        if *self.closed_rx.borrow() {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "Hysteria2 UDP session closed"));
        }
        if data.len() > MAX_UDP_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Hysteria2 UDP payload exceeds 4096 bytes"));
        }
        if address.domain().is_some_and(|domain| domain.len() > MAX_FQDN_LENGTH) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Hysteria2 destination FQDN exceeds 255 bytes"));
        }
        let mut message = UdpMessage {
            session_id: self.session_id,
            packet_id: self.packet_id.fetch_add(1, Ordering::Relaxed) as u16,
            fragment_id: 0,
            fragment_total: 1,
            destination: address.to_string(),
            payload: data.to_vec(),
        };
        let Some(mut max_datagram) = self.connection.max_datagram_size() else {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "Hysteria2 QUIC datagrams are unavailable"));
        };
        max_datagram = max_datagram.min(HYSTERIA2_UDP_MTU);
        let overhead = UdpMessage { payload: Vec::new(), ..message.clone() }.encode()?.len();
        for attempt in 0..=DATAGRAM_MTU_RETRIES {
            let fragments = fragment(&message, max_datagram)?;
            let mut too_large = false;
            for fragment in fragments {
                match self.connection.send_datagram(fragment.encode()?.into()) {
                    Ok(()) => {}
                    Err(quinn::SendDatagramError::TooLarge) => {
                        too_large = true;
                        break;
                    }
                    Err(error) => {
                        return Err(io::Error::other(format!("Hysteria2 send UDP datagram: {error:?}")));
                    }
                }
            }
            if !too_large {
                return Ok(());
            }
            if attempt == DATAGRAM_MTU_RETRIES {
                break;
            }
            // A new packet ID prevents fragments already sent with the previous MTU from
            // being mixed with the retry's differently partitioned packet.
            let next_mtu = prepare_partial_datagram_retry(
                &mut message,
                max_datagram,
                self.connection.max_datagram_size(),
                overhead,
                || self.packet_id.fetch_add(1, Ordering::Relaxed) as u16,
            )
            .ok_or_else(|| io::Error::other("Hysteria2 UDP datagram remains too large after MTU adjustment"))?;
            max_datagram = next_mtu;
        }
        Err(io::Error::other("Hysteria2 UDP datagram exceeds the path MTU retry limit"))
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        Some(self.connection.remote_address())
    }
}

const DATAGRAM_MTU_RETRIES: usize = 32;

fn next_datagram_mtu(current: usize, live_limit: Option<usize>, header_len: usize) -> Option<usize> {
    let live_limit = live_limit.unwrap_or(current).min(HYSTERIA2_UDP_MTU);
    let candidate = if live_limit < current { live_limit } else { current.saturating_sub(32) };
    (candidate > header_len).then_some(candidate)
}

fn prepare_partial_datagram_retry(
    message: &mut UdpMessage,
    current_mtu: usize,
    live_limit: Option<usize>,
    header_len: usize,
    next_packet_id: impl FnOnce() -> u16,
) -> Option<usize> {
    let next_mtu = next_datagram_mtu(current_mtu, live_limit, header_len)?;
    message.packet_id = next_packet_id();
    Some(next_mtu)
}

struct Hysteria2TcpStream {
    send: SendStream,
    recv: RecvStream,
}

struct Hysteria2TcpHandshake;

#[async_trait]
impl ConnectionHandshake for Hysteria2TcpHandshake {
    async fn success(&self, client: &mut BoxStream) -> io::Result<()> {
        let response =
            encode_tcp_response_prefix(0, b"", &random_padding(TCP_RESPONSE_PADDING_MIN, TCP_RESPONSE_PADDING_MAX))?;
        client.write_all(&response).await
    }

    async fn failure(&self, client: &mut BoxStream, error: &RouteError) -> io::Result<()> {
        let message = error.to_string();
        let message = &message.as_bytes()[..message.len().min(TCP_RESPONSE_MESSAGE_LIMIT)];
        let response = encode_tcp_response_prefix(
            1,
            message,
            &random_padding(TCP_RESPONSE_PADDING_MIN, TCP_RESPONSE_PADDING_MAX),
        )?;
        client.write_all(&response).await
    }
}

impl AsyncRead for Hysteria2TcpStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buffer)
    }
}

impl AsyncWrite for Hysteria2TcpStream {
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

fn random_padding(minimum: usize, maximum_exclusive: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    let length = rng.random_range(minimum..maximum_exclusive);
    (0..length).map(|_| PADDING_CHARS[rng.random_range(0..PADDING_CHARS.len())]).collect()
}

fn unsupported_config_field(field: &str) -> String {
    format!("{field}: `{field}` is not supported by rust-box yet")
}

fn other(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_uses_a_newly_reported_smaller_live_limit() {
        assert_eq!(next_datagram_mtu(1197, Some(1000), 24), Some(1000));
    }

    #[test]
    fn retry_downshifts_when_the_live_limit_is_stale() {
        assert_eq!(next_datagram_mtu(1197, Some(1197), 24), Some(1165));
        assert_eq!(next_datagram_mtu(1197, None, 24), Some(1165));
    }

    #[test]
    fn retry_stops_when_no_room_remains_for_payload() {
        assert_eq!(next_datagram_mtu(100, Some(100), 68), None);
    }

    #[test]
    fn partial_datagram_retry_downshifts_mtu_and_uses_a_fresh_packet_id() {
        let mut message = UdpMessage {
            session_id: 7,
            packet_id: 11,
            fragment_id: 0,
            fragment_total: 1,
            destination: "192.0.2.1:53".to_string(),
            payload: vec![1; 1400],
        };

        let next_mtu = prepare_partial_datagram_retry(&mut message, 1197, None, 24, || 12);

        assert_eq!(next_mtu, Some(1165));
        assert_eq!(message.packet_id, 12);
    }

    fn auth_request(password: &str, client_rx: Option<&str>) -> Request<()> {
        let mut request = Request::builder().method(Method::POST).uri(format!("https://{AUTH_HOST}{AUTH_PATH}"));
        if !password.is_empty() {
            request = request.header("hysteria-auth", password);
        }
        if let Some(client_rx) = client_rx {
            request = request.header("hysteria-cc-rx", client_rx);
        }
        request.body(()).unwrap()
    }

    #[test]
    fn auth_maps_password_to_user_and_accepts_brutal_bandwidth() {
        let request = auth_request("alice-secret", Some("2000000"));
        let users = HashMap::from([("alice-secret".to_string(), "alice".to_string())]);
        let controller = quinn::congestion::Hysteria2NegotiatedConfig::default();

        let user = authenticate_request(&request, &users, 1_000_000, 0, false, &controller).unwrap();

        assert_eq!(user.as_deref(), Some("alice"));
    }

    #[test]
    fn auth_rejects_unknown_password() {
        let request = auth_request("wrong", Some("1000000"));
        let users = HashMap::from([("alice-secret".to_string(), "alice".to_string())]);
        let controller = quinn::congestion::Hysteria2NegotiatedConfig::default();

        assert!(matches!(authenticate_request(&request, &users, 0, 0, false, &controller), Err(AuthFailure::Rejected)));
    }

    #[test]
    fn auth_selects_pinned_meta2_standard_profile_when_brutal_is_not_selected() {
        let request = auth_request("alice-secret", None);
        let users = HashMap::from([("alice-secret".to_string(), "alice".to_string())]);
        let controller = Arc::new(quinn::congestion::Hysteria2NegotiatedConfig::default());

        assert_eq!(
            authenticate_request(&request, &users, 0, 0, false, &controller).unwrap(),
            Some("alice".to_string())
        );
        let selected = quinn::congestion::ControllerFactory::build(controller.clone(), Instant::now(), 1200);
        assert_eq!(selected.initial_window(), 32 * 1200);
    }

    #[test]
    fn auth_response_has_sing_quic_status_and_headers() {
        let response = auth_response(123_456, false, true).unwrap();

        assert_eq!(response.status().as_u16(), AUTH_OK_STATUS);
        assert_eq!(response.headers()["hysteria-udp"], "true");
        assert_eq!(response.headers()["hysteria-cc-rx"], "123456");
        let padding = response.headers()["hysteria-padding"].to_str().unwrap();
        assert!((256..2048).contains(&padding.len()));
        assert!(padding.bytes().all(|byte| PADDING_CHARS.contains(&byte)));
    }

    #[test]
    fn authenticated_duplicate_auth_does_not_recheck_password() {
        let request = auth_request("", None);

        let response = authenticated_request_response(&request, 0, false, true).unwrap();

        assert_eq!(response.status().as_u16(), AUTH_OK_STATUS);
        assert_eq!(response.headers()["hysteria-udp"], "true");
    }

    #[test]
    fn authenticated_non_auth_request_returns_not_found() {
        let request = Request::builder().method(Method::GET).uri("https://example.com/other").body(()).unwrap();

        let response = authenticated_request_response(&request, 0, false, true).unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn destination_parser_accepts_domain_ipv4_and_ipv6() {
        for destination in ["example.test:443", "127.0.0.1:53", "[2001:db8::1]:8443"] {
            assert_eq!(parse_destination(destination).unwrap().to_string(), destination);
        }
    }

    #[test]
    fn destination_parser_rejects_malformed_and_oversized_hosts() {
        for destination in ["", "example.test", "example.test:not-a-port", "example.test:65536", "[not-ipv6]:443"] {
            assert!(parse_destination(destination).is_err(), "accepted {destination:?}");
        }
        let oversized = format!("{}:443", "a".repeat(MAX_FQDN_LENGTH + 1));
        assert!(parse_destination(&oversized).is_err());
    }
}
