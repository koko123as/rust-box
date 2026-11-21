//! The `trojan` inbound and outbound (sing-box `protocol/trojan`) with the
//! wire format of sing-box `transport/trojan`.
//!
//! A request is `hex(SHA224(password)) CRLF command address CRLF`, then the
//! payload. Command 1 carries a TCP stream; command 3 carries UDP packets,
//! each `address length CRLF payload`. The client sends the TCP request
//! right after the dial (sing-box's `kickWriteHandshake` writes it with an
//! empty payload when nothing is cached) and the UDP request with its first
//! packet.
//!
//! The inbound authenticates the first 56 bytes (one read, as sing-box);
//! a connection that does not authenticate goes to `fallback` (or the
//! `fallback_for_alpn` server for its negotiated ALPN) with the bytes read
//! put back in front, else it is closed.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use async_trait::async_trait;
use rb_adapter::{
    BoxStream, ConnectionRouter, Inbound, InboundContext, Network, Outbound, PacketConn, PrefixedStream, RouteError,
    SharedPacketConn, Socksaddr,
};
use rb_config::{TrojanInbound as InboundOptions, TrojanOutbound as OutboundOptions};
use rb_dialer::listener::Listener;
use rb_dialer::{new_outbound_dialer, Dialer, DialerEnv};
use sha2::{Digest, Sha224};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::framed::{self, cause, FrameReader};

pub const KEY_LENGTH: usize = 56;
pub const COMMAND_TCP: u8 = 1;
pub const COMMAND_UDP: u8 = 3;
/// trojan-go multiplex (smux over the request).
pub const COMMAND_MUX: u8 = 0x7f;
const CRLF: &[u8] = b"\r\n";

/// sing-box `trojan.Key`: the hex SHA-224 of the password.
pub fn key(password: &str) -> [u8; KEY_LENGTH] {
    let digest = Sha224::digest(password.as_bytes());
    let mut key = [0u8; KEY_LENGTH];
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in digest.iter().enumerate() {
        key[index * 2] = HEX[(byte >> 4) as usize];
        key[index * 2 + 1] = HEX[(byte & 0x0f) as usize];
    }
    key
}

/// A request header and its payload (sing-box `ClientHandshake`).
pub fn encode_request(
    key: &[u8; KEY_LENGTH],
    command: u8,
    destination: &Socksaddr,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let mut buffer = Vec::with_capacity(KEY_LENGTH + 5 + rb_shadowsocks::address_len(destination) + payload.len());
    buffer.extend_from_slice(key);
    buffer.extend_from_slice(CRLF);
    buffer.push(command);
    rb_shadowsocks::write_address(&mut buffer, destination)?;
    buffer.extend_from_slice(CRLF);
    buffer.extend_from_slice(payload);
    Ok(buffer)
}

/// One UDP packet (sing-box `WritePacket`).
pub fn encode_packet(destination: &Socksaddr, payload: &[u8]) -> io::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "trojan: packet too large"));
    }
    let mut buffer = Vec::with_capacity(rb_shadowsocks::address_len(destination) + 4 + payload.len());
    rb_shadowsocks::write_address(&mut buffer, destination)?;
    buffer.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    buffer.extend_from_slice(CRLF);
    buffer.extend_from_slice(payload);
    Ok(buffer)
}

/// The first UDP packet with the request in front (sing-box
/// `ClientHandshakePacket`).
pub fn encode_packet_request(key: &[u8; KEY_LENGTH], destination: &Socksaddr, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut buffer = encode_request(key, COMMAND_UDP, destination, &[])?;
    buffer.extend_from_slice(&encode_packet(destination, payload)?);
    Ok(buffer)
}

/// A packet's address and payload.
pub type Packet = (Socksaddr, Vec<u8>);

/// A whole UDP packet at the front of `data` (sing-box `ReadPacket`; the
/// CRLF is skipped unchecked, as there).
pub fn parse_packet(data: &[u8]) -> io::Result<Option<(Packet, usize)>> {
    let (address, position) = match rb_shadowsocks::read_address(data) {
        Ok(found) => found,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(cause(error, "read destination")),
    };
    let Some(length) = framed::u16_at(data, position) else { return Ok(None) };
    let start = position + 4;
    let end = start + length as usize;
    if data.len() < end {
        return Ok(None);
    }
    Ok(Some(((address, data[start..end].to_vec()), end)))
}

/// The packets of a trojan UDP request, for either side. The client side
/// writes the request in front of its first packet.
pub struct TrojanPacketConn {
    reader: tokio::sync::Mutex<FrameReader<ReadHalf<BoxStream>>>,
    writer: tokio::sync::Mutex<(WriteHalf<BoxStream>, Option<[u8; KEY_LENGTH]>)>,
}

impl TrojanPacketConn {
    /// The server side of a request that was read.
    pub fn server(stream: BoxStream) -> Self {
        Self::new(stream, None)
    }

    /// The client side (sing-box `ClientPacketConn`).
    pub fn client(stream: BoxStream, key: [u8; KEY_LENGTH]) -> Self {
        Self::new(stream, Some(key))
    }

    fn new(stream: BoxStream, key: Option<[u8; KEY_LENGTH]>) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        TrojanPacketConn {
            reader: tokio::sync::Mutex::new(FrameReader::new(reader)),
            writer: tokio::sync::Mutex::new((writer, key)),
        }
    }
}

#[async_trait]
impl PacketConn for TrojanPacketConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let (address, payload) = self.reader.lock().await.next(parse_packet).await?;
        let length = payload.len().min(buffer.len());
        buffer[..length].copy_from_slice(&payload[..length]);
        Ok((length, address))
    }

    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        let mut guard = self.writer.lock().await;
        let (writer, key) = &mut *guard;
        let frame = match key.take() {
            Some(key) => encode_packet_request(&key, address, data).map_err(|error| cause(error, "write request"))?,
            None => encode_packet(address, data)?,
        };
        writer.write_all(&frame).await?;
        writer.flush().await
    }
}

/// The `trojan` outbound.
pub struct TrojanOutbound {
    tag: String,
    /// The server dialer, TLS on top when `tls` is enabled.
    dialer: Arc<dyn Dialer>,
    server: Socksaddr,
    key: [u8; KEY_LENGTH],
    transport: Option<crate::v2ray::StreamTransport>,
    tls_server_name: Option<String>,
    networks: Vec<Network>,
    /// The sing-mux client when `multiplex` is enabled.
    mux: Option<rb_mux::Client>,
}

impl TrojanOutbound {
    /// sing-box `trojan.NewOutbound`.
    pub fn new(
        options: &OutboundOptions,
        tag: String,
        env: &DialerEnv,
        certificates: &Arc<rb_certificate::Store>,
    ) -> Result<Arc<Self>, String> {
        let server = Socksaddr::from_host_port(&options.server, options.server_port);
        let transport = crate::v2ray::transport_options(options.transport.as_ref())?;
        let mut tls_server_name = None;
        let mut dialer = new_outbound_dialer(
            &options.dialer_options(),
            server.domain().is_some(),
            env,
            &format!("outbound/trojan[{tag}]"),
        )?;
        if let Some(tls) = options.tls.as_ref().filter(|tls| tls.enabled) {
            let client = rb_tls::TlsClient::new(tls, &options.server, certificates)?;
            tls_server_name = Some(client.server_name().to_owned());
            let client = if transport.is_some() { crate::v2ray::transport_tls_client(client) } else { client };
            dialer = Arc::new(rb_tls::TlsDialer::new(dialer, client));
        }
        let multiplex = crate::multiplex::client_options(options.multiplex.as_ref())?;
        let networks = options
            .network
            .build()
            .iter()
            .map(|network| if network == "udp" { Network::Udp } else { Network::Tcp })
            .collect();
        Ok(Arc::new_cyclic(|this| TrojanOutbound {
            tag,
            dialer,
            server,
            key: key(&options.password),
            transport,
            tls_server_name,
            networks,
            mux: crate::multiplex::new_client(this, multiplex),
        }))
    }

    /// A trojan TCP connection to `destination`, its request sent (sing-box
    /// `trojanDialer.DialContext` with the request written at once). A
    /// multiplex client dials its sessions with this.
    pub async fn connect(&self, destination: &Socksaddr) -> io::Result<BoxStream> {
        let mut stream = self.dialer.dial_tcp(&self.server).await?;
        if let Some(transport) = &self.transport {
            stream = crate::v2ray::transport_client(stream, &self.server, transport, self.tls_server_name.as_deref())
                .await?;
        }
        let request =
            encode_request(&self.key, COMMAND_TCP, destination, &[]).map_err(|error| cause(error, "write request"))?;
        stream.write_all(&request).await.map_err(|error| cause(error, "write request"))?;
        stream.flush().await?;
        Ok(stream)
    }

    /// A trojan UDP request to the server (its request goes with the first
    /// packet).
    pub async fn connect_packet(&self) -> io::Result<TrojanPacketConn> {
        let mut stream = self.dialer.dial_tcp(&self.server).await?;
        if let Some(transport) = &self.transport {
            stream = crate::v2ray::transport_client(stream, &self.server, transport, self.tls_server_name.as_deref())
                .await?;
        }
        Ok(TrojanPacketConn::client(stream, self.key))
    }
}

#[async_trait]
impl Outbound for TrojanOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "trojan"
    }

    fn networks(&self) -> &[Network] {
        &self.networks
    }

    async fn dial_tcp(&self, context: &InboundContext) -> io::Result<BoxStream> {
        match &self.mux {
            Some(mux) => mux.dial_tcp(&context.destination).await,
            None => self.connect(&context.destination).await,
        }
    }

    async fn listen_packet(&self, context: &InboundContext) -> io::Result<SharedPacketConn> {
        match &self.mux {
            Some(mux) => mux.listen_packet(&context.destination).await,
            None => Ok(Arc::new(self.connect_packet().await?)),
        }
    }
}

#[async_trait]
impl crate::multiplex::MuxConnect for TrojanOutbound {
    async fn connect_mux(&self, destination: &Socksaddr) -> io::Result<BoxStream> {
        self.connect(destination).await
    }
}

/// The `trojan` inbound.
pub struct TrojanInbound {
    tag: String,
    listener: Listener,
    names: Vec<String>,
    keys: HashMap<[u8; KEY_LENGTH], usize>,
    tls: Option<rb_tls::TlsServer>,
    transport: Option<crate::v2ray::StreamTransport>,
    /// Whether unauthenticated connections go to a fallback at all.
    fallback_enabled: bool,
    fallback: Option<Socksaddr>,
    fallback_for_alpn: HashMap<String, Socksaddr>,
    detour: Option<String>,
    router: Arc<dyn ConnectionRouter>,
    /// The sing-mux server when `multiplex` is enabled.
    multiplex: Option<rb_mux::ServerOptions>,
    /// The inbound itself, for the streams of multiplexed connections.
    this: OnceLock<Weak<Self>>,
    local_addr: OnceLock<SocketAddr>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl TrojanInbound {
    /// sing-box `trojan.NewInbound`.
    pub fn new(options: &InboundOptions, tag: String, router: Arc<dyn ConnectionRouter>) -> Result<Self, String> {
        let transport = crate::v2ray::transport_options(options.transport.as_ref())?;
        let tls = match options.tls.as_ref().filter(|tls| tls.enabled) {
            Some(tls) => Some(crate::v2ray::transport_tls_server(tls, transport.as_ref())?),
            None => None,
        };
        let fallback = options
            .fallback
            .as_ref()
            .filter(|fallback| !fallback.server.is_empty())
            .map(|fallback| Socksaddr::from_host_port(&fallback.server, fallback.server_port));
        let mut fallback_for_alpn = HashMap::new();
        if !options.fallback_for_alpn.is_empty() {
            if tls.is_none() {
                return Err("fallback for ALPN is not supported without TLS".into());
            }
            for (protocol, destination) in &options.fallback_for_alpn {
                let (server, port) = destination
                    .as_ref()
                    .map_or(("", 0), |destination| (destination.server.as_str(), destination.server_port));
                if server.is_empty() {
                    return Err(format!("invalid fallback address for ALPN {protocol}: :{port}"));
                }
                fallback_for_alpn.insert(protocol.clone(), Socksaddr::from_host_port(server, port));
            }
        }
        // sing-box `Service.UpdateUsers`.
        let mut keys = HashMap::new();
        for (index, user) in options.users.iter().enumerate() {
            if let Some(old) = keys.insert(key(&user.password), index) {
                return Err(format!("user already exists: password used by {old}"));
            }
        }
        let multiplex = crate::multiplex::server_options(options.multiplex.as_ref())?;
        let listen = options.listen_options();
        Ok(TrojanInbound {
            tag,
            listener: Listener::new(&listen)?,
            names: options.users.iter().map(|user| user.name.clone()).collect(),
            keys,
            tls,
            transport,
            fallback_enabled: fallback.is_some() || !fallback_for_alpn.is_empty(),
            fallback,
            fallback_for_alpn,
            detour: (!listen.detour.is_empty()).then(|| listen.detour.clone()),
            router,
            multiplex,
            this: OnceLock::new(),
            local_addr: OnceLock::new(),
            task: Mutex::new(None),
        })
    }

    fn log_prefix(&self) -> String {
        format!("inbound/trojan[{}]", self.tag)
    }

    /// Serves one connection (sing-box `Inbound.NewConnection`).
    async fn handle(&self, stream: BoxStream, context: InboundContext) {
        let source = context.source;
        let (stream, alpn): (BoxStream, Option<String>) = match &self.tls {
            Some(tls) => match tls.handshake(stream).await {
                Ok(stream) => {
                    let alpn =
                        stream.get_ref().1.alpn_protocol().map(|alpn| String::from_utf8_lossy(alpn).into_owned());
                    (Box::new(stream), alpn)
                }
                Err(error) => {
                    error!("{}: process connection from {source}: TLS handshake: {error}", self.log_prefix());
                    return;
                }
            },
            None => (stream, None),
        };
        let stream = match &self.transport {
            Some(transport) => match crate::v2ray::transport_server(stream, transport).await {
                Ok(stream) => stream,
                Err(error) => {
                    error!(
                        "{}: process connection from {source}: {} handshake: {error}",
                        self.log_prefix(),
                        transport.log_name()
                    );
                    return;
                }
            },
            None => stream,
        };
        if let Err(error) = self.serve(stream, context, alpn).await {
            error!("{}: process connection from {source}: {error}", self.log_prefix());
        }
    }

    /// sing-box `trojan.Service.NewConnection`.
    async fn serve(&self, mut stream: BoxStream, context: InboundContext, alpn: Option<String>) -> io::Result<()> {
        let mut key = [0u8; KEY_LENGTH];
        // One read, as sing-box: a short first read is not a trojan request.
        let read = stream.read(&mut key).await?;
        if read == 0 {
            return Err(framed::eof());
        }
        if read != KEY_LENGTH {
            return self.fallback(stream, key[..read].to_vec(), "bad request size", context, alpn).await;
        }
        let Some(&user) = self.keys.get(&key) else {
            return self.fallback(stream, key.to_vec(), "bad request", context, alpn).await;
        };
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).await.map_err(|error| cause(error, "skip crlf"))?;
        let command = stream.read_u8().await.map_err(|error| cause(error, "read command"))?;
        if !matches!(command, COMMAND_TCP | COMMAND_UDP | COMMAND_MUX) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("unknown command {command}")));
        }
        let destination =
            rb_shadowsocks::read_address_from(&mut stream).await.map_err(|error| cause(error, "read destination"))?;
        stream.read_exact(&mut crlf).await.map_err(|error| cause(error, "skip crlf"))?;
        match command {
            COMMAND_TCP => self.route(context, user, destination, stream).await,
            COMMAND_UDP => self.route_packet(context, user, destination, stream).await,
            _ => return self.serve_trojan_go_mux(stream, context, user).await,
        }
        Ok(())
    }

    /// The logged name of a user and the one routing sees (only a
    /// configured name: sing-box leaves `metadata.User` empty otherwise).
    fn user(&self, index: usize) -> (String, Option<String>) {
        match self.names.get(index).filter(|name| !name.is_empty()) {
            Some(name) => (name.clone(), Some(name.clone())),
            None => (index.to_string(), None),
        }
    }

    async fn route(&self, mut context: InboundContext, user: usize, destination: Socksaddr, stream: BoxStream) {
        let (logged, routed) = self.user(user);
        info!("{}: [{logged}] inbound connection to {destination}", self.log_prefix());
        context.inbound = self.tag.clone();
        context.inbound_type = "trojan";
        context.network = Network::Tcp;
        context.user = routed;
        if let Some(options) = self.multiplex.as_ref().filter(|_| rb_mux::is_destination(&destination)) {
            if let Some(this) = self.this.get().and_then(Weak::upgrade) {
                crate::multiplex::serve(this, options, context, stream, self.log_prefix()).await;
            }
            return;
        }
        context.destination = destination;
        self.finish(context.source, self.router.route_connection(context, stream).await);
    }

    /// trojan-go multiplex (sing-box `transport/trojan/mux.go`): an smux
    /// session whose streams start with a command and an address.
    async fn serve_trojan_go_mux(&self, stream: BoxStream, context: InboundContext, user: usize) -> io::Result<()> {
        let session = rb_mux::session::Session::smux(stream, false);
        loop {
            let mut stream: BoxStream = Box::new(session.accept().await?);
            let Some(this) = self.this.get().and_then(Weak::upgrade) else { return Ok(()) };
            let context = context.clone();
            tokio::spawn(async move {
                let result = async {
                    let command = stream.read_u8().await.map_err(|error| cause(error, "read command"))?;
                    let destination = rb_shadowsocks::read_address_from(&mut stream)
                        .await
                        .map_err(|error| cause(error, "read destination"))?;
                    match command {
                        COMMAND_TCP => this.route(context, user, destination, stream).await,
                        COMMAND_UDP => this.route_packet(context, user, destination, stream).await,
                        command => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("unknown command {command}"),
                            ))
                        }
                    }
                    Ok(())
                }
                .await;
                if let Err(error) = result {
                    error!("{}: process trojan-go multiplex connection: {error}", this.log_prefix());
                }
            });
        }
    }

    async fn route_packet(&self, mut context: InboundContext, user: usize, destination: Socksaddr, stream: BoxStream) {
        let (logged, routed) = self.user(user);
        info!("{}: [{logged}] inbound packet connection to {destination}", self.log_prefix());
        context.inbound = self.tag.clone();
        context.inbound_type = "trojan";
        context.network = Network::Udp;
        context.destination = destination;
        context.user = routed;
        let conn: SharedPacketConn = Arc::new(TrojanPacketConn::server(stream));
        self.finish(context.source, self.router.route_packet_connection(context, conn).await);
    }

    fn finish(&self, source: SocketAddr, result: Result<(), RouteError>) {
        match result {
            Ok(()) | Err(RouteError::Rejected) => {}
            Err(error) => warn!("{}: {source}: {error}", self.log_prefix()),
        }
    }

    /// sing-box `Service.fallback` and `Inbound.fallbackConnection`.
    async fn fallback(
        &self,
        stream: BoxStream,
        header: Vec<u8>,
        reason: &str,
        mut context: InboundContext,
        alpn: Option<String>,
    ) -> io::Result<()> {
        if !self.fallback_enabled {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{reason}: fallback disabled")));
        }
        let source = context.source;
        let mut destination = None;
        if !self.fallback_for_alpn.is_empty() {
            if let Some(protocol) = alpn.filter(|protocol| !protocol.is_empty()) {
                match self.fallback_for_alpn.get(&protocol) {
                    Some(found) => destination = Some(found.clone()),
                    None => {
                        debug!(
                            "{}: process connection from {source}: fallback disabled for ALPN: {protocol}",
                            self.log_prefix()
                        );
                        return Ok(());
                    }
                }
            }
        }
        let destination = match destination.or_else(|| self.fallback.clone()) {
            Some(destination) => destination,
            None => {
                debug!("{}: process connection from {source}: fallback disabled by default", self.log_prefix());
                return Ok(());
            }
        };
        info!("{}: fallback connection to {destination}", self.log_prefix());
        context.inbound = self.tag.clone();
        context.inbound_type = "trojan";
        context.network = Network::Tcp;
        context.destination = destination;
        let stream: BoxStream = Box::new(PrefixedStream::new(header, stream));
        self.finish(source, self.router.route_connection(context, stream).await);
        Ok(())
    }
}

#[async_trait]
impl crate::multiplex::MuxRouteTarget for TrojanInbound {
    async fn route_mux_stream(&self, mut context: InboundContext, destination: Socksaddr, stream: BoxStream) {
        context.network = Network::Tcp;
        context.destination = destination;
        self.finish(context.source, self.router.route_connection(context, stream).await);
    }

    async fn route_mux_packets(&self, mut context: InboundContext, destination: Socksaddr, conn: SharedPacketConn) {
        context.network = Network::Udp;
        context.destination = destination;
        self.finish(context.source, self.router.route_packet_connection(context, conn).await);
    }
}

fn canonical(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip().to_canonical(), address.port())
}

#[async_trait]
impl Inbound for TrojanInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "trojan"
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr.get().copied()
    }

    async fn start(self: Arc<Self>) -> io::Result<()> {
        let _ = self.this.set(Arc::downgrade(&self));
        if let Some(tls) = &self.tls {
            tls.start().map_err(|error| io::Error::other(format!("create TLS config: {error}")))?;
        }
        let listener = self.listener.listen_tcp()?;
        let local = listener.local_addr()?;
        let _ = self.local_addr.set(local);
        info!("{}: tcp server started at {}", self.log_prefix(), local);
        let inbound = self.clone();
        let task = tokio::spawn(async move {
            let mut accept_delay = Duration::ZERO;
            loop {
                match listener.accept().await {
                    Ok((stream, source)) => {
                        accept_delay = Duration::ZERO;
                        if let Err(error) = inbound.listener.accepted(&stream) {
                            debug!("{}: {source}: set socket options: {error}", inbound.log_prefix());
                        }
                        let origin = stream.local_addr().ok();
                        let inbound = inbound.clone();
                        tokio::spawn(async move {
                            info!("{}: inbound connection from {}", inbound.log_prefix(), source);
                            let mut context = InboundContext::new(
                                &inbound.tag,
                                "trojan",
                                Network::Tcp,
                                canonical(source),
                                Socksaddr::from(source),
                            );
                            context.origin_destination = origin;
                            context.inbound_detour = inbound.detour.clone();
                            inbound.handle(Box::new(stream), context).await
                        });
                    }
                    Err(error) => {
                        accept_delay = if accept_delay.is_zero() {
                            Duration::from_millis(5)
                        } else {
                            (accept_delay * 2).min(Duration::from_secs(1))
                        };
                        error!("{}: {error}, retrying in {accept_delay:?}", inbound.log_prefix());
                        tokio::time::sleep(accept_delay).await;
                    }
                }
            }
        });
        *self.task.lock().unwrap() = Some(task);
        Ok(())
    }

    async fn close(&self) {
        if let Some(task) = self.task.lock().unwrap().take() {
            task.abort();
        }
        if let Some(tls) = &self.tls {
            tls.close();
        }
    }

    /// A connection handed over by another inbound's `detour`.
    async fn new_connection(&self, context: InboundContext, stream: BoxStream) -> io::Result<()> {
        let mut context = context;
        context.inbound = self.tag.clone();
        context.inbound_type = "trojan";
        self.handle(stream, context).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_hex_sha224() {
        // printf password | sha224sum
        assert_eq!(&key("password"), b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01");
        assert_eq!(&key(""), b"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
    }

    #[test]
    fn request_and_packet_vectors() {
        let key = key("password");
        let destination = Socksaddr::from_host_port("example.com", 443);
        let request = encode_request(&key, COMMAND_TCP, &destination, b"hi").unwrap();
        let mut expected = key.to_vec();
        expected.extend_from_slice(b"\r\n\x01\x03\x0bexample.com\x01\xbb\r\nhi");
        assert_eq!(request, expected);

        let destination = Socksaddr::from_host_port("1.2.3.4", 53);
        let packet = encode_packet(&destination, b"abc").unwrap();
        assert_eq!(packet, b"\x01\x01\x02\x03\x04\x00\x35\x00\x03\r\nabc");
        let first = encode_packet_request(&key, &destination, b"abc").unwrap();
        let mut expected = key.to_vec();
        expected.extend_from_slice(b"\r\n\x03\x01\x01\x02\x03\x04\x00\x35\r\n");
        expected.extend_from_slice(&packet);
        assert_eq!(first, expected);

        assert!(parse_packet(&packet[..packet.len() - 1]).unwrap().is_none());
        let mut two = packet.clone();
        two.extend_from_slice(&packet);
        let ((address, payload), used) = parse_packet(&two).unwrap().unwrap();
        assert_eq!((address, payload.as_slice(), used), (destination, &b"abc"[..], packet.len()));
        let v6 = Socksaddr::from_host_port("::1", 1);
        let packet = encode_packet(&v6, b"").unwrap();
        assert_eq!(parse_packet(&packet).unwrap().unwrap().0 .0, v6);
        assert!(parse_packet(b"\x09\x00").is_err());
    }
}
