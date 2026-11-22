//! User-space WireGuard endpoint for sing-box v1.14.4.
//!
//! The WireGuard crypto state is provided by Boringtun; `rb-netstack` carries
//! decrypted IP packets and originates TCP/UDP flows on the configured tunnel
//! addresses. Peer selection follows the longest matching AllowedIPs prefix.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rb_adapter::{
    BoxStream, ConnectionRouter, DnsResolver, InboundContext, LookupOptions, Network as AdapterNetwork, Outbound,
    PacketConn, SharedPacketConn, Socksaddr,
};
use rb_config::tun::UdpNatBehavior;
use rb_config::types::IpPrefix;
use rb_config::wireguard::WireGuardEndpointOptions;
use rb_dialer::{new_outbound_dialer, Dialer, DialerEnv};
use rb_netstack::{
    ClientUdpConn, Handler, NatBehavior, Network as StackNetwork, Stack, StackOptions, TcpConn, UdpSession, Verdict,
};
use rb_route::Router;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

const DEFAULT_MTU: usize = 1408;
const WIREGUARD_BUFFER: usize = 65535;
const TIMER_INTERVAL: Duration = Duration::from_millis(250);
const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(300);
const NETWORKS: &[AdapterNetwork] = &[AdapterNetwork::Tcp, AdapterNetwork::Udp];

struct Peer {
    endpoint: Socksaddr,
    allowed_ips: Vec<IpPrefix>,
    reserved: [u8; 3],
    tunnel: tokio::sync::Mutex<Tunn>,
    transport: RwLock<Option<SharedPacketConn>>,
}

struct Runtime {
    stack: Arc<Stack>,
    input: mpsc::Sender<Vec<u8>>,
    output: Option<mpsc::Receiver<Vec<u8>>>,
    tasks: Vec<JoinHandle<()>>,
}

/// A WireGuard endpoint is also an outbound, as in sing-box v1.14.4.
pub struct WireGuardOutbound {
    tag: String,
    mtu: usize,
    addresses: Vec<IpPrefix>,
    peers: Vec<Arc<Peer>>,
    dialer: Arc<dyn Dialer>,
    dns: Arc<dyn DnsResolver>,
    udp_timeout: Duration,
    udp_mapping: NatBehavior,
    udp_filtering: NatBehavior,
    udp_nat_max: usize,
    router: OnceLock<Arc<Router>>,
    runtime: Mutex<Option<Runtime>>,
    running: AtomicBool,
}

impl WireGuardOutbound {
    pub fn new(
        options: &WireGuardEndpointOptions,
        tag: String,
        dialer_env: &DialerEnv,
        path: &str,
    ) -> Result<Self, String> {
        options.validate(path).map_err(|error| error.to_string())?;
        let private_key = decode_key(&options.private_key, &format!("{path}.private_key"), true)?;
        let mut peers = Vec::with_capacity(options.peers.len());
        let mut any_peer_domain = false;
        for (index, peer) in options.peers.iter().enumerate() {
            let peer_path = format!("{path}.peers[{index}]");
            let public_key = decode_key(&peer.public_key, &format!("{peer_path}.public_key"), true)?;
            let preshared_key = if peer.pre_shared_key.is_empty() {
                None
            } else {
                Some(decode_key(&peer.pre_shared_key, &format!("{peer_path}.pre_shared_key"), true)?)
            };
            if peer.allowed_ips.0.is_empty() {
                return Err(format!("{peer_path}.allowed_ips: missing peer AllowedIPs"));
            }
            if peer.address.is_empty() {
                return Err(format!(
                    "{peer_path}.address: a peer endpoint address is required when listen_port is not supported"
                ));
            }
            if peer.port == 0 {
                return Err(format!("{peer_path}.port: peer endpoint port must be non-zero"));
            }
            let endpoint = Socksaddr::from_host_port(&peer.address, peer.port);
            any_peer_domain |= endpoint.domain().is_some();
            let reserved = match peer.reserved.as_slice() {
                [] => [0; 3],
                [a, b, c] => [*a, *b, *c],
                _ => return Err(format!("{peer_path}.reserved: reserved must contain exactly 3 bytes")),
            };
            let peer_index = u32::try_from(index + 1)
                .ok()
                .filter(|index| *index <= 0x00ff_ffff)
                .ok_or_else(|| format!("{peer_path}: too many WireGuard peers"))?;
            let keepalive = (peer.persistent_keepalive_interval != 0).then_some(peer.persistent_keepalive_interval);
            let tunnel = Tunn::new(
                StaticSecret::from(private_key),
                PublicKey::from(public_key),
                preshared_key,
                keepalive,
                peer_index,
                None,
            );
            peers.push(Arc::new(Peer {
                endpoint,
                allowed_ips: peer.allowed_ips.0.clone(),
                reserved,
                tunnel: tokio::sync::Mutex::new(tunnel),
                transport: RwLock::new(None),
            }));
        }
        if options.listen_port != 0 {
            return Err(format!("{path}.listen_port: listening for incoming WireGuard peers is not supported yet"));
        }
        let dialer = new_outbound_dialer(
            &options.dialer_options(),
            any_peer_domain,
            dialer_env,
            &format!("endpoint/wireguard[{tag}]"),
        )
        .map_err(|error| format!("{path}: {error}"))?;
        let addresses = options.address.0.clone();
        let mtu = if options.mtu == 0 { DEFAULT_MTU } else { options.mtu as usize }.clamp(1280, 65535);
        let udp_timeout =
            if options.udp_timeout.0 .0.is_zero() { DEFAULT_UDP_TIMEOUT } else { options.udp_timeout.0 .0 };
        Ok(WireGuardOutbound {
            tag,
            mtu,
            addresses,
            peers,
            dialer,
            dns: dialer_env.dns.clone(),
            udp_timeout,
            udp_mapping: map_nat(options.udp_mapping),
            udp_filtering: map_nat(options.udp_filtering),
            udp_nat_max: options.udp_nat_max as usize,
            router: OnceLock::new(),
            runtime: Mutex::new(None),
            running: AtomicBool::new(false),
        })
    }

    pub fn set_router(&self, router: Arc<Router>) {
        let _ = self.router.set(router);
    }

    /// Creates the inner IP stack. RustBox starts every endpoint stack before
    /// opening peer transports, so endpoint detours can refer to other endpoints.
    pub async fn start_stack(self: &Arc<Self>) -> io::Result<()> {
        if self.runtime.lock().unwrap().is_some() {
            return Ok(());
        }
        let router = self
            .router
            .get()
            .cloned()
            .ok_or_else(|| io::Error::other("WireGuard endpoint router is not initialized"))?;
        let (output_tx, output) = mpsc::channel(rb_netstack::QUEUE_PACKETS);
        let handler = Arc::new(WireGuardHandler {
            router,
            tag: self.tag.clone(),
            addresses: self.addresses.clone(),
            udp_timeout: self.udp_timeout,
        });
        let source_addresses = self.addresses.iter().map(|prefix| (prefix.address, prefix.prefix_len)).collect();
        let interface_addresses = self.addresses.iter().map(|prefix| prefix.address).collect();
        let stack = Arc::new(Stack::new(
            StackOptions {
                mtu: self.mtu,
                udp_mapping: self.udp_mapping,
                udp_filtering: self.udp_filtering,
                udp_nat_max: self.udp_nat_max,
                interface_addresses,
                source_addresses,
                strict_source_addresses: true,
            },
            handler,
            output_tx,
        ));
        let input = stack.input();
        *self.runtime.lock().unwrap() = Some(Runtime { stack, input, output: Some(output), tasks: Vec::new() });
        Ok(())
    }

    /// Opens the peer UDP transports and starts the encrypted packet loops.
    pub async fn start_transports(self: &Arc<Self>) -> io::Result<()> {
        if self.running.load(Ordering::Acquire) {
            return Ok(());
        }
        if self.runtime.lock().unwrap().is_none() {
            return Err(io::Error::other("WireGuard endpoint stack is not initialized"));
        }
        for peer in &self.peers {
            let transport = self.dialer.dial_udp(&peer.endpoint).await.map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("endpoint/wireguard[{}]: dial peer {}: {error}", self.tag, peer.endpoint),
                )
            })?;
            *peer.transport.write().unwrap() = Some(transport);
        }
        let mut runtime_guard = self.runtime.lock().unwrap();
        let runtime = runtime_guard.as_mut().expect("stack initialized");
        let output = runtime.output.take().expect("WireGuard output loop not already started");
        let peers = self.peers.clone();
        runtime.tasks.push(tokio::spawn(async move { route_stack_packets(peers, output).await }));
        for peer in &self.peers {
            let peer = peer.clone();
            let input = runtime.input.clone();
            runtime.tasks.push(tokio::spawn(async move { run_peer(peer, input).await }));
        }
        self.running.store(true, Ordering::Release);
        Ok(())
    }

    pub fn close(&self) {
        self.running.store(false, Ordering::Release);
        if let Some(mut runtime) = self.runtime.lock().unwrap().take() {
            for task in runtime.tasks.drain(..) {
                task.abort();
            }
            runtime.stack.close();
        }
        for peer in &self.peers {
            *peer.transport.write().unwrap() = None;
        }
    }

    fn stack(&self) -> io::Result<Arc<Stack>> {
        self.runtime
            .lock()
            .unwrap()
            .as_ref()
            .map(|runtime| runtime.stack.clone())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "WireGuard is not ready yet"))
    }

    async fn resolve_destination(&self, context: &InboundContext) -> io::Result<Vec<IpAddr>> {
        if let Some(address) = context.destination.ip() {
            return Ok(vec![address]);
        }
        if !context.destination_addresses.is_empty() {
            return Ok(context.destination_addresses.clone());
        }
        let Some(domain) = context.destination.domain() else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid WireGuard destination"));
        };
        let options = LookupOptions::for_context(context);
        self.dns.lookup(domain, &options).await
    }

    async fn connect_tcp(&self, context: &InboundContext) -> io::Result<BoxStream> {
        let stack = self.stack()?;
        let addresses = self.resolve_destination(context).await?;
        if addresses.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("{}: no addresses", context.destination)));
        }
        let mut last_error = None;
        for address in addresses {
            match stack.connect_tcp(SocketAddr::new(address, context.destination.port)).await {
                Ok(connection) => return Ok(Box::new(connection)),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no WireGuard destination addresses")))
    }

    async fn listen_udp(&self, context: &InboundContext) -> io::Result<SharedPacketConn> {
        let stack = self.stack()?;
        let addresses = self.resolve_destination(context).await?;
        if addresses.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("{}: no addresses", context.destination)));
        }
        let mut last_error = None;
        for address in addresses {
            match stack.open_udp(SocketAddr::new(address, context.destination.port)).await {
                Ok(connection) => return Ok(Arc::new(WireGuardPacketConn { inner: connection })),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no WireGuard destination addresses")))
    }
}

#[async_trait]
impl Outbound for WireGuardOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "wireguard"
    }

    fn networks(&self) -> &[AdapterNetwork] {
        NETWORKS
    }

    async fn dial_tcp(&self, context: &InboundContext) -> io::Result<BoxStream> {
        if !self.running.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "WireGuard is not ready yet"));
        }
        self.connect_tcp(context).await
    }

    async fn listen_packet(&self, context: &InboundContext) -> io::Result<SharedPacketConn> {
        if !self.running.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "WireGuard is not ready yet"));
        }
        self.listen_udp(context).await
    }
}

struct WireGuardHandler {
    router: Arc<Router>,
    tag: String,
    addresses: Vec<IpPrefix>,
    udp_timeout: Duration,
}

#[async_trait]
impl Handler for WireGuardHandler {
    async fn judge(
        &self,
        _network: StackNetwork,
        _source: SocketAddr,
        _destination: SocketAddr,
        _first_packet: &[u8],
    ) -> Verdict {
        Verdict::Accept
    }

    fn new_tcp(&self, connection: TcpConn) {
        let (destination, original) = self.redirect_local(connection.destination());
        let mut context = InboundContext::new(
            &self.tag,
            "wireguard",
            AdapterNetwork::Tcp,
            connection.source(),
            Socksaddr::from(destination),
        );
        context.origin_destination = original;
        let router = self.router.clone();
        tokio::spawn(async move {
            if let Err(error) = router.route_connection(context, Box::new(connection)).await {
                debug!(%error, "WireGuard inbound TCP flow closed");
            }
        });
    }

    fn new_udp(&self, session: UdpSession, destination: SocketAddr) {
        let (destination, original) = self.redirect_local(destination);
        let source = session.source();
        let mut context =
            InboundContext::new(&self.tag, "wireguard", AdapterNetwork::Udp, source, Socksaddr::from(destination));
        context.inbound_udp_timeout = Some(self.udp_timeout);
        context.origin_destination = original;
        let router = self.router.clone();
        let connection: SharedPacketConn = Arc::new(WireGuardSessionPacketConn { session });
        tokio::spawn(async move {
            if let Err(error) = router.route_packet_connection(context, connection).await {
                debug!(%error, "WireGuard inbound UDP flow closed");
            }
        });
    }

    fn dns_packet(
        &self,
        _payload: Vec<u8>,
        _source: SocketAddr,
        _destination: SocketAddr,
        _reply: rb_netstack::UdpReply,
    ) {
        // Router's `hijack-dns` action is applied after the flow is injected.
    }
}

impl WireGuardHandler {
    fn redirect_local(&self, destination: SocketAddr) -> (SocketAddr, Option<SocketAddr>) {
        if !self.addresses.iter().any(|prefix| prefix_contains(*prefix, destination.ip())) {
            return (destination, None);
        }
        let loopback = match destination.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        };
        (SocketAddr::new(loopback, destination.port()), Some(destination))
    }
}

struct WireGuardPacketConn {
    inner: ClientUdpConn,
}

#[async_trait]
impl PacketConn for WireGuardPacketConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let (length, source) = self.inner.recv_from(buffer).await?;
        Ok((length, Socksaddr::from(source)))
    }

    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        let destination = address
            .ip()
            .map(|ip| SocketAddr::new(ip, address.port))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "WireGuard UDP destination was not resolved"))?;
        self.inner.send_to(data, destination).await
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        Some(self.inner.local_addr())
    }
}

struct WireGuardSessionPacketConn {
    session: UdpSession,
}

#[async_trait]
impl PacketConn for WireGuardSessionPacketConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let (length, destination) = self.session.recv(buffer).await?;
        Ok((length, Socksaddr::from(destination)))
    }

    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        let source = address
            .ip()
            .map(|ip| SocketAddr::new(ip, address.port))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "WireGuard UDP source was not resolved"))?;
        self.session.send(data, source)
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        Some(self.session.source())
    }
}

async fn route_stack_packets(peers: Vec<Arc<Peer>>, mut packets: mpsc::Receiver<Vec<u8>>) {
    while let Some(packet) = packets.recv().await {
        let Some(destination) = rb_netstack::parse(&packet).map(|parsed| parsed.dst) else {
            continue;
        };
        let Some(peer) = select_peer(&peers, destination) else {
            warn!(%destination, "WireGuard has no peer for AllowedIPs destination");
            continue;
        };
        let encrypted = {
            let mut tunnel = peer.tunnel.lock().await;
            encapsulate(&mut tunnel, &packet)
        };
        match encrypted {
            Ok(Some(datagram)) => {
                if let Err(error) = send_peer_datagram(&peer, datagram).await {
                    warn!(peer = %peer.endpoint, %error, "WireGuard peer UDP send failed");
                }
            }
            Ok(None) => {}
            Err(error) => warn!(peer = %peer.endpoint, %error, "WireGuard packet encryption failed"),
        }
    }
}

async fn run_peer(peer: Arc<Peer>, input: mpsc::Sender<Vec<u8>>) {
    let Some(transport) = peer.transport.read().unwrap().clone() else {
        return;
    };
    let mut buffer = vec![0u8; WIREGUARD_BUFFER];
    let mut timer = tokio::time::interval(TIMER_INTERVAL);
    loop {
        tokio::select! {
            received = transport.read_packet(&mut buffer) => match received {
                Ok((length, source)) => {
                    clear_reserved(&mut buffer[..length]);
                    let source_ip = source.ip().or_else(|| transport.peer_addr().map(|address| address.ip()));
                    if let Err(error) = decapsulate_datagram(&peer, source_ip, &buffer[..length], &input).await {
                        debug!(peer = %peer.endpoint, %error, "WireGuard inbound packet processing stopped");
                        break;
                    }
                }
                Err(error) => {
                    if error.kind() != io::ErrorKind::Interrupted {
                        warn!(peer = %peer.endpoint, %error, "WireGuard peer UDP receive failed");
                    }
                    break;
                }
            },
            _ = timer.tick() => {
                let timer_result = {
                    let mut tunnel = peer.tunnel.lock().await;
                    let mut output = vec![0u8; WIREGUARD_BUFFER];
                    match tunnel.update_timers(&mut output) {
                        TunnResult::WriteToNetwork(packet) => Some(Ok(packet.to_vec())),
                        TunnResult::Err(error) => Some(Err(format!("{error:?}"))),
                        TunnResult::Done => None,
                        _ => Some(Err("unexpected WireGuard timer result".into())),
                    }
                };
                if let Some(Ok(packet)) = timer_result {
                    if let Err(error) = send_peer_datagram(&peer, packet).await {
                        debug!(peer = %peer.endpoint, %error, "WireGuard timer packet send failed");
                    }
                } else if let Some(Err(error)) = timer_result {
                    debug!(peer = %peer.endpoint, %error, "WireGuard timer update failed");
                }
            }
        }
    }
}

async fn decapsulate_datagram(
    peer: &Peer,
    source: Option<IpAddr>,
    datagram: &[u8],
    input: &mpsc::Sender<Vec<u8>>,
) -> io::Result<()> {
    let mut inner_packets = Vec::new();
    let mut network_packets = Vec::new();
    {
        let mut tunnel = peer.tunnel.lock().await;
        let mut next_datagram = datagram;
        loop {
            let mut output = vec![0u8; WIREGUARD_BUFFER];
            match tunnel.decapsulate(source, next_datagram, &mut output) {
                TunnResult::WriteToNetwork(packet) => {
                    network_packets.push(packet.to_vec());
                    next_datagram = &[];
                }
                TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                    inner_packets.push(packet.to_vec());
                    break;
                }
                TunnResult::Done => break,
                TunnResult::Err(error) => {
                    debug!(peer = %peer.endpoint, ?error, "WireGuard rejected peer datagram");
                    break;
                }
            }
        }
    }
    for packet in network_packets {
        send_peer_datagram(peer, packet).await?;
    }
    for packet in inner_packets {
        input
            .send(packet)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "WireGuard IP stack stopped"))?;
    }
    Ok(())
}

fn encapsulate(tunnel: &mut Tunn, packet: &[u8]) -> io::Result<Option<Vec<u8>>> {
    let capacity = packet.len().saturating_add(256).clamp(148, WIREGUARD_BUFFER);
    let mut output = vec![0u8; capacity];
    match tunnel.encapsulate(packet, &mut output) {
        TunnResult::WriteToNetwork(datagram) => Ok(Some(datagram.to_vec())),
        TunnResult::Done => Ok(None),
        TunnResult::Err(error) => Err(io::Error::other(format!("{error:?}"))),
        _ => Err(io::Error::other("unexpected WireGuard encapsulation result")),
    }
}

async fn send_peer_datagram(peer: &Peer, mut datagram: Vec<u8>) -> io::Result<()> {
    apply_reserved(&mut datagram, peer.reserved);
    let transport = peer
        .transport
        .read()
        .unwrap()
        .clone()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "WireGuard peer transport is not ready"))?;
    transport.write_packet(&datagram, &peer.endpoint).await
}

fn apply_reserved(datagram: &mut [u8], reserved: [u8; 3]) {
    if datagram.len() > 3 {
        datagram[1..4].copy_from_slice(&reserved);
    }
}

fn clear_reserved(datagram: &mut [u8]) {
    if datagram.len() > 3 {
        datagram[1..4].fill(0);
    }
}

fn select_peer(peers: &[Arc<Peer>], destination: IpAddr) -> Option<Arc<Peer>> {
    peers
        .iter()
        .flat_map(|peer| {
            peer.allowed_ips
                .iter()
                .filter(move |prefix| prefix_contains(**prefix, destination))
                .map(move |prefix| (peer, prefix))
        })
        .max_by_key(|(_, prefix)| prefix.prefix_len)
        .map(|(peer, _)| peer.clone())
}

fn prefix_contains(prefix: IpPrefix, address: IpAddr) -> bool {
    match (prefix.address, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) => {
            let bits = u32::from(prefix.prefix_len);
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            u32::from(network) & mask == u32::from(address) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(address)) => {
            let bits = u32::from(prefix.prefix_len);
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            u128::from(network) & mask == u128::from(address) & mask
        }
        _ => false,
    }
}

fn decode_key(value: &str, path: &str, required: bool) -> Result<[u8; 32], String> {
    if value.is_empty() {
        return if required { Err(format!("{path}: missing key")) } else { Ok([0; 32]) };
    }
    let decoded = STANDARD.decode(value).map_err(|error| format!("{path}: invalid base64 key: {error}"))?;
    decoded.try_into().map_err(|bytes: Vec<u8>| format!("{path}: key must be exactly 32 bytes, got {}", bytes.len()))
}

fn map_nat(behavior: UdpNatBehavior) -> NatBehavior {
    match behavior {
        UdpNatBehavior::EndpointIndependent => NatBehavior::EndpointIndependent,
        UdpNatBehavior::AddressDependent => NatBehavior::AddressDependent,
        UdpNatBehavior::AddressAndPortDependent => NatBehavior::AddressAndPortDependent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(allowed_ips: &[&str]) -> Arc<Peer> {
        Arc::new(Peer {
            endpoint: Socksaddr::from_host_port("127.0.0.1", 51820),
            allowed_ips: allowed_ips.iter().map(|prefix| prefix.parse().unwrap()).collect(),
            reserved: [0; 3],
            tunnel: tokio::sync::Mutex::new(Tunn::new(
                StaticSecret::from([1; 32]),
                PublicKey::from([2; 32]),
                None,
                None,
                1,
                None,
            )),
            transport: RwLock::new(None),
        })
    }

    #[test]
    fn allowed_ips_uses_longest_prefix_and_address_family() {
        let default = peer(&["0.0.0.0/0", "::/0"]);
        let subnet = peer(&["10.0.0.0/8"]);
        let host = peer(&["10.1.2.3/32"]);
        let peers = vec![default.clone(), subnet.clone(), host.clone()];
        assert!(Arc::ptr_eq(&select_peer(&peers, "10.1.2.3".parse().unwrap()).unwrap(), &host));
        assert!(Arc::ptr_eq(&select_peer(&peers, "10.2.0.1".parse().unwrap()).unwrap(), &subnet));
        assert!(Arc::ptr_eq(&select_peer(&peers, "192.0.2.1".parse().unwrap()).unwrap(), &default));
        assert!(Arc::ptr_eq(&select_peer(&peers, "2001:db8::1".parse().unwrap()).unwrap(), &default));
    }

    fn decapsulate_for_test(tunnel: &mut Tunn, source: IpAddr, datagram: &[u8]) -> (Vec<Vec<u8>>, Option<Vec<u8>>) {
        let mut network_packets = Vec::new();
        let mut tunnel_packet = None;
        let mut next_datagram = datagram;
        loop {
            let mut output = vec![0; WIREGUARD_BUFFER];
            match tunnel.decapsulate(Some(source), next_datagram, &mut output) {
                TunnResult::WriteToNetwork(packet) => {
                    network_packets.push(packet.to_vec());
                    next_datagram = &[];
                }
                TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                    tunnel_packet = Some(packet.to_vec());
                    break;
                }
                TunnResult::Done | TunnResult::Err(_) => break,
            }
        }
        (network_packets, tunnel_packet)
    }

    #[test]
    fn boringtun_peers_handshake_and_exchange_inner_ip_packet() {
        let initiator_private = StaticSecret::from([11; 32]);
        let responder_private = StaticSecret::from([29; 32]);
        let initiator_public = PublicKey::from(&initiator_private);
        let responder_public = PublicKey::from(&responder_private);
        let mut initiator = Tunn::new(initiator_private, responder_public, None, None, 1, None);
        let mut responder = Tunn::new(responder_private, initiator_public, None, None, 2, None);
        let inner = rb_netstack::build_udp(
            "10.0.0.2:12345".parse().unwrap(),
            "198.51.100.8:53".parse().unwrap(),
            b"handshake-data",
        );

        let mut buffer = vec![0; inner.len() + 256];
        let initiation = match initiator.encapsulate(&inner, &mut buffer) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            result => panic!("expected handshake initiation, got {result:?}"),
        };
        let (response_packets, _) = decapsulate_for_test(&mut responder, "192.0.2.1".parse().unwrap(), &initiation);
        assert_eq!(response_packets.len(), 1);

        let (encrypted_packets, _) =
            decapsulate_for_test(&mut initiator, "192.0.2.2".parse().unwrap(), &response_packets[0]);
        assert!(encrypted_packets.len() >= 2, "handshake response queues keepalive and payload");
        let mut decrypted = None;
        for packet in encrypted_packets {
            let (_, inner_packet) = decapsulate_for_test(&mut responder, "192.0.2.1".parse().unwrap(), &packet);
            decrypted = decrypted.or(inner_packet);
        }
        assert_eq!(decrypted.as_deref(), Some(inner.as_slice()));
    }

    #[test]
    fn reserved_bytes_are_set_and_cleared_only_on_wireguard_datagrams() {
        let mut packet = vec![0, 1, 2, 3, 4];
        apply_reserved(&mut packet, [9, 8, 7]);
        assert_eq!(&packet[1..4], &[9, 8, 7]);
        clear_reserved(&mut packet);
        assert_eq!(&packet[1..4], &[0, 0, 0]);
        let mut short = [0, 1, 2];
        apply_reserved(&mut short, [9, 8, 7]);
        clear_reserved(&mut short);
        assert_eq!(&short, &[0, 1, 2]);
    }

    #[test]
    fn key_decode_reports_path_and_exact_length() {
        let error = decode_key("not base64!", "endpoints[0].private_key", true).unwrap_err();
        assert!(error.contains("endpoints[0].private_key"));
        let key = STANDARD.encode([0x42; 32]);
        assert_eq!(decode_key(&key, "key", true).unwrap(), [0x42; 32]);
        let short = STANDARD.encode([0x42; 31]);
        assert!(decode_key(&short, "key", true).unwrap_err().contains("exactly 32 bytes"));
    }
}
