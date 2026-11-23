//! rust-box's user-space TCP/IP stack for the `tun` inbound, standing in
//! for sing-tun's `gvisor`, `system` and `mixed` stacks.
//!
//! IP packets read from the TUN device go in through [`Stack::input`], and
//! the packets the stack sends go out through the channel given to
//! [`Stack::new`]. TCP runs on [smoltcp](https://docs.rs/smoltcp): every new
//! connection (a SYN to any address) is judged by the [`Handler`] first,
//! then gets a smoltcp socket listening on its destination, so the stack
//! completes the handshake for whatever address the client dialed. UDP and
//! ICMP are handled here without smoltcp: UDP through a NAT table of
//! sessions with sing-box's mapping and filtering behaviors, ICMP echo
//! requests answered locally, as sing-tun does for an accepted ping.

mod packet;
mod tcp;
mod udp;

#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Checksum, ChecksumCapabilities, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp as smol_tcp;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpListenEndpoint};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::task::JoinHandle;

pub use packet::{build_udp, is_global_unicast, parse, Parsed};
pub use tcp::TcpConn;
pub use udp::{ClientUdpConn, NatBehavior, UdpReply, UdpSession};

use packet::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP, TCP_ACK, TCP_RST, TCP_SYN};
use tcp::{Shared, QUEUE_LIMIT};
use udp::{NatKey, Table};

/// The transport of a new flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
    Icmp,
}

/// What to do with a new flow (sing-tun `FlowVerdict`, the actions rust-box
/// has: no `flow`/`bypass` ports).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Hand it to the handler (a TCP connection, a UDP session, a ping
    /// answered locally).
    Accept,
    /// Refuse it: a TCP reset, an ICMP port unreachable for UDP.
    Reject,
    /// Drop it silently.
    Drop,
    /// UDP only: answer the packet as a DNS query ([`Handler::dns_packet`]).
    HijackDns,
}

/// What the stack hands flows to (sing-tun `Handler`).
#[async_trait]
pub trait Handler: Send + Sync + 'static {
    /// Judges a new flow; for UDP with its first packet (sing-tun `JudgeFlow`).
    async fn judge(
        &self,
        network: Network,
        source: SocketAddr,
        destination: SocketAddr,
        first_packet: &[u8],
    ) -> Verdict;
    /// A TCP connection whose handshake completed.
    fn new_tcp(&self, conn: TcpConn);
    /// A new UDP session; its first packet (to `destination`) is queued.
    fn new_udp(&self, session: UdpSession, destination: SocketAddr);
    /// A UDP packet judged [`Verdict::HijackDns`].
    fn dns_packet(&self, payload: Vec<u8>, source: SocketAddr, destination: SocketAddr, reply: UdpReply);
}

/// Stack settings (from the `tun` inbound).
#[derive(Debug, Clone)]
pub struct StackOptions {
    /// The TUN MTU: the largest packet the stack sends.
    pub mtu: usize,
    pub udp_mapping: NatBehavior,
    pub udp_filtering: NatBehavior,
    /// The most UDP sessions at once; 0 for no limit.
    pub udp_nat_max: usize,
    /// The TUN interface's own addresses, which the stack's internal
    /// addresses must differ from.
    pub interface_addresses: Vec<IpAddr>,
    /// Local addresses from the tunnel configuration, with their CIDR prefixes.
    pub source_addresses: Vec<(IpAddr, u8)>,
    /// Require a configured local address for the destination's address family.
    pub strict_source_addresses: bool,
}

impl Default for StackOptions {
    fn default() -> Self {
        StackOptions {
            mtu: 9000,
            udp_mapping: NatBehavior::default(),
            udp_filtering: NatBehavior::default(),
            udp_nat_max: 0,
            interface_addresses: Vec::new(),
            source_addresses: Vec::new(),
            strict_source_addresses: false,
        }
    }
}

/// Buffer sizes of a TCP socket in each direction.
const TCP_BUFFER: usize = 128 * 1024;
/// How many packets wait for the TUN device before the stack waits too.
pub const QUEUE_PACKETS: usize = 1024;

/// A running stack. Dropping it (or [`Stack::close`]) stops it.
pub struct Stack {
    input: mpsc::Sender<Vec<u8>>,
    commands: mpsc::Sender<Command>,
    task: JoinHandle<()>,
    table: Arc<Table>,
}

impl Stack {
    /// Starts the stack on the current tokio runtime. Packets for the TUN
    /// device are sent to `output`.
    pub fn new(options: StackOptions, handler: Arc<dyn Handler>, output: mpsc::Sender<Vec<u8>>) -> Stack {
        let (input, packets) = mpsc::channel(QUEUE_PACKETS);
        let (commands, command_rx) = mpsc::channel(128);
        let table = Arc::new(Table::default());
        let worker = Worker::new(options, handler, output, table.clone(), commands.clone(), command_rx);
        let task = tokio::spawn(worker.run(packets));
        Stack { input, commands, task, table }
    }

    /// Where packets read from the TUN device go.
    pub fn input(&self) -> mpsc::Sender<Vec<u8>> {
        self.input.clone()
    }

    /// Opens a TCP connection through this IP stack. The returned stream is
    /// ready after the TCP handshake completes.
    pub async fn connect_tcp(&self, destination: SocketAddr) -> io::Result<TcpConn> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::ConnectTcp { destination, reply })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "network stack stopped"))?;
        response.await.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "network stack stopped"))?
    }

    /// Opens a UDP socket through this IP stack. Packets can be sent to any
    /// address and replies are returned with their source address.
    pub async fn open_udp(&self, destination: SocketAddr) -> io::Result<ClientUdpConn> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::OpenUdp { destination, reply })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "network stack stopped"))?;
        response.await.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "network stack stopped"))?
    }

    /// The number of UDP sessions.
    pub fn udp_sessions(&self) -> usize {
        self.table.len()
    }

    /// Stops the stack: its connections and sessions end.
    pub fn close(&self) {
        self.task.abort();
        self.table.close_all();
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        self.close();
    }
}

/// smoltcp's device: packets queued in both directions.
struct QueueDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

struct RxToken(Vec<u8>);
struct TxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl smoltcp::phy::TxToken for TxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        self.0.push_back(buffer);
        result
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn receive(&mut self, _: smoltcp::time::Instant) -> Option<(RxToken, TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((RxToken(packet), TxToken(&mut self.tx)))
    }

    fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<TxToken<'_>> {
        Some(TxToken(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        let mut checksum = ChecksumCapabilities::default();
        checksum.ipv4 = Checksum::Both;
        checksum.tcp = Checksum::Both;
        capabilities.checksum = checksum;
        capabilities
    }
}

type FlowKey = (SocketAddr, SocketAddr);

pub(crate) enum Command {
    ConnectTcp { destination: SocketAddr, reply: oneshot::Sender<io::Result<TcpConn>> },
    OpenUdp { destination: SocketAddr, reply: oneshot::Sender<io::Result<ClientUdpConn>> },
    SendUdp { source: SocketAddr, destination: SocketAddr, data: Vec<u8> },
    CloseUdp { source: SocketAddr },
}

struct UdpClient {
    incoming: mpsc::Sender<(Vec<u8>, SocketAddr)>,
}

/// A TCP connection the stack holds a socket for.
struct Conn {
    key: FlowKey,
    /// Set once the handshake completed and the handler has the connection.
    shared: Option<Arc<Shared>>,
    closing: bool,
    connect_reply: Option<oneshot::Sender<io::Result<TcpConn>>>,
}

/// A judged flow, back from its judging task.
enum Judged {
    Tcp(FlowKey, Verdict),
    Udp(NatKey, Verdict),
}

struct PendingUdp {
    source: SocketAddr,
    destination: SocketAddr,
    /// The packets (whole, for an ICMP unreachable) that arrived while the
    /// flow was judged.
    packets: Vec<Vec<u8>>,
}

struct Worker {
    options: StackOptions,
    handler: Arc<dyn Handler>,
    output: mpsc::Sender<Vec<u8>>,
    commands_tx: mpsc::Sender<Command>,
    commands: mpsc::Receiver<Command>,
    table: Arc<Table>,
    device: QueueDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    v4: Ipv4Addr,
    v6: Ipv6Addr,
    next_port: u16,
    conns: HashMap<SocketHandle, Conn>,
    udp_clients: HashMap<SocketAddr, UdpClient>,
    flows: HashSet<FlowKey>,
    pending_tcp: HashMap<FlowKey, Vec<u8>>,
    pending_udp: HashMap<NatKey, PendingUdp>,
    notify: Arc<Notify>,
    judged_tx: mpsc::UnboundedSender<Judged>,
    judged_rx: Option<mpsc::UnboundedReceiver<Judged>>,
}

/// An address for the stack's own interface that is not one of `taken`.
fn internal_address<T: Copy + Into<IpAddr>>(candidates: &[T], taken: &[IpAddr]) -> T {
    *candidates.iter().find(|candidate| !taken.contains(&(**candidate).into())).unwrap_or(&candidates[0])
}

fn missing_source_address(destination: IpAddr) -> io::Error {
    let family = if destination.is_ipv4() { "IPv4" } else { "IPv6" };
    io::Error::new(io::ErrorKind::AddrNotAvailable, format!("missing {family} local address"))
}

fn now() -> smoltcp::time::Instant {
    smoltcp::time::Instant::now()
}

impl Worker {
    fn new(
        options: StackOptions,
        handler: Arc<dyn Handler>,
        output: mpsc::Sender<Vec<u8>>,
        table: Arc<Table>,
        commands_tx: mpsc::Sender<Command>,
        commands: mpsc::Receiver<Command>,
    ) -> Self {
        let mut device = QueueDevice { rx: VecDeque::new(), tx: VecDeque::new(), mtu: options.mtu.clamp(1280, 65535) };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand_seed();
        let mut iface = Interface::new(config, &mut device, now());
        let v4 = internal_address(
            &[Ipv4Addr::new(10, 255, 255, 254), Ipv4Addr::new(10, 255, 255, 253)],
            &options.interface_addresses,
        );
        let v6 = internal_address(
            &[
                Ipv6Addr::new(0xfdfe, 0xdcba, 0x9876, 0xffff, 0, 0, 0, 0xfffe),
                Ipv6Addr::new(0xfdfe, 0xdcba, 0x9876, 0xffff, 0, 0, 0, 0xfffd),
            ],
            &options.interface_addresses,
        );
        iface.update_ip_addrs(|addresses| {
            let _ = addresses.push(IpCidr::new(v4.into(), 32));
            let _ = addresses.push(IpCidr::new(v6.into(), 128));
            for (address, prefix) in &options.source_addresses {
                let _ = addresses.push(IpCidr::new((*address).into(), *prefix));
            }
        });
        let _ = iface.routes_mut().add_default_ipv4_route(v4);
        let _ = iface.routes_mut().add_default_ipv6_route(v6);
        iface.set_any_ip(true);
        let (judged_tx, judged_rx) = mpsc::unbounded_channel();
        Worker {
            options,
            handler,
            output,
            commands_tx,
            commands,
            table,
            device,
            iface,
            sockets: SocketSet::new(Vec::new()),
            v4,
            v6,
            next_port: 49152,
            conns: HashMap::new(),
            udp_clients: HashMap::new(),
            flows: HashSet::new(),
            pending_tcp: HashMap::new(),
            pending_udp: HashMap::new(),
            notify: Arc::new(Notify::new()),
            judged_tx,
            judged_rx: Some(judged_rx),
        }
    }

    async fn run(mut self, mut packets: mpsc::Receiver<Vec<u8>>) {
        let mut judged = self.judged_rx.take().unwrap();
        loop {
            let delay = self
                .iface
                .poll_delay(now(), &self.sockets)
                .map(|delay| Duration::from_micros(delay.total_micros()))
                .unwrap_or(Duration::from_secs(60));
            let notify = self.notify.clone();
            tokio::select! {
                packet = packets.recv() => match packet {
                    Some(packet) => {
                        self.input(packet);
                        // Take what else is waiting before polling smoltcp.
                        for _ in 0..64 {
                            match packets.try_recv() {
                                Ok(packet) => self.input(packet),
                                Err(_) => break,
                            }
                        }
                    }
                    None => break,
                },
                command = self.commands.recv() => match command {
                    Some(command) => self.command(command),
                    None => break,
                },
                Some(result) = judged.recv() => self.judged(result),
                _ = notify.notified() => {}
                _ = tokio::time::sleep(delay) => {}
            }
            while let Ok(result) = judged.try_recv() {
                self.judged(result);
            }
            self.poll();
            if self.flush().await.is_err() {
                break;
            }
        }
        self.table.close_all();
        for conn in self.conns.values_mut() {
            if let Some(reply) = conn.connect_reply.take() {
                let _ = reply.send(Err(io::Error::new(io::ErrorKind::BrokenPipe, "network stack stopped")));
            }
        }
        for conn in self.conns.values() {
            if let Some(shared) = &conn.shared {
                let mut state = shared.state.lock().unwrap();
                state.reset = true;
                wake(&mut state);
            }
        }
    }

    /// Sends what smoltcp queued to the TUN device.
    async fn flush(&mut self) -> Result<(), ()> {
        while let Some(packet) = self.device.tx.pop_front() {
            self.output.send(packet).await.map_err(|_| ())?;
        }
        Ok(())
    }

    fn send(&self, packet: Vec<u8>) {
        let _ = self.output.try_send(packet);
    }

    fn command(&mut self, command: Command) {
        match command {
            Command::ConnectTcp { destination, reply } => self.connect_tcp(destination, reply),
            Command::OpenUdp { destination, reply } => self.open_udp(destination, reply),
            Command::SendUdp { source, destination, data } => {
                if self.udp_clients.contains_key(&source) && data.len() <= 65507 {
                    self.send(packet::build_udp(source, destination, &data));
                }
            }
            Command::CloseUdp { source } => {
                self.udp_clients.remove(&source);
            }
        }
    }

    fn connect_tcp(&mut self, destination: SocketAddr, reply: oneshot::Sender<io::Result<TcpConn>>) {
        if destination.port() == 0 {
            let _ = reply.send(Err(io::Error::new(io::ErrorKind::InvalidInput, "TCP destination port is zero")));
            return;
        }
        let Some(source_ip) = self.source_ip(destination.ip()) else {
            let _ = reply.send(Err(missing_source_address(destination.ip())));
            return;
        };
        let Some(port) = self.allocate_port() else {
            let _ = reply.send(Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "no source ports available")));
            return;
        };
        let mut socket = smol_tcp::Socket::new(
            smol_tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
            smol_tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
        );
        socket.set_nagle_enabled(false);
        socket.set_ack_delay(None);
        let endpoint = (IpAddress::from(destination.ip()), destination.port());
        if let Err(error) = socket.connect(self.iface.context(), endpoint, port) {
            let _ = reply.send(Err(io::Error::other(format!("{destination}: {error}"))));
            return;
        }
        let source = SocketAddr::new(source_ip, port);
        let key = (source, destination);
        let handle = self.sockets.add(socket);
        self.conns.insert(handle, Conn { key, shared: None, closing: false, connect_reply: Some(reply) });
    }

    fn open_udp(&mut self, destination: SocketAddr, reply: oneshot::Sender<io::Result<ClientUdpConn>>) {
        if destination.port() == 0 {
            let _ = reply.send(Err(io::Error::new(io::ErrorKind::InvalidInput, "UDP destination port is zero")));
            return;
        }
        let Some(source_ip) = self.source_ip(destination.ip()) else {
            let _ = reply.send(Err(missing_source_address(destination.ip())));
            return;
        };
        let Some(port) = self.allocate_port() else {
            let _ = reply.send(Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "no source ports available")));
            return;
        };
        let source = SocketAddr::new(source_ip, port);
        let (incoming, packets) = mpsc::channel(256);
        self.udp_clients.insert(source, UdpClient { incoming });
        let conn = ClientUdpConn::new(source, self.commands_tx.clone(), packets);
        let _ = reply.send(Ok(conn));
    }

    fn source_ip(&self, destination: IpAddr) -> Option<IpAddr> {
        self.options
            .source_addresses
            .iter()
            .find(|(address, _)| address.is_ipv4() == destination.is_ipv4())
            .map(|(address, _)| *address)
            .or_else(|| {
                (!self.options.strict_source_addresses).then_some(if destination.is_ipv4() {
                    self.v4.into()
                } else {
                    self.v6.into()
                })
            })
    }

    fn allocate_port(&mut self) -> Option<u16> {
        for _ in 0..16384 {
            let port = self.next_port;
            self.next_port = if port == u16::MAX { 49152 } else { port + 1 };
            let tcp_in_use = self.conns.values().any(|conn| conn.key.0.port() == port);
            let udp_in_use = self.udp_clients.keys().any(|source| source.port() == port);
            if !tcp_in_use && !udp_in_use {
                return Some(port);
            }
        }
        None
    }

    /// A packet from the TUN device.
    fn input(&mut self, packet: Vec<u8>) {
        let Some(parsed) = packet::parse(&packet) else { return };
        if !is_global_unicast(parsed.dst) {
            return;
        }
        match parsed.protocol {
            PROTO_TCP => self.input_tcp(&parsed, &packet),
            PROTO_UDP => self.input_udp(&parsed),
            PROTO_ICMP if parsed.dst.is_ipv4() => self.input_icmp(&parsed),
            PROTO_ICMPV6 if parsed.dst.is_ipv6() => self.input_icmp(&parsed),
            _ => {}
        }
    }

    fn input_tcp(&mut self, parsed: &Parsed<'_>, packet: &[u8]) {
        let Some((src_port, dst_port, _, _, flags)) = packet::parse_tcp(parsed.payload) else { return };
        let key = (SocketAddr::new(parsed.src, src_port), SocketAddr::new(parsed.dst, dst_port));
        let new_flow = flags & TCP_SYN != 0 && flags & (TCP_ACK | TCP_RST) == 0;
        if new_flow && !self.flows.contains(&key) {
            if self.pending_tcp.contains_key(&key) {
                return; // a retransmitted SYN while it is judged
            }
            self.pending_tcp.insert(key, packet.to_vec());
            let (handler, judged) = (self.handler.clone(), self.judged_tx.clone());
            tokio::spawn(async move {
                let verdict = handler.judge(Network::Tcp, key.0, key.1, &[]).await;
                let _ = judged.send(Judged::Tcp(key, verdict));
            });
            return;
        }
        self.device.rx.push_back(packet.to_vec());
    }

    fn accept_tcp(&mut self, key: FlowKey, syn: Vec<u8>) {
        let mut socket = smol_tcp::Socket::new(
            smol_tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
            smol_tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
        );
        socket.set_nagle_enabled(false);
        socket.set_ack_delay(None);
        let endpoint = IpListenEndpoint { addr: Some(key.1.ip().into()), port: key.1.port() };
        if socket.listen(endpoint).is_err() {
            return;
        }
        let handle = self.sockets.add(socket);
        self.conns.insert(handle, Conn { key, shared: None, closing: false, connect_reply: None });
        self.flows.insert(key);
        self.device.rx.push_back(syn);
    }

    fn input_udp(&mut self, parsed: &Parsed<'_>) {
        if parsed.fragment {
            return;
        }
        let Some((src_port, dst_port, data)) = packet::parse_udp(parsed.payload) else { return };
        let source = SocketAddr::new(parsed.src, src_port);
        let destination = SocketAddr::new(parsed.dst, dst_port);
        if let Some(client) = self.udp_clients.get(&destination) {
            let _ = client.incoming.try_send((data.to_vec(), source));
            return;
        }
        let key = NatKey::new(self.options.udp_mapping, source, destination);
        if let Some(session) = self.table.get(&key) {
            session.push(data, destination);
            return;
        }
        if let Some(pending) = self.pending_udp.get_mut(&key) {
            if pending.packets.len() < 64 {
                pending.packets.push(parsed.packet.to_vec());
            }
            return;
        }
        self.pending_udp.insert(key, PendingUdp { source, destination, packets: vec![parsed.packet.to_vec()] });
        let (handler, judged, first) = (self.handler.clone(), self.judged_tx.clone(), data.to_vec());
        tokio::spawn(async move {
            let verdict = handler.judge(Network::Udp, source, destination, &first).await;
            let _ = judged.send(Judged::Udp(key, verdict));
        });
    }

    fn input_icmp(&mut self, parsed: &Parsed<'_>) {
        if parsed.fragment {
            return;
        }
        let Some(reply) = packet::build_echo_reply(parsed) else { return };
        let identifier = u16::from_be_bytes([parsed.payload[4], parsed.payload[5]]);
        let (source, destination) = (SocketAddr::new(parsed.src, identifier), SocketAddr::new(parsed.dst, identifier));
        let (handler, output) = (self.handler.clone(), self.output.clone());
        tokio::spawn(async move {
            if handler.judge(Network::Icmp, source, destination, &[]).await == Verdict::Accept {
                let _ = output.send(reply).await;
            }
        });
    }

    fn judged(&mut self, result: Judged) {
        match result {
            Judged::Tcp(key, verdict) => {
                let Some(syn) = self.pending_tcp.remove(&key) else { return };
                match verdict {
                    Verdict::Accept => self.accept_tcp(key, syn),
                    Verdict::Reject => {
                        if let Some(reset) = packet::parse(&syn).and_then(|parsed| packet::build_tcp_reset(&parsed)) {
                            self.send(reset);
                        }
                    }
                    Verdict::Drop | Verdict::HijackDns => {}
                }
            }
            Judged::Udp(key, verdict) => {
                let Some(pending) = self.pending_udp.remove(&key) else { return };
                let datagrams = pending.packets.iter().filter_map(|whole| {
                    let parsed = packet::parse(whole)?;
                    let (src_port, dst_port, data) = packet::parse_udp(parsed.payload)?;
                    Some((parsed, SocketAddr::new(parsed.src, src_port), SocketAddr::new(parsed.dst, dst_port), data))
                });
                match verdict {
                    Verdict::Accept => {
                        let session = self.table.insert(
                            key,
                            pending.source,
                            self.options.udp_filtering,
                            self.output.clone(),
                            self.options.udp_nat_max,
                        );
                        if let Some(shared) = self.table.get(&key) {
                            for (_, _, destination, data) in datagrams {
                                shared.push(data, destination);
                            }
                        }
                        self.handler.new_udp(session, pending.destination);
                    }
                    Verdict::Reject => {
                        if let Some((parsed, ..)) = datagrams.into_iter().next() {
                            self.send(packet::build_port_unreachable(&parsed));
                        }
                    }
                    Verdict::HijackDns => {
                        for (_, source, destination, data) in datagrams {
                            let reply = UdpReply { client: source, out: self.output.clone() };
                            self.handler.dns_packet(data.to_vec(), source, destination, reply);
                        }
                    }
                    Verdict::Drop => {}
                }
            }
        }
    }

    /// Runs smoltcp and moves data between its sockets and the connections.
    fn poll(&mut self) {
        // Twice: once for what arrived, once for what the connections queued.
        for _ in 0..2 {
            self.iface.poll(now(), &mut self.device, &mut self.sockets);
            self.service();
        }
    }

    fn service(&mut self) {
        let mut closed = Vec::new();
        for (&handle, conn) in &mut self.conns {
            let socket = self.sockets.get_mut::<smol_tcp::Socket>(handle);
            let state = socket.state();
            if conn.shared.is_none() {
                match state {
                    smol_tcp::State::Established | smol_tcp::State::CloseWait => {
                        let shared = Shared::new(self.notify.clone());
                        conn.shared = Some(shared.clone());
                        let connection = TcpConn::new(shared, conn.key.0, conn.key.1);
                        if let Some(reply) = conn.connect_reply.take() {
                            let _ = reply.send(Ok(connection));
                        } else {
                            self.handler.new_tcp(connection);
                        }
                    }
                    smol_tcp::State::Closed => {
                        if let Some(reply) = conn.connect_reply.take() {
                            let _ = reply.send(Err(io::Error::new(
                                io::ErrorKind::ConnectionRefused,
                                format!("{}: connection refused", conn.key.1),
                            )));
                        }
                        closed.push(handle);
                        continue;
                    }
                    _ => continue,
                }
            }
            let shared = conn.shared.as_ref().unwrap();
            let mut guard = shared.state.lock().unwrap();
            let shared_state = &mut *guard;
            let mut woke_read = false;
            let mut woke_write = false;
            // Client to application.
            while socket.can_recv() && shared_state.rx.len() < QUEUE_LIMIT {
                let room = QUEUE_LIMIT - shared_state.rx.len();
                let result = socket.recv(|data| {
                    let count = data.len().min(room);
                    (count, data[..count].to_vec())
                });
                match result {
                    Ok(data) if !data.is_empty() => {
                        shared_state.rx.extend(data);
                        woke_read = true;
                    }
                    _ => break,
                }
            }
            if !socket.may_recv() && !socket.can_recv() && !shared_state.rx_closed {
                // The client sent its FIN (or the connection is gone).
                shared_state.rx_closed = true;
                woke_read = true;
            }
            // Application to client.
            while socket.can_send() && !shared_state.tx.is_empty() {
                let (front, _) = shared_state.tx.as_slices();
                match socket.send_slice(front) {
                    Ok(0) | Err(_) => break,
                    Ok(count) => {
                        shared_state.tx.drain(..count);
                        woke_write = true;
                    }
                }
            }
            if shared_state.tx.is_empty() && (shared_state.tx_shutdown || shared_state.dropped) && !conn.closing {
                socket.close();
                conn.closing = true;
                woke_write = true;
            }
            if !socket.may_send() && !shared_state.tx.is_empty() && !matches!(state, smol_tcp::State::CloseWait) {
                // The client is gone: what is left cannot be sent.
                shared_state.tx.clear();
                shared_state.reset = true;
                woke_write = true;
            }
            if state == smol_tcp::State::Closed {
                if !conn.closing {
                    shared_state.reset = true;
                }
                shared_state.rx_closed = true;
                woke_read = true;
                woke_write = true;
                closed.push(handle);
            } else if shared_state.dropped && conn.closing && state == smol_tcp::State::TimeWait {
                closed.push(handle);
            }
            if woke_read {
                if let Some(waker) = shared_state.read_waker.take() {
                    waker.wake();
                }
            }
            if woke_write {
                if let Some(waker) = shared_state.write_waker.take() {
                    waker.wake();
                }
            }
        }
        for handle in closed {
            if let Some(conn) = self.conns.remove(&handle) {
                self.flows.remove(&conn.key);
            }
            self.sockets.remove(handle);
        }
    }
}

fn wake(state: &mut tcp::State) {
    if let Some(waker) = state.read_waker.take() {
        waker.wake();
    }
    if let Some(waker) = state.write_waker.take() {
        waker.wake();
    }
}

fn rand_seed() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() as u64
    );
    hasher.finish()
}
