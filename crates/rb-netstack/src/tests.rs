//! In-memory tests: a smoltcp client (standing in for the kernel behind the
//! TUN device) and hand-built UDP and ICMP packets exchanged with the stack
//! over channels.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::tcp as smol_tcp;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use super::*;

type Judgement = (Network, SocketAddr, SocketAddr, Vec<u8>);

/// Accepts everything except the destinations it is told to refuse; echoes
/// TCP and UDP back; answers hijacked DNS with the query reversed.
struct TestHandler {
    verdicts: Mutex<Vec<(Network, SocketAddr, Verdict)>>,
    judged: Mutex<Vec<Judgement>>,
}

impl TestHandler {
    fn new() -> Arc<Self> {
        Arc::new(TestHandler { verdicts: Mutex::new(Vec::new()), judged: Mutex::new(Vec::new()) })
    }
    fn set(&self, network: Network, destination: &str, verdict: Verdict) {
        self.verdicts.lock().unwrap().push((network, destination.parse().unwrap(), verdict));
    }
}

#[async_trait]
impl Handler for TestHandler {
    async fn judge(&self, network: Network, source: SocketAddr, destination: SocketAddr, first: &[u8]) -> Verdict {
        self.judged.lock().unwrap().push((network, source, destination, first.to_vec()));
        self.verdicts
            .lock()
            .unwrap()
            .iter()
            .find(|(n, d, _)| *n == network && (*d == destination || (d.port() == 0 && d.ip() == destination.ip())))
            .map(|(_, _, v)| *v)
            .unwrap_or(Verdict::Accept)
    }

    fn new_tcp(&self, mut conn: TcpConn) {
        tokio::spawn(async move {
            let mut buffer = vec![0; 65536];
            loop {
                match conn.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if conn.write_all(&buffer[..n]).await.is_err() {
                            return;
                        }
                    }
                }
            }
            let _ = conn.shutdown().await;
        });
    }

    fn new_udp(&self, session: UdpSession, _destination: SocketAddr) {
        tokio::spawn(async move {
            let mut buffer = vec![0; 65536];
            while let Ok((n, destination)) = session.recv(&mut buffer).await {
                if &buffer[..n] == b"from-other" {
                    // A reply from somewhere the client never sent to.
                    let _ = session.send(b"other", "9.9.9.9:9".parse().unwrap());
                    let _ = session.send(b"other-port", SocketAddr::new(destination.ip(), 9));
                }
                let _ = session.send(&buffer[..n], destination);
            }
        });
    }

    fn dns_packet(&self, mut payload: Vec<u8>, _source: SocketAddr, destination: SocketAddr, reply: UdpReply) {
        payload.reverse();
        reply.send(&payload, destination).unwrap();
    }
}

struct Harness {
    stack: Stack,
    input: mpsc::Sender<Vec<u8>>,
    output: mpsc::Receiver<Vec<u8>>,
}

fn harness(handler: Arc<TestHandler>, options: StackOptions) -> Harness {
    let (output_tx, output) = mpsc::channel(QUEUE_PACKETS);
    let stack = Stack::new(options, handler, output_tx);
    let input = stack.input();
    Harness { stack, input, output }
}

impl Harness {
    async fn next(&mut self) -> Option<Vec<u8>> {
        tokio::time::timeout(Duration::from_secs(2), self.output.recv()).await.ok().flatten()
    }
}

/// A smoltcp interface playing the kernel's side of the TUN device.
struct Client {
    iface: Interface,
    device: QueueDevice,
    sockets: SocketSet<'static>,
}

impl Client {
    fn new() -> Self {
        let mut device = QueueDevice { rx: VecDeque::new(), tx: VecDeque::new(), mtu: 1500 };
        let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut device, now());
        iface.update_ip_addrs(|addresses| {
            let _ = addresses.push(IpCidr::new(IpAddress::v4(172, 19, 0, 1), 30));
        });
        iface.routes_mut().add_default_ipv4_route(Ipv4Addr::new(172, 19, 0, 2)).unwrap();
        Client { iface, device, sockets: SocketSet::new(Vec::new()) }
    }

    /// Runs both sides until `done` holds (or two seconds pass).
    async fn run(&mut self, harness: &mut Harness, mut done: impl FnMut(&mut Self) -> bool) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline {
            self.iface.poll(now(), &mut self.device, &mut self.sockets);
            while let Some(packet) = self.device.tx.pop_front() {
                harness.input.send(packet).await.unwrap();
            }
            if done(self) {
                return true;
            }
            match tokio::time::timeout(Duration::from_millis(5), harness.output.recv()).await {
                Ok(Some(packet)) => {
                    self.device.rx.push_back(packet);
                    while let Ok(packet) = harness.output.try_recv() {
                        self.device.rx.push_back(packet);
                    }
                }
                Ok(None) => return false,
                Err(_) => {}
            }
        }
        false
    }

    fn connect(&mut self, destination: (IpAddress, u16), local_port: u16) -> smoltcp::iface::SocketHandle {
        let socket = smol_tcp::Socket::new(
            smol_tcp::SocketBuffer::new(vec![0; 256 * 1024]),
            smol_tcp::SocketBuffer::new(vec![0; 256 * 1024]),
        );
        let handle = self.sockets.add(socket);
        let socket = self.sockets.get_mut::<smol_tcp::Socket>(handle);
        socket.connect(self.iface.context(), destination, local_port).unwrap();
        handle
    }
}

#[tokio::test]
async fn tcp_to_any_address_is_accepted_and_relayed() {
    let handler = TestHandler::new();
    let mut harness = harness(handler.clone(), StackOptions::default());
    let mut client = Client::new();
    let handle = client.connect((IpAddress::v4(93, 184, 216, 34), 443), 40000);
    // Several megabytes through the echo, to cross the queue limits.
    let message: Vec<u8> = (0..3 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let mut sent = 0;
    let mut received = Vec::new();
    let finished = client
        .run(&mut harness, |client| {
            let socket = client.sockets.get_mut::<smol_tcp::Socket>(handle);
            if socket.can_send() && sent < message.len() {
                sent += socket.send_slice(&message[sent..]).unwrap();
                if sent == message.len() {
                    socket.close();
                }
            }
            while socket.can_recv() {
                socket.recv(|data| (data.len(), received.extend_from_slice(data))).unwrap();
            }
            received.len() == message.len() && !socket.may_recv()
        })
        .await;
    assert!(finished, "received {} of {}", received.len(), message.len());
    assert!(received == message);
    let judged = handler.judged.lock().unwrap().clone();
    assert_eq!(judged.len(), 1);
    assert_eq!(judged[0].0, Network::Tcp);
    assert_eq!(judged[0].1, "172.19.0.1:40000".parse().unwrap());
    assert_eq!(judged[0].2, "93.184.216.34:443".parse().unwrap());
    // The connection ends on both sides and the stack forgets it.
    let closed = client
        .run(&mut harness, |client| {
            client.sockets.get::<smol_tcp::Socket>(handle).state() == smol_tcp::State::Closed
                || client.sockets.get::<smol_tcp::Socket>(handle).state() == smol_tcp::State::TimeWait
        })
        .await;
    assert!(closed);
}

#[tokio::test]
async fn tcp_reject_resets_and_drop_is_silent() {
    let handler = TestHandler::new();
    handler.set(Network::Tcp, "1.1.1.1:80", Verdict::Reject);
    handler.set(Network::Tcp, "1.1.1.1:81", Verdict::Drop);
    let mut harness = harness(handler.clone(), StackOptions::default());
    let mut client = Client::new();
    let rejected = client.connect((IpAddress::v4(1, 1, 1, 1), 80), 40001);
    let reset = client
        .run(&mut harness, |client| client.sockets.get::<smol_tcp::Socket>(rejected).state() == smol_tcp::State::Closed)
        .await;
    assert!(reset, "a rejected connection is reset");
    let dropped = client.connect((IpAddress::v4(1, 1, 1, 1), 81), 40002);
    let answered = client
        .run(&mut harness, |client| client.sockets.get::<smol_tcp::Socket>(dropped).state() != smol_tcp::State::SynSent)
        .await;
    assert!(!answered, "a dropped connection gets no answer");
    assert_eq!(harness.stack.udp_sessions(), 0);
}

fn udp(src: &str, dst: &str, data: &[u8]) -> Vec<u8> {
    build_udp(src.parse().unwrap(), dst.parse().unwrap(), data)
}

fn reply(packet: &[u8]) -> (SocketAddr, SocketAddr, Vec<u8>) {
    let parsed = parse(packet).unwrap();
    assert_eq!(packet::transport_checksum(parsed.src, parsed.dst, PROTO_UDP, parsed.payload), 0);
    let (src, dst, data) = packet::parse_udp(parsed.payload).unwrap();
    (SocketAddr::new(parsed.src, src), SocketAddr::new(parsed.dst, dst), data.to_vec())
}

#[tokio::test]
async fn udp_sessions_with_endpoint_independent_nat() {
    let handler = TestHandler::new();
    let mut harness = harness(handler.clone(), StackOptions::default());
    harness.input.send(udp("172.19.0.1:5000", "8.8.8.8:443", b"one")).await.unwrap();
    assert_eq!(
        reply(&harness.next().await.unwrap()),
        ("8.8.8.8:443".parse().unwrap(), "172.19.0.1:5000".parse().unwrap(), b"one".to_vec())
    );
    // Another destination from the same client endpoint: the same session.
    harness.input.send(udp("172.19.0.1:5000", "1.0.0.1:443", b"two")).await.unwrap();
    assert_eq!(reply(&harness.next().await.unwrap()).0, "1.0.0.1:443".parse().unwrap());
    // Endpoint-independent filtering lets a reply from anywhere through.
    harness.input.send(udp("172.19.0.1:5000", "1.0.0.1:443", b"from-other")).await.unwrap();
    assert_eq!(reply(&harness.next().await.unwrap()).0, "9.9.9.9:9".parse().unwrap());
    assert_eq!(reply(&harness.next().await.unwrap()).0, "1.0.0.1:9".parse().unwrap());
    assert_eq!(reply(&harness.next().await.unwrap()).2, b"from-other".to_vec());
    assert_eq!(handler.judged.lock().unwrap().len(), 1);
    assert_eq!(handler.judged.lock().unwrap()[0].3, b"one".to_vec());
    assert_eq!(harness.stack.udp_sessions(), 1);
    // IPv6 too.
    harness.input.send(udp("[fdfe:dcba:9876::1]:5000", "[2001:db8::1]:53", b"six")).await.unwrap();
    assert_eq!(reply(&harness.next().await.unwrap()).0, "[2001:db8::1]:53".parse().unwrap());
    assert_eq!(harness.stack.udp_sessions(), 2);
}

#[tokio::test]
async fn udp_dependent_mapping_and_filtering() {
    let handler = TestHandler::new();
    let options = StackOptions {
        udp_mapping: NatBehavior::AddressDependent,
        udp_filtering: NatBehavior::AddressAndPortDependent,
        ..Default::default()
    };
    let mut harness = harness(handler.clone(), options);
    harness.input.send(udp("172.19.0.1:5000", "8.8.8.8:443", b"one")).await.unwrap();
    harness.next().await.unwrap();
    harness.input.send(udp("172.19.0.1:5000", "8.8.8.8:444", b"two")).await.unwrap();
    harness.next().await.unwrap();
    harness.input.send(udp("172.19.0.1:5000", "1.0.0.1:443", b"three")).await.unwrap();
    harness.next().await.unwrap();
    // One session per destination address.
    assert_eq!(handler.judged.lock().unwrap().len(), 2);
    assert_eq!(harness.stack.udp_sessions(), 2);
    // Replies from addresses or ports never contacted are dropped.
    harness.input.send(udp("172.19.0.1:5000", "1.0.0.1:443", b"from-other")).await.unwrap();
    assert_eq!(reply(&harness.next().await.unwrap()).2, b"from-other".to_vec());
}

#[tokio::test]
async fn udp_nat_max_evicts_the_oldest_session() {
    let handler = TestHandler::new();
    let mut harness = harness(handler.clone(), StackOptions { udp_nat_max: 2, ..Default::default() });
    for port in [5000, 5001, 5002] {
        harness.input.send(udp(&format!("172.19.0.1:{port}"), "8.8.8.8:443", b"x")).await.unwrap();
        harness.next().await.unwrap();
    }
    assert_eq!(harness.stack.udp_sessions(), 2);
}

#[tokio::test]
async fn udp_reject_drop_and_hijack() {
    let handler = TestHandler::new();
    handler.set(Network::Udp, "8.8.8.8:1", Verdict::Reject);
    handler.set(Network::Udp, "8.8.8.8:2", Verdict::Drop);
    handler.set(Network::Udp, "172.19.0.2:53", Verdict::HijackDns);
    let mut harness = harness(handler.clone(), StackOptions::default());

    let rejected = udp("172.19.0.1:5000", "8.8.8.8:1", b"x");
    harness.input.send(rejected.clone()).await.unwrap();
    let unreachable = harness.next().await.unwrap();
    let parsed = parse(&unreachable).unwrap();
    assert_eq!(
        (parsed.src, parsed.dst, parsed.protocol),
        ("8.8.8.8".parse::<IpAddr>().unwrap(), "172.19.0.1".parse::<IpAddr>().unwrap(), PROTO_ICMP)
    );
    assert_eq!(&parsed.payload[..2], &[3, 3]);
    assert_eq!(&parsed.payload[8..], &rejected[..]);

    harness.input.send(udp("172.19.0.1:5001", "8.8.8.8:2", b"x")).await.unwrap();
    assert!(harness.next().await.is_none());

    for query in [&b"query-1"[..], b"query-2"] {
        harness.input.send(udp("172.19.0.1:5002", "172.19.0.2:53", query)).await.unwrap();
        let (src, dst, data) = reply(&harness.next().await.unwrap());
        assert_eq!((src, dst), ("172.19.0.2:53".parse().unwrap(), "172.19.0.1:5002".parse().unwrap()));
        let mut expected = query.to_vec();
        expected.reverse();
        assert_eq!(data, expected);
    }
    assert_eq!(harness.stack.udp_sessions(), 0);
}

#[tokio::test]
async fn icmp_echo_is_answered_unless_refused() {
    let handler = TestHandler::new();
    handler.set(Network::Icmp, "1.1.1.1:0", Verdict::Drop);
    let mut harness = harness(handler.clone(), StackOptions::default());
    let ping = |dst: &str| {
        let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0, 1, b'p'];
        let value = packet::checksum(&icmp);
        icmp[2..4].copy_from_slice(&value.to_be_bytes());
        let mut packet = vec![0x45, 0, 0, (20 + icmp.len()) as u8, 0, 0, 0x40, 0, 64, PROTO_ICMP, 0, 0];
        packet.extend_from_slice(&[172, 19, 0, 1]);
        packet.extend_from_slice(&dst.parse::<Ipv4Addr>().unwrap().octets());
        let value = packet::checksum(&packet);
        packet[10..12].copy_from_slice(&value.to_be_bytes());
        packet.extend_from_slice(&icmp);
        packet
    };
    harness.input.send(ping("8.8.4.4")).await.unwrap();
    let echo = harness.next().await.unwrap();
    let parsed = parse(&echo).unwrap();
    assert_eq!(parsed.src, "8.8.4.4".parse::<IpAddr>().unwrap());
    assert_eq!(parsed.payload[0], 0);
    harness.input.send(ping("1.1.1.1")).await.unwrap();
    assert!(harness.next().await.is_none());
    // Multicast and broadcast destinations are not handled.
    harness.input.send(ping("255.255.255.255")).await.unwrap();
    assert!(harness.next().await.is_none());
    let judged = handler.judged.lock().unwrap();
    assert_eq!(judged[0].2, "8.8.4.4:4660".parse().unwrap());
}

fn stack_pair(handler: Arc<TestHandler>) -> (Stack, Stack, tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>) {
    let (left_output, left_packets) = mpsc::channel(QUEUE_PACKETS);
    let (right_output, right_packets) = mpsc::channel(QUEUE_PACKETS);
    let left = Stack::new(StackOptions::default(), handler.clone(), left_output);
    let right = Stack::new(StackOptions::default(), handler, right_output);
    let left_input = left.input();
    let right_input = right.input();
    let left_to_right = tokio::spawn(async move {
        let mut packets = left_packets;
        while let Some(packet) = packets.recv().await {
            if right_input.send(packet).await.is_err() {
                break;
            }
        }
    });
    let right_to_left = tokio::spawn(async move {
        let mut packets = right_packets;
        while let Some(packet) = packets.recv().await {
            if left_input.send(packet).await.is_err() {
                break;
            }
        }
    });
    (left, right, left_to_right, right_to_left)
}

#[tokio::test]
async fn client_tcp_connect_uses_the_stack_and_returns_a_stream() {
    let handler = TestHandler::new();
    let (left, right, _left_to_right, _right_to_left) = stack_pair(handler);
    let mut connection =
        tokio::time::timeout(Duration::from_secs(5), left.connect_tcp("93.184.216.34:443".parse().unwrap()))
            .await
            .expect("TCP handshake timed out")
            .expect("TCP connection failed");
    connection.write_all(b"wireguard tcp").await.unwrap();
    let mut response = vec![0; 13];
    tokio::time::timeout(Duration::from_secs(5), connection.read_exact(&mut response))
        .await
        .expect("TCP echo timed out")
        .unwrap();
    assert_eq!(&response, b"wireguard tcp");
    drop(connection);
    left.close();
    right.close();
}

#[tokio::test]
async fn client_udp_socket_sends_and_receives_through_the_stack() {
    let handler = TestHandler::new();
    let (left, right, _left_to_right, _right_to_left) = stack_pair(handler);
    let connection = left.open_udp("8.8.8.8:53".parse().unwrap()).await.unwrap();
    connection.send_to(b"wireguard udp", "8.8.8.8:53".parse().unwrap()).await.unwrap();
    let mut response = [0; 32];
    let (length, source) = tokio::time::timeout(Duration::from_secs(5), connection.recv_from(&mut response))
        .await
        .expect("UDP echo timed out")
        .unwrap();
    assert_eq!(&response[..length], b"wireguard udp");
    assert_eq!(source, "8.8.8.8:53".parse().unwrap());
    drop(connection);
    left.close();
    right.close();
}
