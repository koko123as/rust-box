use super::*;
use rb_adapter::{ConnectionHandshake, Host, Network, Socksaddr};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

struct HandshakeOutbound {
    succeeds: bool,
    outcome: Arc<AtomicU8>,
}

#[async_trait]
impl Outbound for HandshakeOutbound {
    fn tag(&self) -> &str {
        "handshake"
    }
    fn kind(&self) -> &'static str {
        "handshake"
    }
    async fn dial_tcp(&self, _context: &InboundContext) -> io::Result<BoxStream> {
        self.outcome.store(if self.succeeds { 1 } else { 2 }, Ordering::SeqCst);
        if !self.succeeds {
            return Err(io::Error::other("outbound dial failed"));
        }
        let (stream, peer) = tokio::io::duplex(1024);
        drop(peer);
        Ok(Box::new(stream))
    }
}

struct HandshakeRecorder(Arc<AtomicU8>);

#[async_trait]
impl ConnectionHandshake for HandshakeRecorder {
    async fn success(&self, client: &mut BoxStream) -> io::Result<()> {
        assert_eq!(self.0.load(Ordering::SeqCst), 1);
        client.write_all(b"success").await
    }
    async fn failure(&self, client: &mut BoxStream, _error: &RouteError) -> io::Result<()> {
        assert_eq!(self.0.load(Ordering::SeqCst), 2);
        client.write_all(b"failure").await
    }
}

fn handshake_router(succeeds: bool, outcome: Arc<AtomicU8>) -> Router {
    let options: RouteOptions = serde_json::from_str(r#"{"final":"handshake"}"#).unwrap();
    let outbounds: Vec<Arc<dyn Outbound>> = vec![Arc::new(HandshakeOutbound { succeeds, outcome })];
    let dns: Arc<dyn DnsResolver> = Arc::new(FakeDns::default());
    Router::new(&options, outbounds, dns, rb_adapter::InboundRegistry::new(), &rb_rule::RuleSets::new()).unwrap()
}

struct FakeOutbound(&'static str);

#[async_trait]
impl Outbound for FakeOutbound {
    fn tag(&self) -> &str {
        self.0
    }
    fn kind(&self) -> &'static str {
        "fake"
    }
    async fn dial_tcp(&self, _context: &InboundContext) -> io::Result<BoxStream> {
        Err(io::Error::other("fake"))
    }
}

#[derive(Default)]
struct FakeDns {
    lookups: Mutex<Vec<String>>,
    reverse: Mutex<std::collections::HashMap<IpAddr, String>>,
}

#[async_trait]
impl DnsResolver for FakeDns {
    async fn lookup(&self, domain: &str, options: &LookupOptions) -> io::Result<Vec<IpAddr>> {
        self.lookups.lock().unwrap().push(format!("{domain}@{}", options.server.clone().unwrap_or_default()));
        Ok(vec!["10.0.0.7".parse().unwrap()])
    }
    async fn exchange(&self, query: &[u8], _options: &LookupOptions) -> io::Result<Option<Vec<u8>>> {
        let mut answer = b"answer:".to_vec();
        answer.extend_from_slice(&query[..2]);
        Ok(Some(answer))
    }
    fn reverse_lookup(&self, address: IpAddr) -> io::Result<Option<String>> {
        Ok(self.reverse.lock().unwrap().get(&address).cloned())
    }
}

/// The client side of a UDP session: packets come from a channel, written
/// packets are collected. Reads wait forever once the channel is drained.
struct FakeClient {
    incoming: tokio::sync::Mutex<mpsc::UnboundedReceiver<(Vec<u8>, Socksaddr)>>,
    written: Mutex<Vec<(Vec<u8>, String)>>,
}

impl FakeClient {
    fn new(packets: Vec<(Vec<u8>, &str)>) -> Arc<Self> {
        let (sender, receiver) = mpsc::unbounded_channel();
        for (data, destination) in packets {
            let destination: std::net::SocketAddr = destination.parse().unwrap();
            sender.send((data, destination.into())).unwrap();
        }
        std::mem::forget(sender);
        Arc::new(FakeClient { incoming: tokio::sync::Mutex::new(receiver), written: Mutex::default() })
    }
}

#[async_trait]
impl rb_adapter::PacketConn for FakeClient {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let (data, address) = self.incoming.lock().await.recv().await.unwrap();
        buffer[..data.len()].copy_from_slice(&data);
        Ok((data.len(), address))
    }
    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        self.written.lock().unwrap().push((data.to_vec(), address.to_string()));
        Ok(())
    }
}

/// An outbound whose packet connection sends every packet straight back.
#[derive(Default)]
struct EchoOutbound(Mutex<Option<InboundContext>>);

struct EchoRemote(
    tokio::sync::Mutex<mpsc::UnboundedReceiver<(Vec<u8>, Socksaddr)>>,
    mpsc::UnboundedSender<(Vec<u8>, Socksaddr)>,
);

#[async_trait]
impl rb_adapter::PacketConn for EchoRemote {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let (data, address) = self.0.lock().await.recv().await.unwrap();
        buffer[..data.len()].copy_from_slice(&data);
        Ok((data.len(), address))
    }
    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        self.1.send((data.to_vec(), address.clone())).map_err(|_| io::Error::other("closed"))
    }
}

#[async_trait]
impl Outbound for EchoOutbound {
    fn tag(&self) -> &str {
        "echo"
    }
    fn kind(&self) -> &'static str {
        "echo"
    }
    async fn dial_tcp(&self, _context: &InboundContext) -> io::Result<BoxStream> {
        Err(io::Error::other("echo"))
    }
    async fn listen_packet(&self, context: &InboundContext) -> io::Result<SharedPacketConn> {
        *self.0.lock().unwrap() = Some(context.clone());
        let (sender, receiver) = mpsc::unbounded_channel();
        Ok(Arc::new(EchoRemote(tokio::sync::Mutex::new(receiver), sender)))
    }
}

fn router(rules: &str, dns: Arc<FakeDns>) -> Router {
    router_with(rules, dns, Arc::new(EchoOutbound::default()))
}

fn router_with(rules: &str, dns: Arc<FakeDns>, echo: Arc<EchoOutbound>) -> Router {
    let options: RouteOptions = serde_json::from_str(&format!(r#"{{"rules":{rules},"final":"proxy"}}"#)).unwrap();
    let outbounds: Vec<Arc<dyn Outbound>> =
        vec![Arc::new(FakeOutbound("direct")), Arc::new(FakeOutbound("proxy")), echo];
    Router::new(&options, outbounds, dns, rb_adapter::InboundRegistry::new(), &rb_rule::RuleSets::new()).unwrap()
}

fn udp_context(destination: &str) -> InboundContext {
    let destination: std::net::SocketAddr = destination.parse().unwrap();
    let mut context =
        InboundContext::new("socks-in", "socks", Network::Udp, "127.0.0.1:40000".parse().unwrap(), destination.into());
    context.inbound_udp_timeout = Some(Duration::from_millis(200));
    context
}

#[tokio::test]
async fn fakeip_destination_is_restored_before_route_matching() {
    let fake_address: IpAddr = "198.18.0.2".parse().unwrap();
    let dns = Arc::new(FakeDns::default());
    dns.reverse.lock().unwrap().insert(fake_address, "fake.example".into());
    let router = router(r#"[{"domain":"fake.example","outbound":"direct"}]"#, dns);
    let mut context = InboundContext::new(
        "socks-in",
        "socks",
        Network::Tcp,
        "127.0.0.1:40000".parse().unwrap(),
        Socksaddr::new(Host::Ip(fake_address), 443),
    );
    let mut client = None;

    assert_eq!(router.decide(&mut context, &mut client).await.unwrap(), Decision::Route("direct".into()));
    assert_eq!(context.destination.domain(), Some("fake.example"));
    assert_eq!(context.fake_ip_original_destination.unwrap().ip(), Some(fake_address));
}

#[tokio::test]
async fn udp_sniff_dns_then_hijack() {
    let router = router(r#"[{"action":"sniff"},{"protocol":"dns","action":"hijack-dns"}]"#, Arc::default());
    let client = FakeClient::new(vec![(sniff::tests::dns_query_packet(), "1.1.1.1:53")]);
    let started = std::time::Instant::now();
    router.route_packet_connection(udp_context("1.1.1.1:53"), client.clone()).await.unwrap();
    // Ends after the (inbound) idle timeout.
    assert!(started.elapsed() < Duration::from_secs(5));
    let written = client.written.lock().unwrap().clone();
    assert_eq!(written, vec![(b"answer:\x12\x34".to_vec(), "1.1.1.1:53".to_string())]);
}

#[tokio::test]
async fn udp_route_options_relay_and_timeout() {
    let echo = Arc::new(EchoOutbound::default());
    let router = router_with(
        r#"[{"network":"udp","action":"route-options","udp_timeout":"150ms","udp_connect":true},
            {"network":"tcp","action":"reject"},
            {"port":9999,"outbound":"echo","udp_disable_domain_unmapping":true}]"#,
        Arc::default(),
        echo.clone(),
    );
    let client = FakeClient::new(vec![(b"ping".to_vec(), "9.9.9.9:9999"), (b"pong".to_vec(), "8.8.8.8:9999")]);
    let mut context = udp_context("9.9.9.9:9999");
    context.inbound_udp_timeout = Some(Duration::from_secs(60));
    let started = std::time::Instant::now();
    router.route_packet_connection(context, client.clone()).await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    let written = client.written.lock().unwrap().clone();
    assert_eq!(
        written,
        vec![(b"ping".to_vec(), "9.9.9.9:9999".to_string()), (b"pong".to_vec(), "8.8.8.8:9999".to_string())]
    );
    let seen = echo.0.lock().unwrap().clone().unwrap();
    assert!(seen.udp_connect && seen.udp_disable_domain_unmapping);
    assert_eq!(seen.udp_timeout, Some(Duration::from_millis(150)));
    assert_eq!(seen.network, Network::Udp);
}

#[tokio::test]
async fn udp_sniff_quic_server_name() {
    let router = router(
        r#"[{"action":"sniff","sniffer":["quic"]},{"domain":"www.google.com","outbound":"direct"}]"#,
        Arc::default(),
    );
    let line = include_str!("testdata/quic_firefox.hex").trim();
    let packet: Vec<u8> =
        (0..line.len()).step_by(2).map(|i| u8::from_str_radix(&line[i..i + 2], 16).unwrap()).collect();
    let client: SharedPacketConn = FakeClient::new(vec![(packet, "142.250.1.1:443")]);
    let mut cached = Vec::new();
    let mut context = udp_context("142.250.1.1:443");
    let decision =
        router.decide_input(&mut context, Input::Packet { conn: &client, cached: &mut cached }).await.unwrap();
    assert_eq!(decision, Decision::Route("direct".into()));
    assert_eq!(context.protocol.as_deref(), Some("quic"));
    assert_eq!(cached.len(), 1);
    assert_eq!(udp_timeout(&context), Some(Duration::from_millis(200)));
}

#[tokio::test]
async fn udp_reject_and_tcp_only_sniffers() {
    let router = router(
        r#"[{"action":"sniff","sniffer":"tls","timeout":"5s"},{"network":"udp","action":"reject"}]"#,
        Arc::default(),
    );
    let client = FakeClient::new(vec![(b"x".to_vec(), "1.2.3.4:5")]);
    let started = std::time::Instant::now();
    let result = router.route_packet_connection(udp_context("1.2.3.4:5"), client).await;
    assert!(matches!(result, Err(RouteError::Rejected)));
    // A stream-only sniffer does not wait for packets.
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn udp_timeouts() {
    let mut context = udp_context("1.1.1.1:53");
    context.inbound_udp_timeout = Some(DEFAULT_UDP_TIMEOUT);
    assert_eq!(udp_timeout(&context), Some(Duration::from_secs(10)));
    context.destination.port = 443;
    assert_eq!(udp_timeout(&context), Some(Duration::from_secs(30)));
    context.destination.port = 5000;
    assert_eq!(udp_timeout(&context), Some(DEFAULT_UDP_TIMEOUT));
    context.protocol = Some("stun".into());
    assert_eq!(udp_timeout(&context), Some(Duration::from_secs(10)));
    context.udp_timeout = Some(Duration::from_secs(3600));
    // Never longer than the inbound's.
    assert_eq!(udp_timeout(&context), Some(DEFAULT_UDP_TIMEOUT));
}

fn context(host: &str, port: u16) -> InboundContext {
    InboundContext::new(
        "mixed-in",
        "mixed",
        Network::Tcp,
        "127.0.0.1:40000".parse().unwrap(),
        Socksaddr::from_host_port(host, port),
    )
}

#[tokio::test]
async fn sniff_then_route_by_sniffed_domain() {
    let dns = Arc::new(FakeDns::default());
    let router =
        router(r#"[{"action":"sniff"},{"protocol":"tls","domain_suffix":"example.com","outbound":"direct"}]"#, dns);
    let (mut client_side, server_side) = tokio::io::duplex(65536);
    client_side.write_all(&sniff::tests::client_hello("www.example.com")).await.unwrap();
    let mut stream: Option<BoxStream> = Some(Box::new(server_side));
    let mut ctx = context("93.184.216.34", 443);
    let decision = router.decide(&mut ctx, &mut stream).await.unwrap();
    assert_eq!(decision, Decision::Route("direct".into()));
    assert_eq!(ctx.protocol.as_deref(), Some("tls"));
    // The sniffed bytes are still there for the outbound.
    let mut first = [0u8; 1];
    stream.unwrap().read_exact(&mut first).await.unwrap();
    assert_eq!(first[0], 0x16);
}

#[tokio::test]
async fn sniff_times_out_on_silent_client() {
    let dns = Arc::new(FakeDns::default());
    let router = router(r#"[{"action":"sniff","timeout":"50ms"},{"protocol":"tls","outbound":"direct"}]"#, dns);
    let (_client_side, server_side) = tokio::io::duplex(1024);
    let mut stream: Option<BoxStream> = Some(Box::new(server_side));
    let mut ctx = context("example.com", 443);
    let started = std::time::Instant::now();
    assert_eq!(router.decide(&mut ctx, &mut stream).await.unwrap(), Decision::Route("proxy".into()));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn resolve_then_match_ip() {
    let dns = Arc::new(FakeDns::default());
    let router = router(
        r#"[{"action":"resolve","server":"google"},{"ip_cidr":"10.0.0.0/8","outbound":"direct"},{"action":"reject"}]"#,
        dns.clone(),
    );
    let mut stream: Option<BoxStream> = None;
    let mut ctx = context("intranet.example", 80);
    assert_eq!(router.decide(&mut ctx, &mut stream).await.unwrap(), Decision::Route("direct".into()));
    assert_eq!(dns.lookups.lock().unwrap().as_slice(), ["intranet.example@google"]);
    // An IP destination is not resolved, and falls to the reject rule.
    let mut ctx = context("8.8.8.8", 80);
    assert!(matches!(ctx.destination.host, Host::Ip(_)));
    assert!(matches!(router.decide(&mut ctx, &mut stream).await.unwrap(), Decision::Reject(_)));
}

#[tokio::test]
async fn route_options_apply_to_the_context() {
    let router = router(
        r#"[{"domain":"a.test","action":"route-options","override_address":"b.test","fallback_delay":300000000,
             "tls_fragment":true,"tls_fragment_fallback_delay":"20ms"},
            {"domain":"b.test","outbound":"direct","override_port":8443,"tls_record_fragment":true,
             "network_strategy":"hybrid"},
            {"outbound":"proxy"}]"#,
        Arc::default(),
    );
    let mut context = InboundContext::new(
        "in",
        "socks",
        Network::Tcp,
        "127.0.0.1:1".parse().unwrap(),
        Socksaddr::from_host_port("a.test", 443),
    );
    context.destination_addresses = vec!["10.0.0.1".parse().unwrap()];
    let decision = router.decide(&mut context, &mut None).await.unwrap();
    assert_eq!(decision, Decision::Route("direct".into()));
    // The override changed what later rules match, and the address list.
    assert_eq!(context.destination.to_string(), "b.test:8443");
    assert!(context.destination_addresses.is_empty());
    assert_eq!(context.route_original_destination.as_ref().unwrap().to_string(), "a.test:443");
    // fallback_delay is a number of nanoseconds (sing-box's uint32).
    assert_eq!(context.fallback_delay, Some(Duration::from_millis(300)));
    assert!(context.tls_fragment && context.tls_record_fragment);
    assert_eq!(context.tls_fragment_fallback_delay, Some(Duration::from_millis(20)));
}

#[tokio::test]
async fn bypass_routes_or_is_skipped() {
    let router = router(
        r#"[{"port":1,"action":"bypass"},{"port":1,"outbound":"direct"},
            {"port":2,"action":"bypass","outbound":"echo","override_port":3}]"#,
        Arc::default(),
    );
    let mut context = udp_context("10.0.0.1:1");
    assert_eq!(router.decide(&mut context, &mut None).await.unwrap(), Decision::Route("direct".into()));
    let mut context = udp_context("10.0.0.1:2");
    assert_eq!(router.decide(&mut context, &mut None).await.unwrap(), Decision::Route("echo".into()));
    assert_eq!(context.destination.port, 3);
}

#[tokio::test]
async fn udp_override_maps_replies_back() {
    let echo = Arc::new(EchoOutbound::default());
    let router = router_with(
        r#"[{"network":"udp","action":"route-options","override_address":"10.9.9.9","override_port":99},
            {"outbound":"echo"}]"#,
        Arc::default(),
        echo.clone(),
    );
    let client = FakeClient::new(vec![(b"ping".to_vec(), "10.0.0.1:53")]);
    let _ = router.route_packet_connection(udp_context("10.0.0.1:53"), client.clone()).await;
    // The outbound saw the new destination; the client sees the original.
    assert_eq!(echo.0.lock().unwrap().as_ref().unwrap().destination.to_string(), "10.9.9.9:99");
    assert_eq!(client.written.lock().unwrap().as_slice(), &[(b"ping".to_vec(), "10.0.0.1:53".to_string())]);
}

#[tokio::test]
async fn inbound_detour_errors() {
    let router = router("[]", Arc::default());
    let mut context = udp_context("10.0.0.1:1");
    context.network = Network::Tcp;
    context.inbound_detour = Some("missing".into());
    let (client, _server) = tokio::io::duplex(64);
    let error = router.route_connection(context, Box::new(client)).await.unwrap_err();
    assert!(error.to_string().contains("inbound detour not found: missing"), "{error}");
}

#[tokio::test]
async fn routed_handshake_success_is_sent_after_outbound_dial() {
    let outcome = Arc::new(AtomicU8::new(0));
    let router = Arc::new(handshake_router(true, outcome.clone()));
    let handshake = Arc::new(HandshakeRecorder(outcome));
    let (mut client, server) = tokio::io::duplex(1024);
    let route = {
        let router = router.clone();
        let handshake = handshake.clone();
        tokio::spawn(async move {
            router
                .route_connection_with_handshake(context("example.com", 443), Box::new(server), handshake.as_ref())
                .await
        })
    };
    let mut response = [0; 7];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"success");
    drop(client);
    route.await.unwrap().unwrap();
}

#[tokio::test]
async fn routed_handshake_failure_is_sent_after_outbound_dial_fails() {
    let outcome = Arc::new(AtomicU8::new(0));
    let router = Arc::new(handshake_router(false, outcome.clone()));
    let handshake = Arc::new(HandshakeRecorder(outcome));
    let (mut client, server) = tokio::io::duplex(1024);
    let route = {
        let router = router.clone();
        let handshake = handshake.clone();
        tokio::spawn(async move {
            router
                .route_connection_with_handshake(context("example.com", 443), Box::new(server), handshake.as_ref())
                .await
        })
    };
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"failure");
    assert!(matches!(route.await.unwrap(), Err(RouteError::Dial(_))));
}
