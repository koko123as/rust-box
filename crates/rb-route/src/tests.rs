use super::*;
use rb_adapter::{Host, Network, Socksaddr};
use std::net::IpAddr;
use std::sync::Mutex;

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
struct FakeDns(Mutex<Vec<String>>);

#[async_trait]
impl DnsResolver for FakeDns {
    async fn lookup(&self, domain: &str, options: &LookupOptions) -> io::Result<Vec<IpAddr>> {
        self.0.lock().unwrap().push(format!("{domain}@{}", options.server.clone().unwrap_or_default()));
        Ok(vec!["10.0.0.7".parse().unwrap()])
    }
}

fn router(rules: &str, dns: Arc<FakeDns>) -> Router {
    let options: RouteOptions = serde_json::from_str(&format!(r#"{{"rules":{rules},"final":"proxy"}}"#)).unwrap();
    let outbounds: Vec<Arc<dyn Outbound>> = vec![Arc::new(FakeOutbound("direct")), Arc::new(FakeOutbound("proxy"))];
    Router::new(&options, outbounds, dns).unwrap()
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
    use tokio::io::AsyncWriteExt;
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
    assert_eq!(dns.0.lock().unwrap().as_slice(), ["intranet.example@google"]);
    // An IP destination is not resolved, and falls to the reject rule.
    let mut ctx = context("8.8.8.8", 80);
    assert!(matches!(ctx.destination.host, Host::Ip(_)));
    assert!(matches!(router.decide(&mut ctx, &mut stream).await.unwrap(), Decision::Reject(_)));
}
