use std::sync::Arc;

use rb_adapter::{BoxStream, Outbound};
use rb_config::RouteOptions as RouteConfig;

use super::*;

#[test]
fn interface_names_like_sing_tun() {
    assert_eq!(calculate_interface_name(&[]), "tun0");
    assert_eq!(calculate_interface_name(&["lo".into(), "eth0".into()]), "tun0");
    assert_eq!(calculate_interface_name(&["tun0".into(), "tun3".into(), "tunnel".into()]), "tun4");
    // "tun" alone and non-numbers do not count.
    assert_eq!(calculate_interface_name(&["tun".into(), "tun-x".into()]), "tun0");
}

#[test]
fn dns_addresses_like_sing_tun() {
    let p = |s: &str| {
        let (address, len) = s.split_once('/').unwrap();
        Prefix::new(address.parse().unwrap(), len.parse().unwrap())
    };
    assert_eq!(
        dns_hijack_addresses(&[p("172.19.0.1/30")], &[p("fdfe:dcba:9876::1/126")]).unwrap(),
        vec!["172.19.0.2".parse::<IpAddr>().unwrap(), "fdfe:dcba:9876::2".parse().unwrap()]
    );
    // A /32 has no next address; the IPv6 one is enough.
    assert_eq!(
        dns_hijack_addresses(&[p("172.19.0.1/32")], &[p("fdfe:dcba:9876::1/126")]).unwrap(),
        vec!["fdfe:dcba:9876::2".parse::<IpAddr>().unwrap()]
    );
    let error = dns_hijack_addresses(&[], &[p("fdfe:dcba:9876::1/128")]).unwrap_err();
    assert_eq!(error, "no IPv6 server configured and no usable next address in fdfe:dcba:9876::1/128 for DNS");
}

struct Direct;

#[async_trait]
impl Outbound for Direct {
    fn tag(&self) -> &str {
        "direct"
    }
    fn kind(&self) -> &'static str {
        "direct"
    }
    async fn dial_tcp(&self, _context: &InboundContext) -> io::Result<BoxStream> {
        Err(io::Error::other("unreachable in this test"))
    }
}

struct NoDns;

#[async_trait]
impl DnsResolver for NoDns {
    async fn lookup(&self, _domain: &str, _options: &LookupOptions) -> io::Result<Vec<IpAddr>> {
        Ok(Vec::new())
    }
}

fn handler(rules: &str) -> FlowHandler {
    let options: RouteConfig = serde_json::from_str(&format!(r#"{{"rules":{rules}}}"#)).unwrap();
    let router = Router::new(
        &options,
        vec![Arc::new(Direct)],
        Arc::new(NoDns),
        rb_adapter::InboundRegistry::new(),
        &Default::default(),
    )
    .unwrap();
    FlowHandler {
        tag: "tun-in".into(),
        router: Arc::new(router),
        dns: Arc::new(NoDns),
        dns_hijack: vec!["172.19.0.2".parse().unwrap()],
        udp_timeout: DEFAULT_UDP_TIMEOUT,
    }
}

#[tokio::test]
async fn flows_are_judged_like_sing_box() {
    let handler = handler(
        r#"[{"ip_cidr":"1.1.1.1/32","action":"reject"},{"inbound":"tun-in","port":9,"action":"reject","method":"drop"}]"#,
    );
    let source: SocketAddr = "172.19.0.1:40000".parse().unwrap();
    let judge = |network, destination: &str| {
        let destination: SocketAddr = destination.parse().unwrap();
        let handler = &handler;
        async move { handler.judge(network, source, destination, b"").await }
    };
    use rb_netstack::Network as N;
    // The DNS address: UDP is hijacked, TCP goes on (as `protocol: dns`).
    assert_eq!(judge(N::Udp, "172.19.0.2:53").await, Verdict::HijackDns);
    assert_eq!(judge(N::Tcp, "172.19.0.2:53").await, Verdict::Accept);
    assert_eq!(judge(N::Tcp, "1.1.1.1:443").await, Verdict::Reject);
    assert_eq!(judge(N::Udp, "8.8.8.8:9").await, Verdict::Drop);
    assert_eq!(judge(N::Udp, "8.8.8.8:443").await, Verdict::Accept);
    assert_eq!(judge(N::Icmp, "1.1.1.1:0").await, Verdict::Accept);
    let context = handler.context(Network::Tcp, source, "172.19.0.2:53".parse().unwrap());
    assert_eq!(context.protocol.as_deref(), Some("dns"));
    assert_eq!(context.inbound_type, "tun");
    let context = handler.context(Network::Udp, source, "8.8.8.8:443".parse().unwrap());
    assert_eq!(context.inbound_udp_timeout, Some(DEFAULT_UDP_TIMEOUT));
    assert!(context.protocol.is_none());
}

#[tokio::test]
async fn unknown_stack_fails_at_start() {
    use rb_adapter::Inbound as _;
    let options: TunOptions = serde_json::from_str(r#"{"stack":"lwip"}"#).unwrap();
    let inbound = Arc::new(TunInbound::new(&options, "t".into(), handler("[]").router, Arc::new(NoDns)).unwrap());
    assert_eq!(inbound.start().await.unwrap_err().to_string(), "unknown stack: lwip");
}

#[test]
fn options_and_defaults() {
    let options: TunOptions = serde_json::from_str(
        r#"{"address":["172.19.0.1/30","fdfe:dcba:9876::1/126"],"auto_route":true,"include_uid":[1000],
            "route_exclude_address":["10.0.0.0/8"]}"#,
    )
    .unwrap();
    let inbound = TunInbound::new(&options, "tun-in".into(), handler("[]").router, Arc::new(NoDns)).unwrap();
    assert_eq!(inbound.mtu(), if cfg!(target_os = "android") { 9000 } else { 65535 });
    let route = inbound.route_options("tun0").unwrap();
    assert_eq!((route.table_index, route.rule_index), (2022, 9000));
    assert_eq!(route.include_uid, vec![(1000, 1000)]);
    assert_eq!(dns_mode(&inbound.options), "hijack");
    let platform = inbound.platform_options("tun0", &route, &inbound.dns_servers(&route));
    assert_eq!(platform.dns_server_address.len(), 2);
    assert!(platform.inet4_route_range.iter().all(|it| !it.contains("10.1.2.3".parse().unwrap())));
    assert_eq!(platform.inet6_route_range, vec![Prefix::new("::".parse().unwrap(), 0)]);
    let options: TunOptions = serde_json::from_str(r#"{"stack":"lwip"}"#).unwrap();
    let inbound = TunInbound::new(&options, "t".into(), handler("[]").router, Arc::new(NoDns)).unwrap();
    assert_eq!(inbound.interface_name(), None);
    // Without auto_route there is no default table and DNS is not hijacked.
    let options: TunOptions = serde_json::from_str(r#"{"address":"172.19.0.1/30"}"#).unwrap();
    let inbound = TunInbound::new(&options, "t".into(), handler("[]").router, Arc::new(NoDns)).unwrap();
    assert_eq!(inbound.route_options("tun0").unwrap().table_index, 0);
    assert_eq!(dns_mode(&inbound.options), "disabled");
}
