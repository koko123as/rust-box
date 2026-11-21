use super::*;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::UdpSocket;
use tokio::sync::Notify;

static HOSTS_TEST_IDS: AtomicUsize = AtomicUsize::new(0);

/// A tiny DNS server answering every A query with `v4`, AAAA with `v6`, and
/// `nx.test` with NXDOMAIN. Returns its address and a query counter.
async fn fake_server(v4: [u8; 4], v6: std::net::Ipv6Addr) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let counter = count.clone();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 4096];
        loop {
            let Ok((size, peer)) = socket.recv_from(&mut buffer).await else { return };
            counter.fetch_add(1, Ordering::SeqCst);
            let request = Message::from_vec(&buffer[..size]).unwrap();
            let query = request.queries()[0].clone();
            let mut response = Message::new();
            response.set_id(request.id()).set_message_type(MessageType::Response).add_query(query.clone());
            if query.name().to_ascii() == "nx.test." {
                response.set_response_code(ResponseCode::NXDomain);
            } else if query.query_type() == RecordType::A {
                response.add_answer(Record::from_rdata(query.name().clone(), 300, RData::A(A(v4.into()))));
            } else if query.query_type() == RecordType::AAAA {
                response.add_answer(Record::from_rdata(query.name().clone(), 300, RData::AAAA(AAAA(v6))));
            } else if query.query_type() == RecordType::TXT {
                let txt = hickory_proto::rr::rdata::TXT::new(vec!["hello".into()]);
                response.add_answer(Record::from_rdata(query.name().clone(), 60, RData::TXT(txt)));
            }
            socket.send_to(&response.to_vec().unwrap(), peer).await.unwrap();
        }
    });
    (address, count)
}

async fn controlled_server(
    v4: [u8; 4],
    v6: std::net::Ipv6Addr,
    gate: Option<tokio::sync::oneshot::Receiver<()>>,
) -> (std::net::SocketAddr, Arc<AtomicUsize>, Arc<Notify>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let counter = count.clone();
    let received = Arc::new(Notify::new());
    let received_signal = received.clone();
    tokio::spawn(async move {
        let mut gate = gate;
        let mut buffer = vec![0u8; 4096];
        loop {
            let Ok((size, peer)) = socket.recv_from(&mut buffer).await else { return };
            counter.fetch_add(1, Ordering::SeqCst);
            received_signal.notify_one();
            if let Some(gate) = gate.take() {
                let _ = gate.await;
            }
            let request = Message::from_vec(&buffer[..size]).unwrap();
            let query = request.queries()[0].clone();
            let mut response = Message::new();
            response.set_id(request.id()).set_message_type(MessageType::Response).add_query(query.clone());
            if query.query_type() == RecordType::A {
                response.add_answer(Record::from_rdata(query.name().clone(), 300, RData::A(A(v4.into()))));
            } else if query.query_type() == RecordType::AAAA {
                response.add_answer(Record::from_rdata(query.name().clone(), 300, RData::AAAA(AAAA(v6))));
            }
            socket.send_to(&response.to_vec().unwrap(), peer).await.unwrap();
        }
    });
    (address, count, received)
}

fn try_router(options: &rb_config::DnsOptions) -> Result<Arc<DnsRouter>, DnsError> {
    let certificates = rb_certificate::Store::new(None).unwrap();
    DnsRouter::new(
        options,
        &Default::default(),
        &rb_adapter::OutboundRegistry::new(),
        &rb_rule::RuleSets::new(),
        &certificates,
    )
}

fn router(json: String) -> Arc<DnsRouter> {
    let options: rb_config::DnsOptions = serde_json::from_str(&json).unwrap();
    try_router(&options).unwrap()
}

#[tokio::test]
async fn udp_rules_strategy_and_cache() {
    let (first, first_count) = fake_server([1, 1, 1, 1], "2001:db8::1".parse().unwrap()).await;
    let (second, _) = fake_server([2, 2, 2, 2], "2001:db8::2".parse().unwrap()).await;
    let dns = router(format!(
        r#"{{"servers":[
            {{"type":"udp","tag":"first","server":"127.0.0.1","server_port":{}}},
            {{"type":"udp","tag":"second","server":"127.0.0.1","server_port":{}}}],
          "rules":[{{"domain_suffix":"two.test","server":"second","strategy":"ipv4_only"}},
                   {{"domain":"blocked.test","action":"reject"}}],
          "final":"first","strategy":"prefer_ipv6"}}"#,
        first.port(),
        second.port()
    ));
    let options = LookupOptions::default();
    let addresses = dns.lookup("one.test", &options).await.unwrap();
    assert_eq!(addresses, vec!["2001:db8::1".parse::<IpAddr>().unwrap(), "1.1.1.1".parse().unwrap()]);
    assert_eq!(first_count.load(Ordering::SeqCst), 2);
    // Cached: no new queries.
    dns.lookup("ONE.test.", &options).await.unwrap();
    assert_eq!(first_count.load(Ordering::SeqCst), 2);
    let addresses = dns.lookup("a.two.test", &options).await.unwrap();
    assert_eq!(addresses, vec!["2.2.2.2".parse::<IpAddr>().unwrap()]);
    assert!(dns.lookup("blocked.test", &options).await.is_err());
    let error = dns.lookup("nx.test", &options).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    // An explicit server bypasses the rules; IP literals are returned as is.
    let explicit =
        LookupOptions { server: Some("first".into()), strategy: DomainStrategy::Ipv4Only, ..Default::default() };
    assert_eq!(dns.lookup("a.two.test", &explicit).await.unwrap(), vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);
    assert_eq!(dns.lookup("10.0.0.1", &options).await.unwrap(), vec!["10.0.0.1".parse::<IpAddr>().unwrap()]);
}

#[tokio::test]
async fn local_resolver() {
    let dns = router(r#"{}"#.into());
    let addresses = dns.lookup("localhost", &LookupOptions::default()).await.unwrap();
    assert!(addresses.iter().all(|address| address.is_loopback()), "{addresses:?}");
}

#[test]
fn dot_server_defaults_to_853_and_requires_explicit_domain_resolver() {
    let dns = router(
        r#"{"servers":[{"type":"local","tag":"bootstrap"},
            {"type":"tls","tag":"dot","server":"dns.example","domain_resolver":"bootstrap"}],
            "final":"dot"}"#
            .into(),
    );
    let Transport::Dot(dot) = dns.servers.get("dot").unwrap().as_ref() else { panic!() };
    assert_eq!(dot.server(), &Socksaddr::from_host_port("dns.example", 853));

    let options: rb_config::DnsOptions =
        serde_json::from_str(r#"{"servers":[{"type":"tls","server":"dns.example"}]}"#).unwrap();
    let certificates = rb_certificate::Store::new(None).unwrap();
    let error = match DnsRouter::new(
        &options,
        &Default::default(),
        &rb_adapter::OutboundRegistry::new(),
        &rb_rule::RuleSets::new(),
        &certificates,
    ) {
        Ok(_) => panic!("domain DoT server without a resolver must fail during construction"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("missing domain resolver for domain server address"), "{error}");
}

#[test]
fn doq_server_defaults_to_853_and_sets_default_alpn() {
    let dns = router(
        r#"{"servers":[{"type":"local","tag":"bootstrap"},
            {"type":"quic","tag":"doq","server":"dns.example","domain_resolver":"bootstrap"}],
            "final":"doq"}"#
            .into(),
    );
    let Transport::Doq(doq) = dns.servers.get("doq").unwrap().as_ref() else { panic!() };
    assert_eq!(doq.server(), &Socksaddr::from_host_port("dns.example", 853));
    assert_eq!(doq.tls_server_name(), "dns.example");
    assert_eq!(doq.tls_alpn(), vec!["doq"]);

    let options: rb_config::DnsOptions =
        serde_json::from_str(r#"{"servers":[{"type":"quic","server":"dns.example"}]}"#).unwrap();
    let certificates = rb_certificate::Store::new(None).unwrap();
    let error = match DnsRouter::new(
        &options,
        &Default::default(),
        &rb_adapter::OutboundRegistry::new(),
        &rb_rule::RuleSets::new(),
        &certificates,
    ) {
        Ok(_) => panic!("domain DoQ server without a resolver must fail during construction"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("missing domain resolver for domain server address"), "{error}");
}

#[test]
fn http3_server_defaults_and_forces_h3_alpn_without_overriding_tls_identity() {
    let dns = router(
        r#"{"servers":[{"type":"local","tag":"bootstrap"},
            {"type":"h3","tag":"h3","server":"dns.example","domain_resolver":"bootstrap"}],
            "final":"h3"}"#
            .into(),
    );
    let Transport::H3(h3) = dns.servers.get("h3").unwrap().as_ref() else { panic!() };
    assert_eq!(h3.server(), &Socksaddr::from_host_port("dns.example", 443));
    assert_eq!(h3.authority(), "dns.example");
    assert_eq!(h3.path(), "/dns-query");
    assert_eq!(h3.uri().to_string(), "https://dns.example/dns-query");
    assert_eq!(h3.tls_server_name(), "dns.example");
    assert_eq!(h3.tls_alpn(), vec!["h3"]);

    let dns = router(
        r#"{"servers":[{"type":"local","tag":"bootstrap"},
            {"type":"h3","tag":"h3","server":"dns.example","server_port":8443,
             "domain_resolver":"bootstrap","path":"custom","method":"GET",
             "headers":{"Host":"resolver.example"},"tls":{"server_name":"verify.example","alpn":["h2"]}}],
            "final":"h3"}"#
            .into(),
    );
    let Transport::H3(h3) = dns.servers.get("h3").unwrap().as_ref() else { panic!() };
    assert_eq!(h3.server(), &Socksaddr::from_host_port("dns.example", 8443));
    assert_eq!(h3.authority(), "resolver.example:8443");
    assert_eq!(h3.uri().to_string(), "https://resolver.example:8443/custom");
    assert_eq!(h3.tls_server_name(), "verify.example");
    assert_eq!(h3.tls_alpn(), vec!["h3"]);

    let options: rb_config::DnsOptions =
        serde_json::from_str(r#"{"servers":[{"type":"h3","server":"dns.example"}]}"#).unwrap();
    let certificates = rb_certificate::Store::new(None).unwrap();
    let error = match DnsRouter::new(
        &options,
        &Default::default(),
        &rb_adapter::OutboundRegistry::new(),
        &rb_rule::RuleSets::new(),
        &certificates,
    ) {
        Ok(_) => panic!("domain DoH3 server without a resolver must fail during construction"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("missing domain resolver for domain server address"), "{error}");
}

#[test]
fn doh_server_defaults_and_uses_host_only_for_http_authority() {
    let dns = router(
        r#"{"servers":[{"type":"local","tag":"bootstrap"},
            {"type":"https","tag":"doh","server":"dns.example","domain_resolver":"bootstrap"}],
            "final":"doh"}"#
            .into(),
    );
    let Transport::Doh(doh) = dns.servers.get("doh").unwrap().as_ref() else { panic!() };
    assert_eq!(doh.server(), &Socksaddr::from_host_port("dns.example", 443));
    assert_eq!(doh.authority(), "dns.example");
    assert_eq!(doh.path(), "/dns-query");
    assert_eq!(doh.tls_server_name(), "dns.example");
    assert_eq!(doh.tls_alpn(), vec!["h2", "http/1.1"]);

    let dns = router(
        r#"{"servers":[{"type":"local","tag":"bootstrap"},
            {"type":"https","tag":"doh","server":"dns.example","domain_resolver":"bootstrap",
             "path":"/custom","headers":{"Host":"resolver.example"},
             "tls":{"server_name":"verify.example"}}],"final":"doh"}"#
            .into(),
    );
    let Transport::Doh(doh) = dns.servers.get("doh").unwrap().as_ref() else { panic!() };
    assert_eq!(doh.authority(), "resolver.example");
    assert_eq!(doh.path(), "/custom");
    assert_eq!(doh.tls_server_name(), "verify.example");

    let options: rb_config::DnsOptions =
        serde_json::from_str(r#"{"servers":[{"type":"https","server":"dns.example"}]}"#).unwrap();
    let certificates = rb_certificate::Store::new(None).unwrap();
    let error = match DnsRouter::new(
        &options,
        &Default::default(),
        &rb_adapter::OutboundRegistry::new(),
        &rb_rule::RuleSets::new(),
        &certificates,
    ) {
        Ok(_) => panic!("domain DoH server without a resolver must fail during construction"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("missing domain resolver for domain server address"), "{error}");
}

#[test]
fn cache_eviction() {
    let mut cache = Cache { entries: HashMap::new(), capacity: 2, disable_expire: false };
    cache.put(("s".to_string(), "ttl".to_string(), 1), vec!["1.1.1.1".parse().unwrap()], 60);
    assert!(cache.get(&("s".to_string(), "ttl".to_string(), 1)).unwrap().ttl <= 60);
    cache.entries.clear();
    let key = |name: &str| ("s".to_string(), name.to_string(), 1u16);
    cache.put(key("a"), vec![], 60);
    cache.put(key("b"), vec![], 60);
    cache.put(key("c"), vec![], 60);
    assert_eq!(cache.entries.len(), 2);
    cache.put(key("zero"), vec![], 0);
    assert!(cache.get(&key("zero")).is_none());
}

fn query(name: &str, query_type: RecordType) -> Vec<u8> {
    let mut message = Message::new();
    message
        .set_id(0x4242)
        .set_message_type(MessageType::Query)
        .set_recursion_desired(true)
        .add_query(hickory_proto::op::Query::query(hickory_proto::rr::Name::from_ascii(name).unwrap(), query_type));
    message.to_vec().unwrap()
}

#[tokio::test]
async fn exchange_messages() {
    let (server, count) = fake_server([1, 2, 3, 4], "2001:db8::1".parse().unwrap()).await;
    let dns = router(format!(
        r#"{{"servers":[{{"type":"udp","tag":"up","server":"127.0.0.1","server_port":{}}}],
          "rules":[{{"domain":"refused.test","action":"reject"}},
                   {{"domain":"dropped.test","action":"reject","method":"drop"}},
                   {{"domain":"v4.test","server":"up","strategy":"ipv4_only"}}]}}"#,
        server.port()
    ));
    let options = LookupOptions::default();
    let answer = dns.exchange(&query("a.test.", RecordType::A), &options).await.unwrap().unwrap();
    let answer = Message::from_vec(&answer).unwrap();
    assert_eq!(answer.id(), 0x4242);
    assert_eq!(answer.message_type(), MessageType::Response);
    assert!(matches!(answer.answers()[0].data(), RData::A(a) if a.0 == std::net::Ipv4Addr::new(1, 2, 3, 4)));
    // Answered from the cache the second time.
    dns.exchange(&query("a.test.", RecordType::A), &options).await.unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);
    // Other types are forwarded as they are.
    let answer = dns.exchange(&query("a.test.", RecordType::TXT), &options).await.unwrap().unwrap();
    let answer = Message::from_vec(&answer).unwrap();
    assert_eq!(answer.id(), 0x4242);
    assert!(matches!(answer.answers()[0].data(), RData::TXT(_)));
    let answer = dns.exchange(&query("nx.test.", RecordType::A), &options).await.unwrap().unwrap();
    assert_eq!(Message::from_vec(&answer).unwrap().response_code(), ResponseCode::NXDomain);
    let answer = dns.exchange(&query("refused.test.", RecordType::A), &options).await.unwrap().unwrap();
    assert_eq!(Message::from_vec(&answer).unwrap().response_code(), ResponseCode::Refused);
    assert!(dns.exchange(&query("dropped.test.", RecordType::A), &options).await.unwrap().is_none());
    // ipv4_only answers AAAA with no records, without asking upstream.
    let before = count.load(Ordering::SeqCst);
    let answer = dns.exchange(&query("v4.test.", RecordType::AAAA), &options).await.unwrap().unwrap();
    let answer = Message::from_vec(&answer).unwrap();
    assert_eq!(answer.response_code(), ResponseCode::NoError);
    assert!(answer.answers().is_empty());
    assert_eq!(count.load(Ordering::SeqCst), before);
    assert!(dns.exchange(b"garbage", &options).await.is_err());
}

#[test]
fn direct_dns_options_validate_evaluate_server_references() {
    for (json, expected) in [
        (r#"{"rules":[{"action":"evaluate"}]}"#, "dns.rules[0]: missing server field"),
        (r#"{"rules":[{"action":"evaluate","server":"missing"}]}"#, "dns.rules[0]: DNS server not found: missing"),
        (
            r#"{"servers":[{"type":"fakeip","tag":"fake","inet4_range":"198.18.0.0/15"}],
                "rules":[{"action":"evaluate","server":"fake"}]}"#,
            "dns.rules[0]: evaluate action cannot use fakeip server: fake",
        ),
    ] {
        let options: rb_config::DnsOptions = serde_json::from_str(json).unwrap();
        let error = match try_router(&options) {
            Ok(_) => panic!("invalid evaluate server reference was accepted"),
            Err(error) => error.to_string(),
        };
        assert_eq!(error, expected);
    }
}

#[test]
fn nested_dns_rule_actions_are_rejected_in_every_mode() {
    for legacy in [false, true] {
        let route_action = || DnsRuleAction::Route {
            server: "local".into(),
            options: Default::default(),
            speculative: false,
            race: false,
        };
        let nested = rb_config::DnsRule::Default {
            matcher: rb_config::DnsRuleMatch { ip_is_private: legacy, ..Default::default() },
            action: Some(route_action()),
        };
        let logical = rb_config::DnsRule::Logical {
            mode: rb_config::LogicalMode::And,
            rules: vec![nested],
            invert: false,
            action: Some(route_action()),
        };
        let options = rb_config::DnsOptions {
            servers: vec![DnsServer::Local { tag: "local".into() }],
            rules: vec![logical],
            ..Default::default()
        };
        let error = match try_router(&options) {
            Ok(_) => panic!("nested DNS rule actions must be rejected in every rule mode"),
            Err(error) => error.to_string(),
        };
        assert_eq!(error, "dns rule[0]: sub rule[0]: DNS rule action is not supported in nested rules");
    }
}

#[tokio::test]
async fn evaluate_respond_preserves_tagged_response_and_isolates_requests() {
    let (first, first_count) = fake_server([1, 2, 3, 4], "2001:db8::1".parse().unwrap()).await;
    let (second, second_count) = fake_server([5, 6, 7, 8], "2001:db8::2".parse().unwrap()).await;
    let dns = router(format!(
        r#"{{"disable_cache":true,"servers":[
            {{"type":"udp","tag":"first","server":"127.0.0.1","server_port":{}}},
            {{"type":"udp","tag":"second","server":"127.0.0.1","server_port":{}}}],
          "rules":[
            {{"domain":"tag.test","action":"evaluate","server":"first","tag":"primary"}},
            {{"domain":"tag.test","action":"evaluate","server":"second"}},
            {{"domain":"tag.test","match_response":"primary","action":"respond"}},
            {{"domain":"isolated.test","action":"respond"}}]}}"#,
        first.port(),
        second.port()
    ));
    let lookup_options = LookupOptions { strategy: DomainStrategy::Ipv4Only, ..Default::default() };
    assert_eq!(dns.lookup("tag.test", &lookup_options).await.unwrap(), vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
    assert_eq!(first_count.load(Ordering::SeqCst), 1);
    assert_eq!(second_count.load(Ordering::SeqCst), 1);

    let answer = dns.exchange(&query("tag.test.", RecordType::A), &LookupOptions::default()).await.unwrap().unwrap();
    let answer = Message::from_vec(&answer).unwrap();
    assert_eq!(answer.id(), 0x4242);
    assert_eq!(answer.response_code(), ResponseCode::NoError);
    assert!(matches!(answer.answers()[0].data(), RData::A(a) if a.0 == std::net::Ipv4Addr::new(1, 2, 3, 4)));
    assert_eq!(first_count.load(Ordering::SeqCst), 2);
    assert_eq!(second_count.load(Ordering::SeqCst), 2);

    let error = dns.lookup("isolated.test", &lookup_options).await.unwrap_err();
    assert_eq!(error.to_string(), "respond action requires an evaluated response from a preceding evaluate action");
    let error = dns.exchange(&query("isolated.test.", RecordType::A), &LookupOptions::default()).await.unwrap_err();
    assert_eq!(error.to_string(), "respond action requires an evaluated response from a preceding evaluate action");
}

#[tokio::test]
async fn evaluate_failure_and_missing_response_return_compatibility_error() {
    let failed_evaluate = router(
        r#"{"servers":[{"type":"local","tag":"local"}],
            "rules":[{"domain":"failed.test","action":"evaluate","server":"local"},
                     {"domain":"failed.test","action":"respond"}]}"#
            .into(),
    );
    let error =
        failed_evaluate.exchange(&query("failed.test.", RecordType::TXT), &LookupOptions::default()).await.unwrap_err();
    assert_eq!(error.to_string(), "respond action requires an evaluated response from a preceding evaluate action");

    let missing = router(r#"{"rules":[{"domain":"missing.test","action":"respond"}]}"#.into());
    let options = LookupOptions { strategy: DomainStrategy::Ipv4Only, ..Default::default() };
    let error = missing.lookup("missing.test", &options).await.unwrap_err();
    assert_eq!(error.to_string(), "respond action requires an evaluated response from a preceding evaluate action");
    let error = missing.exchange(&query("missing.test.", RecordType::A), &LookupOptions::default()).await.unwrap_err();
    assert_eq!(error.to_string(), "respond action requires an evaluated response from a preceding evaluate action");
}

#[tokio::test]
async fn race_response_selects_ready_match_without_waiting_for_earlier_pending_rule() {
    let (slow_gate, slow_release) = tokio::sync::oneshot::channel();
    let (slow, _, slow_received) =
        controlled_server([1, 2, 3, 4], "2001:db8::1".parse().unwrap(), Some(slow_release)).await;
    let (fast, _, fast_received) = controlled_server([5, 6, 7, 8], "2001:db8::2".parse().unwrap(), None).await;
    let dns = router(format!(
        r#"{{"disable_cache":true,"servers":[
            {{"type":"udp","tag":"slow","server":"127.0.0.1","server_port":{}}},
            {{"type":"udp","tag":"fast","server":"127.0.0.1","server_port":{}}}],
          "rules":[
            {{"domain":"race.test","action":"evaluate","server":"slow","tag":"slow"}},
            {{"domain":"race.test","action":"evaluate","server":"fast","tag":"fast"}},
            {{"domain":"race.test","match_response":"slow","response_rcode":"NOERROR","action":"respond","race":true}},
            {{"domain":"race.test","match_response":"fast","response_rcode":"NOERROR","action":"respond","race":true}}]}}"#,
        slow.port(),
        fast.port()
    ));
    let task = tokio::spawn(async move {
        dns.exchange(&query("race.test.", RecordType::A), &LookupOptions::default()).await.unwrap().unwrap()
    });
    tokio::time::timeout(Duration::from_secs(2), slow_received.notified()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), fast_received.notified()).await.unwrap();
    let answer = tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap();
    let _ = slow_gate.send(());
    let answer = Message::from_vec(&answer).unwrap();
    assert!(matches!(answer.answers()[0].data(), RData::A(a) if a.0 == std::net::Ipv4Addr::new(5, 6, 7, 8)));
}

#[tokio::test]
async fn ordinary_response_rule_waits_for_earlier_evaluate_before_later_response() {
    let (slow_gate, slow_release) = tokio::sync::oneshot::channel();
    let (slow, _, slow_received) =
        controlled_server([1, 2, 3, 4], "2001:db8::1".parse().unwrap(), Some(slow_release)).await;
    let (fast, _, fast_received) = controlled_server([5, 6, 7, 8], "2001:db8::2".parse().unwrap(), None).await;
    let dns = router(format!(
        r#"{{"disable_cache":true,"servers":[
            {{"type":"udp","tag":"slow","server":"127.0.0.1","server_port":{}}},
            {{"type":"udp","tag":"fast","server":"127.0.0.1","server_port":{}}}],
          "rules":[
            {{"domain":"ordered.test","action":"evaluate","server":"slow","tag":"slow"}},
            {{"domain":"ordered.test","action":"evaluate","server":"fast","tag":"fast"}},
            {{"domain":"ordered.test","match_response":"slow","action":"respond"}},
            {{"domain":"ordered.test","match_response":"fast","action":"respond"}}]}}"#,
        slow.port(),
        fast.port()
    ));
    let task = tokio::spawn(async move {
        dns.exchange(&query("ordered.test.", RecordType::A), &LookupOptions::default()).await.unwrap().unwrap()
    });
    tokio::time::timeout(Duration::from_secs(2), slow_received.notified()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), fast_received.notified()).await.unwrap();
    assert!(!task.is_finished(), "a later ready response must not bypass an earlier non-race response rule");
    let _ = slow_gate.send(());
    let answer = tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap();
    let answer = Message::from_vec(&answer).unwrap();
    assert!(matches!(answer.answers()[0].data(), RData::A(a) if a.0 == std::net::Ipv4Addr::new(1, 2, 3, 4)));
}

#[tokio::test]
async fn pending_race_miss_is_a_barrier_before_default_final_server() {
    let (evaluate_gate, evaluate_release) = tokio::sync::oneshot::channel();
    let (evaluate, _, evaluate_received) =
        controlled_server([1, 2, 3, 4], "2001:db8::1".parse().unwrap(), Some(evaluate_release)).await;
    let (final_server, _, final_received) =
        controlled_server([9, 10, 11, 12], "2001:db8::9".parse().unwrap(), None).await;
    let dns = router(format!(
        r#"{{"disable_cache":true,"servers":[
            {{"type":"udp","tag":"evaluate","server":"127.0.0.1","server_port":{}}},
            {{"type":"udp","tag":"final","server":"127.0.0.1","server_port":{}}}],
          "rules":[
            {{"domain":"fallback.test","action":"evaluate","server":"evaluate","tag":"probe"}},
            {{"domain":"fallback.test","match_response":"probe","response_rcode":"NXDOMAIN","action":"respond","race":true}}],
          "final":"final"}}"#,
        evaluate.port(),
        final_server.port()
    ));
    let task = tokio::spawn(async move {
        dns.exchange(&query("fallback.test.", RecordType::A), &LookupOptions::default()).await.unwrap().unwrap()
    });
    tokio::time::timeout(Duration::from_secs(2), evaluate_received.notified()).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), final_received.notified()).await.is_err(),
        "the default final server must wait until the earlier race rule resolves"
    );
    let _ = evaluate_gate.send(());
    let final_answer = tokio::time::timeout(Duration::from_secs(2), final_received.notified()).await;
    assert!(final_answer.is_ok(), "a race miss must fall through to the default final server");
    let answer = tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap();
    let answer = Message::from_vec(&answer).unwrap();
    assert!(matches!(answer.answers()[0].data(), RData::A(a) if a.0 == std::net::Ipv4Addr::new(9, 10, 11, 12)));
}

#[tokio::test]
async fn speculative_route_starts_while_race_response_is_pending() {
    let (evaluate_gate, evaluate_release) = tokio::sync::oneshot::channel();
    let (evaluate, _, evaluate_received) =
        controlled_server([1, 2, 3, 4], "2001:db8::1".parse().unwrap(), Some(evaluate_release)).await;
    let (final_server, _, final_received) =
        controlled_server([9, 10, 11, 12], "2001:db8::9".parse().unwrap(), None).await;
    let dns = router(format!(
        r#"{{"disable_cache":true,"servers":[
            {{"type":"udp","tag":"evaluate","server":"127.0.0.1","server_port":{}}},
            {{"type":"udp","tag":"final","server":"127.0.0.1","server_port":{}}}],
          "rules":[
            {{"domain":"speculative.test","action":"evaluate","server":"evaluate","tag":"probe"}},
            {{"domain":"speculative.test","match_response":"probe","response_rcode":"NXDOMAIN","action":"respond","race":true}},
            {{"domain":"speculative.test","action":"route","server":"final","speculative":true}}]}}"#,
        evaluate.port(),
        final_server.port()
    ));
    let task = tokio::spawn(async move {
        dns.exchange(&query("speculative.test.", RecordType::A), &LookupOptions::default()).await.unwrap().unwrap()
    });
    tokio::time::timeout(Duration::from_secs(2), evaluate_received.notified()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), final_received.notified()).await.unwrap();
    let _ = evaluate_gate.send(());
    let answer = tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap();
    let answer = Message::from_vec(&answer).unwrap();
    assert!(matches!(answer.answers()[0].data(), RData::A(a) if a.0 == std::net::Ipv4Addr::new(9, 10, 11, 12)));
}

#[tokio::test]
async fn hosts_predefined_path_order_and_dns_responses() {
    let id = HOSTS_TEST_IDS.fetch_add(1, Ordering::Relaxed);
    let first = std::env::temp_dir().join(format!("rust-box-hosts-{}-{id}-first", std::process::id()));
    let second = std::env::temp_dir().join(format!("rust-box-hosts-{}-{id}-second", std::process::id()));
    std::fs::write(&first, "1.1.1.1 file.test first-only.test pre.test\n").unwrap();
    std::fs::write(&second, "3.3.3.3 file.test second-only.test pre.test\n").unwrap();
    let config = serde_json::json!({
        "disable_cache": true,
        "servers": [{
            "type": "hosts",
            "tag": "hosts",
            "path": [first.to_string_lossy(), second.to_string_lossy()],
            "predefined": {"pre.test": ["9.9.9.9", "2001:db8::9"]}
        }],
        "final": "hosts"
    })
    .to_string();
    let dns = router(config);
    let options = LookupOptions::default();

    assert_eq!(
        dns.lookup("pre.test", &options).await.unwrap(),
        vec!["9.9.9.9".parse::<IpAddr>().unwrap(), "2001:db8::9".parse().unwrap()]
    );
    assert_eq!(dns.lookup("file.test", &options).await.unwrap(), vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);
    assert_eq!(dns.lookup("first-only.test", &options).await.unwrap(), vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);
    assert_eq!(dns.lookup("second-only.test", &options).await.unwrap(), vec!["3.3.3.3".parse::<IpAddr>().unwrap()]);

    let answer = dns.exchange(&query("pre.test.", RecordType::A), &options).await.unwrap().unwrap();
    let answer = Message::from_vec(&answer).unwrap();
    assert_eq!(answer.response_code(), ResponseCode::NoError);
    assert_eq!(answer.answers().len(), 1);
    assert_eq!(answer.answers()[0].ttl(), 600);
    assert!(
        matches!(answer.answers()[0].data(), RData::A(address) if address.0 == std::net::Ipv4Addr::new(9, 9, 9, 9))
    );

    let answer = dns.exchange(&query("pre.test.", RecordType::AAAA), &options).await.unwrap().unwrap();
    let answer = Message::from_vec(&answer).unwrap();
    assert_eq!(answer.answers().len(), 1);
    assert_eq!(answer.answers()[0].ttl(), 600);
    assert!(
        matches!(answer.answers()[0].data(), RData::AAAA(address) if address.0 == "2001:db8::9".parse::<std::net::Ipv6Addr>().unwrap())
    );

    let answer = dns.exchange(&query("file.test.", RecordType::AAAA), &options).await.unwrap().unwrap();
    let answer = Message::from_vec(&answer).unwrap();
    assert_eq!(answer.response_code(), ResponseCode::NoError);
    assert!(answer.answers().is_empty());

    for (name, query_type) in [("missing.test.", RecordType::A), ("pre.test.", RecordType::TXT)] {
        let answer = dns.exchange(&query(name, query_type), &options).await.unwrap().unwrap();
        assert_eq!(Message::from_vec(&answer).unwrap().response_code(), ResponseCode::NXDomain);
    }
    assert_eq!(dns.lookup("missing.test", &options).await.unwrap_err().kind(), io::ErrorKind::NotFound);
    std::fs::remove_file(first).unwrap();
    std::fs::remove_file(second).unwrap();
}

#[tokio::test]
async fn fakeip_allocates_per_domain_and_supports_reverse_lookup() {
    let dns = router(
        r#"{"servers":[
            {"type":"fakeip","tag":"fake","inet4_range":"198.18.0.0/15","inet6_range":"2001:2::/48"},
            {"type":"local","tag":"local"}],"final":"local"}"#
            .into(),
    );
    let options =
        LookupOptions { server: Some("fake".into()), strategy: DomainStrategy::Ipv4Only, ..Default::default() };
    let first = dns.lookup("one.test", &options).await.unwrap();
    assert_eq!(first, vec!["198.18.0.2".parse::<IpAddr>().unwrap()]);
    assert_eq!(dns.lookup("ONE.TEST.", &options).await.unwrap(), first);
    assert_eq!(dns.reverse_lookup(first[0]).unwrap().as_deref(), Some("one.test"));
    assert_eq!(dns.reverse_lookup("203.0.113.1".parse().unwrap()).unwrap(), None);
    assert!(dns
        .reverse_lookup("198.18.0.4".parse().unwrap())
        .unwrap_err()
        .to_string()
        .contains("missing fakeip record"));

    let v6 = LookupOptions { strategy: DomainStrategy::Ipv6Only, ..options };
    assert_eq!(dns.lookup("one.test", &v6).await.unwrap(), vec!["2001:2::2".parse::<IpAddr>().unwrap()]);
}

#[test]
fn fakeip_server_must_be_unique_and_not_the_default() {
    for config in [
        r#"{"servers":[{"type":"fakeip","inet4_range":"198.18.0.0/15"}]}"#,
        r#"{"servers":[{"type":"fakeip","tag":"a","inet4_range":"198.18.0.0/15"},
            {"type":"fakeip","tag":"b","inet6_range":"2001:2::/48"}],"final":"local"}"#,
    ] {
        let options: rb_config::DnsOptions = serde_json::from_str(config).unwrap();
        let certificates = rb_certificate::Store::new(None).unwrap();
        let error = match DnsRouter::new(
            &options,
            &Default::default(),
            &rb_adapter::OutboundRegistry::new(),
            &rb_rule::RuleSets::new(),
            &certificates,
        ) {
            Ok(_) => panic!("invalid FakeIP server registration must fail"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("default server cannot be fakeip") || error.contains("multiple fakeip server"),
            "{error}"
        );
    }
}
