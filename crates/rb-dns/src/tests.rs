use super::*;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::UdpSocket;

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
            }
            socket.send_to(&response.to_vec().unwrap(), peer).await.unwrap();
        }
    });
    (address, count)
}

fn router(json: String) -> DnsRouter {
    let options: rb_config::DnsOptions = serde_json::from_str(&json).unwrap();
    DnsRouter::new(&options).unwrap()
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
fn cache_eviction() {
    let mut cache = Cache { entries: HashMap::new(), capacity: 2, disable_expire: false };
    let key = |name: &str| ("s".to_string(), name.to_string(), 1u16);
    cache.put(key("a"), vec![], 60);
    cache.put(key("b"), vec![], 60);
    cache.put(key("c"), vec![], 60);
    assert_eq!(cache.entries.len(), 2);
    cache.put(key("zero"), vec![], 0);
    assert!(cache.get(&key("zero")).is_none());
}
