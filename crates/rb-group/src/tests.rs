use super::*;

use std::net::SocketAddr;

use rb_config::types::Duration as ConfigDuration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// An outbound that connects every TCP connection to `target` (none: fails).
struct Fixed {
    tag: String,
    target: Option<SocketAddr>,
    networks: &'static [Network],
}

fn fixed(tag: &str, target: Option<SocketAddr>) -> Arc<dyn Outbound> {
    Arc::new(Fixed { tag: tag.into(), target, networks: TCP_UDP })
}

#[async_trait]
impl Outbound for Fixed {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "direct"
    }

    fn networks(&self) -> &[Network] {
        self.networks
    }

    async fn dial_tcp(&self, _context: &InboundContext) -> io::Result<BoxStream> {
        match self.target {
            Some(target) => Ok(Box::new(TcpStream::connect(target).await?)),
            None => Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused")),
        }
    }
}

/// An HTTP server answering `204` to every request after `delay`.
async fn http_server(delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 4096];
                let mut read = 0;
                while !buffer[..read].windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut buffer[read..]).await {
                        Ok(0) | Err(_) => return,
                        Ok(count) => read += count,
                    }
                }
                assert!(buffer.starts_with(b"HEAD /generate_204 HTTP/1.1\r\nHost: test.invalid\r\n"));
                tokio::time::sleep(delay).await;
                let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await;
            });
        }
    });
    address
}

fn context(cache_file: Option<Arc<CacheFile>>) -> GroupContext {
    GroupContext { cache_file, history: HistoryStorage::new(), store: Store::new(None).unwrap() }
}

fn lookup(outbounds: &[Arc<dyn Outbound>]) -> impl Fn(&str) -> Option<Arc<dyn Outbound>> + '_ {
    move |tag| outbounds.iter().find(|outbound| outbound.tag() == tag).cloned()
}

fn selector_options(default: &str) -> SelectorOutbound {
    SelectorOutbound {
        tag: "proxy".into(),
        outbounds: vec!["a".into(), "b".into(), "c".into()],
        default: default.into(),
        interrupt_exist_connections: false,
    }
}

const LINK: &str = "http://test.invalid/generate_204";

#[test]
fn selector_selection_and_persistence() {
    let members = [fixed("a", None), fixed("b", None), fixed("c", None)];
    let directory = tempfile::tempdir().unwrap();
    let cache_options = rb_config::CacheFileOptions {
        enabled: true,
        path: directory.path().join("cache.db").to_string_lossy().into_owned(),
        ..Default::default()
    };
    let cache_file = Arc::new(CacheFile::new(&cache_options));
    cache_file.open().unwrap();

    let selector = Selector::new(&selector_options(""), context(Some(cache_file.clone())));
    selector.start(&lookup(&members)).unwrap();
    assert_eq!(selector.now().unwrap().tag(), "a");

    let selector = Selector::new(&selector_options("b"), context(Some(cache_file.clone())));
    selector.start(&lookup(&members)).unwrap();
    assert_eq!(selector.now().unwrap().tag(), "b");
    assert!(!selector.select_outbound("missing"));
    assert!(selector.select_outbound("c"));
    assert_eq!(cache_file.load_selected("proxy"), "c");

    // The saved selection wins over `default`; an unknown saved one does not.
    let selector = Selector::new(&selector_options("b"), context(Some(cache_file.clone())));
    selector.start(&lookup(&members)).unwrap();
    assert_eq!(selector.now().unwrap().tag(), "c");
    cache_file.store_selected("proxy", "gone").unwrap();
    let selector = Selector::new(&selector_options("b"), context(Some(cache_file.clone())));
    selector.start(&lookup(&members)).unwrap();
    assert_eq!(selector.now().unwrap().tag(), "b");

    let selector = Selector::new(&selector_options("x"), context(None));
    assert_eq!(selector.start(&lookup(&members)).unwrap_err(), "default outbound not found: x");
    let selector = Selector::new(&selector_options(""), context(None));
    assert_eq!(selector.start(&lookup(&members[..2])).unwrap_err(), "outbound 2 not found: c");
}

#[test]
fn selector_interrupts_attached_connections() {
    let members = [fixed("a", None), fixed("b", None), fixed("c", None)];
    for interrupt_external in [false, true] {
        let options = SelectorOutbound { interrupt_exist_connections: interrupt_external, ..selector_options("") };
        let selector = Selector::new(&options, context(None));
        selector.start(&lookup(&members)).unwrap();
        let external = Interrupt::new(true);
        let internal = Interrupt::new(false);
        let _external = selector.attach(external.clone());
        let internal_attachment = selector.attach(internal.clone());
        assert_eq!(selector.attached(), 2);
        // Selecting the current member changes nothing.
        assert!(selector.select_outbound("a"));
        assert!(!internal.is_closed());
        assert!(selector.select_outbound("b"));
        assert!(internal.is_closed());
        assert_eq!(external.is_closed(), interrupt_external);
        drop(internal_attachment);
        assert_eq!(selector.attached(), usize::from(!interrupt_external));
    }
}

fn urltest_options(members: &[&str]) -> UrlTestOutbound {
    UrlTestOutbound {
        tag: "auto".into(),
        outbounds: members.iter().map(|tag| tag.to_string()).collect(),
        url: LINK.into(),
        ..Default::default()
    }
}

fn record(history: &HistoryStorage, tag: &str, delay: u16) {
    history.store(tag, UrlTestHistory { time: SystemTime::now(), delay });
}

#[test]
fn urltest_selection_and_tolerance() {
    let members = [fixed("a", None), fixed("b", None), fixed("c", None)];
    let shared = context(None);
    let urltest = UrlTest::new(&urltest_options(&["a", "b", "c"]), shared.clone());
    urltest.start(&lookup(&members)).unwrap();
    // No results: the first member, not adopted as tested.
    assert_eq!(urltest.selected(Network::Tcp).unwrap().tag(), "a");
    let group = urltest.state.get().unwrap().clone();
    record(&shared.history, "b", 200);
    record(&shared.history, "c", 120);
    group.perform_update_check();
    assert_eq!(urltest.selected(Network::Tcp).unwrap().tag(), "c");
    let interrupt = Interrupt::new(true);
    let _attachment = urltest.attach(interrupt.clone());
    // Within the tolerance (50 ms) the selection stays.
    record(&shared.history, "a", 80);
    group.perform_update_check();
    assert_eq!(urltest.selected(Network::Tcp).unwrap().tag(), "c");
    assert!(!interrupt.is_closed());
    // Beyond it the selection moves; external connections stay unless
    // `interrupt_exist_connections`.
    record(&shared.history, "a", 60);
    group.perform_update_check();
    assert_eq!(urltest.selected(Network::Udp).unwrap().tag(), "a");
    assert!(!interrupt.is_closed());

    let mut options = urltest_options(&["a"]);
    options.interval = ConfigDuration(Duration::from_secs(3600));
    options.idle_timeout = ConfigDuration(Duration::from_secs(60));
    let urltest = UrlTest::new(&options, context(None));
    assert_eq!(urltest.start(&lookup(&members)).unwrap_err(), "interval must be less or equal than idle_timeout");
}

#[tokio::test]
async fn url_test_measures_delay() {
    let server = http_server(Duration::from_millis(30)).await;
    let store = Store::new(None).unwrap();
    let delay = url_test(LINK, &fixed("a", Some(server)), &store).await.unwrap();
    assert!((30..2000).contains(&delay), "{delay}");
    assert!(url_test(LINK, &fixed("b", None), &store).await.is_err());
    assert!(url_test("ftp://x/", &fixed("a", Some(server)), &store).await.is_err());
}

#[tokio::test]
async fn url_test_outbounds_through_groups() {
    let slow = http_server(Duration::from_millis(250)).await;
    let fast = http_server(Duration::from_millis(10)).await;
    let shared = context(None);
    let a = fixed("a", Some(slow));
    let b = fixed("b", Some(fast));
    let dead = fixed("dead", None);
    record(&shared.history, "dead", 5);
    let auto: Arc<UrlTest> = Arc::new(UrlTest::new(&urltest_options(&["a", "b", "dead"]), shared.clone()));
    let members = vec![a.clone(), b.clone(), dead.clone()];
    auto.start(&lookup(&members)).unwrap();
    let auto_outbound: Arc<dyn Outbound> = auto.clone();
    let selector_options =
        SelectorOutbound { tag: "proxy".into(), outbounds: vec!["auto".into(), "a".into()], ..Default::default() };
    let selector = Arc::new(Selector::new(&selector_options, shared.clone()));
    let all = vec![a.clone(), b.clone(), dead.clone(), auto_outbound.clone()];
    selector.start(&lookup(&all)).unwrap();
    let selector_outbound: Arc<dyn Outbound> = selector.clone();

    let result = url_test_outbounds(
        std::slice::from_ref(&selector_outbound),
        LINK,
        DEFAULT_INTERVAL,
        true,
        &shared.history,
        &shared.store,
    )
    .await;
    assert!(result.contains_key("a") && result.contains_key("b"), "{result:?}");
    assert!(!result.contains_key("dead"));
    assert!(shared.history.load("dead").is_none());
    assert_eq!(auto.selected(Network::Tcp).unwrap().tag(), "b");
    // The groups report their TCP selection's delay.
    assert_eq!(result["auto"], result["b"]);
    assert_eq!(result["proxy"], result["b"]);

    // Fresh results are kept without `force`.
    let again =
        url_test_outbounds(std::slice::from_ref(&a), LINK, DEFAULT_INTERVAL, false, &shared.history, &shared.store)
            .await;
    assert!(again.is_empty());

    // Dialing through the group attaches the connection to it.
    let stream = auto_outbound
        .dial_tcp(&InboundContext::internal(
            Network::Tcp,
            rb_adapter::Socksaddr::new(rb_adapter::Host::Domain("x".into()), 80),
        ))
        .await
        .unwrap();
    assert_eq!(auto.attached(), 1);
    drop(stream);
    assert_eq!(auto.attached(), 0);
    auto.close();
}
