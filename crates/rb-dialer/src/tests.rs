use super::*;
use rb_config::{Duration as ConfigDuration, FwMark, ListenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn dialer(options: DialerOptions) -> DefaultDialer {
    DefaultDialer::new(&options, &NetworkDefaults::default(), false).unwrap()
}

async fn echo_listener() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let mut buffer = [0u8; 1024];
                while let Ok(read) = stream.read(&mut buffer).await {
                    if read == 0 || stream.write_all(&buffer[..read]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    address
}

async fn roundtrip(mut stream: BoxStream) {
    stream.write_all(b"ping").await.unwrap();
    let mut reply = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut reply)).await.unwrap().unwrap();
    assert_eq!(&reply, b"ping");
}

#[tokio::test]
async fn bind_address_and_keep_alive() {
    let echo = echo_listener().await;
    let dialer = dialer(DialerOptions {
        inet4_bind_address: Some("127.0.0.1".parse().unwrap()),
        bind_address_no_port: true,
        tcp_keep_alive: ConfigDuration(Duration::from_secs(42)),
        tcp_keep_alive_interval: ConfigDuration(Duration::from_secs(7)),
        ..Default::default()
    });
    let stream = dialer.connect_tcp(echo).await.unwrap();
    assert_eq!(stream.local_addr().unwrap().ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let fd = stream.as_raw_fd();
        assert_eq!(sys::getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE).unwrap(), 1);
        assert_eq!(sys::getsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE).unwrap(), 42);
        assert_eq!(sys::getsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL).unwrap(), 7);
    }
    roundtrip(Box::new(stream)).await;

    // disable_tcp_keep_alive leaves keep-alive off.
    let dialer = self::dialer(DialerOptions { disable_tcp_keep_alive: true, ..Default::default() });
    let stream = dialer.connect_tcp(echo).await.unwrap();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    assert_eq!(sys::getsockopt_int(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_KEEPALIVE).unwrap(), 0);
    drop(stream);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn udp_fragment_and_reuse() {
    // direct: fragmentation on by default (IP_PMTUDISC_DONT = 0).
    let direct = DefaultDialer::new(&DialerOptions::default(), &NetworkDefaults::default(), true).unwrap();
    let (socket, _) = direct.listen_udp(Some("127.0.0.1".parse().unwrap())).await.unwrap();
    assert_eq!(sys::udp_fragment_mode(socket.as_raw_fd(), false).unwrap(), 0);
    // DNS servers: off by default (IP_PMTUDISC_DO = 2).
    let dns = dialer(DialerOptions { reuse_addr: true, ..Default::default() });
    let (socket, _) = dns.listen_udp(Some("127.0.0.1".parse().unwrap())).await.unwrap();
    assert_eq!(sys::udp_fragment_mode(socket.as_raw_fd(), false).unwrap(), 2);
    assert_eq!(sys::getsockopt_int(socket.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEPORT).unwrap(), 1);
    // udp_fragment set explicitly wins over the default.
    let explicit = DefaultDialer::new(
        &DialerOptions { udp_fragment: Some(false), ..Default::default() },
        &NetworkDefaults::default(),
        true,
    )
    .unwrap();
    let socket = explicit.connect_udp("127.0.0.1:53".parse().unwrap()).await.unwrap();
    assert_eq!(sys::udp_fragment_mode(socket.as_raw_fd(), false).unwrap(), 2);
}

#[tokio::test]
async fn listen_udp_families() {
    let dialer = dialer(DialerOptions::default());
    // An IPv4 destination gets an IPv4-only socket, as sing-box's "udp4".
    let (socket, dual) = dialer.listen_udp(Some("127.0.0.1".parse().unwrap())).await.unwrap();
    assert!(!dual);
    assert!(socket.local_addr().unwrap().is_ipv4());
    // inet4_bind_address decides the family and the address.
    let bound =
        self::dialer(DialerOptions { inet4_bind_address: Some("127.0.0.1".parse().unwrap()), ..Default::default() });
    let (socket, dual) = bound.listen_udp(None).await.unwrap();
    assert!(!dual);
    assert_eq!(socket.local_addr().unwrap().ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
    // A packet connection sends to IP addresses only.
    let conn = bound.listen_packet(&Socksaddr::from_host_port("127.0.0.1", 9)).await.unwrap();
    let error = conn.write_packet(b"x", &Socksaddr::from_host_port("example.com", 9)).await.unwrap_err();
    assert!(error.to_string().contains("domain not resolved"), "{error}");
}

#[tokio::test]
async fn tcp_fast_open_lazy_connect() {
    let echo = echo_listener().await;
    let dialer = dialer(DialerOptions { tcp_fast_open: true, ..Default::default() });
    // Nothing is sent before the first write; the data then opens the
    // connection (in the SYN when the kernel allows, else after a connect).
    let stream = dialer.dial_tcp_stream(echo, false).await.unwrap();
    roundtrip(stream).await;
    // A server-first port connects at once.
    let stream = dialer.dial_tcp_stream(echo, true).await.unwrap();
    assert!((*stream).as_any().downcast_ref::<TcpStream>().is_some());
}

#[tokio::test]
async fn tcp_multi_path_falls_back() {
    let echo = echo_listener().await;
    let dialer = dialer(DialerOptions { tcp_multi_path: true, ..Default::default() });
    roundtrip(Box::new(dialer.connect_tcp(echo).await.unwrap())).await;
}

#[tokio::test]
async fn connect_timeout_and_errors() {
    let dialer =
        dialer(DialerOptions { connect_timeout: ConfigDuration(Duration::from_millis(1)), ..Default::default() });
    assert_eq!(dialer.connect_timeout(), Duration::from_millis(1));
    assert_eq!(self::dialer(DialerOptions::default()).connect_timeout(), DEFAULT_CONNECT_TIMEOUT);
    let error = dialer.dial_tcp(&Socksaddr::from_host_port("example.com", 80)).await.err().unwrap();
    assert!(error.to_string().contains("domain not resolved"), "{error}");
    // A refused connection reports the address.
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    };
    let error = self::dialer(DialerOptions::default()).connect_tcp(closed).await.unwrap_err();
    assert!(error.to_string().contains(&closed.to_string()), "{error}");
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn interface_mark_and_netns() {
    let echo = echo_listener().await;
    let error = dialer(DialerOptions { bind_interface: "rb-no-such-if0".into(), ..Default::default() })
        .connect_tcp(echo)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("interface rb-no-such-if0 not found"), "{error}");
    // Binding to lo needs no privileges on recent kernels; refused otherwise.
    match dialer(DialerOptions { bind_interface: "lo".into(), ..Default::default() }).connect_tcp(echo).await {
        Ok(stream) => roundtrip(Box::new(stream)).await,
        Err(error) => assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}"),
    }
    // SO_MARK needs CAP_NET_ADMIN.
    match dialer(DialerOptions { routing_mark: FwMark(0x10), ..Default::default() }).connect_tcp(echo).await {
        Ok(stream) => {
            assert_eq!(sys::getsockopt_int(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_MARK).unwrap(), 0x10)
        }
        Err(error) => assert!(error.to_string().contains("set mark 16"), "{error}"),
    }
    // route.default_mark applies when the dialer has no mark of its own.
    let defaults = NetworkDefaults { default_mark: 7, ..Default::default() };
    let with_default = DefaultDialer::new(&DialerOptions::default(), &defaults, false).unwrap();
    assert_eq!(with_default.routing_mark, Some(7));
    // default_interface does not apply when the dialer binds an address.
    let defaults = NetworkDefaults { default_interface: "eth9".into(), ..Default::default() };
    let bound = DefaultDialer::new(
        &DialerOptions { inet4_bind_address: Some("127.0.0.1".parse().unwrap()), ..Default::default() },
        &defaults,
        false,
    )
    .unwrap();
    assert_eq!(bound.bind_interface, None);
    assert_eq!(
        DefaultDialer::new(&DialerOptions::default(), &defaults, false).unwrap().bind_interface.as_deref(),
        Some("eth9")
    );
    // A namespace that does not exist.
    let error = dialer(DialerOptions { netns: "rb-no-such-ns".into(), ..Default::default() })
        .connect_tcp(echo)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("get netns /var/run/netns/rb-no-such-ns"), "{error}");
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn protect_path_hands_over_the_socket() {
    use std::os::unix::net::UnixListener;
    let directory = std::env::temp_dir().join(format!("rb-protect-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&directory);
    let path = directory.join("protect.sock");
    let _ = std::fs::remove_file(&path);
    let protector = UnixListener::bind(&path).unwrap();
    let server = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let (mut connection, _) = protector.accept().unwrap();
        let mut byte = [0u8; 1];
        connection.read_exact(&mut byte).unwrap();
        connection.write_all(&[1]).unwrap();
    });
    let echo = echo_listener().await;
    let dialer = dialer(DialerOptions { protect_path: path.display().to_string(), ..Default::default() });
    roundtrip(Box::new(dialer.connect_tcp(echo).await.unwrap())).await;
    server.join().unwrap();
    let error = dialer.connect_tcp(echo).await.unwrap_err();
    assert!(error.to_string().contains("connect protect path"), "{error}");
}

/// Without a platform interface the platform network fields leave dialing
/// as it is (sing-box's command line).
#[tokio::test]
async fn platform_network_fields_have_no_effect() {
    let echo = echo_listener().await;
    let dialer = dialer(DialerOptions {
        network_strategy: Some(rb_config::NetworkStrategy::Fallback),
        network_type: rb_config::Listable(vec![rb_config::InterfaceType::Cellular]),
        fallback_network_type: Some(rb_config::Listable(vec![rb_config::InterfaceType::Wifi])),
        ..Default::default()
    });
    roundtrip(Box::new(dialer.connect_tcp(echo).await.unwrap())).await;
}

#[test]
fn refused_options() {
    let new = |options: DialerOptions| DefaultDialer::new(&options, &NetworkDefaults::default(), false).err();
    // Without a platform interface sing-box accepts the platform network
    // fields without effect, and refuses them only next to a socket binding.
    assert!(new(DialerOptions { network_strategy: Some(rb_config::NetworkStrategy::Hybrid), ..Default::default() })
        .is_none());
    assert!(new(DialerOptions {
        network_strategy: Some(rb_config::NetworkStrategy::Hybrid),
        tcp_fast_open: true,
        ..Default::default()
    })
    .unwrap()
    .contains("`network_strategy` is conflict with"));
    assert!(new(DialerOptions { inet4_bind_address: Some("::1".parse().unwrap()), ..Default::default() })
        .unwrap()
        .contains("not an IPv4 address"));
    assert!(new(DialerOptions { inet6_bind_address: Some("127.0.0.1".parse().unwrap()), ..Default::default() })
        .unwrap()
        .contains("not an IPv6 address"));
}

#[tokio::test]
async fn listener_fields() {
    // `listen` defaults to 127.0.0.1.
    let listener = listener::Listener::new(&ListenOptions::default()).unwrap();
    assert_eq!(listener.address(), "127.0.0.1:0".parse().unwrap());
    let options = ListenOptions {
        listen: Some("127.0.0.1".parse().unwrap()),
        reuse_addr: true,
        tcp_fast_open: true,
        tcp_multi_path: true,
        tcp_keep_alive: ConfigDuration(Duration::from_secs(30)),
        ..Default::default()
    };
    let listener = listener::Listener::new(&options).unwrap();
    let tcp = listener.listen_tcp().unwrap();
    let address = tcp.local_addr().unwrap();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let fd = tcp.as_raw_fd();
        assert_eq!(sys::getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT).unwrap(), 1);
        assert!(sys::getsockopt_int(fd, libc::IPPROTO_TCP, sys::TCP_FASTOPEN).unwrap() > 0);
    }
    let client = tokio::spawn(async move { TcpStream::connect(address).await.unwrap() });
    let (accepted, _) = tcp.accept().await.unwrap();
    listener.accepted(&accepted).unwrap();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    assert_eq!(sys::getsockopt_int(accepted.as_raw_fd(), libc::IPPROTO_TCP, libc::TCP_KEEPIDLE).unwrap(), 30);
    client.await.unwrap();
    // The UDP socket of an inbound.
    let udp = listener.listen_packet("127.0.0.1:0".parse().unwrap()).unwrap();
    assert!(udp.local_addr().unwrap().port() != 0);
}

struct Protector(std::sync::Mutex<Vec<std::os::fd::RawFd>>);

impl rb_platform::PlatformInterface for Protector {
    fn open_tun(&self, _options: &rb_platform::TunOptions) -> io::Result<std::os::fd::RawFd> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn auto_detect_interface_control(&self, fd: std::os::fd::RawFd) -> io::Result<()> {
        self.0.lock().unwrap().push(fd);
        Ok(())
    }
    fn start_default_interface_monitor(
        &self,
        _listener: Arc<dyn rb_platform::InterfaceUpdateListener>,
    ) -> io::Result<()> {
        Ok(())
    }
    fn get_interfaces(&self) -> io::Result<Vec<rb_platform::NetworkInterface>> {
        Ok(Vec::new())
    }
}

/// route.auto_detect_interface: sockets go through the platform's protect
/// unless the dialer binds an address or interface of its own.
#[tokio::test]
async fn auto_detect_interface_protects_through_the_platform() {
    let protector = Arc::new(Protector(Default::default()));
    rb_platform::set_platform(Some(protector.clone()));
    let defaults = NetworkDefaults { auto_detect_interface: true, ..Default::default() };
    let protected = DefaultDialer::new(&DialerOptions::default(), &defaults, false).unwrap();
    let listener = echo_listener().await;
    roundtrip(protected.dial_tcp_stream(listener, false).await.unwrap()).await;
    assert_eq!(protector.0.lock().unwrap().len(), 1);
    let bound = DefaultDialer::new(
        &DialerOptions { inet4_bind_address: Some("127.0.0.1".parse().unwrap()), ..Default::default() },
        &defaults,
        false,
    )
    .unwrap();
    roundtrip(bound.dial_tcp_stream(listener, false).await.unwrap()).await;
    rb_platform::set_platform(None);
    assert_eq!(protector.0.lock().unwrap().len(), 1);
}
