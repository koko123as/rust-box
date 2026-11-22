//! End to end `tun` on Linux. These need root (or `CAP_NET_ADMIN`) and the
//! `ip` command, so they only run with `RB_TUN_TEST=1`, for example:
//!
//! ```sh
//! cargo test -p rust-box --test tun --no-run
//! sudo RB_TUN_TEST=1 SING_BOX_BIN=/path/to/sing-box target/debug/deps/tun-*
//! ```
//!
//! Traffic to a documentation range routed into the TUN comes back out of
//! the direct outbound to local servers (`override_address: 127.0.0.1`):
//! TCP, UDP, ICMP echo, a rejected TCP connection, and a DNS query to the
//! TUN's DNS address answered by `hijack-dns`. With `SING_BOX_BIN` the
//! kernel state auto_route leaves behind (addresses, routes, rules) is
//! compared with what sing-box v1.14.4 itself sets up for the same options.

use std::process::Command;
use std::time::Duration;

use rust_box::RustBox;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// The tests share rule priorities and table numbers: one at a time.
static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn enabled() -> bool {
    std::env::var("RB_TUN_TEST").is_ok_and(|value| value == "1")
}

fn tun_config(name: &str, extra: &str) -> String {
    format!(
        r#"{{"log":{{"level":"error"}},
        "dns":{{"servers":[{{"type":"hosts","tag":"hosts","predefined":{{"tun.test":"192.0.2.77"}}}}]}},
        "inbounds":[{{"type":"tun","tag":"tun-in","interface_name":"{name}","mtu":1500,
            "address":["172.29.0.1/30","fdfe:dcba:9929::1/126"],"auto_route":true,
            "route_address":["198.51.100.0/24","2001:db8:100::/48"]{extra}}}],
        "outbounds":[{{"type":"direct","tag":"direct"}}],
        "route":{{"rules":[
            {{"protocol":"dns","action":"hijack-dns"}},
            {{"ip_cidr":["198.51.100.9/32"],"action":"reject"}},
            {{"ip_cidr":["198.51.100.0/24","2001:db8:100::/48"],"action":"route-options","override_address":"127.0.0.1"}}],
            "final":"direct"}}}}"#
    )
}

fn kernel_state(name: &str) -> String {
    let run = |args: &[&str]| {
        let output = Command::new("ip").args(args).output().expect("ip");
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    let addresses: String = run(&["addr", "show", name])
        .lines()
        .filter(|line| line.contains("inet") && !line.contains("fe80"))
        // Duplicate address detection may still be running.
        .map(|line| format!("{}\n", line.replace(" tentative", "")))
        .collect();
    [
        run(&["rule"]),
        run(&["-6", "rule"]),
        run(&["route", "show", "table", "2022"]),
        run(&["-6", "route", "show", "table", "2022"]),
        addresses,
    ]
    .concat()
}

#[tokio::test(flavor = "multi_thread")]
async fn tun_end_to_end() {
    if !enabled() {
        eprintln!("skipped: set RB_TUN_TEST=1 and run as root");
        return;
    }
    let _guard = LOCK.lock().await;
    // Local servers the TUN destinations are redirected to.
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_port = tcp.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = tcp.accept().await {
            tokio::spawn(async move {
                let mut buffer = vec![0; 65536];
                while let Ok(n) = stream.read(&mut buffer).await {
                    if n == 0 || stream.write_all(&buffer[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = udp.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buffer = [0; 2048];
        while let Ok((n, peer)) = udp.recv_from(&mut buffer).await {
            let _ = udp.send_to(&buffer[..n], peer).await;
        }
    });

    let options = rb_config::parse(&tun_config("rbtest0", "")).unwrap();
    let instance = RustBox::new(&options).unwrap();
    instance.start().await.unwrap();

    // TCP through the TUN and back, with more data than one window.
    for host in ["198.51.100.7", "[2001:db8:100::7]"] {
        let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(format!("{host}:{tcp_port}")))
            .await
            .unwrap()
            .unwrap();
        let message: Vec<u8> = (0..1_000_000).map(|i| (i % 253) as u8).collect();
        let (mut reader, mut writer) = stream.split();
        let send = async {
            writer.write_all(&message).await.unwrap();
        };
        let mut received = vec![0; message.len()];
        let receive = async { reader.read_exact(&mut received).await.unwrap() };
        tokio::time::timeout(Duration::from_secs(20), async { tokio::join!(send, receive) }).await.unwrap();
        assert!(received == message, "{host}");
    }
    // A rejected connection is reset at once.
    let error = TcpStream::connect(format!("198.51.100.9:{tcp_port}")).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
    // UDP.
    let client = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    client.send_to(b"over tun", format!("198.51.100.7:{udp_port}")).await.unwrap();
    let mut buffer = [0; 64];
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buffer)).await.unwrap().unwrap();
    assert_eq!(&buffer[..n], b"over tun");
    assert_eq!(from, format!("198.51.100.7:{udp_port}").parse().unwrap());
    // DNS to the TUN's DNS address is hijacked.
    let mut query = vec![0xbe, 0xef, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    query.extend_from_slice(b"\x03tun\x04test\x00\x00\x01\x00\x01");
    client.send_to(&query, "172.29.0.2:53").await.unwrap();
    let mut answer = [0; 512];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut answer)).await.unwrap().unwrap();
    assert_eq!(&answer[..2], &[0xbe, 0xef]);
    assert!(answer[..n].ends_with(&[192, 0, 2, 77]), "{:?}", &answer[..n]);
    // ICMP echo is answered.
    if Command::new("ping").arg("-V").output().is_ok() {
        let ping = Command::new("ping").args(["-c", "1", "-W", "2", "198.51.100.7"]).output().unwrap();
        assert!(ping.status.success(), "{}", String::from_utf8_lossy(&ping.stdout));
    }
    // direct refuses to dial into the TUN range itself (it would loop): the
    // stack accepted the connection, which then closes at once.
    if let Ok(mut stream) = TcpStream::connect("[fdfe:dcba:9929::3]:80").await {
        let mut byte = [0; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut byte)).await.unwrap();
        assert!(matches!(read, Ok(0) | Err(_)));
    }

    instance.close().await;
    // Everything is removed again.
    assert!(!kernel_state("rbtest0").contains("lookup 2022"));
    assert!(!std::path::Path::new("/sys/class/net/rbtest0").exists());
}

/// The same routes, rules and addresses as sing-box v1.14.4 sets up.
#[tokio::test(flavor = "multi_thread")]
async fn tun_auto_route_matches_sing_box() {
    let Some(sing_box) = std::env::var_os("SING_BOX_BIN") else { return };
    if !enabled() {
        return;
    }
    let _guard = LOCK.lock().await;
    for extra in [
        "",
        r#","strict_route":true,"exclude_uid":[1234],"include_interface":["eth9"]"#,
        r#","exclude_interface":["eth9"],"include_uid_range":["1000:2000"],"route_exclude_address":["198.51.100.128/25"]"#,
    ] {
        let config = tun_config("rbtest1", extra);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        std::fs::write(&path, &config).unwrap();
        let mut child = Command::new(&sing_box).args(["run", "-c"]).arg(&path).spawn().unwrap();
        tokio::time::sleep(Duration::from_secs(3)).await;
        let expected = kernel_state("rbtest1");
        // SIGINT for a clean shutdown.
        // SAFETY: signalling our own child.
        unsafe { libc_kill(child.id() as i32, 2) };
        let _ = child.wait();
        tokio::time::sleep(Duration::from_millis(500)).await;

        let options = rb_config::parse(&config).unwrap();
        let instance = RustBox::new(&options).unwrap();
        instance.start().await.unwrap();
        let actual = kernel_state("rbtest1");
        instance.close().await;
        assert_eq!(actual, expected, "options: {extra}");
    }
}

extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, signal: i32) -> i32;
}

/// Full auto_route (the default route into the TUN) in a network
/// namespace: with `auto_detect_interface` the direct outbound binds to the
/// namespace's real interface and reaches a server outside; this is the
/// setup that loops without it, in sing-box as in rust-box.
#[tokio::test(flavor = "multi_thread")]
async fn tun_full_auto_route_with_auto_detect_interface() {
    if !enabled() {
        return;
    }
    let _guard = LOCK.lock().await;
    let sh = |script: &str| {
        let status = Command::new("sh").args(["-c", script]).status().unwrap();
        assert!(status.success(), "{script}");
    };
    let _ = Command::new("ip").args(["netns", "del", "rbtestns"]).status();
    let _ = Command::new("ip").args(["link", "del", "rbtveth0"]).status();
    sh("ip netns add rbtestns && ip link add rbtveth0 type veth peer name rbtveth1 && \
        ip link set rbtveth1 netns rbtestns && ip addr add 10.210.0.1/24 dev rbtveth0 && \
        ip addr add 10.211.0.1/32 dev rbtveth0 && ip link set rbtveth0 up && \
        ip netns exec rbtestns sh -c 'ip link set lo up && ip link set rbtveth1 up && \
        ip addr add 10.210.0.2/24 dev rbtveth1 && ip route add default via 10.210.0.1'");
    let server = TcpListener::bind("10.211.0.1:0").await.unwrap();
    let port = server.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = server.accept().await {
            let _ = stream.write_all(b"outside").await;
        }
    });
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.json");
    std::fs::write(
        &path,
        r#"{"log":{"level":"error"},
            "inbounds":[{"type":"tun","interface_name":"tun0","address":"172.19.0.1/30","auto_route":true,"strict_route":true}],
            "outbounds":[{"type":"direct"}],"route":{"auto_detect_interface":true}}"#,
    )
    .unwrap();
    let mut child = Command::new("ip")
        .args(["netns", "exec", "rbtestns", env!("CARGO_BIN_EXE_rust-box"), "run", "-c"])
        .arg(&path)
        .spawn()
        .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let output = Command::new("ip")
        .args(["netns", "exec", "rbtestns", "bash", "-c"])
        .arg(format!("exec 3<>/dev/tcp/10.211.0.1/{port} && timeout 5 cat <&3"))
        .output()
        .unwrap();
    let routed = Command::new("ip").args(["netns", "exec", "rbtestns", "ip", "route", "get", "10.211.0.1"]).output();
    // SAFETY: signalling our own child.
    unsafe { libc_kill(child.id() as i32, 2) };
    let _ = child.wait();
    let _ = Command::new("ip").args(["netns", "del", "rbtestns"]).status();
    let _ = Command::new("ip").args(["link", "del", "rbtveth0"]).status();
    assert!(String::from_utf8_lossy(&routed.unwrap().stdout).contains("tun0"));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "outside");
}
