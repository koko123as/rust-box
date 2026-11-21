//! Vectors from the Go libraries sing-box uses (`testdata/vectors.json`,
//! made by `testdata/generate`), and rust-box client ↔ server round trips.

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::server::{Accepted, Service};
use crate::tcp::{AeadReader, ReadInit, Reader, ShadowStream, WriteInit, WriteMode, Writer};
use crate::udp::ClientPacketCodec;

const VECTORS: &str = include_str!("../testdata/vectors.json");
const PSK16: &str = "AAECAwQFBgcICQoLDA0ODw==";
const UPSK16: &str = "EBESExQVFhcYGRobHB0eHw==";
const PSK32: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

/// The time the vectors were made at (their 2022 timestamps).
static VECTOR_TIME: AtomicI64 = AtomicI64::new(0);

fn vector_time() -> i64 {
    VECTOR_TIME.load(Ordering::Relaxed)
}

fn vectors() -> Value {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    VECTOR_TIME.store(vectors["time"].as_i64().unwrap(), Ordering::Relaxed);
    vectors
}

fn hex(text: &Value) -> Vec<u8> {
    let text = text.as_str().unwrap();
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn address(text: &str) -> Socksaddr {
    let (host, port) = text.rsplit_once(':').unwrap();
    Socksaddr::from_host_port(host, port.parse().unwrap())
}

#[test]
fn key_derivation() {
    let vectors = vectors();
    for vector in vectors["keys"].as_array().unwrap() {
        let password = vector["password"].as_str().unwrap();
        let size = vector["size"].as_u64().unwrap() as usize;
        assert_eq!(cipher::evp_bytes_to_key(password.as_bytes(), size), hex(&vector["key"]));
    }
    for vector in vectors["aead_subkeys"].as_array().unwrap() {
        assert_eq!(cipher::aead_subkey(&hex(&vector["key"]), &hex(&vector["salt"])), hex(&vector["out"]));
    }
    for vector in vectors["session_keys"].as_array().unwrap() {
        let size = vector["size"].as_u64().unwrap() as usize;
        assert_eq!(cipher::session_key(&hex(&vector["key"]), &hex(&vector["salt"]), size), hex(&vector["out"]));
    }
    for vector in vectors["identity_subkeys"].as_array().unwrap() {
        let size = vector["size"].as_u64().unwrap() as usize;
        assert_eq!(cipher::identity_subkey(&hex(&vector["key"]), &hex(&vector["salt"]), size), hex(&vector["out"]));
    }
    for (key, hash) in vectors["psk_hashes"].as_object().unwrap() {
        assert_eq!(cipher::psk_hash(&hex(&Value::String(key.clone()))).to_vec(), hex(hash));
    }
    for vector in vectors["sha256_keys"].as_array().unwrap() {
        let size = vector["size"].as_u64().unwrap() as usize;
        assert_eq!(cipher::sha256_key(&hex(&vector["key"]), size), hex(&vector["out"]));
    }
}

#[test]
fn base64_like_go() {
    let vectors = vectors();
    for (input, error) in vectors["base64_errors"].as_object().unwrap() {
        let error = error.as_str().unwrap();
        match decode_base64(input) {
            Ok(_) => assert!(error.is_empty(), "{input}: decoded, Go says {error}"),
            Err(ours) => assert_eq!(ours, error, "{input}"),
        }
    }
    assert_eq!(decode_base64("AAA=").unwrap(), vec![0, 0]);
    assert_eq!(decode_base64(PSK16).unwrap(), (0u8..16).collect::<Vec<_>>());
    // Non-canonical trailing bits are accepted, as Go's StdEncoding does.
    assert_eq!(decode_base64("AB==").unwrap(), vec![0]);
}

#[test]
fn rc4_matches_reference() {
    // RFC 6229 test vector, key 0x0102030405, first 16 bytes of key stream.
    let mut data = [0u8; 16];
    cipher::Rc4::new(&[1, 2, 3, 4, 5]).apply(&mut data);
    assert_eq!(data[..8], [0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27]);
}

fn single_or_multi(vector: &Value) -> Service {
    let method = vector["method"].as_str().unwrap();
    let password = vector["server_password"].as_str().unwrap();
    let mut service = match vector["users"].as_array() {
        Some(users) => {
            let users: Vec<String> = users.iter().map(|user| user.as_str().unwrap().to_string()).collect();
            Service::multi(method, password, &users, Duration::from_secs(300)).unwrap()
        }
        None => Service::single(method, password, Duration::from_secs(300)).unwrap(),
    };
    service.time = vector_time;
    service
}

/// A stream that yields `data` and accepts writes.
fn feed(data: Vec<u8>) -> tokio::io::DuplexStream {
    let (ours, mut theirs) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        theirs.write_all(&data).await.unwrap();
        // Keep the other end open while the test reads.
        let mut sink = Vec::new();
        let _ = theirs.read_to_end(&mut sink).await;
    });
    ours
}

/// Go clients' requests through rust-box's services.
#[tokio::test]
async fn go_requests() {
    let vectors = vectors();
    for vector in vectors["tcp"].as_array().unwrap() {
        let method = vector["method"].as_str().unwrap();
        if MethodKind::parse(method).is_some_and(|kind| matches!(kind, MethodKind::Stream(_))) {
            continue;
        }
        let service = single_or_multi(vector);
        let accepted =
            service.accept(feed(hex(&vector["request"]))).await.unwrap_or_else(|error| panic!("{method}: {error}"));
        let Accepted::Stream { mut stream, destination, user } = accepted else { panic!("{method}: relay") };
        assert_eq!(destination, address(vector["destination"].as_str().unwrap()), "{method}");
        if let Some(users) = vector["users"].as_array() {
            assert_eq!(user, Some(users.len() - 1), "{method}");
        }
        let mut payload = [0u8; 5];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(payload.to_vec(), hex(&vector["payload"]), "{method}");
    }
}

/// Go servers' responses read by rust-box's client.
#[tokio::test]
async fn go_responses() {
    let vectors = vectors();
    for vector in vectors["tcp"].as_array().unwrap() {
        let method = vector["method"].as_str().unwrap();
        let request = hex(&vector["request"]);
        let client = ClientMethod::new(method, vector["client_password"].as_str().unwrap()).unwrap();
        let (reader, expected) = match client.kind {
            MethodKind::None => continue,
            // No Go stream server: a request has the response's format,
            // so it reads as the address and the payload.
            MethodKind::Stream(kind) => {
                let reader =
                    Reader::Stream { kind, key: client.key().to_vec(), salt: Vec::new(), filled: 0, cipher: None };
                let mut expected = Vec::new();
                write_address(&mut expected, &address(vector["destination"].as_str().unwrap())).unwrap();
                expected.extend_from_slice(b"hello");
                (reader, expected)
            }
            MethodKind::Aead(kind) => {
                let init = ReadInit::AeadSalt { kind, key: client.key().to_vec() };
                (Reader::Aead(Box::new(AeadReader::client(init))), b"world".to_vec())
            }
            MethodKind::Ss2022(kind) => {
                let init = ReadInit::Ss2022Response {
                    kind,
                    psk: client.user_psk().to_vec(),
                    request_salt: request[..kind.key_size()].to_vec(),
                    time: vector_time,
                };
                (Reader::Aead(Box::new(AeadReader::client(init))), b"world".to_vec())
            }
        };
        let response = match client.kind {
            MethodKind::Stream(_) => request.clone(),
            _ => hex(&vector["response"]),
        };
        let writer = Writer::new(WriteMode::Plain, WriteInit::Ready, Vec::new());
        let mut stream = ShadowStream::from_parts(feed(response), reader, writer);
        let mut data = vec![0u8; expected.len()];
        stream.read_exact(&mut data).await.unwrap_or_else(|error| panic!("{method}: {error}"));
        assert_eq!(data, expected, "{method}");
    }
}

/// Go clients' packets decoded by rust-box's services (and, for the
/// symmetric formats, by its client).
#[test]
fn go_packets() {
    let vectors = vectors();
    for vector in vectors["udp"].as_array().unwrap() {
        let method = vector["method"].as_str().unwrap();
        let password = vector["password"].as_str().unwrap();
        let destination = address(vector["destination"].as_str().unwrap());
        let payload = hex(&vector["payload"]);
        let kind = MethodKind::parse(method).unwrap();
        if matches!(kind, MethodKind::None | MethodKind::Aead(_) | MethodKind::Stream(_)) {
            let codec = ClientPacketCodec::new(&ClientMethod::new(method, password).unwrap());
            let mut packet = hex(&vector["packet"]);
            let (source, start) = codec.decode(&mut packet).unwrap_or_else(|error| panic!("{method}: {error}"));
            assert_eq!((source, packet[start..].to_vec()), (destination.clone(), payload.clone()), "{method}");
        }
        if matches!(kind, MethodKind::Stream(_)) {
            continue;
        }
        let mut service = match password.split_once(':') {
            Some((identity, user)) => {
                Service::multi(method, identity, &[user.to_string()], Duration::from_secs(300)).unwrap()
            }
            None => Service::single(method, password, Duration::from_secs(300)).unwrap(),
        };
        service.time = vector_time;
        let mut packet = hex(&vector["packet"]);
        let decoded = service.decode_packet(&mut packet).unwrap_or_else(|error| panic!("{method}: {error}"));
        assert_eq!(decoded.destination, destination, "{method}");
        assert_eq!(packet[decoded.payload_start..].to_vec(), payload, "{method}");
        if password.contains(':') {
            assert_eq!(decoded.user, Some(0));
        }
    }
}

const METHODS: &[(&str, &str)] = &[
    ("none", ""),
    ("aes-128-gcm", "test"),
    ("aes-192-gcm", "test"),
    ("aes-256-gcm", "test"),
    ("chacha20-ietf-poly1305", "test"),
    ("xchacha20-ietf-poly1305", "test"),
    ("2022-blake3-aes-128-gcm", PSK16),
    ("2022-blake3-aes-256-gcm", PSK32),
    ("2022-blake3-chacha20-poly1305", PSK32),
];

/// rust-box client ↔ rust-box server over TCP, both directions, with
/// data larger than a chunk.
#[tokio::test]
async fn tcp_round_trip() {
    let big: Vec<u8> = (0..100_000u32).map(|i| i as u8).collect();
    for (method, password) in METHODS {
        let service = Service::single(method, password, Duration::from_secs(60)).unwrap();
        tcp_exchange(&service, method, password, None, &big).await;
    }
    let service =
        Service::multi("2022-blake3-aes-128-gcm", PSK16, &[UPSK16.into(), PSK16.into()], Duration::from_secs(60))
            .unwrap();
    tcp_exchange(&service, "2022-blake3-aes-128-gcm", &format!("{PSK16}:{UPSK16}"), Some(0), &big).await;
    let service = Service::multi("aes-256-gcm", "", &["a".into(), "b".into()], Duration::from_secs(60)).unwrap();
    tcp_exchange(&service, "aes-256-gcm", "b", Some(1), &big).await;
}

async fn tcp_exchange(service: &Service, method: &str, password: &str, user: Option<usize>, data: &[u8]) {
    let client = ClientMethod::new(method, password).unwrap();
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let destination = Socksaddr::from_host_port("example.com", 443);
    let mut stream = ShadowStream::client(&client, client_io, &destination).unwrap();
    let sent = data.to_vec();
    let writer = tokio::spawn(async move {
        stream.flush().await.unwrap();
        stream.write_all(&sent).await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = vec![0u8; sent.len()];
        stream.read_exact(&mut echoed).await.unwrap();
        echoed
    });
    let Accepted::Stream { mut stream, destination: found, user: found_user } =
        service.accept(server_io).await.unwrap_or_else(|error| panic!("{method}: {error}"))
    else {
        panic!("relay")
    };
    assert_eq!(found, destination, "{method}");
    assert_eq!(found_user, user, "{method}");
    let mut received = vec![0u8; data.len()];
    stream.read_exact(&mut received).await.unwrap();
    assert_eq!(received, data, "{method}");
    stream.write_all(&received).await.unwrap();
    stream.flush().await.unwrap();
    assert_eq!(writer.await.unwrap(), data, "{method}");
}

/// rust-box client ↔ rust-box server packets, both directions.
#[test]
fn udp_round_trip() {
    let destination = Socksaddr::from_host_port("1.1.1.1", 53);
    let mut cases: Vec<(Service, String, Option<usize>)> = METHODS
        .iter()
        .map(|(method, password)| {
            (Service::single(method, password, Duration::from_secs(60)).unwrap(), method.to_string(), None)
        })
        .collect();
    cases.push((
        Service::multi("2022-blake3-aes-256-gcm", PSK32, &[PSK32.into()], Duration::from_secs(60)).unwrap(),
        "2022-blake3-aes-256-gcm".into(),
        Some(0),
    ));
    for (service, method, user) in &cases {
        let password = match (method.as_str(), user) {
            ("2022-blake3-aes-256-gcm", Some(_)) => format!("{PSK32}:{PSK32}"),
            _ => METHODS.iter().find(|(name, _)| name == method).unwrap().1.to_string(),
        };
        let client = ClientPacketCodec::new(&ClientMethod::new(method, &password).unwrap());
        for round in 0..3u8 {
            let mut packet = client.encode(&[round; 100], &destination).unwrap();
            let decoded = service.decode_packet(&mut packet).unwrap_or_else(|error| panic!("{method}: {error}"));
            assert_eq!(decoded.destination, destination, "{method}");
            assert_eq!(decoded.user, *user, "{method}");
            assert_eq!(packet[decoded.payload_start..], [round; 100], "{method}");
            let mut reply = decoded.reply.encode(b"pong", &destination).unwrap();
            let (source, start) = client.decode(&mut reply).unwrap_or_else(|error| panic!("{method}: {error}"));
            assert_eq!((source, &reply[start..]), (destination.clone(), &b"pong"[..]), "{method}");
        }
        if method.starts_with("2022") {
            // A replayed packet is refused.
            let mut packet = client.encode(b"x", &destination).unwrap();
            let mut replay = packet.clone();
            service.decode_packet(&mut packet).unwrap();
            let error = service.decode_packet(&mut replay).err().unwrap();
            assert_eq!(error.to_string(), "packet id not unique", "{method}");
        }
    }
}

/// The 2022 relay: the request loses its first identity header and is
/// then a request the user's server takes.
#[tokio::test]
async fn relay() {
    let relay =
        Service::relay("2022-blake3-aes-128-gcm", PSK16, &[PSK16.into(), UPSK16.into()], Duration::from_secs(60))
            .unwrap();
    let upstream = Service::single("2022-blake3-aes-128-gcm", UPSK16, Duration::from_secs(60)).unwrap();
    let client = ClientMethod::new("2022-blake3-aes-128-gcm", &format!("{PSK16}:{UPSK16}")).unwrap();
    let (client_io, relay_io) = tokio::io::duplex(64 * 1024);
    let destination = Socksaddr::from_host_port("example.com", 80);
    let mut stream = ShadowStream::client(&client, client_io, &destination).unwrap();
    stream.flush().await.unwrap();
    stream.write_all(b"hello").await.unwrap();
    stream.flush().await.unwrap();
    let Accepted::Relay { io, prefix, user } = relay.accept(relay_io).await.unwrap() else { panic!() };
    assert_eq!(user, 1);
    let forwarded = rb_adapter::PrefixedStream::new(prefix, io);
    let Accepted::Stream { mut stream, destination: found, .. } = upstream.accept(forwarded).await.unwrap() else {
        panic!()
    };
    assert_eq!(found, destination);
    let mut payload = [0u8; 5];
    stream.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"hello");

    // UDP: the relayed packet decodes with the user's PSK alone.
    let codec = ClientPacketCodec::new(&client);
    let mut packet = codec.encode(b"ping", &destination).unwrap();
    let decoded = relay.decode_packet(&mut packet).unwrap();
    assert_eq!(decoded.user, Some(1));
    let decoded = upstream.decode_packet(&mut packet).unwrap();
    assert_eq!(decoded.destination, destination);
    assert_eq!(&packet[decoded.payload_start..], b"ping");
}

#[tokio::test]
async fn replay_and_clock() {
    let service = Service::single("2022-blake3-aes-128-gcm", PSK16, Duration::from_secs(60)).unwrap();
    let mut client = ClientMethod::new("2022-blake3-aes-128-gcm", PSK16).unwrap();
    let destination = Socksaddr::from_host_port("example.com", 80);
    let request = |client: &ClientMethod| {
        let stream = ShadowStream::client(client, Vec::<u8>::new(), &destination).unwrap();
        // The header waits in the output buffer.
        stream.writer_output().to_vec()
    };
    let first = request(&client);
    assert!(service.accept(feed(first.clone())).await.is_ok());
    let error = service.accept(feed(first)).await.err().unwrap();
    assert_eq!(error.to_string(), "salt not unique");
    client.time = || unix_now() - 31;
    let error = service.accept(feed(request(&client))).await.err().unwrap();
    assert!(error.to_string().starts_with("bad timestamp: received "), "{error}");
    // A wrong password fails authentication.
    let other = ClientMethod::new("2022-blake3-aes-128-gcm", UPSK16).unwrap();
    let error = service.accept(feed(request(&other))).await.err().unwrap();
    assert_eq!(error.to_string(), "cipher: message authentication failed");
}

#[test]
fn method_errors() {
    let error = |method: &str, password: &str| ClientMethod::new(method, password).err().unwrap();
    assert_eq!(error("rc4", "x"), "unknown method: rc4");
    assert_eq!(error("aes-128-gcm", ""), "missing password");
    assert_eq!(error("aes-128-ctr", ""), "missing password");
    assert_eq!(error("2022-blake3-aes-128-gcm", ""), "missing password");
    assert_eq!(error("2022-blake3-aes-128-gcm", "abc"), "decode key: illegal base64 data at input byte 0");
    assert_eq!(error("2022-blake3-aes-128-gcm", PSK32), "bad key length, required 16, got 32");
    assert_eq!(
        error("2022-blake3-chacha20-poly1305", &format!("{PSK32}:{PSK32}")),
        "Shadowsocks 2022 EIH support only available in AES ciphers"
    );
    assert!(ClientMethod::new("none", "").is_ok());
    assert!(ClientMethod::new("xchacha20", "x").is_ok());

    let timeout = Duration::from_secs(1);
    let single = |method: &str, password: &str| Service::single(method, password, timeout).err().unwrap();
    assert_eq!(single("aes-128-ctr", "x"), "unsupported method: aes-128-ctr");
    assert_eq!(single("aes-128-gcm", ""), "missing password");
    assert_eq!(single("2022-blake3-aes-128-gcm", ""), "missing psk");
    assert_eq!(single("2022-blake3-aes-256-gcm", PSK16), "bad key");
    assert_eq!(single("2022-blake3-aes-128-gcm", "!"), "decode psk: illegal base64 data at input byte 0");
    // A longer PSK is hashed down.
    assert!(Service::single("2022-blake3-aes-128-gcm", PSK32, timeout).is_ok());
    let multi = |method: &str, password: &str, users: &[&str]| -> String {
        let users: Vec<String> = users.iter().map(|user| user.to_string()).collect();
        Service::multi(method, password, &users, timeout).err().unwrap()
    };
    assert_eq!(multi("none", "", &["a"]), "unsupported method: none");
    assert_eq!(multi("2022-blake3-chacha20-poly1305", PSK32, &[PSK32]), "invalid argument");
    assert_eq!(multi("2022-blake3-aes-128-gcm", "", &[PSK16]), "missing psk");
    assert_eq!(multi("2022-blake3-aes-128-gcm", PSK16, &[""]), "missing password");
    assert_eq!(multi("aes-128-gcm", "", &["a", ""]), "missing password");
    let relay =
        |method: &str, password: &str| Service::relay(method, password, &[PSK16.into()], timeout).err().unwrap();
    assert_eq!(relay("aes-128-gcm", PSK16), "invalid argument");
    assert_eq!(relay("2022-blake3-chacha20-poly1305", PSK32), "invalid argument");
    assert_eq!(relay("2022-blake3-aes-128-gcm", ""), "missing psk");
}
