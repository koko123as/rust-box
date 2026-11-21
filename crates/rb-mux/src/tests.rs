//! sing-mux tests: each protocol with and without padding, client and
//! server of rust-box over an in-memory connection.

use std::sync::Arc;

use async_trait::async_trait;
use rb_adapter::{BoxStream, SharedPacketConn, Socksaddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

struct Echo;

#[async_trait]
impl ServerHandler for Echo {
    async fn new_connection(self: Arc<Self>, destination: Socksaddr, mut stream: BoxStream) {
        assert_eq!(destination, Socksaddr::from_host_port("example.com", 80));
        let mut buffer = vec![0u8; 70_000];
        let mut total = 0;
        while total < buffer.len() {
            let read = stream.read(&mut buffer[total..]).await.unwrap();
            assert!(read > 0);
            total += read;
        }
        stream.write_all(&buffer).await.unwrap();
        stream.shutdown().await.unwrap();
    }

    async fn new_packet_connection(self: Arc<Self>, _destination: Socksaddr, conn: SharedPacketConn) {
        let mut buffer = [0u8; 2048];
        for _ in 0..3 {
            let (length, address) = conn.read_packet(&mut buffer).await.unwrap();
            conn.write_packet(&buffer[..length], &address).await.unwrap();
        }
    }
}

/// Dials a rust-box server over a pipe.
struct PipeDialer(ServerOptions);

#[async_trait]
impl MuxDialer for PipeDialer {
    async fn dial(&self, destination: &Socksaddr) -> std::io::Result<BoxStream> {
        assert!(is_destination(destination));
        let (client, server) = tokio::io::duplex(1 << 16);
        let options = self.0.clone();
        tokio::spawn(async move {
            serve(Box::new(server), "127.0.0.1:1".parse().unwrap(), &options, Arc::new(Echo), "test".into()).await
        });
        Ok(Box::new(client))
    }
}

#[tokio::test]
async fn every_protocol() {
    for protocol in ["smux", "yamux", "h2mux"] {
        for padding in [false, true] {
            let options = ClientOptions::new(protocol, 0, 0, 0, padding).unwrap();
            let client = Arc::new(Client::new(Arc::new(PipeDialer(ServerOptions { padding })), options));
            let payload: Vec<u8> = (0..70_000u32).map(|index| index as u8).collect();
            let mut tasks = Vec::new();
            for _ in 0..3 {
                let (client, payload) = (client.clone(), payload.clone());
                tasks.push(tokio::spawn(async move {
                    let mut stream = client.dial_tcp(&Socksaddr::from_host_port("example.com", 80)).await.unwrap();
                    stream.write_all(&payload).await.unwrap();
                    let mut echoed = Vec::new();
                    stream.read_to_end(&mut echoed).await.unwrap();
                    assert!(echoed == payload);
                }));
            }
            for task in tasks {
                task.await.unwrap();
            }
            let conn = client.listen_packet(&Socksaddr::from_host_port("1.1.1.1", 53)).await.unwrap();
            let target = Socksaddr::from_host_port("8.8.8.8", 53);
            let mut buffer = [0u8; 64];
            for round in 0..3u8 {
                conn.write_packet(&[round; 10], &target).await.unwrap();
                let (length, address) = conn.read_packet(&mut buffer).await.unwrap();
                assert_eq!((&buffer[..length], address), (&[round; 10][..], target.clone()), "{protocol} {padding}");
            }
            // Every stream went over one session (min_streams 8).
            assert_eq!(client_sessions(&client).await, 1, "{protocol}");
        }
    }
}

async fn client_sessions(client: &Client) -> usize {
    client.sessions_len().await
}

#[tokio::test]
async fn padded_server_rejects_plain() {
    let (mut client, server) = tokio::io::duplex(1024);
    let task = tokio::spawn(async move {
        serve(
            Box::new(server),
            "127.0.0.1:1".parse().unwrap(),
            &ServerOptions { padding: true },
            Arc::new(Echo),
            "t".into(),
        )
        .await
    });
    client
        .write_all(&protocol::encode_request(&protocol::Request { version: 0, protocol: 0, padding: false }))
        .await
        .unwrap();
    task.await.unwrap();
    let mut rest = Vec::new();
    client.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
}

#[tokio::test]
async fn requests() {
    let request = protocol::Request { version: 1, protocol: 2, padding: true };
    let encoded = protocol::encode_request(&request);
    assert!(encoded.len() >= 5 + 256 && encoded.len() < 5 + 768);
    assert_eq!(protocol::read_request(&mut encoded.as_slice()).await.unwrap(), request);
    assert!(protocol::read_request(&mut [2u8, 0].as_slice())
        .await
        .unwrap_err()
        .to_string()
        .contains("unsupported version: 2"));
    let stream = protocol::encode_stream_request(true, true, &Socksaddr::from_host_port("1.2.3.4", 53)).unwrap();
    assert_eq!(stream, [0, 3, 1, 1, 2, 3, 4, 0, 53]);
    let parsed = protocol::read_stream_request(&mut stream.as_slice()).await.unwrap();
    assert!(parsed.udp && parsed.packet_addr);
    assert_eq!(parse_response(&[0]).unwrap().unwrap().1, 1);
    let error = protocol::error_response("nope");
    let (result, used) = parse_response(&error).unwrap().unwrap();
    assert_eq!((result.unwrap_err().to_string(), used), ("remote error: nope".to_string(), error.len()));
    assert!(parse_response(&error[..3]).unwrap().is_none());
}

#[tokio::test]
async fn padding_stream() {
    let (a, b) = tokio::io::duplex(1 << 20);
    let mut writer = protocol::PaddingStream::new(a);
    let mut reader = protocol::PaddingStream::new(b);
    let mut expected = Vec::new();
    for round in 0..20u8 {
        let chunk = vec![round; 100 + round as usize];
        writer.write_all(&chunk).await.unwrap();
        expected.extend_from_slice(&chunk);
    }
    writer.shutdown().await.unwrap();
    drop(writer);
    let mut received = Vec::new();
    reader.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, expected);
}
