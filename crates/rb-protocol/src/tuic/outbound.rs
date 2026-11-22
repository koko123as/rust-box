//! TUIC v5 TCP client runtime, following sing-quic `tuic.Client`.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::wire;
use async_trait::async_trait;
use quinn::{Connection, Endpoint, VarInt};
use rb_adapter::{
    BoxStream, InboundContext, Network, Outbound, PacketConn, SharedPacketConn, Socksaddr, MAX_PACKET_SIZE,
};
use rb_config::{QuicOptions, TuicOutbound as OutboundOptions};
use rb_dialer::{new_outbound_dialer, Dialer, DialerEnv};
use tokio::sync::Mutex;

use super::wire::{TuicAddress, UdpPacket};

/// A TUIC v5 outbound with native DATAGRAM UDP sessions.
pub struct TuicOutbound {
    tag: String,
    dialer: Arc<dyn Dialer>,
    server: Socksaddr,
    server_name: String,
    tls: Arc<rustls::ClientConfig>,
    uuid: [u8; 16],
    password: String,
    heartbeat: Duration,
    quic: QuicOptions,
    networks: Vec<Network>,
}

impl TuicOutbound {
    /// Builds a TUIC outbound with the same required TLS and UUID semantics as
    /// sing-box `protocol/tuic.NewOutbound`.
    pub fn new(
        options: &OutboundOptions,
        tag: String,
        env: &DialerEnv,
        certificates: &Arc<rb_certificate::Store>,
    ) -> Result<Arc<Self>, String> {
        let tls_options = options.tls.as_ref().filter(|tls| tls.enabled).ok_or("TLS is required")?;
        let tls = rb_tls::TlsClient::new(tls_options, &options.server, certificates)?.with_alpn(&["h3"]);
        let uuid = crate::vless::protocol::parse_uuid_strict(&options.uuid).ok_or("invalid uuid")?;
        if !matches!(options.congestion_control.as_str(), "" | "cubic") {
            return Err(format!("congestion control is not supported by rust-box yet: {}", options.congestion_control));
        }
        let server = Socksaddr::from_host_port(&options.server, options.server_port);
        let dialer = new_outbound_dialer(
            &options.dialer_options(),
            server.domain().is_some(),
            env,
            &format!("outbound/tuic[{tag}]"),
        )?;
        let heartbeat = if options.heartbeat.0.is_zero() { Duration::from_secs(10) } else { options.heartbeat.0 };
        let quic = QuicOptions {
            idle_timeout: options.idle_timeout,
            keep_alive_period: options.keep_alive_period,
            stream_receive_window: options.stream_receive_window,
            connection_receive_window: options.connection_receive_window,
            max_concurrent_streams: options.max_concurrent_streams,
            initial_packet_size: options.initial_packet_size,
            disable_path_mtu_discovery: options.disable_path_mtu_discovery,
        };
        let networks = options
            .network
            .build()
            .iter()
            .map(|network| if network == "udp" { Network::Udp } else { Network::Tcp })
            .collect();
        Ok(Arc::new(Self {
            tag,
            dialer,
            server,
            server_name: tls.server_name().to_string(),
            tls: tls.rustls_config(),
            uuid,
            password: options.password.clone(),
            heartbeat,
            quic,
            networks,
        }))
    }

    async fn connect(&self, destination: &Socksaddr) -> io::Result<BoxStream> {
        let (endpoint, connection) = self.open_connection().await?;
        spawn_datagram_reader(connection.clone());
        let (mut send, recv) =
            connection.open_bi().await.map_err(|error| io::Error::other(format!("TUIC open TCP stream: {error}")))?;
        send.write_all(&wire::encode_connect(destination)?).await?;
        Ok(rb_dialer::quic::bidi_stream_with_close(endpoint, connection, send, recv))
    }

    async fn open_connection(&self) -> io::Result<(Endpoint, Connection)> {
        let packet_conn = self.dialer.dial_udp(&self.server).await?;
        let (endpoint, connection) = rb_dialer::quic::connect_with_datagrams(
            packet_conn,
            self.server.clone(),
            self.tls.clone(),
            &self.server_name,
            &self.quic,
        )
        .await?;

        let mut token = [0u8; 32];
        connection
            .export_keying_material(&mut token, &self.uuid, self.password.as_bytes())
            .map_err(|error| io::Error::other(format!("TUIC export keying material: {error:?}")))?;
        let mut auth_stream = connection
            .open_uni()
            .await
            .map_err(|error| io::Error::other(format!("TUIC open authentication stream: {error}")))?;
        auth_stream.write_all(&wire::encode_auth(&self.uuid, &token)).await?;
        auth_stream
            .finish()
            .map_err(|error| io::Error::other(format!("TUIC finish authentication stream: {error}")))?;

        spawn_heartbeat(connection.clone(), self.heartbeat);
        Ok((endpoint, connection))
    }
}

#[async_trait]
impl Outbound for TuicOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "tuic"
    }

    fn networks(&self) -> &[Network] {
        &self.networks
    }

    async fn dial_tcp(&self, context: &InboundContext) -> io::Result<BoxStream> {
        self.connect(&context.destination).await
    }

    async fn listen_packet(&self, _context: &InboundContext) -> io::Result<SharedPacketConn> {
        let (endpoint, connection) = self.open_connection().await?;
        Ok(Arc::new(TuicPacketConn {
            _endpoint: endpoint,
            connection,
            session_id: 0,
            packet_id: AtomicU32::new(0),
            read_lock: Mutex::new(()),
            fragments: Mutex::new(TuicDefragger::default()),
        }))
    }
}

struct TuicPacketConn {
    _endpoint: Endpoint,
    connection: Connection,
    session_id: u16,
    packet_id: AtomicU32,
    read_lock: Mutex<()>,
    fragments: Mutex<TuicDefragger>,
}

impl Drop for TuicPacketConn {
    fn drop(&mut self) {
        self.connection.close(VarInt::from_u32(0), b"UDP session closed");
    }
}

#[async_trait]
impl PacketConn for TuicPacketConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let _read_guard = self.read_lock.lock().await;
        loop {
            let message = self
                .connection
                .read_datagram()
                .await
                .map_err(|error| io::Error::other(format!("TUIC receive datagram: {error}")))?;
            if message.get(1) == Some(&wire::COMMAND_HEARTBEAT) {
                wire::decode_heartbeat(&message)?;
                continue;
            }
            let packet = wire::decode_udp(&message)?;
            if packet.session_id != self.session_id {
                continue;
            }
            let Some((data, destination)) = self.fragments.lock().await.feed(packet)? else { continue };
            if data.len() > buffer.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "short buffer"));
            }
            buffer[..data.len()].copy_from_slice(&data);
            return Ok((data.len(), destination));
        }
    }

    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        if data.len() > u16::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "TUIC UDP data exceeds u16 length"));
        }
        let max_datagram = self
            .connection
            .max_datagram_size()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "TUIC server did not negotiate DATAGRAM"))?;
        let mut encoded_address = Vec::new();
        wire::encode_address(&TuicAddress::Socket(address.clone()), &mut encoded_address)?;
        let first_header = 10 + encoded_address.len();
        let fragment_size = max_datagram
            .checked_sub(first_header)
            .filter(|size| *size > 0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "TUIC UDP datagram limit is too small"))?;
        let fragment_count = data.len().max(1).div_ceil(fragment_size);
        if fragment_count > u8::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "TUIC UDP packet requires too many fragments"));
        }
        let packet_id = self.packet_id.fetch_add(1, Ordering::Relaxed).wrapping_add(1) as u16;
        for fragment_id in 0..fragment_count {
            let start = fragment_id * fragment_size;
            let end = data.len().min(start + fragment_size);
            let packet = UdpPacket {
                session_id: self.session_id,
                packet_id,
                fragment_total: fragment_count as u8,
                fragment_id: fragment_id as u8,
                destination: if fragment_id == 0 { TuicAddress::Socket(address.clone()) } else { TuicAddress::Empty },
                data: data[start..end].to_vec(),
            };
            let encoded = wire::encode_udp(&packet)?;
            self.connection
                .send_datagram(encoded.into())
                .map_err(|error| io::Error::other(format!("TUIC send datagram: {error:?}")))?;
        }
        Ok(())
    }
}

#[derive(Default)]
struct TuicDefragger {
    packets: HashMap<u16, TuicFragments>,
}

struct TuicFragments {
    updated: Instant,
    total: u8,
    parts: Vec<Option<Vec<u8>>>,
    destination: Option<Socksaddr>,
    length: usize,
}

impl TuicDefragger {
    fn feed(&mut self, packet: UdpPacket) -> io::Result<Option<(Vec<u8>, Socksaddr)>> {
        if packet.fragment_total <= 1 {
            return match packet.destination {
                TuicAddress::Socket(destination) => Ok(Some((packet.data, destination))),
                TuicAddress::Empty => Err(io::Error::new(io::ErrorKind::InvalidData, "empty TUIC UDP destination")),
            };
        }
        if packet.fragment_id >= packet.fragment_total {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid TUIC UDP fragment id"));
        }
        let packet_id = packet.packet_id;
        self.packets.retain(|_, entry| entry.updated.elapsed() <= Duration::from_secs(10));
        if self.packets.get(&packet_id).is_some_and(|entry| entry.total != packet.fragment_total) {
            self.packets.remove(&packet_id);
            return Err(io::Error::new(io::ErrorKind::InvalidData, "inconsistent TUIC UDP fragment total"));
        }
        self.packets.entry(packet_id).or_insert_with(|| TuicFragments {
            updated: Instant::now(),
            total: packet.fragment_total,
            parts: vec![None; packet.fragment_total as usize],
            destination: None,
            length: 0,
        });
        if self.packets.len() > 256 {
            if let Some(oldest) = self.packets.iter().min_by_key(|(_, entry)| entry.updated).map(|(&id, _)| id) {
                self.packets.remove(&oldest);
            }
        }
        if packet.fragment_id == 0 && matches!(packet.destination, TuicAddress::Empty) {
            self.packets.remove(&packet_id);
            return Err(io::Error::new(io::ErrorKind::InvalidData, "first TUIC UDP fragment has no destination"));
        }
        let too_large;
        let complete;
        {
            let entry = self.packets.get_mut(&packet_id).expect("fragment entry exists");
            entry.updated = Instant::now();
            let part = &mut entry.parts[packet.fragment_id as usize];
            if part.is_none() {
                if packet.fragment_id == 0 {
                    if let TuicAddress::Socket(destination) = packet.destination {
                        entry.destination = Some(destination);
                    }
                }
                entry.length = entry.length.saturating_add(packet.data.len());
                *part = Some(packet.data);
            }
            too_large = entry.length > MAX_PACKET_SIZE;
            complete = entry.destination.is_some() && entry.parts.iter().all(Option::is_some);
        }
        if too_large {
            self.packets.remove(&packet_id);
            return Err(io::Error::new(io::ErrorKind::InvalidData, "reassembled TUIC UDP packet is too large"));
        }
        if !complete {
            return Ok(None);
        }
        let entry = self.packets.remove(&packet_id).expect("complete fragment entry exists");
        let mut data = Vec::with_capacity(entry.length);
        for part in entry.parts {
            data.extend_from_slice(&part.expect("all fragments are present"));
        }
        Ok(Some((data, entry.destination.expect("fragment destination exists"))))
    }
}

fn spawn_datagram_reader(connection: quinn::Connection) {
    tokio::spawn(async move {
        loop {
            let Ok(message) = connection.read_datagram().await else { break };
            if message.get(1) == Some(&wire::COMMAND_HEARTBEAT) {
                if wire::decode_heartbeat(&message).is_err() {
                    connection.close(VarInt::from_u32(1), b"invalid TUIC heartbeat");
                    break;
                }
            } else if wire::decode_udp(&message).is_err() {
                connection.close(VarInt::from_u32(1), b"invalid TUIC UDP datagram");
                break;
            }
        }
    });
}

fn spawn_heartbeat(connection: quinn::Connection, interval: Duration) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = connection.closed() => break,
                _ = tokio::time::sleep(interval) => {
                    if connection.send_datagram(wire::encode_heartbeat().to_vec().into()).is_err() {
                        break;
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fragment(fragment_id: u8, destination: TuicAddress, data: &[u8]) -> UdpPacket {
        UdpPacket { session_id: 7, packet_id: 9, fragment_total: 2, fragment_id, destination, data: data.to_vec() }
    }

    #[test]
    fn defragger_reassembles_out_of_order_fragments() {
        let destination = Socksaddr::from_host_port("192.0.2.9", 5353);
        let mut defragger = TuicDefragger::default();
        assert_eq!(defragger.feed(fragment(1, TuicAddress::Empty, b"world")).unwrap(), None);
        assert_eq!(
            defragger.feed(fragment(0, TuicAddress::Socket(destination.clone()), b"hello")).unwrap(),
            Some((b"helloworld".to_vec(), destination)),
        );
    }

    #[test]
    fn defragger_rejects_first_fragment_without_destination() {
        let mut defragger = TuicDefragger::default();
        assert!(defragger.feed(fragment(0, TuicAddress::Empty, b"first")).is_err());
    }
}
