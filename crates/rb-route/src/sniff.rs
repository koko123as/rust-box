//! Protocol sniffing on the first client bytes or packets, mirroring
//! sing-box `common/sniff`: stream sniffers (`tls.go`, `http.go`, `dns.go`,
//! `bittorrent.go`, `ssh.go`, `rdp.go`) and packet sniffers (`dns.go`,
//! `quic.go`, `stun.go`, `bittorrent.go`, `dtls.go`, `ntp.go`).

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::Aes128Gcm;
use hickory_proto::op::{Message, MessageType};
use hkdf::Hkdf;
use sha2::Sha256;

/// What a sniffer found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sniffed {
    pub protocol: &'static str,
    pub domain: Option<String>,
}

/// One sniffer's verdict on the bytes so far.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Found(Sniffed),
    /// Could be this protocol; more bytes are needed.
    NeedMore,
    NotThis,
}

/// Stream sniffers in sing-box's default order (`route/route.go` `actionSniff`).
pub const STREAM_SNIFFERS: &[&str] = &["tls", "http", "dns", "bittorrent", "ssh", "rdp"];

/// Packet sniffers in sing-box's default order (`defaultPacketSniffers`).
pub const PACKET_SNIFFERS: &[&str] = &["dns", "quic", "stun", "bittorrent", "dtls", "ntp"];

/// Runs the stream sniffer `name` on the first bytes of a stream.
pub fn sniff(name: &str, data: &[u8]) -> Verdict {
    match name {
        "tls" => tls(data),
        "http" => http(data),
        "dns" => stream_dns(data),
        "bittorrent" => bittorrent(data),
        "ssh" => ssh(data),
        "rdp" => rdp(data),
        _ => Verdict::NotThis,
    }
}

/// Runs the packet sniffer `name` on one packet. QUIC may need several
/// packets (a ClientHello split over Initial packets): it answers
/// [`Verdict::NeedMore`] and [`quic`] is then given all of them.
pub fn sniff_packet(name: &str, packet: &[u8]) -> Verdict {
    let (matched, protocol) = match name {
        "dns" => return packet_dns(packet),
        "quic" => return quic(&[packet]),
        "stun" => (stun(packet), "stun"),
        "bittorrent" => (utp(packet) || udp_tracker(packet), "bittorrent"),
        "dtls" => (dtls(packet), "dtls"),
        "ntp" => (ntp(packet), "ntp"),
        _ => (false, ""),
    };
    if matched {
        Verdict::Found(Sniffed { protocol, domain: None })
    } else {
        Verdict::NotThis
    }
}

/// sing-box `sniff.Skip`: server-first protocols, where waiting for the
/// client to speak only adds the sniff timeout.
pub fn skip_port(port: u16) -> bool {
    matches!(port, 25 | 465 | 587 | 143 | 993 | 110 | 995)
}

fn dns_query(message: &[u8]) -> bool {
    match Message::from_vec(message) {
        Ok(message) => {
            message.message_type() == MessageType::Query
                && !message.queries().is_empty()
                && message.answers().is_empty()
                && message.name_servers().is_empty()
        }
        Err(_) => false,
    }
}

/// sing-box `DomainNameQuery`.
fn packet_dns(packet: &[u8]) -> Verdict {
    if dns_query(packet) {
        Verdict::Found(Sniffed { protocol: "dns", domain: None })
    } else {
        Verdict::NotThis
    }
}

/// sing-box `StreamDomainNameQuery`: a length-prefixed query (DNS over TCP).
fn stream_dns(data: &[u8]) -> Verdict {
    if data.len() < 2 {
        return Verdict::NeedMore;
    }
    let length = u16::from_be_bytes([data[0], data[1]]) as usize;
    if length < 12 {
        return Verdict::NotThis;
    }
    let packet = &data[2..data.len().min(2 + length)];
    // QR set, no question, or answers/authorities in a query: not DNS.
    if packet.len() > 2 && packet[2] & 0x80 != 0 {
        return Verdict::NotThis;
    }
    if packet.len() > 5 && packet[4] == 0 && packet[5] == 0 {
        return Verdict::NotThis;
    }
    if (6..10).any(|index| packet.len() > index && packet[index] != 0) {
        return Verdict::NotThis;
    }
    if packet.len() < length {
        return Verdict::NeedMore;
    }
    packet_dns(packet)
}

/// sing-box `RDP`: an X.224 connection request carrying an RDP
/// negotiation request.
fn rdp(data: &[u8]) -> Verdict {
    // The expected byte at each offset; `None` may be anything.
    const PATTERN: [Option<u8>; 14] = [
        Some(0x03),
        Some(0x00),
        Some(0x00),
        Some(19),
        Some(14),
        Some(0xe0),
        None,
        None,
        None,
        None,
        None,
        Some(0x01),
        None,
        Some(8),
    ];
    for (index, expected) in PATTERN.iter().enumerate() {
        let Some(byte) = data.get(index) else { return Verdict::NeedMore };
        if expected.is_some_and(|expected| expected != *byte) {
            return Verdict::NotThis;
        }
    }
    Verdict::Found(Sniffed { protocol: "rdp", domain: None })
}

/// sing-box `STUNMessage` (RFC 8489 section 5).
fn stun(packet: &[u8]) -> bool {
    packet.len() >= 20
        && packet[4..8] == [0x21, 0x12, 0xa4, 0x42]
        && packet.len() >= 20 + u16::from_be_bytes([packet[2], packet[3]]) as usize
}

/// sing-box `DTLSRecord` (RFC 6347 section 4.1).
fn dtls(packet: &[u8]) -> bool {
    packet.len() >= 13
        && matches!(packet[0], 20 | 21 | 22 | 23 | 25)
        && packet[1] == 0xfe
        && matches!(packet[2], 0xff | 0xfd)
}

/// sing-box `NTP`: a version 3 or 4 client request (RFC 5905).
fn ntp(packet: &[u8]) -> bool {
    if packet.len() < 48 {
        return false;
    }
    let version = (packet[0] >> 3) & 0x07;
    let mode = packet[0] & 0x07;
    let root_delay = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
    let root_dispersion = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);
    (version == 3 || version == 4)
        && mode == 3
        && f64::from(root_delay) / 65536.0 <= 16.0
        && f64::from(root_dispersion) / 65536.0 <= 16.0
}

/// sing-box `UTP` (BEP 29).
fn utp(packet: &[u8]) -> bool {
    if packet.len() < 20 {
        return false;
    }
    let version = packet[0] & 0x0f;
    let kind = packet[0] >> 4;
    if version != 1 || kind > 4 {
        return false;
    }
    let mut extension = packet[1];
    let mut rest = &packet[20..];
    while extension != 0 {
        let [next, length, ..] = rest else { return false };
        if *next > 0x04 {
            return false;
        }
        extension = *next;
        let skip = 2 + *length as usize;
        if rest.len() < skip {
            return false;
        }
        rest = &rest[skip..];
    }
    true
}

/// sing-box `UDPTracker`: a BEP 15 connect request.
fn udp_tracker(packet: &[u8]) -> bool {
    packet.len() >= 16 && packet[..8] == 0x41727101980u64.to_be_bytes() && packet[8..12] == [0, 0, 0, 0]
}

const QUIC_VERSION_DRAFT29: u32 = 0xff00001d;
const QUIC_VERSION_1: u32 = 0x1;
const QUIC_VERSION_2: u32 = 0x6b3343cf;
const QUIC_SALT_DRAFT29: [u8; 20] = [
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8,
    0x99,
];
const QUIC_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f,
    0x0a,
];
const QUIC_SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e,
    0xd9,
];

/// Reads a QUIC variable-length integer (RFC 9000 section 16).
fn varint(reader: &mut Reader<'_>) -> Option<u64> {
    let first = reader.u8()?;
    let length = 1usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    for byte in reader.take(length - 1)? {
        value = value << 8 | u64::from(*byte);
    }
    Some(value)
}

/// TLS 1.3 HKDF-Expand-Label with an empty context (RFC 8446 section 7.1).
fn expand_label(secret: &[u8], label: &str, length: usize) -> Option<Vec<u8>> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full.len());
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(0);
    let hkdf = Hkdf::<Sha256>::from_prk(secret).ok()?;
    let mut output = vec![0u8; length];
    hkdf.expand(&info, &mut output).ok()?;
    Some(output)
}

/// Removes the protection of a client Initial packet (RFC 9001 section 5)
/// and returns its CRYPTO frames as (offset, data).
fn quic_initial_crypto(packet: &[u8]) -> Option<Vec<(u64, Vec<u8>)>> {
    let mut reader = Reader { data: packet };
    let first = reader.u8()?;
    if first & 0x40 == 0 {
        return None;
    }
    let version = u32::from_be_bytes(reader.take(4)?.try_into().ok()?);
    let packet_type = (first & 0x30) >> 4;
    let initial = match version {
        QUIC_VERSION_1 | QUIC_VERSION_DRAFT29 => packet_type == 0,
        QUIC_VERSION_2 => packet_type == 1,
        _ => return None,
    };
    if !initial {
        return None;
    }
    let dcid_length = reader.u8()? as usize;
    if dcid_length == 0 || dcid_length > 20 {
        return None;
    }
    let dcid = reader.take(dcid_length)?;
    let scid_length = reader.u8()? as usize;
    reader.take(scid_length)?;
    let token_length = varint(&mut reader)? as usize;
    reader.take(token_length)?;
    let payload_length = varint(&mut reader)? as usize;
    let header_length = packet.len() - reader.data.len();
    if header_length + payload_length > packet.len() || payload_length < 20 {
        return None;
    }
    let sample = packet.get(header_length + 4..header_length + 20)?;
    let (salt, hp_label, key_label, iv_label) = match version {
        QUIC_VERSION_1 => (&QUIC_SALT_V1, "quic hp", "quic key", "quic iv"),
        QUIC_VERSION_2 => (&QUIC_SALT_V2, "quicv2 hp", "quicv2 key", "quicv2 iv"),
        _ => (&QUIC_SALT_DRAFT29, "quic hp", "quic key", "quic iv"),
    };
    let (initial_secret, _) = Hkdf::<Sha256>::extract(Some(salt), dcid);
    let secret = expand_label(&initial_secret, "client in", 32)?;
    let hp_key = expand_label(&secret, hp_label, 16)?;
    let mut mask = GenericArray::clone_from_slice(sample);
    aes::Aes128::new(GenericArray::from_slice(&hp_key)).encrypt_block(&mut mask);
    let mut header = packet[..header_length + 4].to_vec();
    header[0] ^= mask[0] & 0x0f;
    let pn_length = (header[0] & 0x03) as usize + 1;
    let mut packet_number = 0u64;
    for index in 0..pn_length {
        header[header_length + index] ^= mask[1 + index];
        packet_number = packet_number << 8 | u64::from(header[header_length + index]);
    }
    header.truncate(header_length + pn_length);
    let key = expand_label(&secret, key_label, 16)?;
    let mut nonce = expand_label(&secret, iv_label, 12)?;
    for (index, byte) in packet_number.to_be_bytes().iter().enumerate() {
        nonce[4 + index] ^= byte;
    }
    let ciphertext = &packet[header_length + pn_length..header_length + payload_length];
    let plain = Aes128Gcm::new(GenericArray::from_slice(&key))
        .decrypt(GenericArray::from_slice(&nonce), Payload { msg: ciphertext, aad: &header })
        .ok()?;
    let mut frames = Reader { data: &plain };
    let mut crypto = Vec::new();
    while !frames.data.is_empty() {
        match frames.u8()? {
            0x00 | 0x01 => {} // PADDING, PING
            kind @ (0x02 | 0x03) => {
                // ACK: largest, delay, range count, first range, ranges.
                varint(&mut frames)?;
                varint(&mut frames)?;
                let ranges = varint(&mut frames)?;
                varint(&mut frames)?;
                for _ in 0..ranges {
                    varint(&mut frames)?;
                    varint(&mut frames)?;
                }
                if kind == 0x03 {
                    for _ in 0..3 {
                        varint(&mut frames)?;
                    }
                }
            }
            0x06 => {
                let offset = varint(&mut frames)?;
                let length = varint(&mut frames)? as usize;
                crypto.push((offset, frames.take(length)?.to_vec()));
            }
            0x1c => {
                varint(&mut frames)?;
                varint(&mut frames)?;
                let length = varint(&mut frames)? as usize;
                frames.take(length)?;
            }
            _ => return None,
        }
    }
    Some(crypto)
}

/// sing-box `QUICClientHello`: decrypts client Initial packets, joins their
/// CRYPTO frames and reads the server name from the TLS ClientHello in them.
/// Answers [`Verdict::NeedMore`] while the ClientHello is still incomplete.
pub fn quic(packets: &[&[u8]]) -> Verdict {
    let mut fragments = Vec::new();
    for packet in packets {
        match quic_initial_crypto(packet) {
            Some(crypto) => fragments.extend(crypto),
            None => return Verdict::NotThis,
        }
    }
    let mut stream = Vec::new();
    loop {
        let next = fragments.iter().find(|(offset, data)| {
            !data.is_empty() && *offset <= stream.len() as u64 && *offset + data.len() as u64 > stream.len() as u64
        });
        let Some((offset, data)) = next else { break };
        stream.extend_from_slice(&data[(stream.len() as u64 - offset) as usize..]);
    }
    if stream.len() < 4 || stream[0] != 0x01 {
        return Verdict::NeedMore;
    }
    let length = (stream[1] as usize) << 16 | (stream[2] as usize) << 8 | stream[3] as usize;
    if stream.len() < 4 + length {
        return Verdict::NeedMore;
    }
    let domain = parse_client_hello(&stream[..4 + length]).flatten();
    Verdict::Found(Sniffed { protocol: "quic", domain })
}

fn prefix_verdict(data: &[u8], prefix: &[u8], protocol: &'static str) -> Verdict {
    if data.len() < prefix.len() {
        if prefix.starts_with(data) {
            Verdict::NeedMore
        } else {
            Verdict::NotThis
        }
    } else if data.starts_with(prefix) {
        Verdict::Found(Sniffed { protocol, domain: None })
    } else {
        Verdict::NotThis
    }
}

fn bittorrent(data: &[u8]) -> Verdict {
    prefix_verdict(data, b"\x13BitTorrent protocol", "bittorrent")
}

fn ssh(data: &[u8]) -> Verdict {
    prefix_verdict(data, b"SSH-2.0-", "ssh")
}

const METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"];

fn http(data: &[u8]) -> Verdict {
    let first_space = data.iter().position(|byte| *byte == b' ');
    let method = match first_space {
        Some(index) => &data[..index],
        None => {
            let could_be = data.len() < 8 && METHODS.iter().any(|method| method.as_bytes().starts_with(data));
            return if could_be { Verdict::NeedMore } else { Verdict::NotThis };
        }
    };
    if !METHODS.iter().any(|known| known.as_bytes() == method) {
        return Verdict::NotThis;
    }
    let Some(end) = find(data, b"\r\n\r\n") else {
        return if data.len() > 8192 { Verdict::NotThis } else { Verdict::NeedMore };
    };
    let head = String::from_utf8_lossy(&data[..end]);
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    if !request_line.contains(" HTTP/1.") {
        return Verdict::NotThis;
    }
    let host = lines.find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim().eq_ignore_ascii_case("host").then(|| value.trim().to_string())
    });
    let domain = host.map(|host| strip_port(&host).to_ascii_lowercase()).filter(|host| !host.is_empty());
    Verdict::Found(Sniffed { protocol: "http", domain })
}

/// `example.com:80` -> `example.com`, `[::1]:80` -> `::1`.
pub fn strip_port(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match host.rsplit_once(':') {
        Some((name, port)) if !name.contains(':') && port.bytes().all(|byte| byte.is_ascii_digit()) => name,
        _ => host,
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// Reads the server name from a TLS ClientHello (RFC 8446 section 4.1.2,
/// extension server_name from RFC 6066 section 3).
fn tls(data: &[u8]) -> Verdict {
    if data.is_empty() {
        return Verdict::NeedMore;
    }
    if data[0] != 0x16 {
        return Verdict::NotThis;
    }
    if data.len() < 5 {
        return Verdict::NeedMore;
    }
    if data[1] != 0x03 {
        return Verdict::NotThis;
    }
    let record_length = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_length {
        // The ClientHello may span records; the first record is enough for
        // nearly all clients, and sing-box reads the same way.
        if record_length > 16384 + 2048 {
            return Verdict::NotThis;
        }
        return Verdict::NeedMore;
    }
    match parse_client_hello(&data[5..5 + record_length]) {
        Some(domain) => Verdict::Found(Sniffed { protocol: "tls", domain }),
        None => Verdict::NotThis,
    }
}

struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        if self.data.len() < count {
            return None;
        }
        let (head, tail) = self.data.split_at(count);
        self.data = tail;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|bytes| bytes[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
    }
    fn u24(&mut self) -> Option<usize> {
        self.take(3).map(|bytes| (bytes[0] as usize) << 16 | (bytes[1] as usize) << 8 | bytes[2] as usize)
    }
}

/// Returns `Some(server name)` for a ClientHello (`Some(None)` without SNI),
/// `None` when it is not one.
fn parse_client_hello(handshake: &[u8]) -> Option<Option<String>> {
    let mut reader = Reader { data: handshake };
    if reader.u8()? != 0x01 {
        return None;
    }
    let length = reader.u24()?;
    // A ClientHello longer than its first record is read as far as it goes.
    let body = match reader.take(length) {
        Some(body) => body,
        None => reader.data,
    };
    let mut reader = Reader { data: body };
    reader.take(2)?; // legacy_version
    reader.take(32)?; // random
    let session_id = reader.u8()? as usize;
    reader.take(session_id)?;
    let suites = reader.u16()? as usize;
    reader.take(suites)?;
    let compression = reader.u8()? as usize;
    reader.take(compression)?;
    if reader.data.is_empty() {
        return Some(None);
    }
    let extensions_length = reader.u16()? as usize;
    let mut extensions = Reader { data: reader.take(extensions_length)? };
    while !extensions.data.is_empty() {
        let kind = extensions.u16()?;
        let length = extensions.u16()? as usize;
        let extension = extensions.take(length)?;
        if kind != 0 {
            continue;
        }
        let mut names = Reader { data: extension };
        let list_length = names.u16()? as usize;
        let mut names = Reader { data: names.take(list_length)? };
        while !names.data.is_empty() {
            let name_type = names.u8()?;
            let name_length = names.u16()? as usize;
            let name = names.take(name_length)?;
            if name_type == 0 {
                let name = std::str::from_utf8(name).ok()?.trim_end_matches('.').to_ascii_lowercase();
                return Some(Some(name));
            }
        }
    }
    Some(None)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A minimal ClientHello for `example.com`.
    pub fn client_hello(server_name: &str) -> Vec<u8> {
        let mut sni = Vec::new();
        sni.extend_from_slice(&((server_name.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        sni.extend_from_slice(server_name.as_bytes());
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut handshake = vec![0x01];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn tls_server_name() {
        let hello = client_hello("Example.COM");
        assert_eq!(
            sniff("tls", &hello),
            Verdict::Found(Sniffed { protocol: "tls", domain: Some("example.com".into()) })
        );
        assert_eq!(sniff("tls", &hello[..10]), Verdict::NeedMore);
        assert_eq!(sniff("tls", b"GET / HTTP/1.1\r\n"), Verdict::NotThis);
    }

    #[test]
    fn http_host() {
        let request = b"GET /a HTTP/1.1\r\nHost: Example.com:8080\r\nUser-Agent: t\r\n\r\n";
        assert_eq!(
            sniff("http", request),
            Verdict::Found(Sniffed { protocol: "http", domain: Some("example.com".into()) })
        );
        assert_eq!(sniff("http", b"GE"), Verdict::NeedMore);
        assert_eq!(sniff("http", b"GET / HTTP/1.1\r\nHost: a"), Verdict::NeedMore);
        assert_eq!(sniff("http", b"\x16\x03\x01"), Verdict::NotThis);
    }

    fn hex_packets(text: &str) -> Vec<Vec<u8>> {
        text.lines()
            .filter(|line| !line.is_empty())
            .map(|line| (0..line.len()).step_by(2).map(|i| u8::from_str_radix(&line[i..i + 2], 16).unwrap()).collect())
            .collect()
    }

    // Test vectors from sing-box `common/sniff/quic_test.go`.
    #[test]
    fn quic_single_packet() {
        let packets = hex_packets(include_str!("testdata/quic_firefox.hex"));
        assert_eq!(
            sniff_packet("quic", &packets[0]),
            Verdict::Found(Sniffed { protocol: "quic", domain: Some("www.google.com".into()) })
        );
        // Corrupt the payload: authentication fails.
        let mut broken = packets[0].clone();
        broken[200] ^= 1;
        assert_eq!(sniff_packet("quic", &broken), Verdict::NotThis);
    }

    #[test]
    fn quic_fragmented_client_hello() {
        let packets = hex_packets(include_str!("testdata/quic_chrome_fragmented.hex"));
        let refs: Vec<&[u8]> = packets.iter().map(Vec::as_slice).collect();
        assert_eq!(quic(&refs[..1]), Verdict::NeedMore);
        assert_eq!(quic(&refs[..2]), Verdict::NeedMore);
        assert_eq!(quic(&refs), Verdict::Found(Sniffed { protocol: "quic", domain: Some("www.google.com".into()) }));
    }

    pub fn dns_query_packet() -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        packet.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        packet
    }

    #[test]
    fn dns_packets_and_streams() {
        let query = dns_query_packet();
        assert!(matches!(sniff_packet("dns", &query), Verdict::Found(Sniffed { protocol: "dns", .. })));
        let mut response = query.clone();
        response[2] |= 0x80;
        assert_eq!(sniff_packet("dns", &response), Verdict::NotThis);
        let mut framed = (query.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&query);
        assert!(matches!(sniff("dns", &framed), Verdict::Found(_)));
        assert_eq!(sniff("dns", &framed[..8]), Verdict::NeedMore);
        assert_eq!(sniff("dns", &[0, 5, 1, 2]), Verdict::NotThis);
        assert_eq!(sniff("dns", b"GET / HTTP/1.1\r\n"), Verdict::NotThis);
    }

    #[test]
    fn small_packet_sniffers() {
        let mut stun = vec![0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42];
        stun.extend_from_slice(&[0u8; 12]);
        assert!(matches!(sniff_packet("stun", &stun), Verdict::Found(Sniffed { protocol: "stun", .. })));
        let mut dtls = vec![22, 0xfe, 0xfd];
        dtls.extend_from_slice(&[0u8; 10]);
        assert!(matches!(sniff_packet("dtls", &dtls), Verdict::Found(_)));
        let mut ntp = vec![0x23];
        ntp.extend_from_slice(&[0u8; 47]);
        assert!(matches!(sniff_packet("ntp", &ntp), Verdict::Found(_)));
        ntp[0] = 0x24; // mode 4, a server reply
        assert_eq!(sniff_packet("ntp", &ntp), Verdict::NotThis);
        let mut tracker = 0x41727101980u64.to_be_bytes().to_vec();
        tracker.extend_from_slice(&[0u8; 8]);
        assert!(matches!(sniff_packet("bittorrent", &tracker), Verdict::Found(_)));
        let mut utp = vec![0x41, 0];
        utp.extend_from_slice(&[0u8; 18]);
        assert!(matches!(sniff_packet("bittorrent", &utp), Verdict::Found(_)));
        assert_eq!(sniff_packet("stun", b"short"), Verdict::NotThis);
        let rdp = [3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0];
        assert!(matches!(sniff("rdp", &rdp), Verdict::Found(_)));
        assert_eq!(sniff("rdp", &rdp[..5]), Verdict::NeedMore);
    }

    #[test]
    fn prefixes_and_ports() {
        assert!(matches!(sniff("bittorrent", b"\x13BitTorrent protocol..."), Verdict::Found(_)));
        assert!(matches!(sniff("ssh", b"SSH-2.0-OpenSSH"), Verdict::Found(_)));
        assert_eq!(sniff("ssh", b"SS"), Verdict::NeedMore);
        assert_eq!(strip_port("[::1]:80"), "::1");
        assert_eq!(strip_port("::1"), "::1");
        assert_eq!(strip_port("a.com:443"), "a.com");
    }
}
