//! Parsing and building the IP packets the stack handles itself (UDP,
//! ICMP echo, TCP resets, ICMP unreachable), with their checksums.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

/// TTL / hop limit of the packets the stack builds (sing-tun `synthesizedTTL`).
const TTL: u8 = 64;

/// The parts of an IP packet the stack looks at.
#[derive(Debug, Clone, Copy)]
pub struct Parsed<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// The transport protocol (the IPv6 next header after the fixed header).
    pub protocol: u8,
    /// The transport header and data.
    pub payload: &'a [u8],
    /// An IPv4 fragment (more fragments, or a non-zero offset).
    pub fragment: bool,
    /// The whole packet, trimmed to its length.
    pub packet: &'a [u8],
}

pub fn parse(packet: &[u8]) -> Option<Parsed<'_>> {
    match packet.first()? >> 4 {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            if header_len < 20 || total < header_len || total > packet.len() {
                return None;
            }
            let flags_offset = u16::from_be_bytes([packet[6], packet[7]]);
            let fragment = flags_offset & 0x2000 != 0 || flags_offset & 0x1fff != 0;
            let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            Some(Parsed {
                src: src.into(),
                dst: dst.into(),
                protocol: packet[9],
                payload: &packet[header_len..total],
                fragment,
                packet: &packet[..total],
            })
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            if 40 + payload_len > packet.len() {
                return None;
            }
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?);
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?);
            Some(Parsed {
                src: src.into(),
                dst: dst.into(),
                protocol: packet[6],
                payload: &packet[40..40 + payload_len],
                fragment: false,
                packet: &packet[..40 + payload_len],
            })
        }
        _ => None,
    }
}

/// Whether the stack handles packets to `address` (sing-tun drops the
/// others: Go `netip.Addr.IsGlobalUnicast`, and the IPv4 broadcast).
pub fn is_global_unicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !(address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || address.is_link_local()
                || address.is_broadcast())
        }
        IpAddr::V6(address) => {
            if let Some(v4) = address.to_ipv4_mapped() {
                return is_global_unicast(v4.into());
            }
            let first = address.segments()[0];
            !(address.is_unspecified() || address.is_loopback() || address.is_multicast() || first & 0xffc0 == 0xfe80)
        }
    }
}

fn sum(data: &[u8], mut acc: u32) -> u32 {
    let (chunks, remainder) = data.as_chunks::<2>();
    for chunk in chunks {
        acc += u32::from(u16::from_be_bytes(*chunk));
    }
    if let [last] = remainder {
        acc += u32::from(*last) << 8;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// The Internet checksum of `data`.
pub fn checksum(data: &[u8]) -> u16 {
    fold(sum(data, 0))
}

fn pseudo_header_sum(src: IpAddr, dst: IpAddr, protocol: u8, length: usize) -> u32 {
    let mut acc = 0;
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            acc = sum(&src.octets(), acc);
            acc = sum(&dst.octets(), acc);
            acc += u32::from(protocol);
            acc += length as u32;
        }
        (src, dst) => {
            acc = sum(&to_v6(src).octets(), acc);
            acc = sum(&to_v6(dst).octets(), acc);
            acc += (length as u32) >> 16;
            acc += (length as u32) & 0xffff;
            acc += u32::from(protocol);
        }
    }
    acc
}

fn to_v6(address: IpAddr) -> Ipv6Addr {
    match address {
        IpAddr::V4(address) => address.to_ipv6_mapped(),
        IpAddr::V6(address) => address,
    }
}

/// The transport checksum of `segment` (with its checksum field zeroed).
pub fn transport_checksum(src: IpAddr, dst: IpAddr, protocol: u8, segment: &[u8]) -> u16 {
    fold(sum(segment, pseudo_header_sum(src, dst, protocol, segment.len())))
}

/// Builds an IP packet around `transport` (whose checksum is filled in at
/// `checksum_at`, if any). The family follows `src`; an IPv4 address with
/// an IPv6 peer is written as IPv4-mapped.
fn build_ip(src: IpAddr, dst: IpAddr, protocol: u8, mut transport: Vec<u8>, checksum_at: Option<usize>) -> Vec<u8> {
    let (src, dst) = match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => (IpAddr::V4(src), IpAddr::V4(dst)),
        (src, dst) => (IpAddr::V6(to_v6(src)), IpAddr::V6(to_v6(dst))),
    };
    if let Some(at) = checksum_at {
        transport[at..at + 2].copy_from_slice(&[0, 0]);
        let mut value = if protocol == PROTO_ICMP {
            checksum(&transport)
        } else {
            transport_checksum(src, dst, protocol, &transport)
        };
        if protocol == PROTO_UDP && value == 0 {
            value = 0xffff;
        }
        transport[at..at + 2].copy_from_slice(&value.to_be_bytes());
    }
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let total = 20 + transport.len();
            let mut packet = Vec::with_capacity(total);
            packet.extend_from_slice(&[0x45, 0]);
            packet.extend_from_slice(&(total as u16).to_be_bytes());
            packet.extend_from_slice(&[0, 0, 0x40, 0, TTL, protocol, 0, 0]);
            packet.extend_from_slice(&src.octets());
            packet.extend_from_slice(&dst.octets());
            let header_checksum = checksum(&packet[..20]);
            packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
            packet.extend_from_slice(&transport);
            packet
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let mut packet = Vec::with_capacity(40 + transport.len());
            packet.extend_from_slice(&[0x60, 0, 0, 0]);
            packet.extend_from_slice(&(transport.len() as u16).to_be_bytes());
            packet.extend_from_slice(&[protocol, TTL]);
            packet.extend_from_slice(&src.octets());
            packet.extend_from_slice(&dst.octets());
            packet.extend_from_slice(&transport);
            packet
        }
        _ => unreachable!(),
    }
}

/// A UDP packet from `src` to `dst`.
pub fn build_udp(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let length = 8 + payload.len();
    let mut udp = Vec::with_capacity(length);
    udp.extend_from_slice(&src.port().to_be_bytes());
    udp.extend_from_slice(&dst.port().to_be_bytes());
    udp.extend_from_slice(&(length as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    build_ip(src.ip(), dst.ip(), PROTO_UDP, udp, Some(6))
}

/// Splits a UDP segment into its ports and data.
pub fn parse_udp(segment: &[u8]) -> Option<(u16, u16, &[u8])> {
    if segment.len() < 8 {
        return None;
    }
    let length = usize::from(u16::from_be_bytes([segment[4], segment[5]]));
    if length < 8 || length > segment.len() {
        return None;
    }
    Some((
        u16::from_be_bytes([segment[0], segment[1]]),
        u16::from_be_bytes([segment[2], segment[3]]),
        &segment[8..length],
    ))
}

/// TCP ports and flags of a segment: (source, destination, seq, ack, flags).
pub fn parse_tcp(segment: &[u8]) -> Option<(u16, u16, u32, u32, u8)> {
    if segment.len() < 20 {
        return None;
    }
    Some((
        u16::from_be_bytes([segment[0], segment[1]]),
        u16::from_be_bytes([segment[2], segment[3]]),
        u32::from_be_bytes([segment[4], segment[5], segment[6], segment[7]]),
        u32::from_be_bytes([segment[8], segment[9], segment[10], segment[11]]),
        segment[13],
    ))
}

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

/// The RST|ACK answering a SYN (gVisor `Complete(true)`, a refused connection).
pub fn build_tcp_reset(syn: &Parsed<'_>) -> Option<Vec<u8>> {
    let (src_port, dst_port, seq, _, flags) = parse_tcp(syn.payload)?;
    let ack = seq.wrapping_add(1).wrapping_add(u32::from(flags & TCP_FIN != 0));
    let mut tcp = Vec::with_capacity(20);
    tcp.extend_from_slice(&dst_port.to_be_bytes());
    tcp.extend_from_slice(&src_port.to_be_bytes());
    tcp.extend_from_slice(&0u32.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.extend_from_slice(&[0x50, TCP_RST | TCP_ACK, 0, 0, 0, 0, 0, 0]);
    Some(build_ip(syn.dst, syn.src, PROTO_TCP, tcp, Some(16)))
}

/// The echo reply to an ICMP or ICMPv6 echo request, sent from the address
/// it was sent to (sing-tun answers pings itself), or `None` for other ICMP.
pub fn build_echo_reply(request: &Parsed<'_>) -> Option<Vec<u8>> {
    let icmp = request.payload;
    if icmp.len() < 8 {
        return None;
    }
    let (echo_request, echo_reply, protocol) = match request.src {
        IpAddr::V4(_) => (8, 0, PROTO_ICMP),
        IpAddr::V6(_) => (128, 129, PROTO_ICMPV6),
    };
    if icmp[0] != echo_request || icmp[1] != 0 {
        return None;
    }
    let mut reply = icmp.to_vec();
    reply[0] = echo_reply;
    Some(build_ip(request.dst, request.src, protocol, reply, Some(2)))
}

/// The ICMP port unreachable for a UDP packet (gVisor `gWriteUnreachable`),
/// quoting as much of it as fits a minimum MTU.
pub fn build_port_unreachable(packet: &Parsed<'_>) -> Vec<u8> {
    let (kind, code, protocol, limit) = match packet.src {
        IpAddr::V4(_) => (3, 3, PROTO_ICMP, 576 - 20 - 8),
        IpAddr::V6(_) => (1, 4, PROTO_ICMPV6, 1280 - 40 - 8),
    };
    let quoted = &packet.packet[..packet.packet.len().min(limit)];
    let mut icmp = vec![kind, code, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(quoted);
    build_ip(packet.dst, packet.src, protocol, icmp, Some(2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_round_trip() {
        let src: SocketAddr = "172.19.0.1:5353".parse().unwrap();
        let dst: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let packet = build_udp(src, dst, b"hello");
        let parsed = parse(&packet).unwrap();
        assert_eq!((parsed.src, parsed.dst, parsed.protocol), (src.ip(), dst.ip(), PROTO_UDP));
        assert_eq!(checksum(&packet[..20]), 0);
        assert_eq!(transport_checksum(parsed.src, parsed.dst, PROTO_UDP, parsed.payload), 0);
        assert_eq!(parse_udp(parsed.payload).unwrap(), (5353, 53, &b"hello"[..]));

        let src: SocketAddr = "[fdfe:dcba:9876::1]:1000".parse().unwrap();
        let dst: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let packet = build_udp(src, dst, b"quic");
        let parsed = parse(&packet).unwrap();
        assert_eq!(transport_checksum(parsed.src, parsed.dst, PROTO_UDP, parsed.payload), 0);
        assert_eq!(parse_udp(parsed.payload).unwrap(), (1000, 443, &b"quic"[..]));
    }

    #[test]
    fn echo_and_unreachable() {
        // An echo request 172.19.0.1 -> 1.1.1.1.
        let request = build_ip(
            "172.19.0.1".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
            PROTO_ICMP,
            vec![8, 0, 0, 0, 0x12, 0x34, 0, 1, b'p', b'i', b'n', b'g'],
            Some(2),
        );
        let parsed = parse(&request).unwrap();
        let reply = build_echo_reply(&parsed).unwrap();
        let reply = parse(&reply).unwrap();
        assert_eq!((reply.src, reply.dst), (parsed.dst, parsed.src));
        assert_eq!(reply.payload[0], 0);
        assert_eq!(checksum(reply.payload), 0);
        assert_eq!(&reply.payload[4..], &parsed.payload[4..]);

        let udp = build_udp("172.19.0.1:1".parse().unwrap(), "1.1.1.1:2".parse().unwrap(), b"x");
        let unreachable = build_port_unreachable(&parse(&udp).unwrap());
        let unreachable = parse(&unreachable).unwrap();
        assert_eq!(&unreachable.payload[..2], &[3, 3]);
        assert_eq!(checksum(unreachable.payload), 0);
        assert_eq!(&unreachable.payload[8..], &udp[..]);
    }

    #[test]
    fn global_unicast_like_go() {
        for (address, expected) in [
            ("10.0.0.1", true),
            ("1.1.1.1", true),
            ("255.255.255.255", false),
            ("224.0.0.1", false),
            ("169.254.1.1", false),
            ("127.0.0.1", false),
            ("0.0.0.0", false),
            ("2001:db8::1", true),
            ("fe80::1", false),
            ("ff02::1", false),
            ("::1", false),
        ] {
            assert_eq!(is_global_unicast(address.parse().unwrap()), expected, "{address}");
        }
    }
}
