//! TUIC v5 wire framing, field-for-field with sing-quic `tuic/{protocol,address,packet}.go`.
use rb_adapter::{Host, Socksaddr};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const VERSION: u8 = 5;
pub const COMMAND_AUTHENTICATE: u8 = 0;
pub const COMMAND_CONNECT: u8 = 1;
pub const COMMAND_PACKET: u8 = 2;
pub const COMMAND_DISSOCIATE: u8 = 3;
pub const COMMAND_HEARTBEAT: u8 = 4;
pub const AUTH_LEN: usize = 50;
const FAMILY_FQDN: u8 = 0x00;
const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;
const FAMILY_EMPTY: u8 = 0xff;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TuicAddress {
    Empty,
    Socket(Socksaddr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpPacket {
    pub session_id: u16,
    pub packet_id: u16,
    pub fragment_total: u8,
    pub fragment_id: u8,
    pub destination: TuicAddress,
    pub data: Vec<u8>,
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}
fn take<'a>(input: &mut &'a [u8], n: usize) -> io::Result<&'a [u8]> {
    if input.len() < n {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated TUIC message"));
    }
    let (head, tail) = input.split_at(n);
    *input = tail;
    Ok(head)
}
fn read_u16(input: &mut &[u8]) -> io::Result<u16> {
    Ok(u16::from_be_bytes(take(input, 2)?.try_into().unwrap()))
}

/// Encode TUIC's address family byte, address bytes and (unless empty) BE port.
pub fn encode_address(address: &TuicAddress, out: &mut Vec<u8>) -> io::Result<()> {
    match address {
        TuicAddress::Empty => out.push(FAMILY_EMPTY),
        TuicAddress::Socket(addr) => match &addr.host {
            Host::Ip(IpAddr::V4(ip)) => {
                out.push(FAMILY_IPV4);
                out.extend_from_slice(&ip.octets());
                out.extend_from_slice(&addr.port.to_be_bytes());
            }
            Host::Ip(IpAddr::V6(ip)) => {
                out.push(FAMILY_IPV6);
                out.extend_from_slice(&ip.octets());
                out.extend_from_slice(&addr.port.to_be_bytes());
            }
            Host::Domain(name) => {
                let bytes = name.as_bytes();
                if bytes.len() > 255 {
                    return Err(invalid("TUIC FQDN exceeds 255 bytes"));
                }
                out.push(FAMILY_FQDN);
                out.push(bytes.len() as u8);
                out.extend_from_slice(bytes);
                out.extend_from_slice(&addr.port.to_be_bytes());
            }
        },
    }
    Ok(())
}
/// Decode exactly one address. Unknown families and incomplete fields are errors.
pub fn decode_address(input: &mut &[u8]) -> io::Result<TuicAddress> {
    let family = take(input, 1)?[0];
    let address = match family {
        FAMILY_EMPTY => return Ok(TuicAddress::Empty),
        FAMILY_FQDN => {
            let len = take(input, 1)?[0] as usize;
            let bytes = take(input, len)?;
            let name = std::str::from_utf8(bytes).map_err(|_| invalid("TUIC FQDN is not UTF-8"))?.to_owned();
            Host::Domain(name)
        }
        FAMILY_IPV4 => Host::Ip(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(take(input, 4)?).unwrap()))),
        FAMILY_IPV6 => Host::Ip(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(take(input, 16)?).unwrap()))),
        other => return Err(invalid(format!("unknown TUIC address family 0x{other:02x}"))),
    };
    let port = read_u16(input)?;
    Ok(TuicAddress::Socket(Socksaddr::new(address, port)))
}

/// `[version=5, authenticate=0, uuid[16], token[32]]`.
pub fn encode_auth(uuid: &[u8; 16], token: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(AUTH_LEN);
    out.extend_from_slice(&[VERSION, COMMAND_AUTHENTICATE]);
    out.extend_from_slice(uuid);
    out.extend_from_slice(token);
    out
}
pub fn decode_auth(input: &[u8]) -> io::Result<([u8; 16], [u8; 32])> {
    if input.len() != AUTH_LEN {
        return Err(invalid("TUIC auth message must be exactly 50 bytes"));
    }
    if input[0] != VERSION {
        return Err(invalid("invalid TUIC version"));
    }
    if input[1] != COMMAND_AUTHENTICATE {
        return Err(invalid("invalid TUIC auth command"));
    }
    Ok((input[2..18].try_into().unwrap(), input[18..50].try_into().unwrap()))
}
/// CONNECT is a stream prefix followed directly by the serialized address.
pub fn encode_connect(destination: &Socksaddr) -> io::Result<Vec<u8>> {
    let mut out = vec![VERSION, COMMAND_CONNECT];
    encode_address(&TuicAddress::Socket(destination.clone()), &mut out)?;
    Ok(out)
}
pub fn decode_connect(input: &[u8]) -> io::Result<Socksaddr> {
    let mut rest = input;
    check_header(&mut rest, COMMAND_CONNECT)?;
    let addr = decode_address(&mut rest)?;
    if !rest.is_empty() {
        return Err(invalid("trailing bytes in TUIC CONNECT prefix"));
    }
    match addr {
        TuicAddress::Socket(a) => Ok(a),
        TuicAddress::Empty => Err(invalid("empty TUIC CONNECT destination")),
    }
}
fn check_header(input: &mut &[u8], command: u8) -> io::Result<()> {
    let header = take(input, 2)?;
    if header[0] != VERSION {
        return Err(invalid(format!("invalid TUIC version {}", header[0])));
    }
    if header[1] != command {
        return Err(invalid(format!("invalid TUIC command {}", header[1])));
    }
    Ok(())
}
/// Native TUIC packet: v, command, session, packet, fragment total/id, data length, address, payload.
pub fn encode_udp(packet: &UdpPacket) -> io::Result<Vec<u8>> {
    if packet.data.len() > u16::MAX as usize {
        return Err(invalid("TUIC UDP data exceeds u16 length"));
    }
    let mut out = Vec::with_capacity(10 + packet.data.len() + 20);
    out.extend_from_slice(&[VERSION, COMMAND_PACKET]);
    out.extend_from_slice(&packet.session_id.to_be_bytes());
    out.extend_from_slice(&packet.packet_id.to_be_bytes());
    out.push(packet.fragment_total);
    out.push(packet.fragment_id);
    out.extend_from_slice(&(packet.data.len() as u16).to_be_bytes());
    encode_address(&packet.destination, &mut out)?;
    out.extend_from_slice(&packet.data);
    Ok(out)
}
pub fn decode_udp(input: &[u8]) -> io::Result<UdpPacket> {
    let mut rest = input;
    check_header(&mut rest, COMMAND_PACKET)?;
    let session_id = read_u16(&mut rest)?;
    let packet_id = read_u16(&mut rest)?;
    let fragment_total = take(&mut rest, 1)?[0];
    let fragment_id = take(&mut rest, 1)?[0];
    let data_len = read_u16(&mut rest)? as usize;
    let destination = decode_address(&mut rest)?;
    if rest.len() != data_len {
        return Err(invalid("TUIC UDP payload length does not match data length"));
    }
    Ok(UdpPacket { session_id, packet_id, fragment_total, fragment_id, destination, data: rest.to_vec() })
}
/// DISSOCIATE stream frame `[5,3,session_id_be]`.
pub fn encode_dissociate(session_id: u16) -> [u8; 4] {
    [VERSION, COMMAND_DISSOCIATE, (session_id >> 8) as u8, session_id as u8]
}
pub fn decode_dissociate(input: &[u8]) -> io::Result<u16> {
    let mut rest = input;
    check_header(&mut rest, COMMAND_DISSOCIATE)?;
    if rest.len() != 2 {
        return Err(invalid("TUIC DISSOCIATE must contain exactly a session id"));
    }
    read_u16(&mut rest)
}
/// Heartbeat's entire QUIC datagram is `[5,4]`.
pub const fn encode_heartbeat() -> [u8; 2] {
    [VERSION, COMMAND_HEARTBEAT]
}
pub fn decode_heartbeat(input: &[u8]) -> io::Result<()> {
    if input != [VERSION, COMMAND_HEARTBEAT] {
        return Err(invalid("invalid TUIC heartbeat"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn addr(host: &str, port: u16) -> Socksaddr {
        Socksaddr::from_host_port(host, port)
    }
    #[test]
    fn address_roundtrips_all_families() {
        for a in [
            TuicAddress::Socket(addr("example.org", 443)),
            TuicAddress::Socket(addr("192.0.2.7", 53)),
            TuicAddress::Socket(addr("2001:db8::1", 5353)),
            TuicAddress::Empty,
        ] {
            let mut bytes = Vec::new();
            encode_address(&a, &mut bytes).unwrap();
            assert_eq!(decode_address(&mut bytes.as_slice()).unwrap(), a);
        }
    }
    #[test]
    fn auth_connect_and_udp_roundtrip() {
        let uuid = [0x11; 16];
        let token = [0x22; 32];
        assert_eq!(decode_auth(&encode_auth(&uuid, &token)).unwrap(), (uuid, token));
        let destination = addr("2001:db8::2", 8443);
        assert_eq!(decode_connect(&encode_connect(&destination).unwrap()).unwrap(), destination);
        let packet = UdpPacket {
            session_id: 0x1234,
            packet_id: 0xabcd,
            fragment_total: 3,
            fragment_id: 2,
            destination: TuicAddress::Socket(addr("example.org", 53)),
            data: vec![1, 2, 3],
        };
        assert_eq!(decode_udp(&encode_udp(&packet).unwrap()).unwrap(), packet);
    }
    #[test]
    fn rejects_bad_version_lengths_and_families() {
        assert!(decode_auth(&[5, 0]).is_err());
        assert!(decode_auth(&[4; AUTH_LEN]).is_err());
        assert!(decode_address(&mut &[0x7f][..]).is_err());
        assert!(decode_address(&mut &[1, 2][..]).is_err());
        assert!(decode_udp(&[4, COMMAND_PACKET]).is_err());
        let mut bad = encode_udp(&UdpPacket {
            session_id: 1,
            packet_id: 2,
            fragment_total: 4,
            fragment_id: 3,
            destination: TuicAddress::Empty,
            data: vec![9],
        })
        .unwrap();
        bad[9] = 8;
        assert!(decode_udp(&bad).is_err());
        assert!(decode_connect(&[5, COMMAND_CONNECT, FAMILY_EMPTY]).is_err());
    }
    #[test]
    fn udp_fragment_header_is_big_endian_and_preserved() {
        let packet = UdpPacket {
            session_id: 0x1234,
            packet_id: 0xabcd,
            fragment_total: 7,
            fragment_id: 6,
            destination: TuicAddress::Empty,
            data: vec![],
        };
        let bytes = encode_udp(&packet).unwrap();
        assert_eq!(&bytes[2..8], &[0x12, 0x34, 0xab, 0xcd, 7, 6]);
        assert_eq!(decode_udp(&bytes).unwrap(), packet);
    }
}
