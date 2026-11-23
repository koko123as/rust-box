//! Pure-Rust port of the packet-shape heuristic in the pinned fork's magicsock.
//!
//! This classifies packet bytes as WireGuard, STUN binding, or Disco and reports
//! whether the Disco/WireGuard classification came through a fixed Geneve header.
//! A WireGuard result is only the pinned fork's fallback guess; it does not
//! validate WireGuard contents or implement socket, peer, or endpoint runtime.

use crate::{disco, geneve};

const STUN_HEADER_LEN: usize = 20;
const STUN_MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

/// The packet type guessed by magicsock's `packetLooksLike` classifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketKind {
    /// The default classification, including unknown/non-disco datagrams.
    WireGuard,
    /// A STUN message whose method byte is Binding.
    StunBinding,
    /// A packet with the Tailscale Disco magic and minimum 38-byte header.
    Disco,
}

/// Returns the pinned magicsock packet classification and Geneve flag.
///
/// The boolean is true only for recognized Geneve Disco or WireGuard protocol
/// values. It is always false for STUN and naked packets. Unknown traffic falls
/// back to `WireGuard`, as in the Go source; callers must still validate or
/// reject it in the next protocol layer.
pub fn packet_looks_like(packet: &[u8]) -> (PacketKind, bool) {
    if is_stun(packet) && packet[1] == 0x01 {
        return (PacketKind::StunBinding, false);
    }

    let looks_like_disco = |input: &[u8]| input.len() >= disco::DISCO_HEADER_LEN && input.starts_with(&disco::MAGIC);

    if packet.len() >= geneve::FIXED_HEADER_LENGTH && packet[0] & 0xc0 == 0 && packet[1] & 0x3f == 0 && packet[7] == 0 {
        match u16::from_be_bytes([packet[2], packet[3]]) {
            geneve::PROTOCOL_DISCO => {
                if looks_like_disco(&packet[geneve::FIXED_HEADER_LENGTH..]) {
                    return (PacketKind::Disco, true);
                }
                return (PacketKind::WireGuard, false);
            }
            geneve::PROTOCOL_WIREGUARD => return (PacketKind::WireGuard, true),
            _ => {}
        }
    }

    if looks_like_disco(packet) {
        (PacketKind::Disco, false)
    } else {
        (PacketKind::WireGuard, false)
    }
}

fn is_stun(packet: &[u8]) -> bool {
    packet.len() >= STUN_HEADER_LEN && packet[0] & 0xc0 == 0 && packet[4..8] == STUN_MAGIC_COOKIE
}

#[cfg(test)]
mod tests {
    use super::{packet_looks_like, PacketKind};
    use crate::{disco, geneve};

    fn disco_packet(length: usize) -> Vec<u8> {
        let mut packet = vec![0; length];
        let copied = length.min(disco::MAGIC.len());
        packet[..copied].copy_from_slice(&disco::MAGIC[..copied]);
        packet
    }

    fn geneve_packet(protocol: u16, payload: &[u8]) -> Vec<u8> {
        let mut vni = geneve::VirtualNetworkId::default();
        vni.set(0x123456);
        let header = geneve::GeneveHeader { version: 0, protocol, vni, control: false };
        let mut packet = vec![0; geneve::FIXED_HEADER_LENGTH + payload.len()];
        header.encode(&mut packet).unwrap();
        packet[geneve::FIXED_HEADER_LENGTH..].copy_from_slice(payload);
        packet
    }

    #[test]
    fn packet_looks_like_matches_pinned_source_derived_go_vectors() {
        let mut stun_binding = vec![0; 20];
        stun_binding[1] = 0x01;
        stun_binding[2..4].copy_from_slice(&0xffff_u16.to_be_bytes());
        stun_binding[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        let mut stun_cookie_nonbinding = stun_binding.clone();
        stun_cookie_nonbinding[1] = 0;
        let stun_short = stun_binding[..19].to_vec();
        let mut stun_bad_top_bits = stun_binding.clone();
        stun_bad_top_bits[0] = 0x40;
        let mut stun_bad_cookie = stun_binding.clone();
        stun_bad_cookie[7] ^= 1;

        let inner_disco = disco_packet(disco::DISCO_HEADER_LEN);
        let short_inner_disco = disco_packet(disco::DISCO_HEADER_LEN - 1);
        let zero_inner = vec![0; inner_disco.len()];
        let geneve_disco = geneve_packet(geneve::PROTOCOL_DISCO, &inner_disco);
        let geneve_disco_short_inner = geneve_packet(geneve::PROTOCOL_DISCO, &short_inner_disco);
        let geneve_disco_bad_inner = geneve_packet(geneve::PROTOCOL_DISCO, &zero_inner);
        let geneve_wireguard = geneve_packet(geneve::PROTOCOL_WIREGUARD, &[]);
        let geneve_unknown_protocol = geneve_packet(0x1234, &inner_disco);
        let mut geneve_options_ignored = geneve_disco.clone();
        let mut geneve_c_bit_ignored = geneve_disco.clone();
        let mut geneve_o_bit = geneve_disco.clone();
        let mut geneve_reserved_byte = geneve_disco.clone();
        let mut geneve_reserved_bits = geneve_disco.clone();
        let mut geneve_bad_version = geneve_disco.clone();
        geneve_options_ignored[0] |= 1;
        geneve_c_bit_ignored[1] |= 0x40;
        geneve_o_bit[1] |= 0x80;
        geneve_reserved_byte[7] = 1;
        geneve_reserved_bits[1] |= 1;
        geneve_bad_version[0] |= 0x40;

        let cases = [
            ("empty", Vec::new(), (PacketKind::WireGuard, false)),
            ("short_disco", disco_packet(disco::DISCO_HEADER_LEN - 1), (PacketKind::WireGuard, false)),
            ("naked_disco", inner_disco, (PacketKind::Disco, false)),
            ("stun_binding_bad_length_field", stun_binding, (PacketKind::StunBinding, false)),
            ("stun_cookie_nonbinding", stun_cookie_nonbinding, (PacketKind::WireGuard, false)),
            ("stun_short", stun_short, (PacketKind::WireGuard, false)),
            ("stun_bad_top_bits", stun_bad_top_bits, (PacketKind::WireGuard, false)),
            ("stun_bad_cookie", stun_bad_cookie, (PacketKind::WireGuard, false)),
            ("geneve_disco", geneve_disco, (PacketKind::Disco, true)),
            ("geneve_disco_short_inner", geneve_disco_short_inner, (PacketKind::WireGuard, false)),
            ("geneve_disco_bad_inner", geneve_disco_bad_inner, (PacketKind::WireGuard, false)),
            ("geneve_wireguard", geneve_wireguard, (PacketKind::WireGuard, true)),
            ("geneve_unknown_protocol", geneve_unknown_protocol, (PacketKind::WireGuard, false)),
            ("geneve_options_ignored", geneve_options_ignored, (PacketKind::Disco, true)),
            ("geneve_c_bit_ignored", geneve_c_bit_ignored, (PacketKind::Disco, true)),
            ("geneve_o_bit_set", geneve_o_bit, (PacketKind::Disco, true)),
            ("geneve_reserved_byte_rejected", geneve_reserved_byte, (PacketKind::WireGuard, false)),
            ("geneve_reserved_bits_rejected", geneve_reserved_bits, (PacketKind::WireGuard, false)),
            ("geneve_bad_version_falls_through", geneve_bad_version, (PacketKind::WireGuard, false)),
        ];

        for (name, packet, expected) in cases {
            assert_eq!(packet_looks_like(&packet), expected, "{name}");
        }
    }

    #[test]
    fn stun_requires_minimum_header_top_bits_and_magic_cookie() {
        let mut short = vec![0; 19];
        short[1] = 1;
        short[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        assert_eq!(packet_looks_like(&short), (PacketKind::WireGuard, false));

        let mut bad_top_bits = vec![0; 20];
        bad_top_bits[0] = 0x40;
        bad_top_bits[1] = 1;
        bad_top_bits[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        assert_eq!(packet_looks_like(&bad_top_bits), (PacketKind::WireGuard, false));

        let mut bad_cookie = vec![0; 20];
        bad_cookie[1] = 1;
        bad_cookie[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x43]);
        assert_eq!(packet_looks_like(&bad_cookie), (PacketKind::WireGuard, false));
    }
}
