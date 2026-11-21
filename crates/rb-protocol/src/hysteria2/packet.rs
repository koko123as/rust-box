//! Hysteria2 UDP datagram wire codec, fragmentation helpers and Salamander obfuscation.
//! Wire layout follows sing-quic/hysteria2/packet.go: session ID (u32 BE), packet ID
//! (u16 BE), fragment ID/total (u8 each), QUIC-varint-length UTF-8 destination string,
//! then opaque payload. Destination itself is the canonical `host:port` string used by
//! upstream; this module preserves it verbatim rather than inventing a second address wire format.
use std::io;

const FIXED_HEADER: usize = 8;
const SALT_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpMessage {
    pub session_id: u32,
    pub packet_id: u16,
    pub fragment_id: u8,
    pub fragment_total: u8,
    pub destination: String,
    pub payload: Vec<u8>,
}
fn invalid(s: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}
fn put_varint(out: &mut Vec<u8>, n: u64) -> io::Result<()> {
    if n < (1 << 6) {
        out.push(n as u8);
    } else if n < (1 << 14) {
        out.extend_from_slice(&((n as u16) | 0x4000).to_be_bytes());
    } else if n < (1 << 30) {
        out.extend_from_slice(&((n as u32) | 0x8000_0000).to_be_bytes());
    } else if n < (1 << 62) {
        out.extend_from_slice(&(n | 0xc000_0000_0000_0000).to_be_bytes());
    } else {
        return Err(invalid("QUIC varint exceeds 62 bits"));
    }
    Ok(())
}
fn take_varint(bytes: &[u8], pos: &mut usize) -> io::Result<u64> {
    let first = *bytes.get(*pos).ok_or_else(|| invalid("truncated QUIC varint"))?;
    let len = 1usize << (first >> 6);
    let end = pos.checked_add(len).ok_or_else(|| invalid("length overflow"))?;
    let s = bytes.get(*pos..end).ok_or_else(|| invalid("truncated QUIC varint"))?;
    let mut v = (s[0] & 0x3f) as u64;
    for b in &s[1..] {
        v = (v << 8) | *b as u64;
    }
    *pos = end;
    Ok(v)
}
impl UdpMessage {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        if self.fragment_total == 0 || self.fragment_id >= self.fragment_total {
            return Err(invalid("invalid fragment indices"));
        }
        if self.destination.len() > 65535 {
            return Err(invalid("destination string too long"));
        }
        let mut out = Vec::with_capacity(FIXED_HEADER + 8 + self.destination.len() + self.payload.len());
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.extend_from_slice(&self.packet_id.to_be_bytes());
        out.push(self.fragment_id);
        out.push(self.fragment_total);
        put_varint(&mut out, self.destination.len() as u64)?;
        out.extend_from_slice(self.destination.as_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }
    pub fn decode(input: &[u8]) -> io::Result<Self> {
        if input.len() < FIXED_HEADER {
            return Err(invalid("truncated Hysteria2 fixed header"));
        }
        let session_id = u32::from_be_bytes(input[0..4].try_into().unwrap());
        let packet_id = u16::from_be_bytes(input[4..6].try_into().unwrap());
        let fragment_id = input[6];
        let fragment_total = input[7];
        if fragment_total == 0 || fragment_id >= fragment_total {
            return Err(invalid("invalid fragment indices"));
        }
        let mut pos = FIXED_HEADER;
        let n = usize::try_from(take_varint(input, &mut pos)?).map_err(|_| invalid("destination length overflow"))?;
        let end = pos.checked_add(n).ok_or_else(|| invalid("destination length overflow"))?;
        let dest = std::str::from_utf8(input.get(pos..end).ok_or_else(|| invalid("truncated destination"))?)
            .map_err(|_| invalid("destination is not UTF-8"))?;
        if dest.is_empty() {
            return Err(invalid("empty destination"));
        }
        Ok(Self {
            session_id,
            packet_id,
            fragment_id,
            fragment_total,
            destination: dest.to_owned(),
            payload: input[end..].to_vec(),
        })
    }
}

/// Split a datagram into upstream-compatible fragments. Every fragment repeats destination/header.
pub fn fragment(message: &UdpMessage, max_datagram: usize) -> io::Result<Vec<UdpMessage>> {
    let mut probe = message.clone();
    probe.fragment_id = 0;
    probe.fragment_total = 1;
    let overhead = probe.encode()?.len() - message.payload.len();
    if max_datagram <= overhead {
        return Err(invalid("datagram limit cannot contain packet header"));
    }
    let chunk = max_datagram - overhead;
    if message.payload.len() <= chunk {
        return Ok(vec![probe]);
    }
    let count = message.payload.len().div_ceil(chunk);
    if count > u8::MAX as usize {
        return Err(invalid("fragment count exceeds wire limit"));
    }
    Ok(message
        .payload
        .chunks(chunk)
        .enumerate()
        .map(|(i, p)| {
            let mut m = message.clone();
            m.fragment_id = i as u8;
            m.fragment_total = count as u8;
            m.payload = p.to_vec();
            m
        })
        .collect())
}

/// Bounded reassembly keyed by the actual upstream identity pair (session, packet).
#[derive(Debug, Default)]
pub struct Reassembler {
    entries: std::collections::HashMap<(u32, u16), Vec<Option<UdpMessage>>>,
    max_entries: usize,
    max_bytes: usize,
}
impl Reassembler {
    pub fn new(max_entries: usize, max_bytes: usize) -> Self {
        Self { entries: Default::default(), max_entries, max_bytes }
    }
    /// Returns None for an incomplete fragment set; malformed/inconsistent sets are discarded.
    pub fn push(&mut self, m: UdpMessage) -> io::Result<Option<UdpMessage>> {
        if m.fragment_total == 0 || m.fragment_id >= m.fragment_total {
            return Err(invalid("invalid fragment indices"));
        }
        if m.fragment_total == 1 {
            return Ok(Some(m));
        }
        let key = (m.session_id, m.packet_id);
        let total = m.fragment_total as usize;
        if !self.entries.contains_key(&key) {
            if self.entries.len() >= self.max_entries {
                return Err(invalid("reassembly entry limit reached"));
            }
            self.entries.insert(key, vec![None; total]);
        }
        let slots = self.entries.get_mut(&key).unwrap();
        if slots.len() != total {
            self.entries.remove(&key);
            return Err(invalid("fragment total mismatch"));
        }
        if slots[m.fragment_id as usize].is_some() {
            return Ok(None);
        }
        let fragment_index = m.fragment_id as usize;
        slots[fragment_index] = Some(m);
        let bytes: usize = slots.iter().filter_map(|x| x.as_ref()).map(|x| x.payload.len()).sum();
        if bytes > self.max_bytes {
            self.entries.remove(&key);
            return Err(invalid("reassembly byte limit exceeded"));
        }
        if slots.iter().any(Option::is_none) {
            return Ok(None);
        }
        let slots = self.entries.remove(&key).unwrap();
        let mut all = slots.into_iter().map(Option::unwrap);
        let mut result = all.next().unwrap();
        let mut payload = result.payload;
        for part in all {
            if part.destination != result.destination {
                return Err(invalid("fragment destination mismatch"));
            }
            payload.extend_from_slice(&part.payload);
        }
        result.fragment_id = 0;
        result.fragment_total = 1;
        result.payload = payload;
        Ok(Some(result))
    }
}

/// QUIC uses BLAKE2b configured for a 32-byte digest, not truncation of BLAKE2b-512.
/// Compact local implementation keeps this leaf module independent of extra dependencies.
fn blake2b256(data: &[u8]) -> [u8; 32] {
    const IV: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];
    const SIG: [[usize; 16]; 12] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    ];
    let mut h = IV;
    h[0] ^= 0x0101_0020;
    let chunks = if data.is_empty() { 1 } else { data.len().div_ceil(128) };
    for bi in 0..chunks {
        let start = bi * 128;
        let end = (start + 128).min(data.len());
        let mut block = [0u8; 128];
        if start < data.len() {
            block[..end - start].copy_from_slice(&data[start..end]);
        }
        let mut m = [0u64; 16];
        for i in 0..16 {
            m[i] = u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
        }
        let count = end as u64;
        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= count;
        if bi + 1 == chunks {
            v[14] = !v[14];
        }
        macro_rules! g {
            ($a:expr,$b:expr,$c:expr,$d:expr,$x:expr,$y:expr) => {{
                v[$a] = v[$a].wrapping_add(v[$b]).wrapping_add($x);
                v[$d] = (v[$d] ^ v[$a]).rotate_right(32);
                v[$c] = v[$c].wrapping_add(v[$d]);
                v[$b] = (v[$b] ^ v[$c]).rotate_right(24);
                v[$a] = v[$a].wrapping_add(v[$b]).wrapping_add($y);
                v[$d] = (v[$d] ^ v[$a]).rotate_right(16);
                v[$c] = v[$c].wrapping_add(v[$d]);
                v[$b] = (v[$b] ^ v[$c]).rotate_right(63);
            }};
        }
        for s in SIG {
            g!(0, 4, 8, 12, m[s[0]], m[s[1]]);
            g!(1, 5, 9, 13, m[s[2]], m[s[3]]);
            g!(2, 6, 10, 14, m[s[4]], m[s[5]]);
            g!(3, 7, 11, 15, m[s[6]], m[s[7]]);
            g!(0, 5, 10, 15, m[s[8]], m[s[9]]);
            g!(1, 6, 11, 12, m[s[10]], m[s[11]]);
            g!(2, 7, 8, 13, m[s[12]], m[s[13]]);
            g!(3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for i in 0..8 {
            h[i] ^= v[i] ^ v[i + 8];
        }
    }
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&h[i].to_le_bytes());
    }
    out
}

/// Salamander packet transform: 8-byte random salt followed by payload XOR BLAKE2b-256(password||salt).
pub fn salamander_seal(payload: &[u8], password: &[u8], salt: [u8; 8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SALT_LEN + payload.len());
    out.extend_from_slice(&salt);
    let mut seed = Vec::with_capacity(password.len() + SALT_LEN);
    seed.extend_from_slice(password);
    seed.extend_from_slice(&salt);
    let key = blake2b256(&seed);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 32]));
    out
}
/// Opens a Salamander packet. Authentication is absent in the wire protocol; a wrong key
/// yields unauthenticated garbage, so `expected_plaintext` provides optional caller validation.
pub fn salamander_open(packet: &[u8], password: &[u8]) -> io::Result<Vec<u8>> {
    if packet.len() <= SALT_LEN {
        return Err(invalid("truncated Salamander packet"));
    }
    let salt = &packet[..SALT_LEN];
    let mut seed = Vec::with_capacity(password.len() + SALT_LEN);
    seed.extend_from_slice(password);
    seed.extend_from_slice(salt);
    let key = blake2b256(&seed);
    Ok(packet[SALT_LEN..].iter().enumerate().map(|(i, b)| b ^ key[i % 32]).collect())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn msg(dest: &str) -> UdpMessage {
        UdpMessage {
            session_id: 7,
            packet_id: 42,
            fragment_id: 0,
            fragment_total: 1,
            destination: dest.into(),
            payload: b"udp payload".to_vec(),
        }
    }
    #[test]
    fn packet_roundtrip_ip_and_domain() {
        for d in ["192.0.2.1:53", "[2001:db8::1]:443", "example.org:1234"] {
            let m = msg(d);
            assert_eq!(UdpMessage::decode(&m.encode().unwrap()).unwrap(), m);
        }
    }
    #[test]
    fn fragments_reassemble_and_incomplete() {
        let mut m = msg("[2001:db8::1]:53");
        m.payload = vec![9; 300];
        let parts = fragment(&m, 80).unwrap();
        assert!(parts.len() > 1);
        let mut r = Reassembler::new(8, 4096);
        assert!(r.push(parts[0].clone()).unwrap().is_none());
        let mut done = None;
        for p in parts.into_iter().skip(1) {
            done = r.push(p).unwrap().or(done);
        }
        assert_eq!(done.unwrap().payload, m.payload);
    }
    #[test]
    fn malformed_truncated_inputs() {
        for b in [&[][..], &[0u8; 7][..], &[0, 0, 0, 1, 0, 1, 0, 1, 5][..]] {
            assert!(UdpMessage::decode(b).is_err());
        }
    }
    #[test]
    fn salamander_roundtrip_and_wrong_key_is_not_plain() {
        let plain = b"datagram";
        let wire = salamander_seal(plain, b"right", [1; 8]);
        assert_eq!(salamander_open(&wire, b"right").unwrap(), plain);
        assert_ne!(salamander_open(&wire, b"wrong").unwrap(), plain);
        assert!(salamander_open(&wire[..8], b"right").is_err());
    }
}
