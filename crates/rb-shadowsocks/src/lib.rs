//! The shadowsocks wire format as sing-box v1.14.4 speaks it: the client
//! of sing-shadowsocks2 (what the `shadowsocks` outbound uses) and the
//! services of sing-shadowsocks (what the inbound uses).
//!
//! - `none`: the SOCKS address in front of the payload.
//! - AEAD (`aes-*-gcm`, `(x)chacha20-ietf-poly1305`): SIP004 chunks with an
//!   HKDF-SHA1 session key from an `EVP_BytesToKey` password key.
//! - 2022 (`2022-blake3-*`, SIP022): BLAKE3 session keys, timestamped
//!   headers, replay protection, padding, extended identity headers for
//!   multiple users and relays, separate UDP sessions with sliding windows.
//! - Legacy stream ciphers (`aes-*-ctr`, `aes-*-cfb`, `rc4-md5`,
//!   `chacha20-ietf`, `xchacha20`): client only, as in sing-box.
//!
//! [`tcp`] has the encrypted stream for both sides, [`udp`] the packet
//! codecs, [`server`] the server handshakes and user lookup.

pub mod cipher;
pub mod replay;
pub mod server;
pub mod tcp;
pub mod udp;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rb_adapter::{Host, Socksaddr};
use tokio::io::{AsyncRead, AsyncReadExt};

pub use cipher::{AeadKind, StreamKind};

/// The methods of sing-box's inbound (`option.ShadowsocksInboundOptions`).
pub const NONE: &str = "none";
pub const AEAD_METHODS: &[&str] =
    &["aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"];
pub const SS2022_METHODS: &[&str] =
    &["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"];
/// The legacy methods only the outbound has.
pub const STREAM_METHODS: &[&str] = &[
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "rc4-md5",
    "chacha20-ietf",
    "xchacha20",
];

/// 2022 header types.
pub const HEADER_TYPE_CLIENT: u8 = 0;
pub const HEADER_TYPE_SERVER: u8 = 1;
/// Largest 2022 padding.
pub const MAX_PADDING_LENGTH: usize = 900;
/// How far a 2022 timestamp may be from the local clock, in seconds.
pub const MAX_TIME_DIFF: i64 = 30;
/// Largest AEAD chunk payload (SIP004, `shadowaead.MaxPacketSize`).
pub const AEAD_MAX_CHUNK: usize = 16 * 1024 - 1;
/// Largest 2022 chunk payload (`shadowaead_2022.MaxPacketSize`).
pub const SS2022_MAX_CHUNK: usize = 65535;
/// The 2022 client's chunk size (sing-shadowsocks2: `buf.BufferSize - 2 - 2 * 16`).
pub const SS2022_CLIENT_CHUNK: usize = 32 * 1024 - 2 - 2 * cipher::TAG_SIZE;

/// What a method is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodKind {
    None,
    Aead(AeadKind),
    /// The AEAD of the 2022 method (`Aes128Gcm`, `Aes256Gcm` or `ChaCha20Poly1305`).
    Ss2022(AeadKind),
    Stream(StreamKind),
}

impl MethodKind {
    /// Any method sing-box knows.
    pub fn parse(name: &str) -> Option<MethodKind> {
        Some(match name {
            "none" => MethodKind::None,
            "aes-128-gcm" => MethodKind::Aead(AeadKind::Aes128Gcm),
            "aes-192-gcm" => MethodKind::Aead(AeadKind::Aes192Gcm),
            "aes-256-gcm" => MethodKind::Aead(AeadKind::Aes256Gcm),
            "chacha20-ietf-poly1305" => MethodKind::Aead(AeadKind::ChaCha20Poly1305),
            "xchacha20-ietf-poly1305" => MethodKind::Aead(AeadKind::XChaCha20Poly1305),
            "2022-blake3-aes-128-gcm" => MethodKind::Ss2022(AeadKind::Aes128Gcm),
            "2022-blake3-aes-256-gcm" => MethodKind::Ss2022(AeadKind::Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => MethodKind::Ss2022(AeadKind::ChaCha20Poly1305),
            "aes-128-ctr" => MethodKind::Stream(StreamKind::Aes128Ctr),
            "aes-192-ctr" => MethodKind::Stream(StreamKind::Aes192Ctr),
            "aes-256-ctr" => MethodKind::Stream(StreamKind::Aes256Ctr),
            "aes-128-cfb" => MethodKind::Stream(StreamKind::Aes128Cfb),
            "aes-192-cfb" => MethodKind::Stream(StreamKind::Aes192Cfb),
            "aes-256-cfb" => MethodKind::Stream(StreamKind::Aes256Cfb),
            "rc4-md5" => MethodKind::Stream(StreamKind::Rc4Md5),
            "chacha20-ietf" => MethodKind::Stream(StreamKind::ChaCha20Ietf),
            "xchacha20" => MethodKind::Stream(StreamKind::XChaCha20),
            _ => return None,
        })
    }

    /// The salt (and key) size of an AEAD or 2022 method.
    pub fn salt_size(self) -> usize {
        match self {
            MethodKind::None => 0,
            MethodKind::Aead(kind) | MethodKind::Ss2022(kind) => kind.key_size(),
            MethodKind::Stream(kind) => kind.salt_size(),
        }
    }
}

pub(crate) fn error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// Go `crypto/cipher`'s AEAD failure.
pub(crate) fn authentication_failed() -> io::Error {
    error("cipher: message authentication failed")
}

/// sing-shadowsocks `shadowaead_2022.ErrBadTimestamp` with its detail.
pub(crate) fn check_timestamp(epoch: u64, now: i64) -> io::Result<()> {
    let diff = (now - epoch as i64).unsigned_abs();
    if diff > MAX_TIME_DIFF as u64 {
        return Err(error(format!("bad timestamp: received {epoch}, diff {diff}s")));
    }
    Ok(())
}

/// The clock the 2022 timestamps use (sing-box's `ntp` service is not
/// implemented, so the system clock, as sing-box without it).
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// Go `base64.StdEncoding.DecodeString`: padding required, line breaks
/// skipped, non-zero trailing bits accepted, and Go's error text
/// ("illegal base64 data at input byte N").
pub fn decode_base64(text: &str) -> Result<Vec<u8>, String> {
    fn value(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let corrupt = |offset: usize| format!("illegal base64 data at input byte {offset}");
    let source = text.as_bytes();
    let newline = |byte: u8| byte == b'\n' || byte == b'\r';
    let mut out = Vec::with_capacity(source.len() / 4 * 3);
    let mut index = 0;
    loop {
        let mut quantum = [0u8; 4];
        let mut length = 4;
        let mut j = 0;
        while j < 4 {
            if index == source.len() {
                if j == 0 {
                    return Ok(out);
                }
                // Go: padding is required (`si - j`).
                return Err(corrupt(index - j));
            }
            let byte = source[index];
            index += 1;
            if let Some(value) = value(byte) {
                quantum[j] = value;
                j += 1;
                continue;
            }
            if newline(byte) {
                continue;
            }
            if byte != b'=' {
                return Err(corrupt(index - 1));
            }
            // Padding: the end of the data.
            match j {
                0 | 1 => return Err(corrupt(index - 1)),
                2 => {
                    while index < source.len() && newline(source[index]) {
                        index += 1;
                    }
                    if index == source.len() {
                        return Err(corrupt(source.len()));
                    }
                    if source[index] != b'=' {
                        return Err(corrupt(index - 1));
                    }
                    index += 1;
                }
                _ => {}
            }
            while index < source.len() && newline(source[index]) {
                index += 1;
            }
            if index < source.len() {
                return Err(corrupt(index));
            }
            length = j;
            break;
        }
        let bits = (quantum[0] as u32) << 18 | (quantum[1] as u32) << 12 | (quantum[2] as u32) << 6 | quantum[3] as u32;
        let bytes = [(bits >> 16) as u8, (bits >> 8) as u8, bits as u8];
        out.extend_from_slice(&bytes[..length - 1]);
        if length < 4 {
            return Ok(out);
        }
    }
}

const ADDRESS_IPV4: u8 = 1;
const ADDRESS_DOMAIN: u8 = 3;
const ADDRESS_IPV6: u8 = 4;

/// A SOCKS address's encoded length (`M.SocksaddrSerializer.AddrPortLen`).
pub fn address_len(address: &Socksaddr) -> usize {
    match &address.host {
        Host::Ip(IpAddr::V4(_)) => 1 + 4 + 2,
        Host::Ip(IpAddr::V6(_)) => 1 + 16 + 2,
        Host::Domain(domain) => 1 + 1 + domain.len() + 2,
    }
}

/// Writes a SOCKS address (`M.SocksaddrSerializer.WriteAddrPort`).
pub fn write_address(buffer: &mut Vec<u8>, address: &Socksaddr) -> io::Result<()> {
    write_address_with(buffer, address, [ADDRESS_IPV4, ADDRESS_IPV6, ADDRESS_DOMAIN])
}

/// Writes an address with the given family bytes (IPv4, IPv6, domain), as
/// sing's `M.NewSerializer` with other family bytes (UDP over TCP uses 0, 1, 2).
pub fn write_address_with(buffer: &mut Vec<u8>, address: &Socksaddr, families: [u8; 3]) -> io::Result<()> {
    match &address.host {
        Host::Ip(IpAddr::V4(ip)) => {
            buffer.push(families[0]);
            buffer.extend_from_slice(&ip.octets());
        }
        Host::Ip(IpAddr::V6(ip)) => {
            buffer.push(families[1]);
            buffer.extend_from_slice(&ip.octets());
        }
        Host::Domain(domain) => {
            if domain.len() > 255 {
                return Err(error(format!("fqdn too long: {domain}")));
            }
            buffer.push(families[2]);
            buffer.push(domain.len() as u8);
            buffer.extend_from_slice(domain.as_bytes());
        }
    }
    buffer.extend_from_slice(&address.port.to_be_bytes());
    Ok(())
}

/// Reads a SOCKS address from the front of `data`; returns it and its length.
pub fn read_address(data: &[u8]) -> io::Result<(Socksaddr, usize)> {
    read_address_with(data, [ADDRESS_IPV4, ADDRESS_IPV6, ADDRESS_DOMAIN])
}

/// [`read_address`] with other family bytes.
pub fn read_address_with(data: &[u8], families: [u8; 3]) -> io::Result<(Socksaddr, usize)> {
    let short = || io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF");
    let family = *data.first().ok_or_else(short)?;
    let (host, rest) = if family == families[0] {
        let octets: [u8; 4] = data.get(1..5).ok_or_else(short)?.try_into().unwrap();
        (Host::Ip(IpAddr::V4(Ipv4Addr::from(octets))), 5)
    } else if family == families[1] {
        let octets: [u8; 16] = data.get(1..17).ok_or_else(short)?.try_into().unwrap();
        (Host::Ip(IpAddr::V6(Ipv6Addr::from(octets)).to_canonical()), 17)
    } else if family == families[2] {
        let length = *data.get(1).ok_or_else(short)? as usize;
        let domain = data.get(2..2 + length).ok_or_else(short)?;
        let domain = String::from_utf8_lossy(domain);
        (Socksaddr::from_host_port(&domain, 0).host, 2 + length)
    } else {
        return Err(error(format!("unknown address family: {family}")));
    };
    let port = data.get(rest..rest + 2).ok_or_else(short)?;
    Ok((Socksaddr::new(host, u16::from_be_bytes([port[0], port[1]])), rest + 2))
}

/// Reads a SOCKS address from a stream.
pub async fn read_address_from<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Socksaddr> {
    read_address_from_with(reader, [ADDRESS_IPV4, ADDRESS_IPV6, ADDRESS_DOMAIN]).await
}

/// [`read_address_from`] with other family bytes.
pub async fn read_address_from_with<R: AsyncRead + Unpin>(reader: &mut R, families: [u8; 3]) -> io::Result<Socksaddr> {
    let family = reader.read_u8().await?;
    let mut data = vec![family];
    if family == families[0] {
        data.resize(1 + 4 + 2, 0);
        reader.read_exact(&mut data[1..]).await?;
    } else if family == families[1] {
        data.resize(1 + 16 + 2, 0);
        reader.read_exact(&mut data[1..]).await?;
    } else if family == families[2] {
        let length = reader.read_u8().await?;
        data.push(length);
        data.resize(2 + length as usize + 2, 0);
        reader.read_exact(&mut data[2..]).await?;
    } else {
        return Err(error(format!("unknown address family: {family}")));
    }
    Ok(read_address_with(&data, families)?.0)
}

/// A client's method and keys (sing-shadowsocks2 `CreateMethod`).
#[derive(Clone)]
pub struct ClientMethod {
    pub kind: MethodKind,
    /// The key of an AEAD or stream method.
    key: Vec<u8>,
    /// The 2022 PSKs: identity PSKs first, the user PSK last.
    psks: Vec<Vec<u8>>,
    /// The identity of every PSK after the first (`blake3(psk)[:16]`).
    psk_hashes: Vec<[u8; 16]>,
    /// The clock of the 2022 timestamps.
    pub time: fn() -> i64,
}

impl ClientMethod {
    /// sing-shadowsocks2 `CreateMethod` with a password, with its errors.
    pub fn new(name: &str, password: &str) -> Result<ClientMethod, String> {
        let kind = MethodKind::parse(name).ok_or_else(|| format!("unknown method: {name}"))?;
        let mut method =
            ClientMethod { kind, key: Vec::new(), psks: Vec::new(), psk_hashes: Vec::new(), time: unix_now };
        match kind {
            MethodKind::None => {}
            MethodKind::Aead(aead) => {
                if password.is_empty() {
                    return Err("missing password".into());
                }
                method.key = cipher::evp_bytes_to_key(password.as_bytes(), aead.key_size());
            }
            MethodKind::Stream(stream) => {
                if password.is_empty() {
                    return Err("missing password".into());
                }
                method.key = cipher::evp_bytes_to_key(password.as_bytes(), stream.key_size());
            }
            MethodKind::Ss2022(aead) => {
                if !password.is_empty() {
                    for key in password.split(':') {
                        method.psks.push(decode_base64(key).map_err(|error| format!("decode key: {error}"))?);
                    }
                }
                if aead == AeadKind::ChaCha20Poly1305 && method.psks.len() > 1 {
                    return Err("Shadowsocks 2022 EIH support only available in AES ciphers".into());
                }
                if method.psks.is_empty() {
                    return Err("missing password".into());
                }
                for key in &method.psks {
                    if key.len() != aead.key_size() {
                        return Err(format!("bad key length, required {}, got {}", aead.key_size(), key.len()));
                    }
                }
                method.psk_hashes = method.psks.iter().skip(1).map(|psk| cipher::psk_hash(psk)).collect();
            }
        }
        Ok(method)
    }

    pub fn salt_size(&self) -> usize {
        self.kind.salt_size()
    }

    pub(crate) fn key(&self) -> &[u8] {
        &self.key
    }

    pub(crate) fn psks(&self) -> &[Vec<u8>] {
        &self.psks
    }

    /// The user PSK (the last one).
    pub(crate) fn user_psk(&self) -> &[u8] {
        self.psks.last().map(Vec::as_slice).unwrap_or_default()
    }

    pub(crate) fn psk_hashes(&self) -> &[[u8; 16]] {
        &self.psk_hashes
    }
}

/// Random bytes.
pub(crate) fn random_bytes(size: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; size];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut bytes);
    bytes
}

#[cfg(test)]
mod tests;
