//! The value encodings sing-box keeps in the cache file:
//! `adapter.SavedBinary` (remote rule-sets) and `adapter.FakeIPMetadata`
//! (with Go's `netip.Prefix` and `netip.Addr` binary forms).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rb_config::IpPrefix;
use rb_dns::FakeIpMetadata;

/// A remote rule-set as last downloaded (sing-box `adapter.SavedBinary`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedBinary {
    pub content: Vec<u8>,
    pub last_updated: SystemTime,
    pub last_etag: String,
    /// The hash of the URL it came from (version 2 and later).
    pub url_hash: Vec<u8>,
}

impl Default for SavedBinary {
    fn default() -> Self {
        SavedBinary { content: Vec::new(), last_updated: UNIX_EPOCH, last_etag: String::new(), url_hash: Vec::new() }
    }
}

fn put_uvarint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Go `binary.ReadUvarint`.
fn read_uvarint(data: &mut &[u8]) -> Option<u64> {
    let mut value = 0u64;
    for (index, byte) in data.iter().enumerate() {
        if index == 10 {
            return None;
        }
        if index == 9 && *byte > 1 {
            return None;
        }
        value |= u64::from(byte & 0x7F) << (7 * index);
        if byte & 0x80 == 0 {
            *data = &data[index + 1..];
            return Some(value);
        }
    }
    None
}

fn read_bytes<'a>(data: &mut &'a [u8], length: u64) -> Option<&'a [u8]> {
    if length > data.len() as u64 {
        return None;
    }
    let (head, rest) = data.split_at(length as usize);
    *data = rest;
    Some(head)
}

/// Seconds since the Unix epoch, negative before it (Go `Time.Unix`).
pub(crate) fn unix_seconds(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(after) => after.as_secs() as i64,
        Err(before) => {
            let before = before.duration();
            -(before.as_secs() as i64) - i64::from(before.subsec_nanos() > 0)
        }
    }
}

/// Go `time.Unix(seconds, 0)`.
pub(crate) fn from_unix_seconds(seconds: i64) -> SystemTime {
    if seconds >= 0 {
        UNIX_EPOCH + Duration::from_secs(seconds as u64)
    } else {
        UNIX_EPOCH - Duration::from_secs(seconds.unsigned_abs())
    }
}

impl SavedBinary {
    /// `MarshalBinary`: version 2.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.content.len() + self.last_etag.len() + self.url_hash.len() + 24);
        out.push(2);
        put_uvarint(&mut out, self.content.len() as u64);
        out.extend_from_slice(&self.content);
        out.extend_from_slice(&unix_seconds(self.last_updated).to_be_bytes());
        put_uvarint(&mut out, self.last_etag.len() as u64);
        out.extend_from_slice(self.last_etag.as_bytes());
        put_uvarint(&mut out, self.url_hash.len() as u64);
        out.extend_from_slice(&self.url_hash);
        out
    }

    /// `UnmarshalBinary`: versions before 2 have no URL hash.
    pub fn from_bytes(mut data: &[u8]) -> Option<SavedBinary> {
        let data = &mut data;
        let version = *read_bytes(data, 1)?.first()?;
        let length = read_uvarint(data)?;
        let content = read_bytes(data, length)?.to_vec();
        let last_updated = i64::from_be_bytes(read_bytes(data, 8)?.try_into().ok()?);
        let length = read_uvarint(data)?;
        // Go keeps the bytes as they are; an invalid UTF-8 tag is replaced.
        let last_etag = String::from_utf8_lossy(read_bytes(data, length)?).into_owned();
        let mut saved =
            SavedBinary { content, last_updated: from_unix_seconds(last_updated), last_etag, url_hash: vec![] };
        if version < 2 {
            return Some(saved);
        }
        let length = read_uvarint(data)?;
        saved.url_hash = read_bytes(data, length)?.to_vec();
        Some(saved)
    }
}

/// Go `netip.Addr.MarshalBinary`: empty for the zero address, 4 bytes for
/// IPv4, 16 for IPv6 (rust-box has no zones).
fn addr_bytes(address: Option<IpAddr>) -> Vec<u8> {
    match address {
        None => Vec::new(),
        Some(IpAddr::V4(v4)) => v4.octets().to_vec(),
        Some(IpAddr::V6(v6)) => v6.octets().to_vec(),
    }
}

/// Go `netip.Addr.UnmarshalBinary` (a zone after the 16 bytes is dropped).
fn parse_addr(data: &[u8]) -> Result<Option<IpAddr>, ()> {
    match data.len() {
        0 => Ok(None),
        4 => Ok(Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(data).unwrap())))),
        length if length >= 16 => Ok(Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[..16]).unwrap())))),
        _ => Err(()),
    }
}

/// Go `netip.Prefix.MarshalBinary`: the address, then the prefix length
/// (0xFF, Go's -1, for the zero prefix).
fn prefix_bytes(prefix: Option<IpPrefix>) -> Vec<u8> {
    match prefix {
        None => vec![0xFF],
        Some(prefix) => {
            let mut out = addr_bytes(Some(prefix.address));
            out.push(prefix.prefix_len);
            out
        }
    }
}

/// Go `netip.Prefix.UnmarshalBinary` (Go keeps the address bits past the
/// length, as here).
fn parse_prefix(data: &[u8]) -> Result<Option<IpPrefix>, ()> {
    let (&bits, address) = data.split_last().ok_or(())?;
    let Some(address) = parse_addr(address)? else { return Ok(None) };
    let max = if address.is_ipv4() { 32 } else { 128 };
    if bits > max {
        // `PrefixFrom` gives the zero prefix for a length out of range.
        return Ok(None);
    }
    Ok(Some(IpPrefix { address, prefix_len: bits }))
}

/// `FakeIPMetadata.MarshalBinary`: four length-prefixed (u16 big endian)
/// fields.
pub fn fakeip_metadata_to_bytes(metadata: &FakeIpMetadata) -> Vec<u8> {
    let mut out = Vec::new();
    for field in [
        prefix_bytes(metadata.inet4_range),
        prefix_bytes(metadata.inet6_range),
        addr_bytes(metadata.inet4_current),
        addr_bytes(metadata.inet6_current),
    ] {
        out.extend_from_slice(&(field.len() as u16).to_be_bytes());
        out.extend_from_slice(&field);
    }
    out
}

/// `FakeIPMetadata.UnmarshalBinary`.
pub fn fakeip_metadata_from_bytes(mut data: &[u8]) -> Option<FakeIpMetadata> {
    let data = &mut data;
    let mut field = || -> Option<Vec<u8>> {
        let length = u16::from_be_bytes(read_bytes(data, 2)?.try_into().ok()?);
        Some(read_bytes(data, u64::from(length))?.to_vec())
    };
    let inet4_range = parse_prefix(&field()?).ok()?;
    let inet6_range = parse_prefix(&field()?).ok()?;
    let inet4_current = parse_addr(&field()?).ok()?;
    let inet6_current = parse_addr(&field()?).ok()?;
    Some(FakeIpMetadata { inet4_range, inet6_range, inet4_current, inet6_current })
}
