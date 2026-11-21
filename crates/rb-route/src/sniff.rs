//! Protocol sniffing on the first client bytes, mirroring sing-box
//! `common/sniff` (`tls.go`, `http.go`, `bittorrent.go`, `ssh.go`).

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

pub const SNIFFERS: &[&str] = &["tls", "http", "bittorrent", "ssh"];

pub fn sniff(name: &str, data: &[u8]) -> Verdict {
    match name {
        "tls" => tls(data),
        "http" => http(data),
        "bittorrent" => bittorrent(data),
        "ssh" => ssh(data),
        _ => Verdict::NotThis,
    }
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
