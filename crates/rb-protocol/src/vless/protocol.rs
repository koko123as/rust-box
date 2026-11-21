//! The VLESS wire format (sing-vmess `vless/protocol.go`), its user ids
//! (gofrs `uuid.FromString`, else a name-based v5 UUID as sing-vmess does),
//! the VMess address format (port first) and the stream wrapper that writes
//! the request (client) or the response (server) in front of the first
//! write and reads the response (client) before the first read.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use rb_adapter::{Host, Socksaddr};
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

pub const VERSION: u8 = 0;
pub const FLOW_VISION: &str = "xtls-rprx-vision";
pub const COMMAND_TCP: u8 = 1;
pub const COMMAND_UDP: u8 = 2;
pub const COMMAND_MUX: u8 = 3;

/// VMess address family bytes (sing-vmess `AddressSerializer`).
const FAMILY_IPV4: u8 = 0x01;
const FAMILY_DOMAIN: u8 = 0x02;
const FAMILY_IPV6: u8 = 0x03;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// The user id of a `uuid` option: a UUID in any form gofrs/uuid v5
/// parses (canonical, braced, `urn:uuid:`, or 32 hex digits), else the
/// version 5 UUID of the string in the nil namespace (sing-vmess
/// `uuid.NewV5(uuid.Nil, ...)`).
pub fn parse_uuid(text: &str) -> [u8; 16] {
    parse_uuid_strict(text).unwrap_or_else(|| uuid_v5_nil(text))
}

/// gofrs/uuid v5.5.1 `parseBytes`.
pub fn parse_uuid_strict(text: &str) -> Option<[u8; 16]> {
    let mut bytes = text.as_bytes();
    match bytes.len() {
        32 | 36 => {}
        34 | 38 => {
            if bytes[0] != b'{' || bytes[bytes.len() - 1] != b'}' {
                return None;
            }
            bytes = &bytes[1..bytes.len() - 1];
        }
        41 | 45 => {
            if &bytes[..9] != b"urn:uuid:" {
                return None;
            }
            bytes = &bytes[9..];
        }
        _ => return None,
    }
    let hex = |byte: u8| -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    };
    let mut uuid = [0u8; 16];
    if bytes.len() == 36 {
        if bytes[8] != b'-' || bytes[13] != b'-' || bytes[18] != b'-' || bytes[23] != b'-' {
            return None;
        }
        const POSITIONS: [usize; 16] = [0, 2, 4, 6, 9, 11, 14, 16, 19, 21, 24, 26, 28, 30, 32, 34];
        for (index, position) in POSITIONS.iter().enumerate() {
            uuid[index] = (hex(bytes[*position])? << 4) | hex(bytes[position + 1])?;
        }
    } else {
        for index in 0..16 {
            uuid[index] = (hex(bytes[index * 2])? << 4) | hex(bytes[index * 2 + 1])?;
        }
    }
    Some(uuid)
}

/// gofrs/uuid `NewV5(Nil, name)`.
pub fn uuid_v5_nil(name: &str) -> [u8; 16] {
    let mut hash = Sha1::new();
    hash.update([0u8; 16]);
    hash.update(name.as_bytes());
    let digest = hash.finalize();
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&digest[..16]);
    uuid[6] = (uuid[6] & 0x0f) | 0x50;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    uuid
}

/// The canonical text of a UUID (gofrs `UUID.String`).
pub fn uuid_string(uuid: &[u8; 16]) -> String {
    let hex: String = uuid.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
}

/// Writes a VMess address: port first, then 1 (IPv4), 3 (IPv6) or 2
/// (domain) and the address.
pub fn write_address(buffer: &mut Vec<u8>, address: &Socksaddr) -> io::Result<()> {
    buffer.extend_from_slice(&address.port.to_be_bytes());
    match &address.host {
        Host::Ip(std::net::IpAddr::V4(ip)) => {
            buffer.push(FAMILY_IPV4);
            buffer.extend_from_slice(&ip.octets());
        }
        Host::Ip(std::net::IpAddr::V6(ip)) => {
            buffer.push(FAMILY_IPV6);
            buffer.extend_from_slice(&ip.octets());
        }
        Host::Domain(domain) => {
            if domain.len() > 255 {
                return Err(invalid(format!("fqdn too long: {domain}")));
            }
            buffer.push(FAMILY_DOMAIN);
            buffer.push(domain.len() as u8);
            buffer.extend_from_slice(domain.as_bytes());
        }
    }
    Ok(())
}

/// The length [`write_address`] writes.
pub fn address_len(address: &Socksaddr) -> usize {
    rb_shadowsocks::address_len(address)
}

/// A VMess address at the front of `data` and its length; `UnexpectedEof`
/// when `data` ends inside it. IPv4-mapped IPv6 addresses are unwrapped.
pub fn parse_address(data: &[u8]) -> io::Result<(Socksaddr, usize)> {
    let short = || io::Error::new(io::ErrorKind::UnexpectedEof, "EOF");
    let port = data.get(..2).ok_or_else(short)?;
    let port = u16::from_be_bytes([port[0], port[1]]);
    // Reorder into the SOCKS layout rb-shadowsocks parses.
    let family = *data.get(2).ok_or_else(short)?;
    let (address, length) = match family {
        FAMILY_IPV4 => {
            let octets: [u8; 4] = data.get(3..7).ok_or_else(short)?.try_into().unwrap();
            (Socksaddr::new(Host::Ip(std::net::Ipv4Addr::from(octets).into()), port), 7)
        }
        FAMILY_IPV6 => {
            let octets: [u8; 16] = data.get(3..19).ok_or_else(short)?.try_into().unwrap();
            (Socksaddr::new(Host::Ip(std::net::Ipv6Addr::from(octets).to_canonical()), port), 19)
        }
        FAMILY_DOMAIN => {
            let length = *data.get(3).ok_or_else(short)? as usize;
            let domain = data.get(4..4 + length).ok_or_else(short)?;
            (Socksaddr::from_host_port(&String::from_utf8_lossy(domain), port), 4 + length)
        }
        _ => return Err(invalid(format!("unknown address family: {family}"))),
    };
    Ok((address, length))
}

/// Reads a VMess address from a stream (exact reads only).
pub async fn read_address_from<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Socksaddr> {
    let mut data = vec![0u8; 3];
    reader.read_exact(&mut data).await?;
    let rest = match data[2] {
        FAMILY_IPV4 => 4,
        FAMILY_IPV6 => 16,
        FAMILY_DOMAIN => {
            let length = reader.read_u8().await?;
            data.push(length);
            length as usize
        }
        family => return Err(invalid(format!("unknown address family: {family}"))),
    };
    let start = data.len();
    data.resize(start + rest, 0);
    reader.read_exact(&mut data[start..]).await?;
    Ok(parse_address(&data)?.0)
}

/// A VLESS request (sing-vmess `vless.Request`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub uuid: [u8; 16],
    pub command: u8,
    /// Absent for the mux command.
    pub destination: Option<Socksaddr>,
    pub flow: String,
}

fn put_uvarint(buffer: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        buffer.push(value as u8 | 0x80);
        value >>= 7;
    }
    buffer.push(value as u8);
}

/// Go `binary.ReadUvarint` over a slice.
fn read_uvarint(data: &[u8], position: &mut usize) -> io::Result<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for index in 0..10 {
        let byte = *data.get(*position).ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"))?;
        *position += 1;
        if byte < 0x80 {
            if index == 9 && byte > 1 {
                return Err(invalid("binary: varint overflows a 64-bit integer"));
            }
            return Ok(value | (byte as u64) << shift);
        }
        value |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
    }
    Err(invalid("binary: varint overflows a 64-bit integer"))
}

/// Encodes a request (sing-vmess `WriteRequest` / `EncodeRequest`): the
/// flow goes in the protobuf addons (field 1).
pub fn encode_request(request: &Request) -> io::Result<Vec<u8>> {
    let mut buffer = vec![VERSION];
    buffer.extend_from_slice(&request.uuid);
    if request.flow.is_empty() {
        buffer.push(0);
    } else {
        let mut addons = vec![10];
        put_uvarint(&mut addons, request.flow.len() as u64);
        addons.extend_from_slice(request.flow.as_bytes());
        buffer.push(addons.len() as u8);
        buffer.extend_from_slice(&addons);
    }
    buffer.push(request.command);
    if request.command != COMMAND_MUX {
        let destination = request.destination.as_ref().ok_or_else(|| invalid("missing destination"))?;
        write_address(&mut buffer, destination)?;
    }
    Ok(buffer)
}

/// The request of a UDP connection (sing-vmess `WritePacketRequest`, which
/// never writes the flow).
pub fn encode_packet_request(uuid: &[u8; 16], destination: &Socksaddr) -> io::Result<Vec<u8>> {
    let mut buffer = vec![VERSION];
    buffer.extend_from_slice(uuid);
    buffer.push(0);
    buffer.push(COMMAND_UDP);
    write_address(&mut buffer, destination)?;
    Ok(buffer)
}

/// sing-vmess `readAddons`: the flow (field 1) and the seed (field 2).
pub fn parse_addons(data: &[u8]) -> io::Result<String> {
    let mut flow = String::new();
    let mut position = 0;
    while position < data.len() {
        let header = data[position];
        position += 1;
        match header {
            0x0a | 0x12 => {
                let length = read_uvarint(data, &mut position)?;
                if length > (data.len() - position) as u64 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF"));
                }
                let value = &data[position..position + length as usize];
                position += length as usize;
                if header == 0x0a {
                    flow = String::from_utf8_lossy(value).into_owned();
                }
            }
            _ => return Err(invalid(format!("unknown protobuf message header: {header}"))),
        }
    }
    Ok(flow)
}

/// sing-vmess `ReadRequest`, with exact reads only (so nothing after the
/// request is taken from the stream).
pub async fn read_request<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Request> {
    let version = reader.read_u8().await?;
    if version != VERSION {
        return Err(invalid(format!("unknown version: {version}")));
    }
    let mut uuid = [0u8; 16];
    reader.read_exact(&mut uuid).await?;
    let addons_length = reader.read_u8().await?;
    let mut flow = String::new();
    if addons_length > 0 {
        let mut addons = vec![0u8; addons_length as usize];
        reader.read_exact(&mut addons).await?;
        flow = parse_addons(&addons)?;
    }
    let command = reader.read_u8().await?;
    let destination = if command != COMMAND_MUX { Some(read_address_from(reader).await?) } else { None };
    Ok(Request { uuid, command, destination, flow })
}

/// What is left of a VLESS response header to read on the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Response {
    /// The version and addons length, `filled` of 2 read.
    Header {
        version: u8,
        filled: u8,
    },
    /// Addons bytes to skip.
    Skip(u8),
    Done,
}

/// A VLESS stream for either side: `prefix` (the client's request or the
/// server's response `0 0`) goes in front of the first write, and the
/// client reads the response header before its first read (sing-vmess
/// `vless.Conn` and `serverConn`). It never reads more than it returns,
/// so the bytes under it stay in place (Vision relies on that).
pub struct VlessStream<S> {
    inner: S,
    prefix: Option<Vec<u8>>,
    out: Vec<u8>,
    offset: usize,
    response: Response,
}

impl<S> VlessStream<S> {
    /// The client side: `request` is the encoded request.
    pub fn client(inner: S, request: Vec<u8>) -> Self {
        VlessStream {
            inner,
            prefix: Some(request),
            out: Vec::new(),
            offset: 0,
            response: Response::Header { version: 0, filled: 0 },
        }
    }

    /// The server side of a request that was read.
    pub fn server(inner: S) -> Self {
        VlessStream { inner, prefix: Some(vec![VERSION, 0]), out: Vec::new(), offset: 0, response: Response::Done }
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Whether the request (or response) went out already.
    pub fn header_written(&self) -> bool {
        self.prefix.is_none()
    }
}

impl<S: AsyncWrite + Unpin> VlessStream<S> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.offset < self.out.len() {
            let written = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.out[self.offset..]))?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.offset += written;
        }
        self.out.clear();
        self.offset = 0;
        Poll::Ready(Ok(()))
    }

    /// Sends the header alone, as sing-vmess's `Write(nil)` does.
    pub async fn write_header(&mut self) -> io::Result<()> {
        if let Some(prefix) = self.prefix.take() {
            self.out = prefix;
            self.offset = 0;
        }
        std::future::poll_fn(|cx| {
            ready!(self.poll_drain(cx))?;
            Pin::new(&mut self.inner).poll_flush(cx)
        })
        .await
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VlessStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            match this.response {
                Response::Done => return Pin::new(&mut this.inner).poll_read(cx, buf),
                Response::Header { version, filled } => {
                    let mut byte = [0u8; 1];
                    let mut read = ReadBuf::new(&mut byte);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
                    if read.filled().is_empty() {
                        return Poll::Ready(Err(crate::framed::eof()));
                    }
                    if filled == 0 {
                        if byte[0] != VERSION {
                            return Poll::Ready(Err(invalid(format!("unknown version: {}", byte[0]))));
                        }
                        this.response = Response::Header { version: byte[0], filled: 1 };
                    } else {
                        let _ = version;
                        this.response = if byte[0] == 0 { Response::Done } else { Response::Skip(byte[0]) };
                    }
                }
                Response::Skip(left) => {
                    let mut skip = [0u8; 255];
                    let mut read = ReadBuf::new(&mut skip[..left as usize]);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
                    let count = read.filled().len() as u8;
                    if count == 0 {
                        return Poll::Ready(Err(crate::framed::eof()));
                    }
                    this.response = if count == left { Response::Done } else { Response::Skip(left - count) };
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VlessStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        if let Some(mut prefix) = this.prefix.take() {
            // The header and the first data in one write; taken at once,
            // written out by later calls if the stream is busy.
            prefix.extend_from_slice(data);
            this.out = prefix;
            this.offset = 0;
            if let Poll::Ready(Err(error)) = this.poll_drain(cx) {
                return Poll::Ready(Err(error));
            }
            return Poll::Ready(Ok(data.len()));
        }
        Pin::new(&mut this.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(cx))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The response a client of a UDP request reads first, at the front of
/// `data`: its length once whole.
pub fn parse_response(data: &[u8]) -> io::Result<Option<usize>> {
    let Some(&version) = data.first() else { return Ok(None) };
    if version != VERSION {
        return Err(invalid(format!("unknown version: {version}")));
    }
    let Some(&length) = data.get(1) else { return Ok(None) };
    let total = 2 + length as usize;
    Ok((data.len() >= total).then_some(total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_forms() {
        let canonical = "bf000d23-0752-40b4-affe-68f7707a9661";
        let expected = [0xbf, 0x00, 0x0d, 0x23, 0x07, 0x52, 0x40, 0xb4, 0xaf, 0xfe, 0x68, 0xf7, 0x70, 0x7a, 0x96, 0x61];
        for text in [
            canonical,
            "BF000D23-0752-40B4-AFFE-68F7707A9661",
            "{bf000d23-0752-40b4-affe-68f7707a9661}",
            "urn:uuid:bf000d23-0752-40b4-affe-68f7707a9661",
            "bf000d23075240b4affe68f7707a9661",
            "{bf000d23075240b4affe68f7707a9661}",
            "urn:uuid:bf000d23075240b4affe68f7707a9661",
        ] {
            assert_eq!(parse_uuid_strict(text), Some(expected), "{text}");
        }
        assert_eq!(uuid_string(&expected), canonical);
        for text in [
            "",
            "bf000d23-0752-40b4-affe-68f7707a966",
            "bf000d23_0752-40b4-affe-68f7707a9661",
            "(bf000d23075240b4affe68f7707a9661)",
        ] {
            assert_eq!(parse_uuid_strict(text), None, "{text}");
        }
        // uuid.NewV5(uuid.Nil, name) (Python uuid5 with the nil namespace agrees).
        assert_eq!(uuid_string(&parse_uuid("password")), "750db9b2-386a-5d2f-a2ea-64504781c566");
    }

    #[test]
    fn request_round_trip() {
        let uuid = parse_uuid("bf000d23-0752-40b4-affe-68f7707a9661");
        let request = Request {
            uuid,
            command: COMMAND_TCP,
            destination: Some(Socksaddr::from_host_port("example.com", 443)),
            flow: FLOW_VISION.into(),
        };
        let encoded = encode_request(&request).unwrap();
        let mut expected = vec![0];
        expected.extend_from_slice(&uuid);
        expected.extend_from_slice(&[18, 10, 16]);
        expected.extend_from_slice(FLOW_VISION.as_bytes());
        expected.extend_from_slice(&[1, 0x01, 0xbb, 2, 11]);
        expected.extend_from_slice(b"example.com");
        assert_eq!(encoded, expected);
        let decoded = futures_lite_block(read_request(&mut encoded.as_slice())).unwrap();
        assert_eq!(decoded, request);

        let mux = Request { uuid, command: COMMAND_MUX, destination: None, flow: String::new() };
        let encoded = encode_request(&mux).unwrap();
        assert_eq!(encoded.len(), 1 + 16 + 1 + 1);
        assert_eq!(futures_lite_block(read_request(&mut encoded.as_slice())).unwrap(), mux);

        let packet = encode_packet_request(&uuid, &Socksaddr::from_host_port("1.2.3.4", 53)).unwrap();
        assert_eq!(&packet[17..], &[0, 2, 0, 53, 1, 1, 2, 3, 4]);
        let v6 = Socksaddr::from_host_port("2001:db8::1", 80);
        let mut buffer = Vec::new();
        write_address(&mut buffer, &v6).unwrap();
        assert_eq!(buffer[2], 3);
        assert_eq!(parse_address(&buffer).unwrap(), (v6, 19));
        assert_eq!(parse_address(&buffer[..5]).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        assert!(parse_address(&[0, 1, 9]).is_err());
        assert_eq!(parse_addons(&[0x12, 1, b'x', 0x0a, 1, b'f']).unwrap(), "f");
        assert!(parse_addons(&[0x1a, 0]).unwrap_err().to_string().contains("unknown protobuf message header: 26"));
        assert_eq!(parse_response(&[0, 1]).unwrap(), None);
        assert_eq!(parse_response(&[0, 1, 9, 7]).unwrap(), Some(3));
        assert!(parse_response(&[1]).is_err());
    }

    fn futures_lite_block<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(future)
    }

    #[tokio::test]
    async fn stream_headers() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client, mut server) = tokio::io::duplex(1024);
        let mut stream = VlessStream::client(client, b"REQ".to_vec());
        stream.write_all(b"data").await.unwrap();
        stream.flush().await.unwrap();
        let mut received = [0u8; 7];
        server.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"REQdata");
        server.write_all(&[0, 2, 9, 9, b'o', b'k']).await.unwrap();
        let mut reply = [0u8; 2];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ok");

        let (inner, mut peer) = tokio::io::duplex(1024);
        let mut stream = VlessStream::server(inner);
        stream.write_all(b"x").await.unwrap();
        stream.flush().await.unwrap();
        let mut received = [0u8; 3];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, &[0, 0, b'x']);
    }
}
