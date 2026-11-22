//! The HTTP/1.1 server under the API (what Go `net/http` and the WebSocket
//! upgrade of `sagernet/ws` do for it): requests with a `Content-Length`
//! body, plain, chunked and WebSocket text responses.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

const MAX_HEADER: usize = 1 << 20;
const MAX_BODY: usize = 16 << 20;
const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// One request.
#[derive(Debug, Clone, Default)]
pub struct Request {
    pub method: String,
    /// The path as sent, still escaped.
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub keep_alive: bool,
}

impl Request {
    /// The first value of a header, compared ignoring case (`Header.Get`).
    pub fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .unwrap_or("")
    }

    /// The first value of a query parameter, empty when missing
    /// (`URL.Query().Get`).
    pub fn query_get(&self, name: &str) -> String {
        for pair in self.query.split(['&']) {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let Some(key) = crate::util::unescape(key, true) else { continue };
            if key == name {
                return crate::util::unescape(value, true).unwrap_or_default();
            }
        }
        String::new()
    }

    /// Whether it asks for a WebSocket (`Upgrade: websocket`, exactly as
    /// sing-box compares it).
    pub fn is_websocket(&self) -> bool {
        self.header("Upgrade") == "websocket"
    }
}

/// One complete response.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16) -> Self {
        Response { status, headers: Vec::new(), body: Vec::new() }
    }

    pub fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.set(name, value);
        self
    }

    /// Replaces a header (`Header.Set`).
    pub fn set(&mut self, name: &str, value: impl Into<String>) {
        self.headers.retain(|(key, _)| !key.eq_ignore_ascii_case(name));
        self.headers.push((name.to_string(), value.into()));
    }

    /// Adds a header value (`Header.Add`).
    pub fn add(&mut self, name: &str, value: impl Into<String>) {
        self.headers.push((name.to_string(), value.into()));
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
    }

    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }
}

/// `http.StatusText`.
pub fn status_text(status: u16) -> &'static str {
    match status {
        101 => "Switching Protocols",
        200 => "OK",
        204 => "No Content",
        301 => "Moved Permanently",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Request Entity Too Large",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}

/// The `Date` header value (`http.TimeFormat`).
pub fn http_date(time: SystemTime) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let seconds = time.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    let days = seconds.div_euclid(86_400);
    let (year, month, day) = civil(days);
    let second = seconds.rem_euclid(86_400);
    format!(
        "{}, {day:02} {} {year} {:02}:{:02}:{:02} GMT",
        DAYS[days.rem_euclid(7) as usize],
        MONTHS[month as usize - 1],
        second / 3600,
        second / 60 % 60,
        second % 60
    )
}

fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

/// Why reading a request failed.
pub enum ReadError {
    /// The connection ended (or failed) before a request.
    Closed,
    /// A malformed request, answered with this status.
    Bad(u16),
}

/// Reads one request.
pub async fn read_request<R: tokio::io::AsyncRead + Unpin>(reader: &mut BufReader<R>) -> Result<Request, ReadError> {
    let mut head = Vec::new();
    loop {
        let read = reader.read_until(b'\n', &mut head).await.map_err(|_| ReadError::Closed)?;
        if read == 0 {
            return Err(ReadError::Closed);
        }
        if head == b"\r\n" || head == b"\n" {
            // Go skips empty lines before a request.
            head.clear();
            continue;
        }
        if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
            break;
        }
        if head.len() > MAX_HEADER {
            return Err(ReadError::Bad(431));
        }
    }
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut parsed = httparse::Request::new(&mut headers);
    match parsed.parse(&head) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err(ReadError::Bad(400)),
    }
    let target = parsed.path.unwrap_or("/");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let version = parsed.version.unwrap_or(1);
    let mut request = Request {
        method: parsed.method.unwrap_or("GET").to_string(),
        path: path.to_string(),
        query: query.to_string(),
        headers: parsed
            .headers
            .iter()
            .map(|header| (header.name.to_string(), String::from_utf8_lossy(header.value).into_owned()))
            .collect(),
        body: Vec::new(),
        keep_alive: false,
    };
    let connection = request.header("Connection").to_ascii_lowercase();
    request.keep_alive = if version == 0 { connection.contains("keep-alive") } else { !connection.contains("close") };
    if request.header("Transfer-Encoding").eq_ignore_ascii_case("chunked") {
        request.body = read_chunked(reader).await?;
    } else if !request.header("Content-Length").is_empty() {
        let length: usize = request.header("Content-Length").trim().parse().map_err(|_| ReadError::Bad(400))?;
        if length > MAX_BODY {
            return Err(ReadError::Bad(413));
        }
        let mut body = vec![0u8; length];
        reader.read_exact(&mut body).await.map_err(|_| ReadError::Closed)?;
        request.body = body;
    }
    Ok(request)
}

async fn read_chunked<R: tokio::io::AsyncRead + Unpin>(reader: &mut BufReader<R>) -> Result<Vec<u8>, ReadError> {
    let mut body = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.map_err(|_| ReadError::Closed)?;
        let size = line.trim().split(';').next().unwrap_or("");
        let size = usize::from_str_radix(size, 16).map_err(|_| ReadError::Bad(400))?;
        if body.len() + size > MAX_BODY {
            return Err(ReadError::Bad(413));
        }
        if size == 0 {
            loop {
                let mut trailer = String::new();
                let read = reader.read_line(&mut trailer).await.map_err(|_| ReadError::Closed)?;
                if read == 0 || trailer.trim().is_empty() {
                    return Ok(body);
                }
            }
        }
        let start = body.len();
        body.resize(start + size, 0);
        reader.read_exact(&mut body[start..]).await.map_err(|_| ReadError::Closed)?;
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await.map_err(|_| ReadError::Closed)?;
    }
}

fn head(status: u16, headers: &[(String, String)]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status} {}\r\n", status_text(status));
    for (name, value) in headers {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// Writes a complete response the way Go does (a `Date`, a
/// `Content-Length`, and a sniffed `Content-Type` for a body without one).
pub async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    mut response: Response,
    head_only: bool,
    keep_alive: bool,
) -> io::Result<()> {
    if response.get("Date").is_none() {
        response.add("Date", http_date(SystemTime::now()));
    }
    let bodyless = response.status == 204 || response.status == 304;
    if !bodyless {
        if response.get("Content-Type").is_none() && !response.body.is_empty() {
            let kind = if response.body.starts_with(b"<") || response.body.starts_with(b"\n<") {
                "text/html; charset=utf-8"
            } else {
                "text/plain; charset=utf-8"
            };
            response.add("Content-Type", kind);
        }
        if response.get("Content-Length").is_none() {
            response.add("Content-Length", response.body.len().to_string());
        }
    }
    if !keep_alive {
        response.set("Connection", "close");
    }
    let mut bytes = head(response.status, &response.headers);
    if !head_only && !bodyless {
        bytes.extend_from_slice(&response.body);
    }
    writer.write_all(&bytes).await?;
    writer.flush().await
}

/// Starts a chunked `200` response for a stream of JSON lines.
pub async fn start_chunked<W: AsyncWrite + Unpin>(
    writer: &mut W,
    mut headers: Vec<(String, String)>,
) -> io::Result<()> {
    headers.push(("Content-Type".into(), "application/json".into()));
    headers.push(("Date".into(), http_date(SystemTime::now())));
    headers.push(("Transfer-Encoding".into(), "chunked".into()));
    writer.write_all(&head(200, &headers)).await?;
    writer.flush().await
}

pub async fn write_chunk<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> io::Result<()> {
    let mut out = format!("{:x}\r\n", data.len()).into_bytes();
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
    writer.write_all(&out).await?;
    writer.flush().await
}

/// The WebSocket handshake response, or `None` when the request is not a
/// valid upgrade (`ws.UpgradeHTTP` then answers an error and the handler
/// returns).
pub fn websocket_accept(request: &Request, mut headers: Vec<(String, String)>) -> Result<Vec<u8>, Response> {
    let bad = |message: &str| {
        Response::new(400)
            .header("Content-Type", "text/plain; charset=utf-8")
            .header("X-Content-Type-Options", "nosniff")
            .body(format!("{message}\n").into_bytes())
    };
    if request.method != "GET" {
        return Err(Response::new(405)
            .header("Content-Type", "text/plain; charset=utf-8")
            .body(b"bad method\n".to_vec()));
    }
    if !request.header("Connection").split(',').any(|token| token.trim().eq_ignore_ascii_case("upgrade")) {
        return Err(bad("missing or bad \"Connection\" header"));
    }
    if request.header("Sec-WebSocket-Version") != "13" {
        return Err(Response::new(426)
            .header("Sec-WebSocket-Version", "13")
            .header("Content-Type", "text/plain; charset=utf-8")
            .body(b"missing or bad \"Sec-WebSocket-Version\" header\n".to_vec()));
    }
    let key = request.header("Sec-WebSocket-Key");
    let decoded = base64::engine::general_purpose::STANDARD.decode(key).unwrap_or_default();
    if decoded.len() != 16 {
        return Err(bad("missing or bad \"Sec-WebSocket-Key\" header"));
    }
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WEBSOCKET_GUID.as_bytes());
    let accept = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
    headers.push(("Upgrade".into(), "websocket".into()));
    headers.push(("Connection".into(), "Upgrade".into()));
    headers.push(("Sec-WebSocket-Accept".into(), accept));
    Ok(head(101, &headers))
}

/// One unmasked server frame.
pub fn websocket_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x80 | opcode];
    match payload.len() {
        length if length < 126 => frame.push(length as u8),
        length if length <= u16::MAX as usize => {
            frame.push(126);
            frame.extend_from_slice(&(length as u16).to_be_bytes());
        }
        length => {
            frame.push(127);
            frame.extend_from_slice(&(length as u64).to_be_bytes());
        }
    }
    frame.extend_from_slice(payload);
    frame
}

/// Reads client frames until a close frame or the end, answering pings
/// through `pong` (whose frames the writer sends).
pub async fn websocket_drain<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    pong: tokio::sync::mpsc::Sender<Vec<u8>>,
) -> io::Result<()> {
    loop {
        let mut header = [0u8; 2];
        reader.read_exact(&mut header).await?;
        let opcode = header[0] & 0x0f;
        let masked = header[1] & 0x80 != 0;
        let mut length = u64::from(header[1] & 0x7f);
        if length == 126 {
            let mut extended = [0u8; 2];
            reader.read_exact(&mut extended).await?;
            length = u64::from(u16::from_be_bytes(extended));
        } else if length == 127 {
            let mut extended = [0u8; 8];
            reader.read_exact(&mut extended).await?;
            length = u64::from_be_bytes(extended);
        }
        if length > MAX_BODY as u64 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
        }
        let mut mask = [0u8; 4];
        if masked {
            reader.read_exact(&mut mask).await?;
        }
        let mut payload = vec![0u8; length as usize];
        reader.read_exact(&mut payload).await?;
        if masked {
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[index % 4];
            }
        }
        match opcode {
            0x8 => {
                let _ = pong.send(websocket_frame(0x8, payload.get(..2).unwrap_or_default())).await;
                return Ok(());
            }
            0x9 => {
                let _ = pong.send(websocket_frame(0xA, &payload)).await;
            }
            _ => {}
        }
    }
}
