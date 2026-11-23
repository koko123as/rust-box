//! DERP slice primitives from the Tailscale fork pinned by sing-box v1.14.4.
//!
//! This module provides header codecs, bounded frame slice and blocking-stream
//! reads/writes, a server-greeting parser, ClientInfo JSON encoding and in-memory
//! encrypted frame construction, a client key-exchange state machine with a
//! blocking-stream greeting and ClientInfo write path, ServerInfo parsing, and
//! bounded blocking-stream routing for pinned-fork received-message frames. A
//! receive-session helper requests the pinned 120-second read deadline and latches
//! the first error. A pure Rust model of the pinned `rate.Limiter.AllowN` state
//! transition and a bounded SendPacket writer are oracle-tested. `DerpSendWriter`
//! serializes packet, Ping/Pong, NotePreferred, WatchConnectionChanges, and ClosePeer
//! writes under one lock. ForwardPacket's bounded frame writer is also covered, but
//! the shared-writer path now requires an out-of-lock connection closer and arms the
//! pinned five-second watchdog; the stateless helper remains unguarded. `magicsock`
//! handles only the higher-level Ping->Pong branch; complete network lifecycle and
//! server authentication remain unimplemented.

use std::error::Error;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde::de::{self, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

use crate::{disco_crypto::NodeBoxError, NodePrivate, NodePublic};

/// A DERP frame header contains a type byte and a big-endian u32 payload length.
pub const FRAME_HEADER_LEN: usize = 5;
/// Raw node public-key length in DERP frames.
pub const KEY_LEN: usize = 32;
/// Maximum packet length accepted by the pinned fork's `Client.Send`.
pub const MAX_PACKET_SIZE: usize = 64 << 10;
/// Pinned fork timeout before `ForwardPacket` closes the underlying connection.
pub const FORWARD_PACKET_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum payload length accepted by the pinned fork's `WriteFrame`.
pub const MAX_FRAME_WRITE_SIZE: usize = 10 << 20;
/// Maximum single frame payload accepted by the pinned fork's `Client.Recv`.
pub const MAX_CLIENT_RECV_FRAME_LEN: usize = 1 << 20;
/// Magic prefix of a DERP server-key greeting.
pub const MAGIC: [u8; 8] = *b"DERP\xf0\x9f\x94\x91";
/// The server-key frame type.
pub const FRAME_SERVER_KEY: FrameType = FrameType(0x01);
/// The client-info frame type.
pub const FRAME_CLIENT_INFO: FrameType = FrameType(0x02);
/// The server-info frame type.
pub const FRAME_SERVER_INFO: FrameType = FrameType(0x03);
/// The client-to-server packet frame type.
pub const FRAME_SEND_PACKET: FrameType = FrameType(0x04);
/// The mesh client-to-client packet forwarding frame type.
pub const FRAME_FORWARD_PACKET: FrameType = FrameType(0x0a);
/// The received-packet frame type.
pub const FRAME_RECV_PACKET: FrameType = FrameType(0x05);
/// The keep-alive frame type.
pub const FRAME_KEEP_ALIVE: FrameType = FrameType(0x06);
/// The client preferred-server notification frame type.
pub const FRAME_NOTE_PREFERRED: FrameType = FrameType(0x07);
/// The peer-gone frame type.
pub const FRAME_PEER_GONE: FrameType = FrameType(0x08);
/// The peer-present frame type.
pub const FRAME_PEER_PRESENT: FrameType = FrameType(0x09);
/// The mesh connection-list subscription frame type.
pub const FRAME_WATCH_CONNS: FrameType = FrameType(0x10);
/// The privileged peer-close request frame type.
pub const FRAME_CLOSE_PEER: FrameType = FrameType(0x11);
/// The ping frame type.
pub const FRAME_PING: FrameType = FrameType(0x12);
/// The pong frame type.
pub const FRAME_PONG: FrameType = FrameType(0x13);
/// The health frame type.
pub const FRAME_HEALTH: FrameType = FrameType(0x14);
/// The server-restarting frame type.
pub const FRAME_RESTARTING: FrameType = FrameType(0x15);
/// DERP protocol version advertised by the pinned fork.
pub const PROTOCOL_VERSION: isize = 2;

/// A raw DERP frame type. Unknown values are preserved, as in Go's `FrameType`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameType(pub u8);

/// The type and payload length of a DERP frame, excluding the five-byte header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameHeader {
    pub frame_type: FrameType,
    pub frame_len: u32,
}

impl FrameHeader {
    /// Encodes a frame header without writing a payload or flushing a stream.
    pub fn encode(self) -> [u8; FRAME_HEADER_LEN] {
        let length = self.frame_len.to_be_bytes();
        [self.frame_type.0, length[0], length[1], length[2], length[3]]
    }
}

/// An incomplete header or a frame type differing from the expected type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameHeaderError {
    /// A complete five-byte header was not available; the input was not consumed.
    Incomplete,
    /// The header was consumed and its actual length is retained, as in the Go fork.
    UnexpectedType { got: FrameType, want: FrameType, frame_len: u32 },
}

impl fmt::Display for FrameHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Incomplete => f.write_str("EOF"),
            Self::UnexpectedType { got, want, .. } => {
                write!(f, "bad frame type 0x{:X}, want 0x{:X}", got.0, want.0)
            }
        }
    }
}

impl Error for FrameHeaderError {}

/// Reads a complete header and advances `input` only on success.
///
/// This slice API models available bytes only. It cannot represent buffered I/O
/// failures other than missing bytes, and it does not read the payload.
pub fn read_frame_header(input: &mut &[u8]) -> Result<FrameHeader, FrameHeaderError> {
    let Some(header) = input.get(..FRAME_HEADER_LEN) else {
        return Err(FrameHeaderError::Incomplete);
    };
    let frame = FrameHeader {
        frame_type: FrameType(header[0]),
        frame_len: u32::from_be_bytes([header[1], header[2], header[3], header[4]]),
    };
    *input = &input[FRAME_HEADER_LEN..];
    Ok(frame)
}

/// Reads and consumes a complete header before comparing its type.
///
/// On mismatch, the error retains the decoded length; Go returns the length
/// alongside the error despite the upstream comment saying otherwise.
pub fn read_frame_type_header(input: &mut &[u8], want: FrameType) -> Result<u32, FrameHeaderError> {
    let header = read_frame_header(input)?;
    if header.frame_type != want {
        return Err(FrameHeaderError::UnexpectedType { got: header.frame_type, want, frame_len: header.frame_len });
    }
    Ok(header.frame_len)
}

/// The result of the pinned fork's bounded frame read on a byte slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadFrameError {
    /// The complete header was unavailable; no input was consumed.
    IncompleteHeader,
    /// The header was consumed but no payload bytes were consumed.
    ExceedsLimit { frame_len: u32, max_size: u32 },
    /// A payload read started with no available bytes, or a discard ended early.
    EndOfInput,
    /// A payload read received some, but not all, required bytes.
    UnexpectedEndOfInput,
    /// The whole payload was consumed, but only the output prefix was copied.
    ShortBuffer { header: FrameHeader },
}

impl fmt::Display for ReadFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::IncompleteHeader | Self::EndOfInput => f.write_str("EOF"),
            Self::UnexpectedEndOfInput => f.write_str("unexpected EOF"),
            Self::ExceedsLimit { frame_len, max_size } => {
                write!(f, "frame header size {frame_len} exceeds reader limit of {max_size}")
            }
            Self::ShortBuffer { .. } => f.write_str("short buffer"),
        }
    }
}

impl Error for ReadFrameError {}

/// Errors while reading a DERP frame from a blocking stream.
#[derive(Debug)]
pub enum StreamReadFrameError {
    EndOfInput,
    UnexpectedEndOfInput,
    ExceedsLimit { frame_len: u32, max_size: u32 },
    ShortBuffer { header: FrameHeader },
    Allocation,
    Io(io::Error),
}

impl fmt::Display for StreamReadFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EndOfInput => f.write_str("EOF"),
            Self::UnexpectedEndOfInput => f.write_str("unexpected EOF"),
            Self::ExceedsLimit { frame_len, max_size } => {
                write!(f, "frame header size {frame_len} exceeds reader limit of {max_size}")
            }
            Self::ShortBuffer { .. } => f.write_str("short buffer"),
            Self::Allocation => f.write_str("unable to allocate DERP frame buffer"),
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl Error for StreamReadFrameError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::EndOfInput
            | Self::UnexpectedEndOfInput
            | Self::ExceedsLimit { .. }
            | Self::ShortBuffer { .. }
            | Self::Allocation => None,
        }
    }
}

fn read_full_from<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<(), StreamReadFrameError> {
    let mut received = 0;
    while received < buffer.len() {
        match reader.read(&mut buffer[received..]) {
            Ok(0) => {
                return Err(if received == 0 {
                    StreamReadFrameError::EndOfInput
                } else {
                    StreamReadFrameError::UnexpectedEndOfInput
                });
            }
            Ok(count) => received += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(StreamReadFrameError::Io(error)),
        }
    }
    Ok(())
}

fn read_frame_header_from<R: Read>(reader: &mut R) -> Result<FrameHeader, StreamReadFrameError> {
    let mut encoded_header = [0; FRAME_HEADER_LEN];
    read_full_from(reader, &mut encoded_header)?;
    Ok(FrameHeader {
        frame_type: FrameType(encoded_header[0]),
        frame_len: u32::from_be_bytes([encoded_header[1], encoded_header[2], encoded_header[3], encoded_header[4]]),
    })
}

fn reserve_frame_payload(payload_len: usize) -> Result<Vec<u8>, StreamReadFrameError> {
    let mut payload = Vec::new();
    payload.try_reserve_exact(payload_len).map_err(|_| StreamReadFrameError::Allocation)?;
    Ok(payload)
}

/// Reads one bounded DERP frame from a blocking stream, matching the pinned
/// fork's `readFrame` payload consumption and short-buffer behavior.
///
/// An over-limit frame consumes only its header. A short output buffer consumes
/// the rest of that frame before returning `ShortBuffer`, so the next read starts
/// at the following frame. This is synchronous `Read` I/O, not an async or
/// buffered connection implementation.
pub fn read_frame_from<R: Read>(
    reader: &mut R,
    max_size: u32,
    output: &mut [u8],
) -> Result<FrameHeader, StreamReadFrameError> {
    let header = read_frame_header_from(reader)?;
    if header.frame_len > max_size {
        return Err(StreamReadFrameError::ExceedsLimit { frame_len: header.frame_len, max_size });
    }

    let payload_len = header.frame_len as usize;
    let copy_len = payload_len.min(output.len());
    read_full_from(reader, &mut output[..copy_len])?;

    let mut remaining = payload_len - copy_len;
    let mut discard = [0u8; 8192];
    while remaining > 0 {
        let chunk_len = remaining.min(discard.len());
        match reader.read(&mut discard[..chunk_len]) {
            Ok(0) => return Err(StreamReadFrameError::EndOfInput),
            Ok(count) => remaining -= count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(StreamReadFrameError::Io(error)),
        }
    }
    if payload_len > copy_len {
        return Err(StreamReadFrameError::ShortBuffer { header });
    }
    Ok(header)
}

/// Reads one complete bounded DERP frame, allocating only the advertised
/// payload length after validating it against `max_size`. The header is already
/// consumed if allocation fails; in that case the payload remains unread.
pub fn read_frame_vec_from<R: Read>(
    reader: &mut R,
    max_size: u32,
) -> Result<(FrameHeader, Vec<u8>), StreamReadFrameError> {
    let header = read_frame_header_from(reader)?;
    if header.frame_len > max_size {
        return Err(StreamReadFrameError::ExceedsLimit { frame_len: header.frame_len, max_size });
    }
    let payload_len = header.frame_len as usize;
    let mut payload = reserve_frame_payload(payload_len)?;
    payload.resize(payload_len, 0);
    read_full_from(reader, &mut payload)?;
    Ok((header, payload))
}

/// Failure to append a complete frame to an output buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteFrameError {
    /// The payload exceeds the pinned fork's 10 MiB write limit.
    UnreasonablyLarge,
    /// Output buffer allocation failed; no frame bytes were appended.
    Allocation,
}

impl fmt::Display for WriteFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnreasonablyLarge => f.write_str("unreasonably large frame write"),
            Self::Allocation => f.write_str("unable to allocate DERP frame buffer"),
        }
    }
}

impl Error for WriteFrameError {}

/// Appends a frame header and payload, rejecting payloads over 10 MiB before
/// changing `output`, as in the fork's `WriteFrame` size check.
///
/// Unlike Go's buffered writer, this writes to a `Vec`, does not flush a stream,
/// and reports allocation failure without appending a partial frame.
pub fn write_frame(output: &mut Vec<u8>, frame_type: FrameType, payload: &[u8]) -> Result<(), WriteFrameError> {
    if payload.len() > MAX_FRAME_WRITE_SIZE {
        return Err(WriteFrameError::UnreasonablyLarge);
    }
    output.try_reserve(FRAME_HEADER_LEN + payload.len()).map_err(|_| WriteFrameError::Allocation)?;
    let header = FrameHeader { frame_type, frame_len: payload.len() as u32 };
    output.extend_from_slice(&header.encode());
    output.extend_from_slice(payload);
    Ok(())
}

/// Errors while writing and flushing a DERP frame to a blocking stream.
#[derive(Debug)]
pub enum StreamWriteFrameError {
    UnreasonablyLarge,
    Io(io::Error),
}

impl fmt::Display for StreamWriteFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnreasonablyLarge => f.write_str("unreasonably large frame write"),
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl Error for StreamWriteFrameError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::UnreasonablyLarge => None,
        }
    }
}

/// Writes a DERP frame to a blocking stream and flushes it, matching the
/// pinned fork's 10 MiB limit and `WriteFrame` flush boundary.
pub fn write_frame_to<W: Write>(
    writer: &mut W,
    frame_type: FrameType,
    payload: &[u8],
) -> Result<(), StreamWriteFrameError> {
    if payload.len() > MAX_FRAME_WRITE_SIZE {
        return Err(StreamWriteFrameError::UnreasonablyLarge);
    }
    let header = FrameHeader { frame_type, frame_len: payload.len() as u32 }.encode();
    writer.write_all(&header).map_err(StreamWriteFrameError::Io)?;
    writer.write_all(payload).map_err(StreamWriteFrameError::Io)?;
    writer.flush().map_err(StreamWriteFrameError::Io)
}

/// Writes and flushes one Ping frame with the fixed eight-byte payload.
///
/// The pinned fork serializes this operation with the client's write mutex; this
/// stateless helper does not synchronize concurrent users of the same writer.
pub fn write_ping_to<W: Write>(writer: &mut W, data: [u8; 8]) -> Result<(), StreamWriteFrameError> {
    write_frame_to(writer, FRAME_PING, &data)
}

/// Writes and flushes one Pong frame with the fixed eight-byte payload.
///
/// The pinned fork serializes this operation with the client's write mutex; this
/// stateless helper does not synchronize concurrent users of the same writer.
pub fn write_pong_to<W: Write>(writer: &mut W, data: [u8; 8]) -> Result<(), StreamWriteFrameError> {
    write_frame_to(writer, FRAME_PONG, &data)
}

/// The result of attempting one pinned-fork DERP `Client.Send` packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendPacketOutcome {
    Sent,
    /// The rate limiter denied the send; the Go client returns nil and writes nothing.
    Dropped,
}

/// An error from the pinned-fork DERP `Client.Send` packet path.
#[derive(Debug)]
pub enum SendPacketError {
    PacketTooBig { packet_len: usize },
    StreamWrite(StreamWriteFrameError),
}

impl fmt::Display for SendPacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PacketTooBig { packet_len } => write!(f, "derp.Send: packet too big: {packet_len}"),
            Self::StreamWrite(error) => write!(f, "derp.Send: {error}"),
        }
    }
}

impl Error for SendPacketError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::StreamWrite(error) => Some(error),
            Self::PacketTooBig { .. } => None,
        }
    }
}

/// An error from the pinned-fork DERP `Client.ForwardPacket` frame-write path.
#[derive(Debug)]
pub enum ForwardPacketError {
    PacketTooBig { packet_len: usize },
    MissingConnectionCloser,
    WatchdogStart(io::Error),
    StreamWrite(StreamWriteFrameError),
}

impl fmt::Display for ForwardPacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PacketTooBig { packet_len } => write!(f, "derp.ForwardPacket: packet too big: {packet_len}"),
            Self::MissingConnectionCloser => f.write_str("derp.ForwardPacket: connection close handle is required"),
            Self::WatchdogStart(error) => write!(f, "derp.ForwardPacket: failed to start write timeout: {error}"),
            Self::StreamWrite(error) => write!(f, "derp.ForwardPacket: {error}"),
        }
    }
}

impl Error for ForwardPacketError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::StreamWrite(error) => Some(error),
            Self::WatchdogStart(error) => Some(error),
            Self::PacketTooBig { .. } | Self::MissingConnectionCloser => None,
        }
    }
}

/// Writes and flushes one mesh ForwardPacket frame using the pinned fork's
/// 64 KiB packet limit, source/destination key order, and wrapping error text.
///
/// This stateless slice does not apply the Send rate limiter, own the shared
/// writer mutex, or provide Go's five-second close watchdog. Use
/// [`DerpSendWriter::forward_packet`] for the shared-writer client path.
pub fn forward_packet_to<W: Write>(
    writer: &mut W,
    source: NodePublic,
    destination: NodePublic,
    packet: &[u8],
) -> Result<(), ForwardPacketError> {
    if packet.len() > MAX_PACKET_SIZE {
        return Err(ForwardPacketError::PacketTooBig { packet_len: packet.len() });
    }

    let payload_len = 2 * KEY_LEN + packet.len();
    let header = FrameHeader { frame_type: FRAME_FORWARD_PACKET, frame_len: payload_len as u32 }.encode();
    let source_bytes = source.raw_bytes();
    let destination_bytes = destination.raw_bytes();
    write_send_segment(writer, &header).map_err(ForwardPacketError::StreamWrite)?;
    write_send_segment(writer, &source_bytes).map_err(ForwardPacketError::StreamWrite)?;
    write_send_segment(writer, &destination_bytes).map_err(ForwardPacketError::StreamWrite)?;
    write_send_segment(writer, packet).map_err(ForwardPacketError::StreamWrite)?;
    writer.flush().map_err(StreamWriteFrameError::Io).map_err(ForwardPacketError::StreamWrite)
}

/// A `NotePreferred` write error with the pinned Go error prefix.
#[derive(Debug)]
pub struct NotePreferredError(StreamWriteFrameError);

impl fmt::Display for NotePreferredError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "derp.NotePreferred: {}", self.0)
    }
}

impl Error for NotePreferredError {
    // The Go fork formats this error with `%v`, not `%w`; it does not unwrap.
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

/// Writes and flushes one packet using the pinned `Client.Send` size, rate, and
/// wire-length rules. The limiter charge includes the five-byte frame header;
/// the frame payload length is only the 32-byte destination key plus packet.
///
/// The Go client serializes this operation with every other writer method. This
/// helper does not own that shared mutex: callers must serialize it with their
/// Ping/Pong and other writes and pass the time sampled inside that critical section.
/// It issues one `Write` per header/key/packet segment and treats a short write as
/// `io.ErrShortWrite`. It does not model `bufio.Writer`'s internal
/// `AvailableBuffer` fast/slow path or coordinate with other writers.
pub fn send_packet_to<W: Write>(
    writer: &mut W,
    destination: NodePublic,
    packet: &[u8],
    limiter: Option<&mut DerpSendRateLimiter>,
    now: Instant,
) -> Result<SendPacketOutcome, SendPacketError> {
    if packet.len() > MAX_PACKET_SIZE {
        return Err(SendPacketError::PacketTooBig { packet_len: packet.len() });
    }

    if let Some(limiter) = limiter {
        let charged_len = FRAME_HEADER_LEN + KEY_LEN + packet.len();
        if !limiter.allow_n(now, charged_len) {
            return Ok(SendPacketOutcome::Dropped);
        }
    }

    let payload_len = KEY_LEN + packet.len();
    let header = FrameHeader { frame_type: FRAME_SEND_PACKET, frame_len: payload_len as u32 }.encode();
    let destination_bytes = destination.raw_bytes();
    write_send_segment(writer, &header).map_err(SendPacketError::StreamWrite)?;
    write_send_segment(writer, &destination_bytes).map_err(SendPacketError::StreamWrite)?;
    write_send_segment(writer, packet).map_err(SendPacketError::StreamWrite)?;
    writer.flush().map_err(StreamWriteFrameError::Io).map_err(SendPacketError::StreamWrite)?;
    Ok(SendPacketOutcome::Sent)
}

fn write_send_segment<W: Write>(writer: &mut W, bytes: &[u8]) -> Result<(), StreamWriteFrameError> {
    let written = writer.write(bytes).map_err(StreamWriteFrameError::Io)?;
    if written != bytes.len() {
        return Err(StreamWriteFrameError::Io(io::Error::new(io::ErrorKind::WriteZero, "short write")));
    }
    Ok(())
}

/// A connection close operation that can interrupt a blocked writer without
/// acquiring the DERP writer mutex. The callback's close error is intentionally
/// ignored, like the pinned fork's `net.Conn.Close` call.
pub type DerpConnectionCloser = Arc<dyn Fn() + Send + Sync + 'static>;

struct ForwardPacketWatchdog {
    cancel: mpsc::SyncSender<()>,
}

impl ForwardPacketWatchdog {
    fn start(timeout: Duration, close_connection: DerpConnectionCloser) -> io::Result<Self> {
        let (cancel, canceled) = mpsc::sync_channel(1);
        let handle = std::thread::Builder::new().spawn(move || {
            if canceled.recv_timeout(timeout).is_err() {
                close_connection();
            }
        })?;
        drop(handle);
        Ok(Self { cancel })
    }
}

impl Drop for ForwardPacketWatchdog {
    fn drop(&mut self) {
        let _ = self.cancel.send(());
    }
}

struct DerpSendWriterState<W> {
    writer: W,
    limiter: Option<DerpSendRateLimiter>,
}

/// Owns the DERP Send/ForwardPacket/Ping/Pong writer paths under one shared write lock.
///
/// This mirrors the pinned fork's `Client.wmu` for `Send`, `ForwardPacket`, `Ping`,
/// and `Pong`: frame writes are serialized, `Send` rate-limit checks and its send
/// timestamp are sampled under the lock, and packet-size checks happen before it.
/// `forward_packet` requires an out-of-lock connection closer and arms the pinned
/// five-second watchdog after acquiring the lock. Route every operation on the
/// underlying writer through this owner to avoid byte-level frame interleaving.
/// The complete client lifecycle and Go `bufio.Writer.AvailableBuffer` internals
/// are not implemented.
pub struct DerpSendWriter<W> {
    state: Mutex<DerpSendWriterState<W>>,
    connection_closer: Option<DerpConnectionCloser>,
}

impl<W> DerpSendWriter<W> {
    /// Takes ownership of the stream writer and the optional send-rate limiter.
    ///
    /// This protocol-only constructor has no connection close handle; its
    /// `forward_packet` method fails closed. Use `new_with_connection_closer` for
    /// a live connection that needs the pinned write-timeout behavior.
    pub fn new(writer: W, limiter: Option<DerpSendRateLimiter>) -> Self {
        Self { state: Mutex::new(DerpSendWriterState { writer, limiter }), connection_closer: None }
    }

    /// Constructs a writer whose close callback can interrupt a blocked write.
    ///
    /// The callback must close the underlying connection independently of the
    /// writer mutex and should return promptly. The callback is invoked only by a
    /// timed-out `ForwardPacket`.
    pub fn new_with_connection_closer(
        writer: W,
        limiter: Option<DerpSendRateLimiter>,
        connection_closer: DerpConnectionCloser,
    ) -> Self {
        Self { state: Mutex::new(DerpSendWriterState { writer, limiter }), connection_closer: Some(connection_closer) }
    }
}

impl<W: Write> DerpSendWriter<W> {
    fn lock_state(&self) -> MutexGuard<'_, DerpSendWriterState<W>> {
        // Go's sync.Mutex is not poisoned. Recover Rust's mutex guard so a prior
        // panic does not permanently prevent the same unlock/relock behavior.
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Sends a packet while holding the same lock used by Ping and Pong writes.
    pub fn send_packet(&self, destination: NodePublic, packet: &[u8]) -> Result<SendPacketOutcome, SendPacketError> {
        if packet.len() > MAX_PACKET_SIZE {
            return Err(SendPacketError::PacketTooBig { packet_len: packet.len() });
        }
        let mut state = self.lock_state();
        let now = Instant::now();
        let DerpSendWriterState { writer, limiter } = &mut *state;
        send_packet_to(writer, destination, packet, limiter.as_mut(), now)
    }

    /// Writes one ForwardPacket under the shared mutex and arms the five-second watchdog.
    ///
    /// The packet-size check occurs before acquiring the lock, like the Go client.
    /// A connection closer is mandatory; missing handles and watchdog startup
    /// failures return without writing. The close callback runs independently of
    /// this mutex so it can interrupt a blocked write.
    pub fn forward_packet(
        &self,
        source: NodePublic,
        destination: NodePublic,
        packet: &[u8],
    ) -> Result<(), ForwardPacketError> {
        self.forward_packet_with_timeout(source, destination, packet, FORWARD_PACKET_WRITE_TIMEOUT)
    }

    fn forward_packet_with_timeout(
        &self,
        source: NodePublic,
        destination: NodePublic,
        packet: &[u8],
        timeout: Duration,
    ) -> Result<(), ForwardPacketError> {
        if packet.len() > MAX_PACKET_SIZE {
            return Err(ForwardPacketError::PacketTooBig { packet_len: packet.len() });
        }
        let close_connection =
            self.connection_closer.as_ref().cloned().ok_or(ForwardPacketError::MissingConnectionCloser)?;
        let mut state = self.lock_state();
        let watchdog =
            ForwardPacketWatchdog::start(timeout, close_connection).map_err(ForwardPacketError::WatchdogStart)?;
        let result = forward_packet_to(&mut state.writer, source, destination, packet);
        drop(watchdog);
        result
    }

    /// Sends a Ping frame without applying the packet rate limiter.
    pub fn send_ping(&self, data: [u8; 8]) -> Result<(), StreamWriteFrameError> {
        let mut state = self.lock_state();
        write_ping_to(&mut state.writer, data)
    }

    /// Sends a Pong frame without applying the packet rate limiter.
    pub fn send_pong(&self, data: [u8; 8]) -> Result<(), StreamWriteFrameError> {
        let mut state = self.lock_state();
        write_pong_to(&mut state.writer, data)
    }

    /// Sends a preferred-server note under the shared lock, wrapping write
    /// failures with `derp.NotePreferred` without exposing the source error.
    pub fn note_preferred(&self, preferred: bool) -> Result<(), NotePreferredError> {
        let mut state = self.lock_state();
        let payload = [u8::from(preferred)];
        write_frame_to(&mut state.writer, FRAME_NOTE_PREFERRED, &payload).map_err(NotePreferredError)
    }

    /// Requests mesh connection-change notifications under the shared lock.
    /// As in the Go client, this sends the request without locally checking a mesh key.
    pub fn watch_connection_changes(&self) -> Result<(), StreamWriteFrameError> {
        let mut state = self.lock_state();
        write_frame_to(&mut state.writer, FRAME_WATCH_CONNS, &[])
    }

    /// Requests closure of a peer under the shared lock. Authorization is enforced
    /// by the DERP server; the Go client does not perform a local mesh-key check.
    pub fn close_peer(&self, target: NodePublic) -> Result<(), StreamWriteFrameError> {
        let mut state = self.lock_state();
        let target_bytes = target.raw_bytes();
        write_frame_to(&mut state.writer, FRAME_CLOSE_PEER, &target_bytes)
    }

    /// Applies a decoded ServerInfo message like the pinned fork's
    /// `Client.setSendRateLimiter`, under the same lock used by packet writes.
    /// A zero rate removes the limiter; any nonzero rate creates a fresh limiter
    /// with its initial burst tokens. This does not parse or receive ServerInfo.
    pub fn set_rate_limiter_from_server_info(&self, server_info: ServerInfoMessage) {
        let mut state = self.lock_state();
        state.limiter = server_info.rate_limiter_config().map(DerpSendRateLimiter::new);
    }
}

/// Reads a bounded DERP frame into `output`, consuming discarded payload bytes
/// when the output is shorter than the advertised frame, matching Go `readFrame`.
///
/// Missing bytes are treated as end-of-input; this slice interface cannot model
/// arbitrary I/O errors or wait for more data. An over-limit error consumes only
/// the header; callers must not continue parsing that payload as a fresh frame.
pub fn read_frame(input: &mut &[u8], max_size: u32, output: &mut [u8]) -> Result<FrameHeader, ReadFrameError> {
    let header = read_frame_header(input).map_err(|_| ReadFrameError::IncompleteHeader)?;
    if header.frame_len > max_size {
        return Err(ReadFrameError::ExceedsLimit { frame_len: header.frame_len, max_size });
    }

    let frame_len = header.frame_len as usize;
    let copy_len = frame_len.min(output.len());
    let available = copy_len.min(input.len());
    output[..available].copy_from_slice(&input[..available]);
    *input = &input[available..];
    if available < copy_len {
        return Err(if available == 0 { ReadFrameError::EndOfInput } else { ReadFrameError::UnexpectedEndOfInput });
    }
    let discard = frame_len - copy_len;
    if input.len() < discard {
        *input = &[];
        return Err(ReadFrameError::EndOfInput);
    }
    *input = &input[discard..];
    if discard != 0 {
        return Err(ReadFrameError::ShortBuffer { header });
    }
    Ok(header)
}

/// Failure to parse a DERP server-key greeting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerGreetingError {
    Read(ReadFrameError),
    Invalid,
}

impl fmt::Display for ServerGreetingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(err) => err.fmt(f),
            Self::Invalid => f.write_str("invalid server greeting"),
        }
    }
}

impl Error for ServerGreetingError {}

/// Parses the server-key greeting using the fork's 1024-byte frame limit.
/// Extra payload bytes are consumed and ignored, as in `recvServerKey`.
///
/// This parser accepts a zero public key like the fork's parser. It does not
/// authenticate the server, establish encryption, or authorize a connection.
pub fn read_server_greeting(input: &mut &[u8]) -> Result<NodePublic, ServerGreetingError> {
    let mut body = [0u8; 40];
    let header = match read_frame(input, 1 << 10, &mut body) {
        Ok(header) | Err(ReadFrameError::ShortBuffer { header }) => header,
        Err(err) => return Err(ServerGreetingError::Read(err)),
    };
    if header.frame_len < body.len() as u32 || header.frame_type != FRAME_SERVER_KEY || body[..MAGIC.len()] != MAGIC {
        return Err(ServerGreetingError::Invalid);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&body[MAGIC.len()..]);
    Ok(NodePublic::from_raw32(key))
}

/// Client metadata encoded by the pinned fork before NaCl box sealing.
///
/// This type only serializes the plaintext JSON; it does not seal or transmit a
/// DERP ClientInfo frame. Its field omission, order, and string escaping match
/// Go `encoding/json` for the corresponding fork `derp.ClientInfo` fields.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct ClientInfo {
    /// Zero means omitted, matching the fork's `meshKey,omitzero` tag.
    pub mesh_key: [u8; 32],
    /// Zero means omitted, matching the fork's `version,omitempty` tag.
    pub version: isize,
    /// Always emitted, matching the untagged exported Go field.
    pub can_ack_pings: bool,
    /// False means omitted, matching `json:",omitempty"`.
    pub is_prober: bool,
    /// Empty means omitted, matching `json:",omitempty"`.
    pub app_name: String,
}

impl ClientInfo {
    /// Encodes the plaintext exactly in the pinned Go fork's struct field order.
    pub fn to_json(&self) -> String {
        let mut output = String::from("{");
        let mut first = true;
        if self.mesh_key.iter().any(|byte| *byte != 0) {
            push_json_field_name(&mut output, &mut first, "meshKey");
            output.push('"');
            const HEX: &[u8; 16] = b"0123456789abcdef";
            for byte in self.mesh_key {
                output.push(HEX[(byte >> 4) as usize] as char);
                output.push(HEX[(byte & 0x0f) as usize] as char);
            }
            output.push('"');
        }
        if self.version != 0 {
            push_json_field_name(&mut output, &mut first, "version");
            output.push_str(&self.version.to_string());
        }
        push_json_field_name(&mut output, &mut first, "CanAckPings");
        output.push_str(if self.can_ack_pings { "true" } else { "false" });
        if self.is_prober {
            push_json_field_name(&mut output, &mut first, "IsProber");
            output.push_str("true");
        }
        if !self.app_name.is_empty() {
            push_json_field_name(&mut output, &mut first, "AppName");
            push_go_json_string(&mut output, &self.app_name);
        }
        output.push('}');
        output
    }
}

/// Failure to build a complete ClientInfo frame in memory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientInfoFrameError {
    Box(NodeBoxError),
    Allocation,
    Frame(WriteFrameError),
}

impl fmt::Display for ClientInfoFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Box(error) => error.fmt(f),
            Self::Allocation => f.write_str("unable to allocate DERP ClientInfo frame buffer"),
            Self::Frame(error) => error.fmt(f),
        }
    }
}

impl Error for ClientInfoFrameError {}

/// Builds a complete ClientInfo frame in memory using a fresh OS-CSPRNG nonce.
///
/// The result includes the five-byte frame header, sender's raw 32-byte node
/// public key, and NaCl-boxed ClientInfo JSON. It does not write to or flush a
/// stream, authenticate the server greeting, or manage a DERP connection.
pub fn build_client_info_frame(
    private: &NodePrivate,
    server: &NodePublic,
    info: &ClientInfo,
) -> Result<Vec<u8>, ClientInfoFrameError> {
    let sender = private.public().map_err(|_| ClientInfoFrameError::Box(NodeBoxError::ZeroPrivateKey))?;
    let plaintext = info.to_json();
    let sealed = private.seal_to(server, plaintext.as_bytes()).map_err(ClientInfoFrameError::Box)?;
    encode_client_info_frame(sender, &sealed)
}

/// Observable stages of the pinned fork's DERP client key exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DerpClientHandshakeState {
    AwaitingServerKey,
    ReadyToSendClientInfo,
    AwaitingClientInfoWrite,
    Ready,
}

/// Errors from the in-memory DERP client key-exchange state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DerpClientHandshakeError {
    ZeroPrivateKey,
    ZeroServerPublicKey,
    InvalidState { expected: DerpClientHandshakeState, actual: DerpClientHandshakeState },
    ServerGreeting(ServerGreetingError),
    ClientInfo(ClientInfoFrameError),
}

impl fmt::Display for DerpClientHandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroPrivateKey => f.write_str("DERP client private key is zero"),
            Self::ZeroServerPublicKey => f.write_str("DERP server public key is zero"),
            Self::InvalidState { expected, actual } => {
                write!(f, "invalid DERP client handshake state: expected {expected:?}, got {actual:?}")
            }
            Self::ServerGreeting(error) => error.fmt(f),
            Self::ClientInfo(error) => error.fmt(f),
        }
    }
}

impl Error for DerpClientHandshakeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ServerGreeting(error) => Some(error),
            Self::ClientInfo(error) => Some(error),
            Self::ZeroPrivateKey | Self::ZeroServerPublicKey | Self::InvalidState { .. } => None,
        }
    }
}

/// Errors from the blocking DERP client key exchange over a stream.
#[derive(Debug)]
pub enum DerpClientStreamHandshakeError {
    Handshake(DerpClientHandshakeError),
    ServerGreetingRead(StreamReadFrameError),
    InvalidServerGreeting,
    StreamWrite(StreamWriteFrameError),
}

impl fmt::Display for DerpClientStreamHandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Handshake(error) => error.fmt(f),
            Self::ServerGreetingRead(error) => error.fmt(f),
            Self::InvalidServerGreeting => f.write_str("invalid server greeting"),
            Self::StreamWrite(error) => error.fmt(f),
        }
    }
}

impl Error for DerpClientStreamHandshakeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Handshake(error) => Some(error),
            Self::ServerGreetingRead(error) => Some(error),
            Self::StreamWrite(error) => Some(error),
            Self::InvalidServerGreeting => None,
        }
    }
}

#[derive(Clone, Copy)]
enum DerpClientHandshakePhase {
    AwaitingServerKey,
    ReadyToSendClientInfo(NodePublic),
    AwaitingClientInfoWrite(NodePublic),
    Ready(NodePublic),
}

/// Orders the key-exchange steps in the pinned fork's `derp.NewClient` without
/// owning or performing network I/O.
///
/// A known nonzero server key skips the greeting; a zero configured key is a
/// no-op, as in `ServerPublicKey`. With no configured key, callers must supply a
/// complete greeting frame. The protocol version is fixed to
/// [`PROTOCOL_VERSION`], as the Go client does rather than exposing it as an
/// option. After obtaining the ClientInfo frame, callers must fully write and
/// flush it before calling [`Self::client_info_sent`]. Drop this value if that
/// transport operation fails. The stream helpers below perform only this initial
/// key exchange; they do not authenticate the server, create a socket, receive
/// messages, or manage the ongoing connection lifecycle.
pub struct DerpClientHandshake {
    private_key: NodePrivate,
    client_info: ClientInfo,
    phase: DerpClientHandshakePhase,
}

impl DerpClientHandshake {
    /// Starts the key exchange with an optional already-known server key.
    pub fn new(
        private_key: NodePrivate,
        server_public_key: Option<NodePublic>,
        mut client_info: ClientInfo,
    ) -> Result<Self, DerpClientHandshakeError> {
        if private_key.is_zero() {
            return Err(DerpClientHandshakeError::ZeroPrivateKey);
        }
        client_info.version = PROTOCOL_VERSION;
        let phase = match server_public_key.filter(|key| !key.is_zero()) {
            Some(key) => DerpClientHandshakePhase::ReadyToSendClientInfo(key),
            None => DerpClientHandshakePhase::AwaitingServerKey,
        };
        Ok(Self { private_key, client_info, phase })
    }

    /// Returns the externally observable handshake stage.
    pub fn state(&self) -> DerpClientHandshakeState {
        match self.phase {
            DerpClientHandshakePhase::AwaitingServerKey => DerpClientHandshakeState::AwaitingServerKey,
            DerpClientHandshakePhase::ReadyToSendClientInfo(_) => DerpClientHandshakeState::ReadyToSendClientInfo,
            DerpClientHandshakePhase::AwaitingClientInfoWrite(_) => DerpClientHandshakeState::AwaitingClientInfoWrite,
            DerpClientHandshakePhase::Ready(_) => DerpClientHandshakeState::Ready,
        }
    }

    /// Returns the server key once configured or parsed from a greeting.
    pub fn server_public_key(&self) -> Option<NodePublic> {
        match self.phase {
            DerpClientHandshakePhase::AwaitingServerKey => None,
            DerpClientHandshakePhase::ReadyToSendClientInfo(key)
            | DerpClientHandshakePhase::AwaitingClientInfoWrite(key)
            | DerpClientHandshakePhase::Ready(key) => Some(key),
        }
    }

    /// Parses the server greeting and advances to ClientInfo generation.
    ///
    /// This is permitted only when no nonzero server key was configured. The
    /// parser consumes bytes according to the pinned frame reader; it cannot
    /// wait for more bytes or represent transport errors.
    pub fn receive_server_greeting(&mut self, input: &mut &[u8]) -> Result<(), DerpClientHandshakeError> {
        if !matches!(self.phase, DerpClientHandshakePhase::AwaitingServerKey) {
            return Err(DerpClientHandshakeError::InvalidState {
                expected: DerpClientHandshakeState::AwaitingServerKey,
                actual: self.state(),
            });
        }
        let key = read_server_greeting(input).map_err(DerpClientHandshakeError::ServerGreeting)?;
        if key.is_zero() {
            return Err(DerpClientHandshakeError::ZeroServerPublicKey);
        }
        self.phase = DerpClientHandshakePhase::ReadyToSendClientInfo(key);
        Ok(())
    }

    /// Builds the ClientInfo frame once the server key is known.
    ///
    /// On entropy or encoding failure, the frame is not yielded and the state
    /// remains retryable. A successful return advances the state so a second
    /// frame cannot accidentally be generated before the first is sent.
    pub fn build_client_info_frame(&mut self) -> Result<Vec<u8>, DerpClientHandshakeError> {
        let DerpClientHandshakePhase::ReadyToSendClientInfo(server_key) = self.phase else {
            return Err(DerpClientHandshakeError::InvalidState {
                expected: DerpClientHandshakeState::ReadyToSendClientInfo,
                actual: self.state(),
            });
        };
        let frame = build_client_info_frame(&self.private_key, &server_key, &self.client_info)
            .map_err(DerpClientHandshakeError::ClientInfo)?;
        self.phase = DerpClientHandshakePhase::AwaitingClientInfoWrite(server_key);
        Ok(frame)
    }

    /// Marks the ClientInfo frame sent after the caller confirms full write and
    /// flush; this performs no I/O itself.
    pub fn client_info_sent(&mut self) -> Result<(), DerpClientHandshakeError> {
        let DerpClientHandshakePhase::AwaitingClientInfoWrite(server_key) = self.phase else {
            return Err(DerpClientHandshakeError::InvalidState {
                expected: DerpClientHandshakeState::AwaitingClientInfoWrite,
                actual: self.state(),
            });
        };
        self.phase = DerpClientHandshakePhase::Ready(server_key);
        Ok(())
    }

    /// Reads a server greeting from a blocking stream when the server key is not
    /// already configured.
    pub fn receive_server_greeting_from<R: Read>(
        &mut self,
        reader: &mut R,
    ) -> Result<(), DerpClientStreamHandshakeError> {
        if !matches!(self.phase, DerpClientHandshakePhase::AwaitingServerKey) {
            return Err(DerpClientStreamHandshakeError::Handshake(DerpClientHandshakeError::InvalidState {
                expected: DerpClientHandshakeState::AwaitingServerKey,
                actual: self.state(),
            }));
        }
        let mut body = [0; 40];
        let header = match read_frame_from(reader, 1 << 10, &mut body) {
            Ok(header) | Err(StreamReadFrameError::ShortBuffer { header }) => header,
            Err(error) => return Err(DerpClientStreamHandshakeError::ServerGreetingRead(error)),
        };
        if header.frame_len < body.len() as u32 || header.frame_type != FRAME_SERVER_KEY || body[..MAGIC.len()] != MAGIC
        {
            return Err(DerpClientStreamHandshakeError::InvalidServerGreeting);
        }
        let mut key = [0; 32];
        key.copy_from_slice(&body[MAGIC.len()..]);
        let server_key = NodePublic::from_raw32(key);
        if server_key.is_zero() {
            return Err(DerpClientStreamHandshakeError::Handshake(DerpClientHandshakeError::ZeroServerPublicKey));
        }
        self.phase = DerpClientHandshakePhase::ReadyToSendClientInfo(server_key);
        Ok(())
    }

    /// Writes and flushes the encrypted ClientInfo frame to a blocking stream.
    ///
    /// If writing or flushing fails, the stage remains pending and this
    /// handshake must be dropped rather than retried on a possibly partial
    /// stream.
    pub fn send_client_info_to<W: Write>(&mut self, writer: &mut W) -> Result<(), DerpClientStreamHandshakeError> {
        let frame = self.build_client_info_frame().map_err(DerpClientStreamHandshakeError::Handshake)?;
        writer
            .write_all(&frame)
            .map_err(|error| DerpClientStreamHandshakeError::StreamWrite(StreamWriteFrameError::Io(error)))?;
        writer
            .flush()
            .map_err(|error| DerpClientStreamHandshakeError::StreamWrite(StreamWriteFrameError::Io(error)))?;
        self.client_info_sent().map_err(DerpClientStreamHandshakeError::Handshake)
    }

    /// Performs the initial pinned-fork DERP key exchange on one blocking
    /// read/write stream: optionally reads ServerKey, then writes and flushes
    /// ClientInfo. It returns at the point `derp.NewClient` would return, without
    /// receiving ServerInfo or starting packet/message processing.
    pub fn perform_key_exchange<RW: Read + Write>(
        &mut self,
        stream: &mut RW,
    ) -> Result<(), DerpClientStreamHandshakeError> {
        if matches!(self.phase, DerpClientHandshakePhase::AwaitingServerKey) {
            self.receive_server_greeting_from(stream)?;
        }
        self.send_client_info_to(stream)
    }
}

#[cfg(test)]
fn build_client_info_frame_with_nonce(
    private: &NodePrivate,
    server: &NodePublic,
    info: &ClientInfo,
    nonce: &[u8; 24],
) -> Result<Vec<u8>, ClientInfoFrameError> {
    let sender = private.public().map_err(|_| ClientInfoFrameError::Box(NodeBoxError::ZeroPrivateKey))?;
    let plaintext = info.to_json();
    let sealed = private.seal_to_with_nonce(server, plaintext.as_bytes(), nonce).map_err(ClientInfoFrameError::Box)?;
    encode_client_info_frame(sender, &sealed)
}

fn encode_client_info_frame(sender: NodePublic, sealed: &[u8]) -> Result<Vec<u8>, ClientInfoFrameError> {
    let payload_len = 32usize.checked_add(sealed.len()).ok_or(ClientInfoFrameError::Allocation)?;
    let mut payload = Vec::new();
    payload.try_reserve_exact(payload_len).map_err(|_| ClientInfoFrameError::Allocation)?;
    payload.extend_from_slice(&sender.raw_bytes());
    payload.extend_from_slice(sealed);

    let mut frame = Vec::new();
    write_frame(&mut frame, FRAME_CLIENT_INFO, &payload).map_err(ClientInfoFrameError::Frame)?;
    Ok(frame)
}

/// NaCl box nonce size used by DERP ServerInfo payloads.
pub const SERVER_INFO_NONCE_LEN: usize = 24;
/// Maximum plaintext ServerInfo size accepted by the pinned fork.
pub const MAX_SERVER_INFO_JSON_LEN: usize = 1 << 20;
/// Maximum encrypted ServerInfo payload accepted by the pinned fork.
pub const MAX_SERVER_INFO_PAYLOAD_LEN: usize = SERVER_INFO_NONCE_LEN + MAX_SERVER_INFO_JSON_LEN;

/// The numeric rate limits carried by the pinned fork's DERP ServerInfo JSON.
///
/// The decoder preserves Go's ASCII case-insensitive field matching, duplicate
/// field order, null-as-no-op behavior, and signed 64-bit integer range. It
/// rejects non-ASCII field names rather than silently misreading Go's Unicode
/// simple-fold matches; malformed UTF-8 and Go's exact JSON error wording also
/// intentionally remain outside this parser's compatibility claim. The `i64`
/// values match Go `int` on 64-bit targets; 32-bit integer overflow behavior is
/// outside this slice.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ServerInfo {
    pub version: i64,
    pub token_bucket_bytes_per_second: i64,
    pub token_bucket_bytes_burst: i64,
}

/// The message shape that the pinned fork's `Client.Recv` returns for ServerInfo.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ServerInfoMessage {
    pub token_bucket_bytes_per_second: i64,
    pub token_bucket_bytes_burst: i64,
}

/// Configuration passed to the pinned fork's `rate.NewLimiter` call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendRateLimiterConfig {
    pub bytes_per_second: i64,
    pub burst: i64,
}

/// Pure Rust model of the pinned `golang.org/x/time/rate@v0.15.0` limiter.
///
/// The owning DERP send path must serialize calls, as the Go client does with
/// its writer mutex. This object models `NewLimiter`'s initial burst and
/// `AllowN` only; callers still supply the exact request size and monotonic time.
#[derive(Clone, Debug)]
pub struct DerpSendRateLimiter {
    bytes_per_second: f64,
    burst: i64,
    tokens: f64,
    last: Option<Instant>,
}

impl DerpSendRateLimiter {
    /// Creates a limiter with the pinned Go implementation's initial token count.
    pub fn new(config: SendRateLimiterConfig) -> Self {
        Self {
            bytes_per_second: config.bytes_per_second as f64,
            burst: config.burst,
            tokens: config.burst as f64,
            last: None,
        }
    }

    /// Mirrors `AllowN(now, n)` for non-negative request sizes.
    ///
    /// The Go implementation leaves state unchanged on a denied request,
    /// clamps elapsed duration to `time.Duration`'s maximum, and truncates a
    /// positive wait shorter than one nanosecond to zero. Those details are
    /// observable at burst and very-high-rate boundaries.
    pub fn allow_n(&mut self, now: Instant, n: usize) -> bool {
        let mut tokens = self.tokens;
        if let Some(last) = self.last {
            let effective_last = if now < last { now } else { last };
            let elapsed_nanos = now.duration_since(effective_last).as_nanos().min(i64::MAX as u128) as i64;
            if self.bytes_per_second > 0.0 {
                let elapsed_seconds = elapsed_nanos as f64 / 1_000_000_000.0;
                tokens += elapsed_seconds * self.bytes_per_second;
            }
        }

        let burst_as_tokens = self.burst as f64;
        if tokens > burst_as_tokens {
            tokens = burst_as_tokens;
        }
        let within_burst = i64::try_from(n).is_ok_and(|request| request <= self.burst);
        let tokens_after_request = tokens - n as f64;
        let wait_is_zero = if tokens_after_request < 0.0 {
            if self.bytes_per_second <= 0.0 {
                false
            } else {
                let wait_nanos = (-tokens_after_request / self.bytes_per_second) * 1_000_000_000.0;
                wait_nanos < 1.0
            }
        } else {
            true
        };

        if !within_burst || !wait_is_zero {
            return false;
        }

        self.last = Some(now);
        self.tokens = tokens_after_request;
        true
    }
}

impl ServerInfo {
    /// Drops the JSON version field and produces the `Client.Recv` message.
    pub fn into_message(self) -> ServerInfoMessage {
        ServerInfoMessage {
            token_bucket_bytes_per_second: self.token_bucket_bytes_per_second,
            token_bucket_bytes_burst: self.token_bucket_bytes_burst,
        }
    }
}

impl ServerInfoMessage {
    /// Mirrors `setSendRateLimiter`: zero rate disables the limiter; any nonzero
    /// rate creates a limiter with the exact supplied rate and burst values.
    /// This accessor maps configuration only; it does not instantiate
    /// [`DerpSendRateLimiter`].
    pub fn rate_limiter_config(self) -> Option<SendRateLimiterConfig> {
        if self.token_bucket_bytes_per_second == 0 {
            None
        } else {
            Some(SendRateLimiterConfig {
                bytes_per_second: self.token_bucket_bytes_per_second,
                burst: self.token_bucket_bytes_burst,
            })
        }
    }
}

/// A DERP PeerGone message returned by the pinned fork's `Client.Recv`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerGoneMessage {
    pub peer: NodePublic,
    /// The first optional reason byte; absent wire values map to zero.
    pub reason: u8,
}

/// A DERP PeerPresent message returned by the pinned fork's `Client.Recv`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerPresentMessage {
    pub key: NodePublic,
    /// `None` represents Go's invalid zero-value `netip.AddrPort` when omitted.
    pub ip_port: Option<SocketAddr>,
    /// The optional first flags byte; absent wire values map to zero.
    pub flags: u8,
}

/// An incoming packet from a DERP peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedPacket {
    pub source: NodePublic,
    pub data: Vec<u8>,
}

/// The raw Health frame body. Bytes are preserved, including invalid UTF-8 that
/// the Go implementation can retain in its string value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthMessage {
    pub problem: Vec<u8>,
}

/// Advisory reconnect timing announced by a DERP server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerRestartingMessage {
    pub reconnect_in: Duration,
    pub try_for: Duration,
}

/// One message type routed by the pinned fork's `Client.Recv`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceivedMessage {
    ServerInfo(ServerInfoMessage),
    KeepAlive,
    PeerGone(PeerGoneMessage),
    PeerPresent(PeerPresentMessage),
    ReceivedPacket(ReceivedPacket),
    Ping([u8; 8]),
    Pong([u8; 8]),
    Health(HealthMessage),
    ServerRestarting(ServerRestartingMessage),
}

impl<'de> Deserialize<'de> for ServerInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ServerInfoVisitor;

        impl<'de> Visitor<'de> for ServerInfoVisitor {
            type Value = ServerInfo;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a DERP ServerInfo object or null")
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(ServerInfo::default())
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut info = ServerInfo::default();
                while let Some(field) = map.next_key::<String>()? {
                    if !field.is_ascii() {
                        return Err(de::Error::custom("non-ASCII ServerInfo field names are unsupported"));
                    }
                    if field.eq_ignore_ascii_case("version") {
                        if let Some(value) = map.next_value::<Option<i64>>()? {
                            info.version = value;
                        }
                    } else if field.eq_ignore_ascii_case("TokenBucketBytesPerSecond") {
                        if let Some(value) = map.next_value::<Option<i64>>()? {
                            info.token_bucket_bytes_per_second = value;
                        }
                    } else if field.eq_ignore_ascii_case("TokenBucketBytesBurst") {
                        if let Some(value) = map.next_value::<Option<i64>>()? {
                            info.token_bucket_bytes_burst = value;
                        }
                    } else {
                        let _: IgnoredAny = map.next_value()?;
                    }
                }
                Ok(info)
            }
        }

        deserializer.deserialize_any(ServerInfoVisitor)
    }
}

/// Errors while validating and opening an encrypted DERP ServerInfo payload.
#[derive(Debug)]
pub enum ServerInfoError {
    ShortFrame { got: usize },
    LongFrame { got: usize, max: usize },
    Box(NodeBoxError),
    Json(serde_json::Error),
}

impl fmt::Display for ServerInfoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortFrame { .. } => f.write_str("short serverInfo frame"),
            Self::LongFrame { .. } => f.write_str("long serverInfo frame"),
            Self::Box(error) => write!(f, "failed to open DERP ServerInfo box: {error}"),
            Self::Json(error) => write!(f, "invalid JSON: {error}"),
        }
    }
}

impl Error for ServerInfoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Box(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::ShortFrame { .. } | Self::LongFrame { .. } => None,
        }
    }
}

/// Opens and parses a DERP ServerInfo encrypted payload (without its 5-byte
/// frame header), matching the pinned fork's nonce/size checks and box layout.
///
/// Authentication is checked before JSON parsing, so unauthenticated plaintext
/// is never returned. This helper does not read a frame from a stream, validate
/// the DERP greeting, establish connection state, or update a rate limiter.
pub fn parse_server_info_payload(
    client_private: &NodePrivate,
    server_public: &NodePublic,
    payload: &[u8],
) -> Result<ServerInfo, ServerInfoError> {
    if payload.len() < SERVER_INFO_NONCE_LEN {
        return Err(ServerInfoError::ShortFrame { got: payload.len() });
    }
    if payload.len() > MAX_SERVER_INFO_PAYLOAD_LEN {
        return Err(ServerInfoError::LongFrame { got: payload.len(), max: MAX_SERVER_INFO_PAYLOAD_LEN });
    }
    let plaintext = client_private.open_from(server_public, payload).map_err(ServerInfoError::Box)?;
    serde_json::from_slice(&plaintext).map_err(ServerInfoError::Json)
}

/// Failures while decoding one complete in-memory ServerInfo DERP frame.
#[derive(Debug)]
pub enum ServerInfoFrameError {
    IncompleteHeader,
    Oversized { frame_len: u32, max_size: usize },
    IncompletePayload { expected: usize, got: usize },
    UnexpectedType { got: FrameType },
    Payload(ServerInfoError),
}

impl fmt::Display for ServerInfoFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompleteHeader => f.write_str("EOF"),
            Self::Oversized { frame_len, .. } => write!(f, "unexpectedly large frame of {frame_len} bytes returned"),
            Self::IncompletePayload { got: 0, .. } => f.write_str("EOF"),
            Self::IncompletePayload { .. } => f.write_str("unexpected EOF"),
            Self::UnexpectedType { got } => {
                write!(f, "bad frame type 0x{:X}, want 0x{:X}", got.0, FRAME_SERVER_INFO.0)
            }
            Self::Payload(error) => error.fmt(f),
        }
    }
}

impl Error for ServerInfoFrameError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Payload(error) => Some(error),
            Self::IncompleteHeader
            | Self::Oversized { .. }
            | Self::IncompletePayload { .. }
            | Self::UnexpectedType { .. } => None,
        }
    }
}

/// Errors while reading and parsing one ServerInfo frame from a blocking stream.
#[derive(Debug)]
pub enum StreamServerInfoError {
    Read(StreamReadFrameError),
    Oversized { frame_len: u32 },
    UnexpectedType { got: FrameType },
    Payload(ServerInfoError),
}

impl fmt::Display for StreamServerInfoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(error) => error.fmt(f),
            Self::Oversized { frame_len } => write!(f, "unexpectedly large frame of {frame_len} bytes returned"),
            Self::UnexpectedType { got } => {
                write!(f, "bad frame type 0x{:X}, want 0x{:X}", got.0, FRAME_SERVER_INFO.0)
            }
            Self::Payload(error) => write!(f, "invalid server info frame: {error}"),
        }
    }
}

impl Error for StreamServerInfoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read(error) => Some(error),
            Self::Payload(error) => Some(error),
            Self::Oversized { .. } | Self::UnexpectedType { .. } => None,
        }
    }
}

/// Errors while reading and routing a DERP `Client.Recv` message.
#[derive(Debug)]
pub enum RecvMessageError {
    Read(StreamReadFrameError),
    Oversized { frame_len: u32 },
    ServerInfo(ServerInfoError),
}

impl fmt::Display for RecvMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(error) => write!(f, "derp.Recv: {error}"),
            Self::Oversized { frame_len } => {
                write!(f, "derp.Recv: unexpectedly large frame of {frame_len} bytes returned")
            }
            Self::ServerInfo(error) => write!(f, "derp.Recv: invalid server info frame: {error}"),
        }
    }
}

impl Error for RecvMessageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read(error) => Some(error),
            Self::ServerInfo(_) | Self::Oversized { .. } => None,
        }
    }
}

/// A receive-session failure retained and returned on every subsequent call.
#[derive(Clone, Debug)]
pub struct RecvSessionError {
    inner: Arc<RecvMessageError>,
}

impl fmt::Display for RecvSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.inner.as_ref(), f)
    }
}

impl Error for RecvSessionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.inner.as_ref())
    }
}

/// Timeout requested before each read iteration by the pinned fork's `Client.Recv`.
pub const CLIENT_RECV_TIMEOUT: Duration = Duration::from_secs(120);

/// A blocking reader that can accept the absolute read deadlines used by DERP Recv.
pub trait RecvDeadlineReader: Read {
    /// Requests a deadline. The pinned Go client ignores errors from this call.
    fn set_read_deadline(&mut self, deadline: Instant) -> io::Result<()>;
}

/// A stateful DERP receive session with the pinned fork's deadline requests and
/// permanent first-error latch.
///
/// This owns only the read side and the keys needed to decode ServerInfo. It does
/// not provide write serialization, a send limiter, automatic Ping replies, or a
/// complete DERP connection lifecycle.
pub struct DerpRecvSession<R> {
    reader: R,
    client_private: NodePrivate,
    server_public: NodePublic,
    latched_error: Option<RecvSessionError>,
}

impl<R: RecvDeadlineReader> DerpRecvSession<R> {
    pub fn new(reader: R, client_private: NodePrivate, server_public: NodePublic) -> Self {
        Self { reader, client_private, server_public, latched_error: None }
    }

    /// Reads the next recognized message, returning the exact stored error on all
    /// calls after the first receive failure.
    pub fn recv_next(&mut self) -> Result<ReceivedMessage, RecvSessionError> {
        if let Some(error) = self.latched_error.as_ref() {
            return Err(error.clone());
        }

        loop {
            let _ = self.reader.set_read_deadline(Instant::now() + CLIENT_RECV_TIMEOUT);
            match read_received_message_frame_from(&mut self.reader, &self.client_private, &self.server_public) {
                Ok(Some(message)) => return Ok(message),
                Ok(None) => continue,
                Err(error) => {
                    let error = RecvSessionError { inner: Arc::new(error) };
                    self.latched_error = Some(error.clone());
                    return Err(error);
                }
            }
        }
    }

    pub fn reader(&self) -> &R {
        &self.reader
    }

    pub fn into_inner(self) -> R {
        self.reader
    }
}

/// Joins the pinned fork's DERP read-session behavior to its shared send writer.
///
/// When a successfully parsed ServerInfo message is received, its send-rate
/// settings are applied under the writer lock before the message is returned,
/// matching `Client.Recv` calling `setSendRateLimiter`. This still does not own a
/// network connection or implement the complete DERP client lifecycle.
pub struct DerpClientRecvSession<R, W> {
    receiver: DerpRecvSession<R>,
    send_writer: Arc<DerpSendWriter<W>>,
}

impl<R: RecvDeadlineReader, W> DerpClientRecvSession<R, W> {
    /// Joins a reader, client/server keys, and a shared serialized send writer.
    pub fn new(
        reader: R,
        client_private: NodePrivate,
        server_public: NodePublic,
        send_writer: Arc<DerpSendWriter<W>>,
    ) -> Self {
        Self { receiver: DerpRecvSession::new(reader, client_private, server_public), send_writer }
    }
}

impl<R, W> DerpClientRecvSession<R, W> {
    /// Returns the shared writer used for sends and ServerInfo rate updates.
    pub fn send_writer(&self) -> &Arc<DerpSendWriter<W>> {
        &self.send_writer
    }
}

impl<R: RecvDeadlineReader, W: Write> DerpClientRecvSession<R, W> {
    /// Reads the next message and applies ServerInfo rate changes before returning.
    pub fn recv_next(&mut self) -> Result<ReceivedMessage, RecvSessionError> {
        match self.receiver.recv_next()? {
            ReceivedMessage::ServerInfo(server_info) => {
                self.send_writer.set_rate_limiter_from_server_info(server_info);
                Ok(ReceivedMessage::ServerInfo(server_info))
            }
            message => Ok(message),
        }
    }
}

/// Parses one complete ServerInfo frame from an in-memory byte slice.
///
/// The returned `usize` is the number of bytes consumed, so a following frame
/// can remain in the same input. This applies the pinned fork's `Client.Recv`
/// 1 MiB frame limit before payload processing and then delegates to
/// [`parse_server_info_payload`]. Unlike `Client.Recv`, this strict helper
/// returns an error for a non-ServerInfo frame instead of skipping it, and it
/// does not implement stream I/O, buffering, connection state, or flushing.
pub fn parse_server_info_frame(
    client_private: &NodePrivate,
    server_public: &NodePublic,
    frame: &[u8],
) -> Result<(ServerInfo, usize), ServerInfoFrameError> {
    let mut after_header = frame;
    let header = read_frame_header(&mut after_header).map_err(|_| ServerInfoFrameError::IncompleteHeader)?;
    if header.frame_len > MAX_CLIENT_RECV_FRAME_LEN as u32 {
        return Err(ServerInfoFrameError::Oversized {
            frame_len: header.frame_len,
            max_size: MAX_CLIENT_RECV_FRAME_LEN,
        });
    }
    let payload_len = header.frame_len as usize;
    let available = after_header.len().min(payload_len);
    if available < payload_len {
        return Err(ServerInfoFrameError::IncompletePayload { expected: payload_len, got: available });
    }
    if header.frame_type != FRAME_SERVER_INFO {
        return Err(ServerInfoFrameError::UnexpectedType { got: header.frame_type });
    }
    let info = parse_server_info_payload(client_private, server_public, &after_header[..payload_len])
        .map_err(ServerInfoFrameError::Payload)?;
    Ok((info, FRAME_HEADER_LEN + payload_len))
}

/// Parses a ServerInfo frame and maps it to the message returned by `Client.Recv`.
///
/// No limiter is installed; use [`ServerInfoMessage::rate_limiter_config`] to
/// inspect the source-compatible configuration decision.
pub fn parse_server_info_message_frame(
    client_private: &NodePrivate,
    server_public: &NodePublic,
    frame: &[u8],
) -> Result<(ServerInfoMessage, usize), ServerInfoFrameError> {
    let (info, consumed) = parse_server_info_frame(client_private, server_public, frame)?;
    Ok((info.into_message(), consumed))
}

/// Reads and parses exactly one ServerInfo frame from a blocking stream.
///
/// The Client.Recv 1 MiB frame limit is applied before allocating its payload.
/// Unlike Client.Recv, this narrow helper returns an error for a non-ServerInfo
/// frame instead of dispatching or skipping it; it returns configuration only
/// and does not install or execute a token-bucket limiter.
pub fn read_server_info_message_from<R: Read>(
    reader: &mut R,
    client_private: &NodePrivate,
    server_public: &NodePublic,
) -> Result<ServerInfoMessage, StreamServerInfoError> {
    let (header, payload) = match read_frame_vec_from(reader, MAX_CLIENT_RECV_FRAME_LEN as u32) {
        Ok(frame) => frame,
        Err(StreamReadFrameError::ExceedsLimit { frame_len, .. }) => {
            return Err(StreamServerInfoError::Oversized { frame_len });
        }
        Err(error) => return Err(StreamServerInfoError::Read(error)),
    };
    if header.frame_type != FRAME_SERVER_INFO {
        return Err(StreamServerInfoError::UnexpectedType { got: header.frame_type });
    }
    let info =
        parse_server_info_payload(client_private, server_public, &payload).map_err(StreamServerInfoError::Payload)?;
    Ok(info.into_message())
}

/// Reads and routes the next message recognized by the pinned fork's
/// `Client.Recv`, skipping unknown frame types and malformed short fixed-size
/// messages as that implementation does.
///
/// This generic `Read` helper does not set a 120-second deadline, latch errors
/// permanently, update a send limiter, or answer Ping frames. Callers must
/// provide those connection-lifecycle behaviors separately before treating
/// this as a full DERP client.
fn read_received_message_frame_from<R: Read>(
    reader: &mut R,
    client_private: &NodePrivate,
    server_public: &NodePublic,
) -> Result<Option<ReceivedMessage>, RecvMessageError> {
    let (header, payload) = match read_frame_vec_from(reader, MAX_CLIENT_RECV_FRAME_LEN as u32) {
        Ok(frame) => frame,
        Err(StreamReadFrameError::ExceedsLimit { frame_len, .. }) => {
            return Err(RecvMessageError::Oversized { frame_len });
        }
        Err(error) => return Err(RecvMessageError::Read(error)),
    };

    let message = match header.frame_type {
        FRAME_SERVER_INFO => {
            let info = parse_server_info_payload(client_private, server_public, &payload)
                .map_err(RecvMessageError::ServerInfo)?;
            Some(ReceivedMessage::ServerInfo(info.into_message()))
        }
        FRAME_KEEP_ALIVE => Some(ReceivedMessage::KeepAlive),
        FRAME_PEER_GONE if payload.len() >= 32 => {
            let mut raw_key = [0; 32];
            raw_key.copy_from_slice(&payload[..32]);
            Some(ReceivedMessage::PeerGone(PeerGoneMessage {
                peer: NodePublic::from_raw32(raw_key),
                reason: payload.get(32).copied().unwrap_or(0),
            }))
        }
        FRAME_PEER_PRESENT if payload.len() >= 32 => {
            let mut raw_key = [0; 32];
            raw_key.copy_from_slice(&payload[..32]);
            let ip_port = if payload.len() >= 50 {
                let mut raw_ip = [0; 16];
                raw_ip.copy_from_slice(&payload[32..48]);
                let ipv6 = Ipv6Addr::from(raw_ip);
                let ip = ipv6.to_ipv4_mapped().map_or(IpAddr::V6(ipv6), IpAddr::V4);
                let port = u16::from_be_bytes([payload[48], payload[49]]);
                Some(SocketAddr::new(ip, port))
            } else {
                None
            };
            let flags = payload.get(50).copied().unwrap_or(0);
            Some(ReceivedMessage::PeerPresent(PeerPresentMessage {
                key: NodePublic::from_raw32(raw_key),
                ip_port,
                flags,
            }))
        }
        FRAME_RECV_PACKET if payload.len() >= 32 => {
            let mut raw_key = [0; 32];
            raw_key.copy_from_slice(&payload[..32]);
            Some(ReceivedMessage::ReceivedPacket(ReceivedPacket {
                source: NodePublic::from_raw32(raw_key),
                data: payload[32..].to_vec(),
            }))
        }
        FRAME_PING if payload.len() >= 8 => {
            let mut ping = [0; 8];
            ping.copy_from_slice(&payload[..8]);
            Some(ReceivedMessage::Ping(ping))
        }
        FRAME_PONG if payload.len() >= 8 => {
            let mut pong = [0; 8];
            pong.copy_from_slice(&payload[..8]);
            Some(ReceivedMessage::Pong(pong))
        }
        FRAME_HEALTH => Some(ReceivedMessage::Health(HealthMessage { problem: payload })),
        FRAME_RESTARTING if payload.len() >= 8 => {
            let reconnect_in = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
            let try_for = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
            Some(ReceivedMessage::ServerRestarting(ServerRestartingMessage {
                reconnect_in: Duration::from_millis(u64::from(reconnect_in)),
                try_for: Duration::from_millis(u64::from(try_for)),
            }))
        }
        _ => None,
    };
    Ok(message)
}

pub fn read_received_message_from<R: Read>(
    reader: &mut R,
    client_private: &NodePrivate,
    server_public: &NodePublic,
) -> Result<ReceivedMessage, RecvMessageError> {
    loop {
        if let Some(message) = read_received_message_frame_from(reader, client_private, server_public)? {
            return Ok(message);
        }
    }
}

fn push_json_field_name(output: &mut String, first: &mut bool, name: &str) {
    if !*first {
        output.push(',');
    }
    *first = false;
    output.push('"');
    output.push_str(name);
    output.push_str("\":");
}

fn push_go_json_string(output: &mut String, value: &str) {
    let encoded = serde_json::to_string(value).expect("a Rust string is always JSON-serializable");
    for character in encoded.chars() {
        match character {
            '<' => output.push_str("\\u003c"),
            '>' => output.push_str("\\u003e"),
            '&' => output.push_str("\\u0026"),
            '\u{2028}' => output.push_str("\\u2028"),
            '\u{2029}' => output.push_str("\\u2029"),
            other => output.push(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_client_info_frame, build_client_info_frame_with_nonce, read_frame, read_frame_from, read_frame_header,
        read_frame_type_header, read_server_greeting, write_frame, write_frame_to, write_ping_to, write_pong_to,
        ClientInfo, ClientInfoFrameError, DerpClientHandshake, DerpClientHandshakeError, DerpClientHandshakeState,
        DerpClientRecvSession, DerpClientStreamHandshakeError, DerpRecvSession, DerpSendWriter, FrameHeader,
        FrameHeaderError, FrameType, ReadFrameError, RecvDeadlineReader, ServerGreetingError, StreamReadFrameError,
        StreamWriteFrameError, WriteFrameError, CLIENT_RECV_TIMEOUT, FRAME_CLIENT_INFO, FRAME_SERVER_KEY, MAGIC,
        MAX_FRAME_WRITE_SIZE, PROTOCOL_VERSION,
    };
    use crate::{disco_crypto::NodeBoxError, NodePrivate, NodePublic};
    use std::io::{self, Read, Write};
    use std::sync::{Arc, Barrier, Mutex};
    use std::time::{Duration, Instant};

    struct ChunkedReader {
        bytes: Vec<u8>,
        position: usize,
        max_chunk: usize,
    }

    impl ChunkedReader {
        fn new(bytes: Vec<u8>, max_chunk: usize) -> Self {
            Self { bytes, position: 0, max_chunk }
        }

        fn remaining(&self) -> &[u8] {
            &self.bytes[self.position..]
        }
    }

    impl Read for ChunkedReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let count = output.len().min(self.max_chunk).min(self.bytes.len() - self.position);
            output[..count].copy_from_slice(&self.bytes[self.position..self.position + count]);
            self.position += count;
            Ok(count)
        }
    }

    struct DeadlineReader {
        inner: ChunkedReader,
        deadlines: Vec<Instant>,
        read_calls: usize,
        fail_deadline: bool,
    }

    impl Read for DeadlineReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.read_calls += 1;
            self.inner.read(output)
        }
    }

    impl RecvDeadlineReader for DeadlineReader {
        fn set_read_deadline(&mut self, deadline: Instant) -> io::Result<()> {
            self.deadlines.push(deadline);
            if self.fail_deadline {
                Err(io::Error::other("deadline unsupported"))
            } else {
                Ok(())
            }
        }
    }

    struct ChunkedWriter {
        bytes: Vec<u8>,
        max_chunk: usize,
        flushes: usize,
    }

    impl Write for ChunkedWriter {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            let count = input.len().min(self.max_chunk);
            self.bytes.extend_from_slice(&input[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    #[derive(Default)]
    struct SharedWriteObservation {
        bytes: Vec<u8>,
        flushes: usize,
    }

    struct YieldingWriter {
        observation: Arc<Mutex<SharedWriteObservation>>,
    }

    impl Write for YieldingWriter {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            self.observation.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).bytes.extend_from_slice(input);
            std::thread::yield_now();
            Ok(input.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.observation.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).flushes += 1;
            Ok(())
        }
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _input: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("write failed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("write failed"))
        }
    }

    struct WatchdogBlockingWriter {
        started: Option<std::sync::mpsc::Sender<()>>,
        closed: std::sync::mpsc::Receiver<()>,
    }

    impl Write for WatchdogBlockingWriter {
        fn write(&mut self, _input: &[u8]) -> io::Result<usize> {
            if let Some(started) = self.started.take() {
                started.send(()).map_err(|_| io::Error::other("test start receiver dropped"))?;
                self.closed
                    .recv_timeout(Duration::from_secs(2))
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "watchdog did not close connection"))?;
                return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "connection closed"));
            }
            Ok(0)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct ChunkedDuplex {
        incoming: Vec<u8>,
        read_position: usize,
        written: Vec<u8>,
        max_read: usize,
        max_write: usize,
        flushes: usize,
    }

    impl ChunkedDuplex {
        fn new(incoming: Vec<u8>, max_read: usize, max_write: usize) -> Self {
            Self { incoming, read_position: 0, written: Vec::new(), max_read, max_write, flushes: 0 }
        }
    }

    impl Read for ChunkedDuplex {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let count = output.len().min(self.max_read).min(self.incoming.len() - self.read_position);
            output[..count].copy_from_slice(&self.incoming[self.read_position..self.read_position + count]);
            self.read_position += count;
            Ok(count)
        }
    }

    impl Write for ChunkedDuplex {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            let count = input.len().min(self.max_write);
            self.written.extend_from_slice(&input[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        let (pairs, remainder) = input.as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty());
        pairs.iter().map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()).collect()
    }

    #[test]
    fn client_info_frame_matches_pinned_go_send_client_key_vector() {
        let alice =
            NodePrivate::from_text("privkey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let bob =
            NodePrivate::from_text("privkey:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
        let bob_public = bob.public().unwrap();
        let info = ClientInfo {
            mesh_key: std::array::from_fn(|index| index as u8),
            version: PROTOCOL_VERSION,
            can_ack_pings: true,
            is_prober: true,
            app_name: "rust-box".to_owned(),
        };
        let nonce = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51,
            0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        ];
        let actual = build_client_info_frame_with_nonce(&alice, &bob_public, &info, &nonce).unwrap();
        let expected = decode_hex("02000000da8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f404142434445464748494a4b4c4d4e4f5051525354555657147303b734c84218a6821b8dee24d22ac5172debbee276b1da71a1409d48486a531776a875c9d0971161c587ba67a3d2ed00c683094a625a11c10abc9d0385c219127178b0b738ea5398c692734938b6c0994ce794c17e230c9e26b5663a6b77eaa2080b9d358beef3dad000b7081fafc273be933efcaeaa98c6467c436f71cb0800f28203d5475722631274fc55ff8f67757a9331be93ca2a1f5f6bb3661f03e1d9");
        assert_eq!(actual, expected);

        let mut remaining = actual.as_slice();
        let mut payload = vec![0; actual.len() - super::FRAME_HEADER_LEN];
        let header = read_frame(&mut remaining, MAX_FRAME_WRITE_SIZE as u32, &mut payload).unwrap();
        assert_eq!(header.frame_type, FRAME_CLIENT_INFO);
        assert_eq!(header.frame_len as usize, payload.len());
        assert!(remaining.is_empty());
        let alice_public = alice.public().unwrap();
        assert_eq!(&payload[..32], &alice_public.raw_bytes());
        assert_eq!(bob.open_from(&alice_public, &payload[32..]).unwrap(), info.to_json().as_bytes());
    }

    #[test]
    fn client_info_frame_builder_uses_fresh_nonce_and_fails_closed_on_zero_keys() {
        let alice =
            NodePrivate::from_text("privkey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let bob =
            NodePrivate::from_text("privkey:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
        let bob_public = bob.public().unwrap();
        let info = ClientInfo { version: PROTOCOL_VERSION, ..ClientInfo::default() };
        let first = build_client_info_frame(&alice, &bob_public, &info).unwrap();
        let second = build_client_info_frame(&alice, &bob_public, &info).unwrap();
        assert_eq!(&first[..super::FRAME_HEADER_LEN], &second[..super::FRAME_HEADER_LEN]);
        assert_ne!(
            &first[super::FRAME_HEADER_LEN + 32..super::FRAME_HEADER_LEN + 32 + 24],
            &second[super::FRAME_HEADER_LEN + 32..super::FRAME_HEADER_LEN + 32 + 24]
        );

        let zero_private = NodePrivate::from_text(&format!("privkey:{}", "00".repeat(32))).unwrap();
        assert_eq!(
            build_client_info_frame(&zero_private, &bob_public, &info),
            Err(ClientInfoFrameError::Box(NodeBoxError::ZeroPrivateKey))
        );
        assert_eq!(
            build_client_info_frame(&alice, &NodePublic::from_raw32([0; 32]), &info),
            Err(ClientInfoFrameError::Box(NodeBoxError::ZeroPeerPublicKey))
        );
    }

    #[test]
    fn server_info_payload_opens_pinned_go_box_fixture() {
        let alice =
            NodePrivate::from_text("privkey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let bob =
            NodePrivate::from_text("privkey:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
        let payload = decode_hex("808182838485868788898a8b8c8d8e8f90919293949596972a5043cecfb67d977e3a71109462311a38a15b673d7b2bf55da90ef8f0d0c5313f73665a84fefee88e79c04d9f28b8eedadcd657528c5f0c7a08671cf92cd641f0e77fae5c0817566ac2b69be71d61523ec54dd49e137aaa9e0e19cb487e0f7557d9");
        let info = super::parse_server_info_payload(&alice, &bob.public().unwrap(), &payload).unwrap();
        assert_eq!(
            info,
            super::ServerInfo {
                version: 2,
                token_bucket_bytes_per_second: 16_777_216,
                token_bucket_bytes_burst: 4_194_304,
            }
        );
    }

    #[test]
    fn server_info_payload_enforces_length_and_authentication_before_json() {
        let alice =
            NodePrivate::from_text("privkey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let bob =
            NodePrivate::from_text("privkey:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
        let bob_public = bob.public().unwrap();

        assert!(matches!(
            super::parse_server_info_payload(&alice, &bob_public, &[0; 23]),
            Err(super::ServerInfoError::ShortFrame { got: 23 })
        ));
        assert!(matches!(
            super::parse_server_info_payload(
                &alice,
                &bob_public,
                &vec![0; super::MAX_SERVER_INFO_PAYLOAD_LEN + 1]
            ),
            Err(super::ServerInfoError::LongFrame { got, max })
                if got == super::MAX_SERVER_INFO_PAYLOAD_LEN + 1 && max == super::MAX_SERVER_INFO_PAYLOAD_LEN
        ));
        assert!(matches!(
            super::parse_server_info_payload(&alice, &bob_public, &[0; super::SERVER_INFO_NONCE_LEN]),
            Err(super::ServerInfoError::Box(NodeBoxError::Authentication))
        ));

        let mut tampered = decode_hex("808182838485868788898a8b8c8d8e8f90919293949596972a5043cecfb67d977e3a71109462311a38a15b673d7b2bf55da90ef8f0d0c5313f73665a84fefee88e79c04d9f28b8eedadcd657528c5f0c7a08671cf92cd641f0e77fae5c0817566ac2b69be71d61523ec54dd49e137aaa9e0e19cb487e0f7557d9");
        *tampered.last_mut().unwrap() ^= 1;
        assert!(matches!(
            super::parse_server_info_payload(&alice, &bob_public, &tampered),
            Err(super::ServerInfoError::Box(NodeBoxError::Authentication))
        ));
        assert!(matches!(
            super::parse_server_info_payload(&alice, &NodePublic::from_raw32([0; 32]), &[0; 24]),
            Err(super::ServerInfoError::Box(NodeBoxError::ZeroPeerPublicKey))
        ));
    }

    #[test]
    fn server_info_frame_consumes_one_bounded_frame_and_preserves_the_next() {
        let alice =
            NodePrivate::from_text("privkey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let bob =
            NodePrivate::from_text("privkey:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
        let payload = decode_hex("808182838485868788898a8b8c8d8e8f90919293949596972a5043cecfb67d977e3a71109462311a38a15b673d7b2bf55da90ef8f0d0c5313f73665a84fefee88e79c04d9f28b8eedadcd657528c5f0c7a08671cf92cd641f0e77fae5c0817566ac2b69be71d61523ec54dd49e137aaa9e0e19cb487e0f7557d9");
        let mut wire = Vec::new();
        write_frame(&mut wire, super::FRAME_SERVER_INFO, &payload).unwrap();
        let consumed = wire.len();
        wire.extend_from_slice(&[0x06, 0, 0, 0, 0]);

        let (info, frame_len) = super::parse_server_info_frame(&alice, &bob.public().unwrap(), &wire).unwrap();
        assert_eq!(frame_len, consumed);
        assert_eq!(&wire[frame_len..], &[0x06, 0, 0, 0, 0]);
        assert_eq!(info.version, 2);
        assert_eq!(info.token_bucket_bytes_per_second, 16_777_216);
        assert_eq!(info.token_bucket_bytes_burst, 4_194_304);

        let (message, message_len) =
            super::parse_server_info_message_frame(&alice, &bob.public().unwrap(), &wire).unwrap();
        assert_eq!(message_len, consumed);
        assert_eq!(message.token_bucket_bytes_per_second, 16_777_216);
        assert_eq!(message.token_bucket_bytes_burst, 4_194_304);
    }

    #[test]
    fn server_info_frame_matches_client_recv_header_and_size_failure_order() {
        let alice =
            NodePrivate::from_text("privkey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let bob =
            NodePrivate::from_text("privkey:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
        let bob_public = bob.public().unwrap();

        for len in 0..super::FRAME_HEADER_LEN {
            assert!(matches!(
                super::parse_server_info_frame(&alice, &bob_public, &[0; 5][..len]),
                Err(super::ServerInfoFrameError::IncompleteHeader)
            ));
        }
        let too_large = FrameHeader {
            frame_type: super::FRAME_SERVER_INFO,
            frame_len: (super::MAX_CLIENT_RECV_FRAME_LEN + 1) as u32,
        }
        .encode();
        let oversized_error = super::parse_server_info_frame(&alice, &bob_public, &too_large).unwrap_err();
        assert_eq!(
            oversized_error.to_string(),
            format!("unexpectedly large frame of {} bytes returned", super::MAX_CLIENT_RECV_FRAME_LEN + 1)
        );
        assert!(matches!(
            oversized_error,
            super::ServerInfoFrameError::Oversized { frame_len, max_size }
                if frame_len == (super::MAX_CLIENT_RECV_FRAME_LEN + 1) as u32
                    && max_size == super::MAX_CLIENT_RECV_FRAME_LEN
        ));

        let short = FrameHeader { frame_type: super::FRAME_SERVER_INFO, frame_len: 4 }
            .encode()
            .into_iter()
            .chain([1, 2])
            .collect::<Vec<_>>();
        assert!(matches!(
            super::parse_server_info_frame(&alice, &bob_public, &short),
            Err(super::ServerInfoFrameError::IncompletePayload { expected: 4, got: 2 })
        ));

        let mut wrong_type = Vec::new();
        write_frame(&mut wrong_type, FRAME_CLIENT_INFO, &[0; 24]).unwrap();
        assert!(matches!(
            super::parse_server_info_frame(&alice, &bob_public, &wrong_type),
            Err(super::ServerInfoFrameError::UnexpectedType { got: FRAME_CLIENT_INFO })
        ));
    }

    #[test]
    fn server_info_message_maps_fields_and_limiter_branch_like_pinned_client() {
        let unspecified =
            super::ServerInfo { version: 2, token_bucket_bytes_per_second: 0, token_bucket_bytes_burst: 99 }
                .into_message();
        assert_eq!(
            unspecified,
            super::ServerInfoMessage { token_bucket_bytes_per_second: 0, token_bucket_bytes_burst: 99 }
        );
        assert_eq!(unspecified.rate_limiter_config(), None);

        let configured =
            super::ServerInfo { version: 123, token_bucket_bytes_per_second: 4096, token_bucket_bytes_burst: 0 }
                .into_message();
        assert_eq!(
            configured.rate_limiter_config(),
            Some(super::SendRateLimiterConfig { bytes_per_second: 4096, burst: 0 })
        );

        let negative = super::ServerInfoMessage { token_bucket_bytes_per_second: -1, token_bucket_bytes_burst: -7 };
        assert_eq!(
            negative.rate_limiter_config(),
            Some(super::SendRateLimiterConfig { bytes_per_second: -1, burst: -7 })
        );
    }

    #[test]
    fn send_rate_limiter_allow_n_matches_fixed_go_x_time_rate_oracle() {
        use super::{DerpSendRateLimiter, SendRateLimiterConfig};

        let base = Instant::now();
        let mut refill = DerpSendRateLimiter::new(SendRateLimiterConfig { bytes_per_second: 10, burst: 20 });
        let refill_results = [
            refill.allow_n(base, 12),
            refill.allow_n(base, 9),
            refill.allow_n(base + Duration::from_millis(100), 1),
            refill.allow_n(base + Duration::from_millis(150), 1),
            refill.allow_n(base + Duration::from_secs(1), 20),
            refill.allow_n(base + Duration::from_secs(3), 20),
        ];
        assert_eq!(refill_results, [true, false, true, true, false, true]);

        let mut burst = DerpSendRateLimiter::new(SendRateLimiterConfig { bytes_per_second: 10, burst: 20 });
        assert!(!burst.allow_n(base, 21));
        assert!(burst.allow_n(base, 20));
        assert!(!burst.allow_n(base, 1));

        let mut negative_rate = DerpSendRateLimiter::new(SendRateLimiterConfig { bytes_per_second: -1, burst: 12 });
        assert!(negative_rate.allow_n(base, 12));
        assert!(!negative_rate.allow_n(base + Duration::from_secs(86_400), 1));

        let mut zero_rate = DerpSendRateLimiter::new(SendRateLimiterConfig { bytes_per_second: 0, burst: 2 });
        assert!(zero_rate.allow_n(base, 2));
        assert!(!zero_rate.allow_n(base + Duration::from_secs(3_600), 1));

        let mut zero_burst = DerpSendRateLimiter::new(SendRateLimiterConfig { bytes_per_second: 10, burst: 0 });
        assert!(zero_burst.allow_n(base, 0));
        assert!(!zero_burst.allow_n(base, 1));

        let mut negative_burst = DerpSendRateLimiter::new(SendRateLimiterConfig { bytes_per_second: 10, burst: -1 });
        assert!(!negative_burst.allow_n(base, 0));
        assert!(!negative_burst.allow_n(base, 1));

        let mut backwards = DerpSendRateLimiter::new(SendRateLimiterConfig { bytes_per_second: 10, burst: 10 });
        assert!(backwards.allow_n(base, 10));
        assert!(backwards.allow_n(base - Duration::from_secs(1), 0));
        assert!(backwards.allow_n(base + Duration::from_millis(500), 10));

        let mut large_rate = DerpSendRateLimiter::new(SendRateLimiterConfig { bytes_per_second: i64::MAX, burst: 10 });
        assert!(large_rate.allow_n(base, 10));
        assert!(large_rate.allow_n(base + Duration::from_nanos(1), 10));
        assert!(large_rate.allow_n(base + Duration::from_nanos(2), 10));

        let mut subnanosecond =
            DerpSendRateLimiter::new(SendRateLimiterConfig { bytes_per_second: 2_000_000_000, burst: 10 });
        assert!(subnanosecond.allow_n(base, 10));
        assert!(subnanosecond.allow_n(base + Duration::from_nanos(1), 3));
        assert!(!subnanosecond.allow_n(base + Duration::from_nanos(1), 1));
        assert!(subnanosecond.allow_n(base + Duration::from_nanos(2), 1));
    }

    #[test]
    fn send_packet_matches_fixed_go_client_send_wire_size_and_drop_oracle() {
        use super::{DerpSendRateLimiter, SendPacketOutcome, SendRateLimiterConfig};

        let base = Instant::now();
        let destination = NodePublic::from_raw32([
            101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
            122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132,
        ]);

        let pattern = (0..=u8::MAX).collect::<Vec<_>>();
        let max_packet = pattern.repeat(256);
        let mut max_wire = Vec::new();
        assert!(matches!(
            super::send_packet_to(&mut max_wire, destination, &max_packet, None, base),
            Ok(SendPacketOutcome::Sent)
        ));
        assert_eq!(max_wire.len(), super::FRAME_HEADER_LEN + super::KEY_LEN + super::MAX_PACKET_SIZE);
        assert_eq!(&max_wire[..super::FRAME_HEADER_LEN], &[0x04, 0x00, 0x01, 0x00, 0x20]);
        assert_eq!(
            &max_wire[super::FRAME_HEADER_LEN..super::FRAME_HEADER_LEN + super::KEY_LEN],
            &destination.raw_bytes()
        );
        assert_eq!(&max_wire[super::FRAME_HEADER_LEN + super::KEY_LEN..], max_packet.as_slice());

        let packet = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut limiter = DerpSendRateLimiter::new(SendRateLimiterConfig { bytes_per_second: 1, burst: 47 });
        let mut limited_wire = Vec::new();
        let oversized = vec![0; super::MAX_PACKET_SIZE + 1];
        let too_big =
            super::send_packet_to(&mut limited_wire, destination, &oversized, Some(&mut limiter), base).unwrap_err();
        assert_eq!(too_big.to_string(), "derp.Send: packet too big: 65537");
        assert!(limited_wire.is_empty());

        assert!(matches!(
            super::send_packet_to(&mut limited_wire, destination, &packet, Some(&mut limiter), base),
            Ok(SendPacketOutcome::Sent)
        ));
        assert!(matches!(
            super::send_packet_to(&mut limited_wire, destination, &packet, Some(&mut limiter), base),
            Ok(SendPacketOutcome::Dropped)
        ));

        let mut expected = vec![0x04, 0, 0, 0, 0x2a];
        expected.extend_from_slice(&destination.raw_bytes());
        expected.extend_from_slice(&packet);
        assert_eq!(limited_wire, expected);
    }

    #[test]
    fn shared_send_writer_matches_go_limiter_and_control_frame_lock_scope() {
        use super::{DerpSendRateLimiter, SendPacketOutcome, SendRateLimiterConfig};

        let observation = Arc::new(Mutex::new(SharedWriteObservation::default()));
        let writer = DerpSendWriter::new(
            YieldingWriter { observation: Arc::clone(&observation) },
            Some(DerpSendRateLimiter::new(SendRateLimiterConfig { bytes_per_second: 1, burst: 47 })),
        );
        let destination = NodePublic::from_raw32([0xab; 32]);
        let packet = [0x22; 10];
        let oversized = vec![0; super::MAX_PACKET_SIZE + 1];
        assert_eq!(
            writer.send_packet(destination, &oversized).unwrap_err().to_string(),
            "derp.Send: packet too big: 65537"
        );
        assert_eq!(writer.send_packet(destination, &packet).unwrap(), SendPacketOutcome::Sent);
        assert_eq!(writer.send_packet(destination, &packet).unwrap(), SendPacketOutcome::Dropped);
        writer.send_ping([0, 1, 2, 3, 4, 5, 6, 7]).unwrap();
        writer.send_pong([8, 7, 6, 5, 4, 3, 2, 1]).unwrap();

        let observation = observation.lock().unwrap();
        let mut expected = vec![0x04, 0, 0, 0, 42];
        expected.extend_from_slice(&destination.raw_bytes());
        expected.extend_from_slice(&packet);
        expected.extend_from_slice(&[0x12, 0, 0, 0, 8, 0, 1, 2, 3, 4, 5, 6, 7]);
        expected.extend_from_slice(&[0x13, 0, 0, 0, 8, 8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(observation.bytes, expected);
        assert_eq!(observation.flushes, 3);
    }

    #[test]
    fn server_info_replaces_or_disables_shared_send_limiter_like_go_client_recv() {
        let observation = Arc::new(Mutex::new(SharedWriteObservation::default()));
        let writer = DerpSendWriter::new(YieldingWriter { observation: Arc::clone(&observation) }, None);
        let destination = NodePublic::from_raw32([0x73; 32]);
        let packet = [0x29; 10];
        let limited = super::ServerInfoMessage { token_bucket_bytes_per_second: 1, token_bucket_bytes_burst: 47 };

        writer.set_rate_limiter_from_server_info(limited);
        assert_eq!(writer.send_packet(destination, &packet).unwrap(), super::SendPacketOutcome::Sent);
        assert_eq!(writer.send_packet(destination, &packet).unwrap(), super::SendPacketOutcome::Dropped);

        writer.set_rate_limiter_from_server_info(limited);
        assert_eq!(writer.send_packet(destination, &packet).unwrap(), super::SendPacketOutcome::Sent);

        writer.set_rate_limiter_from_server_info(super::ServerInfoMessage {
            token_bucket_bytes_per_second: 0,
            token_bucket_bytes_burst: 0,
        });
        assert_eq!(writer.send_packet(destination, &packet).unwrap(), super::SendPacketOutcome::Sent);
        assert_eq!(writer.send_packet(destination, &packet).unwrap(), super::SendPacketOutcome::Sent);
        assert_eq!(observation.lock().unwrap().flushes, 4);
    }

    #[test]
    fn forward_packet_matches_fixed_go_wire_limit_and_wrapped_error_oracle() {
        let source = NodePublic::from_raw32([0x31; 32]);
        let destination = NodePublic::from_raw32([0x42; 32]);
        let pattern = (0..=u8::MAX).collect::<Vec<_>>();
        let max_packet = pattern.repeat(256);
        let mut max_wire = Vec::new();
        super::forward_packet_to(&mut max_wire, source, destination, &max_packet).unwrap();
        assert_eq!(max_wire.len(), super::FRAME_HEADER_LEN + 2 * super::KEY_LEN + super::MAX_PACKET_SIZE);
        assert_eq!(&max_wire[..super::FRAME_HEADER_LEN], &[0x0a, 0x00, 0x01, 0x00, 0x40]);
        assert_eq!(&max_wire[super::FRAME_HEADER_LEN..super::FRAME_HEADER_LEN + super::KEY_LEN], &[0x31; 32]);
        assert_eq!(
            &max_wire[super::FRAME_HEADER_LEN + super::KEY_LEN..super::FRAME_HEADER_LEN + 2 * super::KEY_LEN],
            &[0x42; 32]
        );
        assert_eq!(&max_wire[super::FRAME_HEADER_LEN + 2 * super::KEY_LEN..], max_packet.as_slice());

        let before = max_wire.clone();
        let oversized = vec![0; super::MAX_PACKET_SIZE + 1];
        let error = super::forward_packet_to(&mut max_wire, source, destination, &oversized).unwrap_err();
        assert_eq!(error.to_string(), "derp.ForwardPacket: packet too big: 65537");
        assert!(std::error::Error::source(&error).is_none());
        assert_eq!(max_wire, before);

        let observation = Arc::new(Mutex::new(SharedWriteObservation::default()));
        let closer: super::DerpConnectionCloser = Arc::new(|| {});
        let writer = DerpSendWriter::new_with_connection_closer(
            YieldingWriter { observation: Arc::clone(&observation) },
            None,
            Arc::clone(&closer),
        );
        writer.forward_packet(source, destination, &[0x55; 8]).unwrap();
        let observation = observation.lock().unwrap();
        let mut expected = vec![0x0a, 0, 0, 0, 72];
        expected.extend_from_slice(&[0x31; 32]);
        expected.extend_from_slice(&[0x42; 32]);
        expected.extend_from_slice(&[0x55; 8]);
        assert_eq!(observation.bytes, expected);
        assert_eq!(observation.flushes, 1);

        let writer = DerpSendWriter::new_with_connection_closer(FailingWriter, None, closer);
        let error = writer.forward_packet(source, destination, &[0x55; 8]).unwrap_err();
        assert_eq!(error.to_string(), "derp.ForwardPacket: write failed");
        assert!(std::error::Error::source(&error).is_some());
    }

    #[test]
    fn forward_packet_fails_closed_without_a_connection_closer() {
        let observation = Arc::new(Mutex::new(SharedWriteObservation::default()));
        let writer = DerpSendWriter::new(YieldingWriter { observation: Arc::clone(&observation) }, None);
        let error = writer
            .forward_packet(NodePublic::from_raw32([0x31; 32]), NodePublic::from_raw32([0x42; 32]), &[1])
            .unwrap_err();
        assert_eq!(error.to_string(), "derp.ForwardPacket: connection close handle is required");
        assert!(observation.lock().unwrap().bytes.is_empty());
    }

    #[test]
    fn forward_packet_watchdog_closes_outside_the_writer_lock() {
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (closed_tx, closed_rx) = std::sync::mpsc::channel();
        let close_calls = Arc::new(Mutex::new(0));
        let close_calls_in_callback = Arc::clone(&close_calls);
        let closer: super::DerpConnectionCloser = Arc::new(move || {
            *close_calls_in_callback.lock().unwrap() += 1;
            closed_tx.send(()).unwrap();
        });
        let writer = DerpSendWriter::new_with_connection_closer(
            WatchdogBlockingWriter { started: Some(started_tx), closed: closed_rx },
            None,
            closer,
        );
        assert_eq!(super::FORWARD_PACKET_WRITE_TIMEOUT, Duration::from_secs(5));

        let error = writer
            .forward_packet_with_timeout(
                NodePublic::from_raw32([0x31; 32]),
                NodePublic::from_raw32([0x42; 32]),
                &[0x55; 8],
                Duration::from_millis(25),
            )
            .unwrap_err();
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(error.to_string(), "derp.ForwardPacket: connection closed");
        assert_eq!(*close_calls.lock().unwrap(), 1);
    }

    #[test]
    fn forward_packet_watchdog_is_canceled_when_write_returns() {
        let observation = Arc::new(Mutex::new(SharedWriteObservation::default()));
        let close_calls = Arc::new(Mutex::new(0));
        let close_calls_in_callback = Arc::clone(&close_calls);
        let closer: super::DerpConnectionCloser = Arc::new(move || {
            *close_calls_in_callback.lock().unwrap() += 1;
        });
        let writer = DerpSendWriter::new_with_connection_closer(
            YieldingWriter { observation: Arc::clone(&observation) },
            None,
            closer,
        );
        writer
            .forward_packet_with_timeout(
                NodePublic::from_raw32([0x31; 32]),
                NodePublic::from_raw32([0x42; 32]),
                &[0x55; 8],
                Duration::from_millis(20),
            )
            .unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(*close_calls.lock().unwrap(), 0);
    }

    #[test]
    fn note_preferred_watch_connections_and_close_peer_match_go_wire_frames() {
        let observation = Arc::new(Mutex::new(SharedWriteObservation::default()));
        let writer = DerpSendWriter::new(YieldingWriter { observation: Arc::clone(&observation) }, None);
        let peer = NodePublic::from_raw32([0x42; 32]);
        writer.note_preferred(true).unwrap();
        writer.note_preferred(false).unwrap();
        writer.watch_connection_changes().unwrap();
        writer.close_peer(peer).unwrap();

        let observation = observation.lock().unwrap();
        let mut expected = vec![0x07, 0, 0, 0, 1, 1, 0x07, 0, 0, 0, 1, 0];
        expected.extend_from_slice(&[0x10, 0, 0, 0, 0]);
        expected.extend_from_slice(&[0x11, 0, 0, 0, 32]);
        expected.extend_from_slice(&peer.raw_bytes());
        assert_eq!(observation.bytes, expected);
        assert_eq!(observation.flushes, 4);
    }

    #[test]
    fn note_preferred_error_prefix_matches_go_non_wrapping_format() {
        let writer = DerpSendWriter::new(FailingWriter, None);
        let error = writer.note_preferred(true).unwrap_err();
        assert_eq!(error.to_string(), "derp.NotePreferred: write failed");
        assert!(std::error::Error::source(&error).is_none());
    }

    #[test]
    fn shared_send_writer_prevents_concurrent_packet_forward_ping_pong_frame_interleaving() {
        const THREADS: usize = 8;
        const OPERATIONS_PER_THREAD: usize = 12;

        let observation = Arc::new(Mutex::new(SharedWriteObservation::default()));
        let writer = Arc::new(DerpSendWriter::new_with_connection_closer(
            YieldingWriter { observation: Arc::clone(&observation) },
            None,
            Arc::new(|| {}),
        ));
        let start = Arc::new(Barrier::new(THREADS + 1));
        let source = NodePublic::from_raw32([0x6b; 32]);
        let destination = NodePublic::from_raw32([0x5a; 32]);
        let mut workers = Vec::new();

        for thread_index in 0..THREADS {
            let writer = Arc::clone(&writer);
            let start = Arc::clone(&start);
            workers.push(std::thread::spawn(move || {
                start.wait();
                for operation in 0..OPERATIONS_PER_THREAD {
                    let tag = (thread_index * OPERATIONS_PER_THREAD + operation + 1) as u8;
                    let data = [tag; 8];
                    match operation % 4 {
                        0 => writer.send_ping(data).unwrap(),
                        1 => writer.send_pong(data).unwrap(),
                        2 => {
                            assert_eq!(writer.send_packet(destination, &data).unwrap(), super::SendPacketOutcome::Sent)
                        }
                        _ => writer.forward_packet(source, destination, &data).unwrap(),
                    }
                }
            }));
        }

        start.wait();
        for worker in workers {
            worker.join().unwrap();
        }

        let observation = observation.lock().unwrap();
        assert_eq!(observation.flushes, THREADS * OPERATIONS_PER_THREAD);
        let mut frame_count = 0;
        let mut offset = 0;
        while offset < observation.bytes.len() {
            assert!(offset + super::FRAME_HEADER_LEN <= observation.bytes.len());
            let frame_type = observation.bytes[offset];
            let frame_len = u32::from_be_bytes(observation.bytes[offset + 1..offset + 5].try_into().unwrap()) as usize;
            let payload_start = offset + super::FRAME_HEADER_LEN;
            let payload_end = payload_start + frame_len;
            assert!(payload_end <= observation.bytes.len());
            let payload = &observation.bytes[payload_start..payload_end];
            match frame_type {
                0x04 => {
                    assert_eq!(frame_len, 40);
                    assert_eq!(&payload[..32], &[0x5a; 32]);
                    assert!(payload[32..].iter().all(|byte| *byte == payload[32]));
                }
                0x0a => {
                    assert_eq!(frame_len, 72);
                    assert_eq!(&payload[..32], &[0x6b; 32]);
                    assert_eq!(&payload[32..64], &[0x5a; 32]);
                    assert!(payload[64..].iter().all(|byte| *byte == payload[64]));
                }
                0x12 | 0x13 => {
                    assert_eq!(frame_len, 8);
                    assert!(payload.iter().all(|byte| *byte == payload[0]));
                }
                other => panic!("unexpected DERP frame type {other:#x}"),
            }
            frame_count += 1;
            offset = payload_end;
        }
        assert_eq!(frame_count, THREADS * OPERATIONS_PER_THREAD);
    }

    #[test]
    fn server_info_json_matches_pinned_go_ascii_field_semantics() {
        use super::ServerInfo;

        assert_eq!(serde_json::from_str::<ServerInfo>("{}").unwrap(), ServerInfo::default());
        assert_eq!(serde_json::from_str::<ServerInfo>("null").unwrap(), ServerInfo::default());
        assert_eq!(
            serde_json::from_str::<ServerInfo>(
                r#"{"VERSION":1,"Version":2,"version":null,"tokenbucketbytespersecond":12,"TOKENBUCKETBYTESBURST":34,"other":{"nested":[1,true,null]}}"#
            )
            .unwrap(),
            ServerInfo { version: 2, token_bucket_bytes_per_second: 12, token_bucket_bytes_burst: 34 }
        );
        assert_eq!(
            serde_json::from_str::<ServerInfo>(
                r#"{"version":9223372036854775807,"TokenBucketBytesBurst":-9223372036854775808}"#
            )
            .unwrap(),
            ServerInfo { version: i64::MAX, token_bucket_bytes_per_second: 0, token_bucket_bytes_burst: i64::MIN }
        );
        for invalid in [
            r#"{"version":9223372036854775808}"#,
            r#"{"version":1.0}"#,
            r#"{"version":"2"}"#,
            "[]",
            "{} {}",
            r#"{"Verſion":2}"#,
        ] {
            assert!(serde_json::from_str::<ServerInfo>(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn client_info_json_matches_pinned_go_encoding_json_oracle() {
        assert_eq!(FRAME_CLIENT_INFO, FrameType(0x02));
        assert_eq!(PROTOCOL_VERSION, 2);
        assert_eq!(ClientInfo::default().to_json(), r#"{"CanAckPings":false}"#);

        let defaults = ClientInfo { version: PROTOCOL_VERSION, ..ClientInfo::default() };
        assert_eq!(defaults.to_json(), r#"{"version":2,"CanAckPings":false}"#);

        let ack = ClientInfo { version: PROTOCOL_VERSION, can_ack_pings: true, ..ClientInfo::default() };
        assert_eq!(ack.to_json(), r#"{"version":2,"CanAckPings":true}"#);

        let full = ClientInfo {
            mesh_key: std::array::from_fn(|index| index as u8),
            version: PROTOCOL_VERSION,
            can_ack_pings: true,
            is_prober: true,
            app_name: "<>& \" \\ /\n\t\u{2028}\u{2029}é".to_owned(),
        };
        assert_eq!(
            full.to_json(),
            r#"{"meshKey":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","version":2,"CanAckPings":true,"IsProber":true,"AppName":"\u003c\u003e\u0026 \" \\ /\n\t\u2028\u2029é"}"#
        );

        let omission = ClientInfo { app_name: "cue".to_owned(), ..ClientInfo::default() };
        assert_eq!(omission.to_json(), r#"{"CanAckPings":false,"AppName":"cue"}"#);
    }

    #[test]
    fn header_bytes_match_pinned_go_source_oracle() {
        for (kind, len, bytes) in [
            (0x01, 0, [0x01, 0, 0, 0, 0]),
            (0x12, 1, [0x12, 0, 0, 0, 1]),
            (0xff, 0x0102_0304, [0xff, 1, 2, 3, 4]),
            (0x00, u32::MAX, [0x00, 0xff, 0xff, 0xff, 0xff]),
        ] {
            let header = FrameHeader { frame_type: FrameType(kind), frame_len: len };
            assert_eq!(header.encode(), bytes);
            let input = [bytes.as_slice(), &[0xaa]].concat();
            let mut remaining = input.as_slice();
            assert_eq!(read_frame_header(&mut remaining), Ok(header));
            assert_eq!(remaining, [0xaa]);
        }
    }

    #[test]
    fn write_frame_matches_pinned_go_size_and_wire_boundaries() {
        for len in [0, 1, MAX_FRAME_WRITE_SIZE] {
            let payload = vec![0x5a; len];
            let mut output = vec![0xaa];
            assert_eq!(write_frame(&mut output, FrameType(0xff), &payload), Ok(()));
            assert_eq!(output.len(), 1 + 5 + len);
            assert_eq!(&output[..6], &[0xaa, 0xff, (len >> 24) as u8, (len >> 16) as u8, (len >> 8) as u8, len as u8]);
            assert_eq!(&output[6..], payload);
        }
        let mut output = vec![0xaa];
        let oversized = vec![0x5a; MAX_FRAME_WRITE_SIZE + 1];
        let error = write_frame(&mut output, FrameType(0xff), &oversized).unwrap_err();
        assert_eq!(error, WriteFrameError::UnreasonablyLarge);
        assert_eq!(error.to_string(), "unreasonably large frame write");
        assert_eq!(output, [0xaa]);
    }

    #[test]
    fn incomplete_header_does_not_consume_input() {
        let bytes = [0x01, 2, 3, 4];
        for n in 0..bytes.len() + 1 {
            let mut input = &bytes[..n];
            assert_eq!(read_frame_header(&mut input), Err(FrameHeaderError::Incomplete));
            assert_eq!(input, &bytes[..n]);
            assert_eq!(read_frame_type_header(&mut input, FrameType(1)), Err(FrameHeaderError::Incomplete));
            assert_eq!(input, &bytes[..n]);
        }
        assert_eq!(FrameHeaderError::Incomplete.to_string(), "EOF");
    }

    #[test]
    fn type_mismatch_consumes_header_and_preserves_length() {
        let bytes = [0x12, 1, 2, 3, 4, 0xaa];
        let mut input = bytes.as_slice();
        assert_eq!(read_frame_type_header(&mut input, FrameType(0x12)), Ok(0x0102_0304));
        assert_eq!(input, &[0xaa]);

        let mut input = bytes.as_slice();
        let err = read_frame_type_header(&mut input, FrameType(0x13)).unwrap_err();
        assert_eq!(
            err,
            FrameHeaderError::UnexpectedType { got: FrameType(0x12), want: FrameType(0x13), frame_len: 0x0102_0304 }
        );
        assert_eq!(err.to_string(), "bad frame type 0x12, want 0x13");
        assert_eq!(input, &[0xaa]);
    }

    #[test]
    fn bounded_read_matches_pinned_go_source_oracle() {
        let header3 = FrameHeader { frame_type: FrameType(0x12), frame_len: 3 };
        let header0 = FrameHeader { frame_type: FrameType(0x12), frame_len: 0 };
        type Case<'a> = (&'a str, &'a [u8], u32, usize, Result<FrameHeader, ReadFrameError>, &'a [u8], &'a [u8]);
        let cases: &[Case<'_>] = &[
            (
                "short_header",
                &[0x12, 0, 0, 0],
                4,
                4,
                Err(ReadFrameError::IncompleteHeader),
                &[0xee; 4],
                &[0x12, 0, 0, 0],
            ),
            ("empty", &[0x12, 0, 0, 0, 0, 0xaa], 0, 0, Ok(header0), &[], &[0xaa]),
            ("full", &[0x12, 0, 0, 0, 3, 1, 2, 3, 0xaa], 3, 3, Ok(header3), &[1, 2, 3], &[0xaa]),
            (
                "short_buffer",
                &[0x12, 0, 0, 0, 3, 1, 2, 3, 0xaa],
                3,
                1,
                Err(ReadFrameError::ShortBuffer { header: header3 }),
                &[1],
                &[0xaa],
            ),
            (
                "zero_buffer",
                &[0x12, 0, 0, 0, 3, 1, 2, 3, 0xaa],
                3,
                0,
                Err(ReadFrameError::ShortBuffer { header: header3 }),
                &[],
                &[0xaa],
            ),
            (
                "too_large",
                &[0x12, 0, 0, 0, 3, 1, 2, 3, 0xaa],
                2,
                3,
                Err(ReadFrameError::ExceedsLimit { frame_len: 3, max_size: 2 }),
                &[0xee; 3],
                &[1, 2, 3, 0xaa],
            ),
            ("body_empty", &[0x12, 0, 0, 0, 3], 3, 3, Err(ReadFrameError::EndOfInput), &[0xee; 3], &[]),
            (
                "body_partial",
                &[0x12, 0, 0, 0, 3, 1, 2],
                3,
                3,
                Err(ReadFrameError::UnexpectedEndOfInput),
                &[1, 2, 0xee],
                &[],
            ),
            ("discard_empty", &[0x12, 0, 0, 0, 3, 1], 3, 1, Err(ReadFrameError::EndOfInput), &[1], &[]),
            ("discard_partial", &[0x12, 0, 0, 0, 3, 1, 2], 3, 1, Err(ReadFrameError::EndOfInput), &[1], &[]),
        ];
        for &(name, data, max, output_len, expected, expected_output, expected_remaining) in cases {
            let mut input = data;
            let mut output = vec![0xee; output_len];
            assert_eq!(read_frame(&mut input, max, &mut output), expected, "{name}");
            assert_eq!(output, expected_output, "{name} output");
            assert_eq!(input, expected_remaining, "{name} remaining input");
        }
        assert_eq!(
            ReadFrameError::ExceedsLimit { frame_len: 3, max_size: 2 }.to_string(),
            "frame header size 3 exceeds reader limit of 2"
        );
        assert_eq!(ReadFrameError::EndOfInput.to_string(), "EOF");
        assert_eq!(ReadFrameError::UnexpectedEndOfInput.to_string(), "unexpected EOF");
        assert_eq!(ReadFrameError::ShortBuffer { header: header3 }.to_string(), "short buffer");
    }

    #[test]
    fn server_greeting_matches_source_derived_go_oracle() {
        for len in [40usize, 41, 1024] {
            let mut body = vec![0x5a; len];
            body[..8].copy_from_slice(&MAGIC);
            let mut wire = Vec::new();
            write_frame(&mut wire, FRAME_SERVER_KEY, &body).unwrap();
            wire.push(0xaa);
            let mut input = wire.as_slice();
            assert_eq!(read_server_greeting(&mut input).unwrap().raw_bytes(), [0x5a; 32]);
            assert_eq!(input, &[0xaa]);
        }

        let mut body = [0x5a; 40];
        body[..8].copy_from_slice(&MAGIC);
        for (kind, payload) in [(FrameType(0x12), body.as_slice()), (FRAME_SERVER_KEY, &body[..39])] {
            let mut wire = Vec::new();
            write_frame(&mut wire, kind, payload).unwrap();
            wire.push(0xaa);
            let mut input = wire.as_slice();
            assert_eq!(read_server_greeting(&mut input), Err(ServerGreetingError::Invalid));
            assert_eq!(input, &[0xaa]);
        }
        body[0] ^= 1;
        let mut wire = Vec::new();
        write_frame(&mut wire, FRAME_SERVER_KEY, &body).unwrap();
        let mut input = wire.as_slice();
        assert_eq!(read_server_greeting(&mut input).unwrap_err().to_string(), "invalid server greeting");

        body[..8].copy_from_slice(&MAGIC);
        body[8..].fill(0);
        wire.clear();
        write_frame(&mut wire, FRAME_SERVER_KEY, &body).unwrap();
        let mut input = wire.as_slice();
        assert!(read_server_greeting(&mut input).unwrap().is_zero());

        wire = FrameHeader { frame_type: FRAME_SERVER_KEY, frame_len: 1025 }.encode().to_vec();
        wire.extend_from_slice(&[0x5a; 1025]);
        wire.push(0xaa);
        let mut input = wire.as_slice();
        assert_eq!(
            read_server_greeting(&mut input),
            Err(ServerGreetingError::Read(ReadFrameError::ExceedsLimit { frame_len: 1025, max_size: 1024 }))
        );
        assert_eq!(input.len(), 1026);

        wire = FrameHeader { frame_type: FRAME_SERVER_KEY, frame_len: 40 }.encode().to_vec();
        wire.extend_from_slice(&body[..39]);
        let mut input = wire.as_slice();
        assert_eq!(
            read_server_greeting(&mut input),
            Err(ServerGreetingError::Read(ReadFrameError::UnexpectedEndOfInput))
        );
        assert!(input.is_empty());
    }

    #[test]
    fn client_handshake_orders_server_key_and_client_info_steps() {
        let alice =
            NodePrivate::from_text("privkey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let bob =
            NodePrivate::from_text("privkey:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
        let bob_public = bob.public().unwrap();
        let mut handshake = DerpClientHandshake::new(
            alice.clone(),
            Some(bob_public),
            ClientInfo { version: 99, can_ack_pings: true, ..ClientInfo::default() },
        )
        .unwrap();

        assert_eq!(handshake.state(), DerpClientHandshakeState::ReadyToSendClientInfo);
        assert_eq!(handshake.server_public_key(), Some(bob_public));
        let frame = handshake.build_client_info_frame().unwrap();
        assert_eq!(handshake.state(), DerpClientHandshakeState::AwaitingClientInfoWrite);
        assert_eq!(
            handshake.build_client_info_frame().unwrap_err(),
            DerpClientHandshakeError::InvalidState {
                expected: DerpClientHandshakeState::ReadyToSendClientInfo,
                actual: DerpClientHandshakeState::AwaitingClientInfoWrite,
            }
        );

        let mut remaining = frame.as_slice();
        let mut payload = vec![0; frame.len() - super::FRAME_HEADER_LEN];
        let header = read_frame(&mut remaining, MAX_FRAME_WRITE_SIZE as u32, &mut payload).unwrap();
        assert_eq!(header.frame_type, FRAME_CLIENT_INFO);
        assert!(remaining.is_empty());
        let alice_public = alice.public().unwrap();
        assert_eq!(&payload[..32], &alice_public.raw_bytes());
        assert_eq!(bob.open_from(&alice_public, &payload[32..]).unwrap(), br#"{"version":2,"CanAckPings":true}"#);

        handshake.client_info_sent().unwrap();
        assert_eq!(handshake.state(), DerpClientHandshakeState::Ready);
        assert_eq!(handshake.server_public_key(), Some(bob_public));
        assert_eq!(
            handshake.client_info_sent().unwrap_err(),
            DerpClientHandshakeError::InvalidState {
                expected: DerpClientHandshakeState::AwaitingClientInfoWrite,
                actual: DerpClientHandshakeState::Ready,
            }
        );
    }

    #[test]
    fn client_handshake_requires_and_validates_greeting_when_key_is_unknown() {
        let alice =
            NodePrivate::from_text("privkey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let bob =
            NodePrivate::from_text("privkey:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
        let bob_public = bob.public().unwrap();
        let zero_public = NodePublic::from_raw32([0; 32]);
        let mut handshake = DerpClientHandshake::new(alice.clone(), Some(zero_public), ClientInfo::default()).unwrap();
        assert_eq!(handshake.state(), DerpClientHandshakeState::AwaitingServerKey);
        assert_eq!(handshake.server_public_key(), None);
        assert_eq!(
            handshake.build_client_info_frame().unwrap_err(),
            DerpClientHandshakeError::InvalidState {
                expected: DerpClientHandshakeState::ReadyToSendClientInfo,
                actual: DerpClientHandshakeState::AwaitingServerKey,
            }
        );

        let mut zero_greeting = [0; 40];
        zero_greeting[..MAGIC.len()].copy_from_slice(&MAGIC);
        let mut wire = Vec::new();
        write_frame(&mut wire, FRAME_SERVER_KEY, &zero_greeting).unwrap();
        let mut input = wire.as_slice();
        assert_eq!(handshake.receive_server_greeting(&mut input), Err(DerpClientHandshakeError::ZeroServerPublicKey));
        assert_eq!(handshake.state(), DerpClientHandshakeState::AwaitingServerKey);

        let mut body = [0; 40];
        body[..MAGIC.len()].copy_from_slice(&MAGIC);
        body[MAGIC.len()..].copy_from_slice(&bob_public.raw_bytes());
        wire.clear();
        write_frame(&mut wire, FRAME_SERVER_KEY, &body).unwrap();
        wire.push(0xaa);
        let mut input = wire.as_slice();
        handshake.receive_server_greeting(&mut input).unwrap();
        assert_eq!(input, &[0xaa]);
        assert_eq!(handshake.state(), DerpClientHandshakeState::ReadyToSendClientInfo);
        assert_eq!(handshake.server_public_key(), Some(bob_public));
        assert_eq!(
            handshake.receive_server_greeting(&mut input).unwrap_err(),
            DerpClientHandshakeError::InvalidState {
                expected: DerpClientHandshakeState::AwaitingServerKey,
                actual: DerpClientHandshakeState::ReadyToSendClientInfo,
            }
        );

        let frame = handshake.build_client_info_frame().unwrap();
        assert_eq!(frame[0], FRAME_CLIENT_INFO.0);
        handshake.client_info_sent().unwrap();
        assert_eq!(handshake.state(), DerpClientHandshakeState::Ready);

        let zero_private = NodePrivate::from_text(&format!("privkey:{}", "00".repeat(32))).unwrap();
        assert_eq!(
            DerpClientHandshake::new(zero_private, Some(bob_public), ClientInfo::default()).err().unwrap(),
            DerpClientHandshakeError::ZeroPrivateKey
        );
    }

    #[test]
    fn stream_frame_reader_handles_partial_reads_and_discards_short_buffer_tail() {
        let mut wire = Vec::new();
        write_frame(&mut wire, FrameType(0x12), &[1, 2, 3, 4]).unwrap();
        write_frame(&mut wire, FrameType(0x13), &[9, 8]).unwrap();
        let mut reader = ChunkedReader::new(wire, 2);
        let mut small = [0; 2];
        assert!(matches!(
            read_frame_from(&mut reader, 16, &mut small),
            Err(StreamReadFrameError::ShortBuffer {
                header: FrameHeader { frame_type: FrameType(0x12), frame_len: 4 }
            })
        ));
        assert_eq!(small, [1, 2]);
        let mut next = [0; 2];
        assert_eq!(
            read_frame_from(&mut reader, 16, &mut next).unwrap(),
            FrameHeader { frame_type: FrameType(0x13), frame_len: 2 }
        );
        assert_eq!(next, [9, 8]);
        assert!(reader.remaining().is_empty());
    }

    #[test]
    fn stream_frame_reader_matches_go_eof_and_over_limit_boundaries() {
        let mut empty = ChunkedReader::new(Vec::new(), 2);
        assert!(matches!(read_frame_from(&mut empty, 10, &mut []), Err(StreamReadFrameError::EndOfInput)));

        let mut partial_header = ChunkedReader::new(vec![0x12, 0, 0], 2);
        assert!(matches!(
            read_frame_from(&mut partial_header, 10, &mut []),
            Err(StreamReadFrameError::UnexpectedEndOfInput)
        ));

        let mut partial_payload = ChunkedReader::new(vec![0x12, 0, 0, 0, 4, 1, 2], 2);
        let mut output = [0; 4];
        assert!(matches!(
            read_frame_from(&mut partial_payload, 10, &mut output),
            Err(StreamReadFrameError::UnexpectedEndOfInput)
        ));
        assert_eq!(&output[..2], &[1, 2]);

        let mut discard_eof = ChunkedReader::new(vec![0x12, 0, 0, 0, 4, 1, 2, 3], 2);
        let mut output = [0; 2];
        assert!(matches!(read_frame_from(&mut discard_eof, 10, &mut output), Err(StreamReadFrameError::EndOfInput)));

        let mut too_large_wire = FrameHeader { frame_type: FrameType(0x12), frame_len: 11 }.encode().to_vec();
        too_large_wire.extend_from_slice(&[0xaa; 11]);
        let mut too_large = ChunkedReader::new(too_large_wire, 3);
        assert!(matches!(
            read_frame_from(&mut too_large, 10, &mut [0; 4]),
            Err(StreamReadFrameError::ExceedsLimit { frame_len: 11, max_size: 10 })
        ));
        assert_eq!(too_large.remaining(), &[0xaa; 11]);
    }

    #[test]
    fn stream_frame_vec_reader_reports_reservation_failure() {
        assert!(matches!(super::reserve_frame_payload(usize::MAX), Err(StreamReadFrameError::Allocation)));
        assert_eq!(StreamReadFrameError::Allocation.to_string(), "unable to allocate DERP frame buffer");
    }

    #[test]
    fn stream_server_info_reader_matches_go_oracle_and_failure_boundaries() {
        let alice =
            NodePrivate::from_text("privkey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let bob =
            NodePrivate::from_text("privkey:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
        let bob_public = bob.public().unwrap();
        let payload = decode_hex("808182838485868788898a8b8c8d8e8f90919293949596972a5043cecfb67d977e3a71109462311a38a15b673d7b2bf55da90ef8f0d0c5313f73665a84fefee88e79c04d9f28b8eedadcd657528c5f0c7a08671cf92cd641f0e77fae5c0817566ac2b69be71d61523ec54dd49e137aaa9e0e19cb487e0f7557d9");
        let mut wire = Vec::new();
        write_frame(&mut wire, super::FRAME_SERVER_INFO, &payload).unwrap();
        wire.extend_from_slice(&[0x12, 0, 0, 0, 0]);
        let mut reader = ChunkedReader::new(wire, 7);
        let message = super::read_server_info_message_from(&mut reader, &alice, &bob_public).unwrap();
        assert_eq!(message.token_bucket_bytes_per_second, 16_777_216);
        assert_eq!(message.token_bucket_bytes_burst, 4_194_304);
        assert_eq!(reader.remaining(), &[0x12, 0, 0, 0, 0]);

        let mut empty = ChunkedReader::new(Vec::new(), 2);
        assert!(matches!(
            super::read_server_info_message_from(&mut empty, &alice, &bob_public),
            Err(super::StreamServerInfoError::Read(StreamReadFrameError::EndOfInput))
        ));
        let mut partial_header = ChunkedReader::new(vec![0x03, 0], 1);
        assert!(matches!(
            super::read_server_info_message_from(&mut partial_header, &alice, &bob_public),
            Err(super::StreamServerInfoError::Read(StreamReadFrameError::UnexpectedEndOfInput))
        ));

        let mut truncated = FrameHeader { frame_type: super::FRAME_SERVER_INFO, frame_len: 3 }.encode().to_vec();
        truncated.extend_from_slice(&[0xaa, 0xbb]);
        let mut truncated = ChunkedReader::new(truncated, 2);
        assert!(matches!(
            super::read_server_info_message_from(&mut truncated, &alice, &bob_public),
            Err(super::StreamServerInfoError::Read(StreamReadFrameError::UnexpectedEndOfInput))
        ));

        let over_limit = FrameHeader {
            frame_type: super::FRAME_SERVER_INFO,
            frame_len: (super::MAX_CLIENT_RECV_FRAME_LEN + 1) as u32,
        }
        .encode();
        let mut over_limit = over_limit.to_vec();
        over_limit.push(0xee);
        let mut over_limit = ChunkedReader::new(over_limit, 2);
        assert!(matches!(
            super::read_server_info_message_from(&mut over_limit, &alice, &bob_public),
            Err(super::StreamServerInfoError::Oversized { frame_len })
                if frame_len == (super::MAX_CLIENT_RECV_FRAME_LEN + 1) as u32
        ));
        assert_eq!(over_limit.remaining(), &[0xee]);

        let mut wrong_type = Vec::new();
        write_frame(&mut wrong_type, FrameType(0x12), &[]).unwrap();
        let mut wrong_type = ChunkedReader::new(wrong_type, 2);
        assert!(matches!(
            super::read_server_info_message_from(&mut wrong_type, &alice, &bob_public),
            Err(super::StreamServerInfoError::UnexpectedType { got: FrameType(0x12) })
        ));
    }

    #[test]
    fn received_message_routing_matches_pinned_go_client_recv_oracle() {
        let alice =
            NodePrivate::from_text("privkey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let bob =
            NodePrivate::from_text("privkey:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
        let bob_public = bob.public().unwrap();
        let peer_gone = [0x11; 32];
        let peer_present = [0x22; 32];
        let packet_source = [0x33; 32];

        let mut peer_gone_with_reason = peer_gone.to_vec();
        peer_gone_with_reason.extend_from_slice(&[0x7a, 0x99]);
        let mut peer_present_short_ip = peer_present.to_vec();
        peer_present_short_ip.extend_from_slice(&[0xaa; 17]);
        let mut peer_present_mapped = peer_present.to_vec();
        peer_present_mapped.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1]);
        peer_present_mapped.extend_from_slice(&[0x1f, 0x90, 0x0d, 0xee]);
        let mut packet = packet_source.to_vec();
        packet.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let mut restarting = [0; 10];
        restarting[..4].copy_from_slice(&123u32.to_be_bytes());
        restarting[4..8].copy_from_slice(&456u32.to_be_bytes());
        restarting[8..].copy_from_slice(&[0xaa, 0xbb]);

        let info_payload = decode_hex("808182838485868788898a8b8c8d8e8f90919293949596972a5043cecfb67d977e3a71109462311a38a15b673d7b2bf55da90ef8f0d0c5313f73665a84fefee88e79c04d9f28b8eedadcd657528c5f0c7a08671cf92cd641f0e77fae5c0817566ac2b69be71d61523ec54dd49e137aaa9e0e19cb487e0f7557d9");
        let cases = [
            ("keepalive-extra", super::FRAME_KEEP_ALIVE, vec![1, 2], super::ReceivedMessage::KeepAlive),
            (
                "peergone-default",
                super::FRAME_PEER_GONE,
                peer_gone.to_vec(),
                super::ReceivedMessage::PeerGone(super::PeerGoneMessage {
                    peer: NodePublic::from_raw32(peer_gone),
                    reason: 0,
                }),
            ),
            (
                "peergone-reason",
                super::FRAME_PEER_GONE,
                peer_gone_with_reason,
                super::ReceivedMessage::PeerGone(super::PeerGoneMessage {
                    peer: NodePublic::from_raw32(peer_gone),
                    reason: 0x7a,
                }),
            ),
            (
                "peerpresent-empty",
                super::FRAME_PEER_PRESENT,
                peer_present.to_vec(),
                super::ReceivedMessage::PeerPresent(super::PeerPresentMessage {
                    key: NodePublic::from_raw32(peer_present),
                    ip_port: None,
                    flags: 0,
                }),
            ),
            (
                "peerpresent-short-ip",
                super::FRAME_PEER_PRESENT,
                peer_present_short_ip,
                super::ReceivedMessage::PeerPresent(super::PeerPresentMessage {
                    key: NodePublic::from_raw32(peer_present),
                    ip_port: None,
                    flags: 0,
                }),
            ),
            (
                "peerpresent-mapped",
                super::FRAME_PEER_PRESENT,
                peer_present_mapped,
                super::ReceivedMessage::PeerPresent(super::PeerPresentMessage {
                    key: NodePublic::from_raw32(peer_present),
                    ip_port: Some("192.0.2.1:8080".parse().unwrap()),
                    flags: 0x0d,
                }),
            ),
            (
                "recv-packet",
                super::FRAME_RECV_PACKET,
                packet,
                super::ReceivedMessage::ReceivedPacket(super::ReceivedPacket {
                    source: NodePublic::from_raw32(packet_source),
                    data: vec![0xde, 0xad, 0xbe, 0xef],
                }),
            ),
            (
                "ping-extra",
                super::FRAME_PING,
                vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
                super::ReceivedMessage::Ping([0, 1, 2, 3, 4, 5, 6, 7]),
            ),
            (
                "pong",
                super::FRAME_PONG,
                vec![8, 7, 6, 5, 4, 3, 2, 1],
                super::ReceivedMessage::Pong([8, 7, 6, 5, 4, 3, 2, 1]),
            ),
            (
                "health-invalid-utf8",
                super::FRAME_HEALTH,
                vec![b'h', b'i', 0xff],
                super::ReceivedMessage::Health(super::HealthMessage { problem: vec![b'h', b'i', 0xff] }),
            ),
            (
                "restarting-extra",
                super::FRAME_RESTARTING,
                restarting.to_vec(),
                super::ReceivedMessage::ServerRestarting(super::ServerRestartingMessage {
                    reconnect_in: std::time::Duration::from_millis(123),
                    try_for: std::time::Duration::from_millis(456),
                }),
            ),
            (
                "serverinfo",
                super::FRAME_SERVER_INFO,
                info_payload,
                super::ReceivedMessage::ServerInfo(super::ServerInfoMessage {
                    token_bucket_bytes_per_second: 16_777_216,
                    token_bucket_bytes_burst: 4_194_304,
                }),
            ),
        ];

        for (name, frame_type, payload, expected) in cases {
            let mut wire = Vec::new();
            write_frame(&mut wire, frame_type, &payload).unwrap();
            let mut reader = ChunkedReader::new(wire, 3);
            assert_eq!(
                super::read_received_message_from(&mut reader, &alice, &bob_public).unwrap(),
                expected,
                "{name}"
            );
            assert!(reader.remaining().is_empty(), "{name}");
        }

        let mut skipped = Vec::new();
        for (frame_type, payload) in [
            (super::FRAME_PEER_GONE, vec![0; 31]),
            (super::FRAME_PEER_PRESENT, vec![0; 31]),
            (super::FRAME_RECV_PACKET, vec![0; 31]),
            (super::FRAME_PING, vec![0; 7]),
            (super::FRAME_PONG, vec![0; 7]),
            (super::FRAME_RESTARTING, vec![0; 7]),
            (FrameType(0x7f), Vec::new()),
            (super::FRAME_KEEP_ALIVE, vec![1, 2]),
        ] {
            write_frame(&mut skipped, frame_type, &payload).unwrap();
        }
        let mut skipped = ChunkedReader::new(skipped, 2);
        assert_eq!(
            super::read_received_message_from(&mut skipped, &alice, &bob_public).unwrap(),
            super::ReceivedMessage::KeepAlive
        );
        assert!(skipped.remaining().is_empty());

        let too_large_header = FrameHeader {
            frame_type: super::FRAME_KEEP_ALIVE,
            frame_len: (super::MAX_CLIENT_RECV_FRAME_LEN + 1) as u32,
        }
        .encode();
        let mut too_large_wire = too_large_header.to_vec();
        too_large_wire.push(0xee);
        let mut too_large = ChunkedReader::new(too_large_wire, 2);
        let error = super::read_received_message_from(&mut too_large, &alice, &bob_public).unwrap_err();
        assert_eq!(error.to_string(), "derp.Recv: unexpectedly large frame of 1048577 bytes returned");
        assert!(matches!(error, super::RecvMessageError::Oversized { frame_len: 1_048_577 }));
        assert_eq!(too_large.remaining(), &[0xee]);

        let server_info_error =
            super::RecvMessageError::ServerInfo(super::ServerInfoError::Box(NodeBoxError::Authentication));
        assert!(std::error::Error::source(&server_info_error).is_none());
    }

    #[test]
    fn recv_session_sets_per_frame_deadlines_and_latches_the_first_error() {
        let alice =
            NodePrivate::from_text("privkey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let bob =
            NodePrivate::from_text("privkey:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
        let mut wire = Vec::new();
        write_frame(&mut wire, FrameType(0x7f), &[0xaa]).unwrap();
        write_frame(&mut wire, super::FRAME_PEER_GONE, &[0; 31]).unwrap();
        write_frame(&mut wire, super::FRAME_KEEP_ALIVE, &[]).unwrap();
        let reader = DeadlineReader {
            inner: ChunkedReader::new(wire, 2),
            deadlines: Vec::new(),
            read_calls: 0,
            fail_deadline: true,
        };
        let mut session = DerpRecvSession::new(reader, alice, bob.public().unwrap());
        let started = Instant::now();
        assert_eq!(session.recv_next().unwrap(), super::ReceivedMessage::KeepAlive);
        let completed = Instant::now();

        assert_eq!(session.reader().deadlines.len(), 3);
        for deadline in &session.reader().deadlines {
            assert!(*deadline >= started + CLIENT_RECV_TIMEOUT - std::time::Duration::from_secs(1));
            assert!(*deadline <= completed + CLIENT_RECV_TIMEOUT);
        }

        let (first_error, first_inner) = {
            let error = session.recv_next().unwrap_err();
            (error.to_string(), Arc::clone(&error.inner))
        };
        assert_eq!(first_error, "derp.Recv: EOF");
        let reads_after_error = session.reader().read_calls;
        let deadlines_after_error = session.reader().deadlines.len();
        let second_error = session.recv_next().unwrap_err();
        assert_eq!(second_error.to_string(), first_error);
        assert!(Arc::ptr_eq(&first_inner, &second_error.inner));
        assert_eq!(session.reader().read_calls, reads_after_error);
        assert_eq!(session.reader().deadlines.len(), deadlines_after_error);
    }

    #[test]
    fn client_recv_session_applies_server_info_rate_before_returning_it() {
        let client =
            NodePrivate::from_text("privkey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let server =
            NodePrivate::from_text("privkey:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
        let client_public = client.public().unwrap();
        let server_public = server.public().unwrap();
        let payload =
            server.seal_to(&client_public, br#"{"TokenBucketBytesPerSecond":1,"TokenBucketBytesBurst":47}"#).unwrap();
        let mut wire = Vec::new();
        write_frame(&mut wire, super::FRAME_SERVER_INFO, &payload).unwrap();
        let reader = DeadlineReader {
            inner: ChunkedReader::new(wire, 3),
            deadlines: Vec::new(),
            read_calls: 0,
            fail_deadline: false,
        };

        let observation = Arc::new(Mutex::new(SharedWriteObservation::default()));
        let writer = Arc::new(DerpSendWriter::new(YieldingWriter { observation: Arc::clone(&observation) }, None));
        let mut session = DerpClientRecvSession::new(reader, client, server_public, Arc::clone(&writer));
        assert_eq!(
            session.recv_next().unwrap(),
            super::ReceivedMessage::ServerInfo(super::ServerInfoMessage {
                token_bucket_bytes_per_second: 1,
                token_bucket_bytes_burst: 47,
            })
        );

        let destination = NodePublic::from_raw32([0x73; 32]);
        let packet = [0x29; 10];
        assert_eq!(writer.send_packet(destination, &packet).unwrap(), super::SendPacketOutcome::Sent);
        assert_eq!(writer.send_packet(destination, &packet).unwrap(), super::SendPacketOutcome::Dropped);
        assert_eq!(observation.lock().unwrap().flushes, 1);
    }

    #[test]
    fn ping_and_pong_writers_match_pinned_go_send_oracle() {
        let mut writer = ChunkedWriter { bytes: Vec::new(), max_chunk: 2, flushes: 0 };
        write_ping_to(&mut writer, [0, 1, 2, 3, 4, 5, 6, 7]).unwrap();
        assert_eq!(writer.bytes, decode_hex("12000000080001020304050607"));
        assert_eq!(writer.flushes, 1);

        write_pong_to(&mut writer, [8, 7, 6, 5, 4, 3, 2, 1]).unwrap();
        assert_eq!(writer.bytes, decode_hex("1200000008000102030405060713000000080807060504030201"));
        assert_eq!(writer.flushes, 2);
    }

    #[test]
    fn stream_frame_writer_handles_partial_writes_flushes_and_rejects_oversize() {
        let mut writer = ChunkedWriter { bytes: Vec::new(), max_chunk: 2, flushes: 0 };
        write_frame_to(&mut writer, FrameType(0x13), &[1, 2, 3, 4, 5]).unwrap();
        let mut expected = Vec::new();
        write_frame(&mut expected, FrameType(0x13), &[1, 2, 3, 4, 5]).unwrap();
        assert_eq!(writer.bytes, expected);
        assert_eq!(writer.flushes, 1);

        let oversized = vec![0; MAX_FRAME_WRITE_SIZE + 1];
        let mut untouched = ChunkedWriter { bytes: Vec::new(), max_chunk: 3, flushes: 0 };
        assert!(matches!(
            write_frame_to(&mut untouched, FrameType(0x13), &oversized),
            Err(StreamWriteFrameError::UnreasonablyLarge)
        ));
        assert!(untouched.bytes.is_empty());
        assert_eq!(untouched.flushes, 0);
    }

    #[test]
    fn blocking_client_key_exchange_reads_greeting_then_writes_and_flushes_client_info() {
        let alice =
            NodePrivate::from_text("privkey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let bob =
            NodePrivate::from_text("privkey:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
        let bob_public = bob.public().unwrap();
        let mut greeting_body = vec![0; 45];
        greeting_body[..MAGIC.len()].copy_from_slice(&MAGIC);
        greeting_body[MAGIC.len()..MAGIC.len() + 32].copy_from_slice(&bob_public.raw_bytes());
        greeting_body[40..].fill(0xa5);
        let mut greeting = Vec::new();
        write_frame(&mut greeting, FRAME_SERVER_KEY, &greeting_body).unwrap();

        let mut stream = ChunkedDuplex::new(greeting.clone(), 3, 2);
        let mut client = DerpClientHandshake::new(
            alice.clone(),
            None,
            ClientInfo { version: 99, can_ack_pings: true, ..ClientInfo::default() },
        )
        .unwrap();
        client.perform_key_exchange(&mut stream).unwrap();
        assert_eq!(client.state(), DerpClientHandshakeState::Ready);
        assert_eq!(client.server_public_key(), Some(bob_public));
        assert_eq!(stream.read_position, greeting.len());
        assert_eq!(stream.flushes, 1);

        let mut remaining = stream.written.as_slice();
        let mut payload = vec![0; stream.written.len() - super::FRAME_HEADER_LEN];
        let header = read_frame(&mut remaining, MAX_FRAME_WRITE_SIZE as u32, &mut payload).unwrap();
        assert_eq!(header.frame_type, FRAME_CLIENT_INFO);
        assert!(remaining.is_empty());
        let alice_public = alice.public().unwrap();
        assert_eq!(bob.open_from(&alice_public, &payload[32..]).unwrap(), br#"{"version":2,"CanAckPings":true}"#);

        let mut known_key_stream = ChunkedDuplex::new(Vec::new(), 2, 3);
        let mut known_key_client = DerpClientHandshake::new(
            alice.clone(),
            Some(bob_public),
            ClientInfo { can_ack_pings: true, ..ClientInfo::default() },
        )
        .unwrap();
        known_key_client.perform_key_exchange(&mut known_key_stream).unwrap();
        assert_eq!(known_key_stream.read_position, 0);
        assert_eq!(known_key_stream.flushes, 1);
        assert_eq!(known_key_client.state(), DerpClientHandshakeState::Ready);

        let mut truncated_stream = ChunkedDuplex::new(greeting[..3].to_vec(), 2, 2);
        let mut truncated_client = DerpClientHandshake::new(alice, None, ClientInfo::default()).unwrap();
        assert!(matches!(
            truncated_client.perform_key_exchange(&mut truncated_stream),
            Err(DerpClientStreamHandshakeError::ServerGreetingRead(StreamReadFrameError::UnexpectedEndOfInput))
        ));
        assert_eq!(truncated_client.state(), DerpClientHandshakeState::AwaitingServerKey);
        assert!(truncated_stream.written.is_empty());
        assert_eq!(truncated_stream.flushes, 0);
    }
}
