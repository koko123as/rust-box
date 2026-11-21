//! The stream multiplexers of sing-mux: smux (sagernet/smux, version 1,
//! keep-alive off) and yamux (hashicorp/yamux with its flow control), on
//! one engine: a task reads frames and fills each stream's inbox, a task
//! writes the frames the streams queue.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll, Waker};

use rb_adapter::BoxStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf};
use tokio::sync::{mpsc, Notify};

/// Frames queued for the connection's writer.
const WRITE_QUEUE: usize = 64;

fn closed_pipe() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "io: read/write on closed pipe")
}

/// The data a stream received and not read yet.
#[derive(Default)]
struct InboxState {
    chunks: VecDeque<Vec<u8>>,
    buffered: usize,
    eof: bool,
    error: Option<(io::ErrorKind, String)>,
    waker: Option<Waker>,
}

#[derive(Default)]
pub(crate) struct Inbox(Mutex<InboxState>);

impl Inbox {
    fn push(&self, data: Vec<u8>) {
        let mut state = self.0.lock().unwrap();
        state.buffered += data.len();
        state.chunks.push_back(data);
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
    }

    fn finish(&self, error: Option<&io::Error>) {
        let mut state = self.0.lock().unwrap();
        match error {
            Some(error) if state.error.is_none() => state.error = Some((error.kind(), error.to_string())),
            _ => state.eof = true,
        }
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
    }

    fn buffered(&self) -> usize {
        self.0.lock().unwrap().buffered
    }
}

/// What a protocol does for its streams.
pub(crate) trait Protocol: Send + Sync + 'static {
    /// Room to send on stream `id` now (yamux's send window).
    fn poll_window(&self, cx: &mut Context<'_>, id: u32) -> Poll<io::Result<usize>>;
    /// The frame of `data` (at most the window) on stream `id`.
    fn data_frame(&self, id: u32, data: &[u8]) -> Vec<u8>;
    /// `count` bytes were read from stream `id`, which buffers
    /// `buffered` more (yamux sends window updates).
    fn consumed(&self, shared: &Shared, id: u32, count: usize, buffered: usize);
    /// The frame that closes stream `id` (or half-closes, yamux).
    fn close_frame(&self, id: u32) -> Vec<u8>;
    /// Largest data of one frame.
    fn max_frame(&self) -> usize;
}

/// What the streams of a session share.
pub(crate) struct Shared {
    pub(crate) writer: mpsc::Sender<Vec<u8>>,
    pub(crate) inboxes: Mutex<HashMap<u32, Arc<Inbox>>>,
    pub(crate) closed: AtomicBool,
    /// Bytes in every inbox (smux's session receive buffer).
    pub(crate) buffered: AtomicUsize,
    pub(crate) drained: Notify,
}

impl Shared {
    fn new(writer: mpsc::Sender<Vec<u8>>) -> Arc<Self> {
        Arc::new(Shared {
            writer,
            inboxes: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
            buffered: AtomicUsize::new(0),
            drained: Notify::new(),
        })
    }

    /// Queues a control frame without waiting.
    pub(crate) fn send_control(&self, frame: Vec<u8>) {
        if let Err(mpsc::error::TrySendError::Full(frame)) = self.writer.try_send(frame) {
            let writer = self.writer.clone();
            tokio::spawn(async move {
                let _ = writer.send(frame).await;
            });
        }
    }

    fn shutdown(&self, error: &io::Error) {
        self.closed.store(true, Ordering::SeqCst);
        for inbox in self.inboxes.lock().unwrap().drain().map(|(_, inbox)| inbox) {
            inbox.finish(Some(error));
        }
        self.drained.notify_waiters();
    }
}

type Reserve = Pin<Box<dyn Future<Output = Result<mpsc::OwnedPermit<Vec<u8>>, mpsc::error::SendError<()>>> + Send>>;

/// One stream of a session.
pub struct MuxStream {
    id: u32,
    inbox: Arc<Inbox>,
    shared: Arc<Shared>,
    protocol: Arc<dyn Protocol>,
    pending: Vec<u8>,
    offset: usize,
    reserve: Option<Reserve>,
    closed: bool,
}

impl MuxStream {
    fn new(id: u32, inbox: Arc<Inbox>, shared: Arc<Shared>, protocol: Arc<dyn Protocol>) -> Self {
        MuxStream { id, inbox, shared, protocol, pending: Vec::new(), offset: 0, reserve: None, closed: false }
    }

    fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            self.shared.send_control(self.protocol.close_frame(self.id));
        }
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.offset >= this.pending.len() {
            let mut state = this.inbox.0.lock().unwrap();
            match state.chunks.pop_front() {
                Some(chunk) => {
                    state.buffered -= chunk.len();
                    let buffered = state.buffered;
                    drop(state);
                    let previous = this.shared.buffered.fetch_sub(chunk.len(), Ordering::SeqCst);
                    if previous >= SMUX_RECEIVE_BUFFER && previous - chunk.len() < SMUX_RECEIVE_BUFFER {
                        this.shared.drained.notify_waiters();
                    }
                    this.protocol.consumed(&this.shared, this.id, chunk.len(), buffered);
                    this.pending = chunk;
                    this.offset = 0;
                }
                None => {
                    if let Some((kind, message)) = &state.error {
                        return Poll::Ready(Err(io::Error::new(*kind, message.clone())));
                    }
                    if state.eof {
                        return Poll::Ready(Ok(()));
                    }
                    state.waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
            }
        }
        let count = (this.pending.len() - this.offset).min(buf.remaining());
        buf.put_slice(&this.pending[this.offset..this.offset + count]);
        this.offset += count;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.closed || this.shared.closed.load(Ordering::SeqCst) {
            return Poll::Ready(Err(closed_pipe()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let window = ready!(this.protocol.poll_window(cx, this.id))?;
        if this.reserve.is_none() {
            this.reserve = Some(Box::pin(this.shared.writer.clone().reserve_owned()));
        }
        let permit = ready!(this.reserve.as_mut().unwrap().as_mut().poll(cx));
        this.reserve = None;
        let permit = permit.map_err(|_| closed_pipe())?;
        let count = data.len().min(window).min(this.protocol.max_frame());
        permit.send(this.protocol.data_frame(this.id, &data[..count]));
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.close();
        Poll::Ready(Ok(()))
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        self.close();
        self.protocol.consumed(&self.shared, self.id, 0, usize::MAX);
    }
}

/// smux's session receive buffer (`MaxReceiveBuffer`): the reader waits
/// while the streams hold more.
const SMUX_RECEIVE_BUFFER: usize = 4 * 1024 * 1024;

/// A multiplexed session over one connection.
pub struct Session {
    shared: Arc<Shared>,
    protocol: Arc<dyn Protocol>,
    kind: Kind,
    yamux: Option<Arc<Yamux>>,
    next_id: AtomicU32,
    accept: tokio::sync::Mutex<mpsc::Receiver<MuxStream>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Smux,
    Yamux,
}

impl Drop for Session {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Session {
    pub fn smux(conn: BoxStream, client: bool) -> Self {
        Session::start(conn, Kind::Smux, if client { 1 } else { 0 })
    }

    pub fn yamux(conn: BoxStream, client: bool) -> Self {
        Session::start(conn, Kind::Yamux, if client { 1 } else { 2 })
    }

    fn start(conn: BoxStream, kind: Kind, first_id: u32) -> Self {
        let (reader, mut writer) = tokio::io::split(conn);
        let (frames, mut queue) = mpsc::channel::<Vec<u8>>(WRITE_QUEUE);
        let shared = Shared::new(frames);
        let yamux = (kind == Kind::Yamux).then(|| Arc::new(Yamux::default()));
        let protocol: Arc<dyn Protocol> = match &yamux {
            Some(yamux) => yamux.clone(),
            None => Arc::new(Smux),
        };
        let writer_shared = shared.clone();
        let writer_task = tokio::spawn(async move {
            while let Some(frame) = queue.recv().await {
                if writer.write_all(&frame).await.is_err() {
                    break;
                }
                if queue.is_empty() && writer.flush().await.is_err() {
                    break;
                }
            }
            writer_shared.shutdown(&closed_pipe());
            let _ = writer.shutdown().await;
        });
        let (accepted, accept) = mpsc::channel(256);
        let reader_shared = shared.clone();
        let reader_protocol = protocol.clone();
        let reader_yamux = yamux.clone();
        let reader_task = tokio::spawn(async move {
            let error = match reader_yamux {
                None => smux_receive(reader, &reader_shared, &reader_protocol, accepted).await,
                Some(yamux) => yamux_receive(reader, &reader_shared, &yamux, &reader_protocol, accepted).await,
            };
            reader_shared.shutdown(&error);
        });
        Session {
            shared,
            protocol,
            kind,
            yamux,
            next_id: AtomicU32::new(first_id),
            accept: tokio::sync::Mutex::new(accept),
            tasks: vec![writer_task, reader_task],
        }
    }

    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::SeqCst)
    }

    pub fn num_streams(&self) -> usize {
        self.shared.inboxes.lock().unwrap().len()
    }

    /// Opens a stream (smux `OpenStream`, yamux `OpenStream`).
    pub async fn open(&self) -> io::Result<MuxStream> {
        if self.is_closed() {
            return Err(closed_pipe());
        }
        let id = match self.kind {
            // smux adds 2 before use; yamux uses then adds 2.
            Kind::Smux => self.next_id.fetch_add(2, Ordering::SeqCst) + 2,
            Kind::Yamux => self.next_id.fetch_add(2, Ordering::SeqCst),
        };
        let inbox = Arc::new(Inbox::default());
        self.shared.inboxes.lock().unwrap().insert(id, inbox.clone());
        let frame = match self.kind {
            Kind::Smux => smux_frame(CMD_SYN, id, &[]),
            Kind::Yamux => {
                if let Some(yamux) = &self.yamux {
                    yamux.open(id);
                }
                yamux_header(TYPE_WINDOW_UPDATE, FLAG_SYN, id, 0)
            }
        };
        self.shared.writer.send(frame).await.map_err(|_| closed_pipe())?;
        Ok(MuxStream::new(id, inbox, self.shared.clone(), self.protocol.clone()))
    }

    /// The next stream the peer opened.
    pub async fn accept(&self) -> io::Result<MuxStream> {
        self.accept.lock().await.recv().await.ok_or_else(closed_pipe)
    }

    pub fn close(&self) {
        if self.kind == Kind::Yamux && !self.is_closed() {
            self.shared.send_control(yamux_header(TYPE_GO_AWAY, 0, 0, 0));
        }
        self.shared.closed.store(true, Ordering::SeqCst);
        // The writer ends once every sender is gone; the reader task is
        // aborted when the session drops.
        for task in &self.tasks[1..] {
            task.abort();
        }
        self.shared.shutdown(&closed_pipe());
    }
}

// ---- smux ----

const SMUX_VERSION: u8 = 1;
const CMD_SYN: u8 = 0;
const CMD_FIN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_NOP: u8 = 3;
const SMUX_MAX_FRAME: usize = 32768;

fn smux_frame(cmd: u8, id: u32, data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(8 + data.len());
    frame.push(SMUX_VERSION);
    frame.push(cmd);
    frame.extend_from_slice(&(data.len() as u16).to_le_bytes());
    frame.extend_from_slice(&id.to_le_bytes());
    frame.extend_from_slice(data);
    frame
}

struct Smux;

impl Protocol for Smux {
    fn poll_window(&self, _cx: &mut Context<'_>, _id: u32) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(SMUX_MAX_FRAME))
    }

    fn data_frame(&self, id: u32, data: &[u8]) -> Vec<u8> {
        smux_frame(CMD_PSH, id, data)
    }

    fn consumed(&self, shared: &Shared, id: u32, _count: usize, buffered: usize) {
        if buffered == usize::MAX {
            // The stream is gone (smux `streamClosed`).
            if let Some(inbox) = shared.inboxes.lock().unwrap().remove(&id) {
                let left = inbox.buffered();
                let previous = shared.buffered.fetch_sub(left, Ordering::SeqCst);
                if previous >= SMUX_RECEIVE_BUFFER && previous - left < SMUX_RECEIVE_BUFFER {
                    shared.drained.notify_waiters();
                }
            }
        }
    }

    fn close_frame(&self, id: u32) -> Vec<u8> {
        smux_frame(CMD_FIN, id, &[])
    }

    fn max_frame(&self) -> usize {
        SMUX_MAX_FRAME
    }
}

async fn smux_receive(
    mut reader: ReadHalf<BoxStream>,
    shared: &Arc<Shared>,
    protocol: &Arc<dyn Protocol>,
    accepted: mpsc::Sender<MuxStream>,
) -> io::Error {
    loop {
        while shared.buffered.load(Ordering::SeqCst) >= SMUX_RECEIVE_BUFFER {
            let drained = shared.drained.notified();
            if shared.buffered.load(Ordering::SeqCst) < SMUX_RECEIVE_BUFFER {
                break;
            }
            drained.await;
        }
        let mut header = [0u8; 8];
        if let Err(error) = reader.read_exact(&mut header).await {
            return error;
        }
        if header[0] != SMUX_VERSION {
            return io::Error::new(io::ErrorKind::InvalidData, "invalid protocol");
        }
        let length = u16::from_le_bytes([header[2], header[3]]) as usize;
        let id = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        match header[1] {
            CMD_NOP => {}
            CMD_SYN => {
                let inbox = match shared.inboxes.lock().unwrap().entry(id) {
                    std::collections::hash_map::Entry::Occupied(_) => None,
                    std::collections::hash_map::Entry::Vacant(entry) => Some(entry.insert(Arc::default()).clone()),
                };
                if let Some(inbox) = inbox {
                    let stream = MuxStream::new(id, inbox, shared.clone(), protocol.clone());
                    if accepted.send(stream).await.is_err() {
                        return closed_pipe();
                    }
                }
            }
            CMD_FIN => {
                if let Some(inbox) = shared.inboxes.lock().unwrap().get(&id) {
                    inbox.finish(None);
                }
            }
            CMD_PSH => {
                if length == 0 {
                    continue;
                }
                let mut data = vec![0u8; length];
                if let Err(error) = reader.read_exact(&mut data).await {
                    return error;
                }
                if let Some(inbox) = shared.inboxes.lock().unwrap().get(&id) {
                    shared.buffered.fetch_add(data.len(), Ordering::SeqCst);
                    inbox.push(data);
                }
            }
            _ => return io::Error::new(io::ErrorKind::InvalidData, "invalid protocol"),
        }
    }
}

// ---- yamux ----

const TYPE_DATA: u8 = 0;
const TYPE_WINDOW_UPDATE: u8 = 1;
const TYPE_PING: u8 = 2;
const TYPE_GO_AWAY: u8 = 3;
const FLAG_SYN: u16 = 1;
const FLAG_ACK: u16 = 2;
const FLAG_FIN: u16 = 4;
const FLAG_RST: u16 = 8;
const YAMUX_WINDOW: u32 = 256 * 1024;
/// Largest data frame rust-box writes.
const YAMUX_MAX_FRAME: usize = 32 * 1024;

fn yamux_header(kind: u8, flags: u16, id: u32, length: u32) -> Vec<u8> {
    let mut header = Vec::with_capacity(12);
    header.push(0);
    header.push(kind);
    header.extend_from_slice(&flags.to_be_bytes());
    header.extend_from_slice(&id.to_be_bytes());
    header.extend_from_slice(&length.to_be_bytes());
    header
}

/// The flow control state of a yamux stream.
struct YamuxStream {
    send_window: u32,
    recv_window: u32,
    /// The flags the next frame carries (SYN when opening, ACK when
    /// accepting), sent once.
    flags: u16,
    waker: Option<Waker>,
}

#[derive(Default)]
struct Yamux {
    streams: Mutex<HashMap<u32, YamuxStream>>,
}

impl Yamux {
    fn open(&self, id: u32) {
        // The SYN goes out with the opening window update.
        self.streams
            .lock()
            .unwrap()
            .insert(id, YamuxStream { send_window: YAMUX_WINDOW, recv_window: YAMUX_WINDOW, flags: 0, waker: None });
    }

    /// A stream the peer opened; the ACK goes out at once, as
    /// hashicorp/yamux `AcceptStream` sends its window update.
    fn accept(&self, id: u32) -> Vec<u8> {
        self.streams
            .lock()
            .unwrap()
            .insert(id, YamuxStream { send_window: YAMUX_WINDOW, recv_window: YAMUX_WINDOW, flags: 0, waker: None });
        yamux_header(TYPE_WINDOW_UPDATE, FLAG_ACK, id, 0)
    }

    fn take_flags(&self, id: u32) -> u16 {
        self.streams.lock().unwrap().get_mut(&id).map_or(0, |stream| std::mem::take(&mut stream.flags))
    }

    fn grow(&self, id: u32, delta: u32) {
        if let Some(stream) = self.streams.lock().unwrap().get_mut(&id) {
            stream.send_window = stream.send_window.saturating_add(delta);
            if let Some(waker) = stream.waker.take() {
                waker.wake();
            }
        }
    }

    fn wake_all(&self) {
        for stream in self.streams.lock().unwrap().values_mut() {
            if let Some(waker) = stream.waker.take() {
                waker.wake();
            }
        }
    }
}

impl Protocol for Yamux {
    fn poll_window(&self, cx: &mut Context<'_>, id: u32) -> Poll<io::Result<usize>> {
        let mut streams = self.streams.lock().unwrap();
        let Some(stream) = streams.get_mut(&id) else { return Poll::Ready(Err(closed_pipe())) };
        if stream.send_window == 0 {
            stream.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Poll::Ready(Ok(stream.send_window as usize))
    }

    fn data_frame(&self, id: u32, data: &[u8]) -> Vec<u8> {
        let flags = {
            let mut streams = self.streams.lock().unwrap();
            match streams.get_mut(&id) {
                Some(stream) => {
                    stream.send_window -= data.len() as u32;
                    std::mem::take(&mut stream.flags)
                }
                None => 0,
            }
        };
        let mut frame = yamux_header(TYPE_DATA, flags, id, data.len() as u32);
        frame.extend_from_slice(data);
        frame
    }

    fn consumed(&self, shared: &Shared, id: u32, _count: usize, buffered: usize) {
        if buffered == usize::MAX {
            self.streams.lock().unwrap().remove(&id);
            shared.inboxes.lock().unwrap().remove(&id);
            return;
        }
        // hashicorp/yamux `sendWindowUpdate`.
        let update = {
            let mut streams = self.streams.lock().unwrap();
            let Some(stream) = streams.get_mut(&id) else { return };
            let delta = (YAMUX_WINDOW - buffered.min(YAMUX_WINDOW as usize) as u32).saturating_sub(stream.recv_window);
            if delta < YAMUX_WINDOW / 2 && stream.flags == 0 {
                return;
            }
            stream.recv_window += delta;
            (std::mem::take(&mut stream.flags), delta)
        };
        shared.send_control(yamux_header(TYPE_WINDOW_UPDATE, update.0, id, update.1));
    }

    fn close_frame(&self, id: u32) -> Vec<u8> {
        let flags = self.take_flags(id) | FLAG_FIN;
        yamux_header(TYPE_WINDOW_UPDATE, flags, id, 0)
    }

    fn max_frame(&self) -> usize {
        YAMUX_MAX_FRAME
    }
}

async fn yamux_receive(
    mut reader: ReadHalf<BoxStream>,
    shared: &Arc<Shared>,
    yamux: &Yamux,
    protocol: &Arc<dyn Protocol>,
    accepted: mpsc::Sender<MuxStream>,
) -> io::Error {
    let error = loop {
        let mut header = [0u8; 12];
        if let Err(error) = reader.read_exact(&mut header).await {
            break error;
        }
        if header[0] != 0 {
            break io::Error::new(io::ErrorKind::InvalidData, "invalid protocol version");
        }
        let flags = u16::from_be_bytes([header[2], header[3]]);
        let id = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
        let length = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
        match header[1] {
            TYPE_DATA | TYPE_WINDOW_UPDATE => {
                if flags & FLAG_SYN != 0 {
                    let inbox = Arc::new(Inbox::default());
                    let duplicate = shared.inboxes.lock().unwrap().insert(id, inbox.clone()).is_some();
                    if duplicate {
                        shared.send_control(yamux_header(TYPE_GO_AWAY, 0, 0, 1));
                        break io::Error::new(io::ErrorKind::InvalidData, "duplicate stream initiated");
                    }
                    shared.send_control(yamux.accept(id));
                    let stream = MuxStream::new(id, inbox, shared.clone(), protocol.clone());
                    if accepted.send(stream).await.is_err() {
                        break closed_pipe();
                    }
                }
                let inbox = shared.inboxes.lock().unwrap().get(&id).cloned();
                if header[1] == TYPE_WINDOW_UPDATE {
                    yamux.grow(id, length);
                } else if length > 0 {
                    let mut data = vec![0u8; length as usize];
                    if let Err(error) = reader.read_exact(&mut data).await {
                        break error;
                    }
                    if let Some(inbox) = &inbox {
                        let mut streams = yamux.streams.lock().unwrap();
                        if let Some(stream) = streams.get_mut(&id) {
                            if length > stream.recv_window {
                                break io::Error::new(io::ErrorKind::InvalidData, "recv window exceeded");
                            }
                            stream.recv_window -= length;
                        }
                        drop(streams);
                        inbox.push(data);
                    }
                }
                if let Some(inbox) = &inbox {
                    if flags & FLAG_FIN != 0 {
                        inbox.finish(None);
                    }
                    if flags & FLAG_RST != 0 {
                        inbox.finish(Some(&io::Error::new(io::ErrorKind::ConnectionReset, "connection reset")));
                        shared.inboxes.lock().unwrap().remove(&id);
                    }
                }
            }
            TYPE_PING => {
                if flags & FLAG_SYN != 0 {
                    shared.send_control(yamux_header(TYPE_PING, FLAG_ACK, 0, length));
                }
            }
            TYPE_GO_AWAY => {
                if length != 0 {
                    break io::Error::other("yamux protocol error");
                }
                shared.closed.store(true, Ordering::SeqCst);
            }
            _ => break io::Error::new(io::ErrorKind::InvalidData, "invalid msg type"),
        }
    };
    yamux.wake_all();
    error
}
