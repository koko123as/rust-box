//! Narrow magicsock-level DERP receive behavior from the pinned Tailscale fork.
//!
//! The low-level DERP receiver continues to return Ping messages unchanged. This
//! wrapper models the higher-level magicsock branch: asynchronously schedule
//! `SendPong`, gate it on the caller-supplied connected/closed state without
//! implicit reconnect, report errors through the caller's logging hook, and
//! continue receiving without returning Ping to the caller. The narrow gate models
//! only `derphttp.Client.SendPong`; it does not own or close the transport. A
//! task-spawner interface keeps this protocol layer independent of a particular
//! executor; the included default uses one Rust standard-library thread per reply
//! and does not claim Go scheduler equivalence. This module does not implement the
//! rest of magicsock, the full `derphttp.Client` lifecycle, or the complete Tailscale
//! endpoint runtime.

use std::error::Error;
use std::fmt;
use std::io::{self, Write};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::derp::{
    DerpClientRecvSession, DerpSendWriter, ReceivedMessage, RecvDeadlineReader, RecvSessionError, StreamWriteFrameError,
};

/// A detached task scheduled for a best-effort DERP Pong reply.
pub type MagicsockTask = Box<dyn FnOnce() + Send + 'static>;

/// Schedules work asynchronously; implementations must not run `task` inline.
pub trait MagicsockTaskSpawner: Send + Sync + 'static {
    /// Schedules a task or reports that it could not be started.
    fn spawn(&self, task: MagicsockTask) -> io::Result<()>;
}

/// A pure Rust asynchronous spawner backed by one detached OS thread per task.
///
/// This provides the required message-level asynchronous behavior, not Go
/// goroutine scheduling, thread-pool, or resource-consumption parity.
#[derive(Clone, Copy, Debug, Default)]
pub struct StdThreadPongSpawner;

impl MagicsockTaskSpawner for StdThreadPongSpawner {
    fn spawn(&self, task: MagicsockTask) -> io::Result<()> {
        let handle = std::thread::Builder::new().spawn(task)?;
        // Dropping a JoinHandle detaches the thread, matching the unjoined Go
        // goroutine behavior at this call site.
        drop(handle);
        Ok(())
    }
}

/// The caller-owned connection state relevant to `derphttp.Client.SendPong`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DerpPongClientState {
    /// A current DERP client is available for a best-effort Pong write.
    Connected,
    /// No current DERP client is available; sending does not connect or reconnect.
    Disconnected,
    /// The higher-level client was permanently closed.
    Closed,
}

/// A `SendPong` availability or frame-write failure.
#[derive(Debug)]
pub enum DerpPongSendError {
    /// The higher-level DERP client has been closed.
    ClientClosed,
    /// No current DERP client is connected; `SendPong` will not reconnect it.
    NotConnected,
    /// The underlying DERP Pong frame write failed.
    Write(StreamWriteFrameError),
}

impl fmt::Display for DerpPongSendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientClosed => f.write_str("derphttp.Client closed"),
            Self::NotConnected => f.write_str("not connected"),
            Self::Write(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl Error for DerpPongSendError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Write(error) => Some(error),
            Self::ClientClosed | Self::NotConnected => None,
        }
    }
}

/// A narrow gate for the pinned fork's `derphttp.Client.SendPong` state checks.
///
/// It never dials or reconnects. The owner supplies the initial state and must
/// update it as its connection lifecycle changes. `mark_closed` only changes this
/// gate; the owner remains responsible for canceling work and closing the actual
/// transport, which this slice does not own.
pub struct DerpPongSendGate<W> {
    writer: Arc<DerpSendWriter<W>>,
    state: Mutex<DerpPongClientState>,
}

impl<W> DerpPongSendGate<W> {
    /// Wraps a shared DERP writer and the owner's current connection state.
    pub fn new(writer: Arc<DerpSendWriter<W>>, state: DerpPongClientState) -> Self {
        Self { writer, state: Mutex::new(state) }
    }

    fn lock_state(&self) -> MutexGuard<'_, DerpPongClientState> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Returns the current state used for best-effort Pong gating.
    pub fn state(&self) -> DerpPongClientState {
        *self.lock_state()
    }

    /// Marks a live connection available, unless the client was permanently closed.
    pub fn mark_connected(&self) -> Result<(), DerpPongSendError> {
        let mut state = self.lock_state();
        if *state == DerpPongClientState::Closed {
            return Err(DerpPongSendError::ClientClosed);
        }
        *state = DerpPongClientState::Connected;
        Ok(())
    }

    /// Marks the current connection unavailable without implicitly reconnecting.
    pub fn mark_disconnected(&self) {
        let mut state = self.lock_state();
        if *state != DerpPongClientState::Closed {
            *state = DerpPongClientState::Disconnected;
        }
    }

    /// Permanently closes this gate; repeated close attempts report the fork error.
    pub fn mark_closed(&self) -> Result<(), DerpPongSendError> {
        let mut state = self.lock_state();
        if *state == DerpPongClientState::Closed {
            return Err(DerpPongSendError::ClientClosed);
        }
        *state = DerpPongClientState::Closed;
        Ok(())
    }
}

impl<W: Write> DerpPongSendGate<W> {
    /// Sends a Pong only when a current client is connected and not closed.
    ///
    /// The state lock is released before writing, matching the pinned fork's
    /// `SendPong` critical-section boundary.
    pub fn send_pong(&self, data: [u8; 8]) -> Result<(), DerpPongSendError> {
        let state = self.lock_state();
        match *state {
            DerpPongClientState::Connected => {}
            DerpPongClientState::Disconnected => return Err(DerpPongSendError::NotConnected),
            DerpPongClientState::Closed => return Err(DerpPongSendError::ClientClosed),
        }
        drop(state);
        self.writer.send_pong(data).map_err(DerpPongSendError::Write)
    }
}

/// A magicsock-level DERP receive-loop slice for asynchronous Ping replies.
pub struct MagicsockDerpRecvLoop<R, W, S = StdThreadPongSpawner> {
    receiver: DerpClientRecvSession<R, W>,
    pong_sender: Arc<DerpPongSendGate<W>>,
    region_id: usize,
    spawner: S,
    log_pong_error: Arc<dyn Fn(String) + Send + Sync + 'static>,
}

impl<R, W> MagicsockDerpRecvLoop<R, W, StdThreadPongSpawner> {
    /// Wraps a DERP client receive session using detached standard-library threads.
    pub fn new(
        receiver: DerpClientRecvSession<R, W>,
        region_id: usize,
        initial_pong_state: DerpPongClientState,
        log_pong_error: impl Fn(String) + Send + Sync + 'static,
    ) -> Self {
        Self::with_spawner(receiver, region_id, initial_pong_state, StdThreadPongSpawner, log_pong_error)
    }
}

impl<R, W, S> MagicsockDerpRecvLoop<R, W, S> {
    /// Wraps a DERP client receive session using the caller's asynchronous spawner.
    pub fn with_spawner(
        receiver: DerpClientRecvSession<R, W>,
        region_id: usize,
        initial_pong_state: DerpPongClientState,
        spawner: S,
        log_pong_error: impl Fn(String) + Send + Sync + 'static,
    ) -> Self {
        let pong_sender = Arc::new(DerpPongSendGate::new(Arc::clone(receiver.send_writer()), initial_pong_state));
        Self { receiver, pong_sender, region_id, spawner, log_pong_error: Arc::new(log_pong_error) }
    }

    /// Returns the gate the owner updates when connection state changes.
    pub fn pong_send_gate(&self) -> &DerpPongSendGate<W> {
        &self.pong_sender
    }
}

impl<R: RecvDeadlineReader, W: Write + Send + 'static, S: MagicsockTaskSpawner> MagicsockDerpRecvLoop<R, W, S> {
    /// Returns the next non-Ping message, scheduling each Pong asynchronously.
    ///
    /// Send failures are reported to `log_pong_error` by the detached task; they
    /// do not terminate this receive loop, matching magicsock's best-effort Ping
    /// branch. A local task-spawner failure is reported and the receive loop also
    /// continues without a synchronous fallback.
    pub fn recv_next(&mut self) -> Result<ReceivedMessage, RecvSessionError> {
        loop {
            let message = match self.receiver.recv_next() {
                Ok(message) => message,
                Err(error) => {
                    self.pong_sender.mark_disconnected();
                    return Err(error);
                }
            };
            match message {
                ReceivedMessage::Ping(data) => {
                    let pong_sender = Arc::clone(&self.pong_sender);
                    let log_pong_error = Arc::clone(&self.log_pong_error);
                    let region_id = self.region_id;
                    let task: MagicsockTask = Box::new(move || {
                        if let Err(error) = pong_sender.send_pong(data) {
                            log_pong_error(format!("magicsock: derp-{region_id} SendPong error: {error}"));
                        }
                    });
                    if let Err(error) = self.spawner.spawn(task) {
                        (self.log_pong_error)(format!(
                            "magicsock: derp-{region_id} SendPong scheduling error: {error}"
                        ));
                    }
                }
                message => return Ok(message),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Read, Write};
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use crate::derp::{
        write_frame, DerpClientRecvSession, DerpSendWriter, FrameHeader, ReceivedMessage, RecvDeadlineReader,
        FRAME_KEEP_ALIVE, FRAME_PING, FRAME_PONG,
    };
    use crate::{NodePrivate, NodePublic};

    use super::{
        DerpPongClientState, DerpPongSendGate, MagicsockDerpRecvLoop, MagicsockTask, MagicsockTaskSpawner,
        StdThreadPongSpawner,
    };

    struct MemoryReader(Cursor<Vec<u8>>);

    impl Read for MemoryReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.0.read(output)
        }
    }

    impl RecvDeadlineReader for MemoryReader {
        fn set_read_deadline(&mut self, _deadline: Instant) -> io::Result<()> {
            Ok(())
        }
    }

    fn incoming_ping_then_keepalive(data: [u8; 8]) -> Vec<u8> {
        let mut wire = Vec::new();
        write_frame(&mut wire, FRAME_PING, &data).unwrap();
        write_frame(&mut wire, FRAME_KEEP_ALIVE, &[]).unwrap();
        wire
    }

    fn new_loop_with_spawner<W: Write + Send + 'static, S: MagicsockTaskSpawner>(
        wire: Vec<u8>,
        writer: W,
        initial_pong_state: DerpPongClientState,
        spawner: S,
        log_error: impl Fn(String) + Send + Sync + 'static,
    ) -> MagicsockDerpRecvLoop<MemoryReader, W, S> {
        let client =
            NodePrivate::from_text("privkey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let receiver = DerpClientRecvSession::new(
            MemoryReader(Cursor::new(wire)),
            client,
            NodePublic::from_raw32([0x42; 32]),
            Arc::new(DerpSendWriter::new(writer, None)),
        );
        MagicsockDerpRecvLoop::with_spawner(receiver, 7, initial_pong_state, spawner, log_error)
    }

    fn new_loop_with_initial_state<W: Write + Send + 'static>(
        wire: Vec<u8>,
        writer: W,
        initial_pong_state: DerpPongClientState,
        log_error: impl Fn(String) + Send + Sync + 'static,
    ) -> MagicsockDerpRecvLoop<MemoryReader, W> {
        new_loop_with_spawner(wire, writer, initial_pong_state, StdThreadPongSpawner, log_error)
    }

    fn new_loop<W: Write + Send + 'static>(
        wire: Vec<u8>,
        writer: W,
        log_error: impl Fn(String) + Send + Sync + 'static,
    ) -> MagicsockDerpRecvLoop<MemoryReader, W> {
        new_loop_with_initial_state(wire, writer, DerpPongClientState::Connected, log_error)
    }

    struct BlockingWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
        started: Option<Sender<()>>,
        release: Receiver<()>,
        flushed: Sender<()>,
    }

    impl Write for BlockingWriter {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            if let Some(started) = self.started.take() {
                started.send(()).map_err(|_| io::Error::other("test start receiver dropped"))?;
                self.release.recv().map_err(|_| io::Error::other("test release sender dropped"))?;
            }
            self.bytes.lock().unwrap().extend_from_slice(input);
            Ok(input.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushed.send(()).map_err(|_| io::Error::other("test flush receiver dropped"))
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

    struct RecordingWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for RecordingWriter {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            self.bytes.lock().unwrap().extend_from_slice(input);
            Ok(input.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FailingSpawner;

    impl MagicsockTaskSpawner for FailingSpawner {
        fn spawn(&self, _task: MagicsockTask) -> io::Result<()> {
            Err(io::Error::other("spawn unavailable"))
        }
    }

    #[test]
    fn ping_schedules_blocking_pong_without_blocking_receive() {
        let ping = *b"pingdata";
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (flushed_tx, flushed_rx) = mpsc::channel();
        let (error_tx, error_rx) = mpsc::channel();
        let writer = BlockingWriter {
            bytes: Arc::clone(&bytes),
            started: Some(started_tx),
            release: release_rx,
            flushed: flushed_tx,
        };
        let mut receive_loop = new_loop(incoming_ping_then_keepalive(ping), writer, move |error| {
            error_tx.send(error).unwrap();
        });

        assert_eq!(receive_loop.recv_next().unwrap(), ReceivedMessage::KeepAlive);
        started_rx.recv_timeout(Duration::from_secs(5)).expect("Pong task should start");
        assert!(error_rx.try_recv().is_err());

        release_tx.send(()).unwrap();
        flushed_rx.recv_timeout(Duration::from_secs(5)).expect("Pong frame should flush");
        let mut expected = FrameHeader { frame_type: FRAME_PONG, frame_len: 8 }.encode().to_vec();
        expected.extend_from_slice(&ping);
        assert_eq!(*bytes.lock().unwrap(), expected);
    }

    #[test]
    fn pong_write_failure_is_reported_but_receive_continues() {
        let (error_tx, error_rx) = mpsc::channel();
        let mut receive_loop = new_loop(incoming_ping_then_keepalive(*b"pingdata"), FailingWriter, move |error| {
            error_tx.send(error).unwrap();
        });

        assert_eq!(receive_loop.recv_next().unwrap(), ReceivedMessage::KeepAlive);
        assert_eq!(
            error_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            "magicsock: derp-7 SendPong error: write failed"
        );
    }

    #[test]
    fn task_spawner_failure_is_reported_but_receive_continues() {
        let (error_tx, error_rx) = mpsc::channel();
        let mut receive_loop = new_loop_with_spawner(
            incoming_ping_then_keepalive(*b"pingdata"),
            FailingWriter,
            DerpPongClientState::Connected,
            FailingSpawner,
            move |error| {
                error_tx.send(error).unwrap();
            },
        );

        assert_eq!(receive_loop.recv_next().unwrap(), ReceivedMessage::KeepAlive);
        assert_eq!(error_rx.try_recv().unwrap(), "magicsock: derp-7 SendPong scheduling error: spawn unavailable");
    }

    #[test]
    fn disconnected_pong_gate_does_not_write_or_reconnect_and_receive_continues() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let (error_tx, error_rx) = mpsc::channel();
        let mut receive_loop = new_loop_with_initial_state(
            incoming_ping_then_keepalive(*b"pingdata"),
            RecordingWriter { bytes: Arc::clone(&bytes) },
            DerpPongClientState::Disconnected,
            move |error| error_tx.send(error).unwrap(),
        );

        assert_eq!(receive_loop.recv_next().unwrap(), ReceivedMessage::KeepAlive);
        assert_eq!(receive_loop.pong_send_gate().state(), DerpPongClientState::Disconnected);
        assert_eq!(
            error_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            "magicsock: derp-7 SendPong error: not connected"
        );
        assert!(bytes.lock().unwrap().is_empty());
    }

    #[test]
    fn closed_pong_gate_is_terminal_and_does_not_write() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let writer = Arc::new(DerpSendWriter::new(RecordingWriter { bytes: Arc::clone(&bytes) }, None));
        let gate = DerpPongSendGate::new(writer, DerpPongClientState::Connected);

        gate.mark_closed().unwrap();
        assert_eq!(gate.send_pong(*b"pingdata").unwrap_err().to_string(), "derphttp.Client closed");
        assert_eq!(gate.mark_connected().unwrap_err().to_string(), "derphttp.Client closed");
        assert_eq!(gate.mark_closed().unwrap_err().to_string(), "derphttp.Client closed");
        assert_eq!(gate.state(), DerpPongClientState::Closed);
        assert!(bytes.lock().unwrap().is_empty());
    }

    #[test]
    fn receive_error_marks_pong_gate_disconnected() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let mut receive_loop =
            new_loop_with_initial_state(Vec::new(), RecordingWriter { bytes }, DerpPongClientState::Connected, |_| {});

        assert_eq!(receive_loop.recv_next().unwrap_err().to_string(), "derp.Recv: EOF");
        assert_eq!(receive_loop.pong_send_gate().state(), DerpPongClientState::Disconnected);
    }

    #[test]
    fn connected_pong_gate_preserves_writer_error_source() {
        let writer = Arc::new(DerpSendWriter::new(FailingWriter, None));
        let gate = DerpPongSendGate::new(writer, DerpPongClientState::Connected);
        let error = gate.send_pong(*b"pingdata").unwrap_err();

        assert_eq!(error.to_string(), "write failed");
        assert!(std::error::Error::source(&error).is_some());
    }
}
