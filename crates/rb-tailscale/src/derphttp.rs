//! Narrow pure-Rust slices from the pinned fork's `derphttp.Client`.
//!
//! This module gates `SendPing` and `SendPong` on caller-supplied connection state,
//! dispatches registered Pong responses, and filters only matching Pong messages
//! from an already-created DERP receive session. It does not connect or reconnect,
//! assign connection generations, close transports, or implement the complete
//! `derphttp.Client` lifecycle.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::io::Write;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::derp::{
    DerpClientRecvSession, DerpSendWriter, ReceivedMessage, RecvDeadlineReader, RecvSessionError, StreamWriteFrameError,
};

/// Caller-owned connection state checked by the pinned fork's lower-level send methods.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DerpClientState {
    /// A current DERP client is available for frame writes.
    Connected,
    /// No current DERP client is available; these methods do not reconnect.
    Disconnected,
    /// The higher-level DERP client was permanently closed.
    Closed,
}

/// Compatibility name for the state used by the magicsock SendPong slice.
pub type DerpPongClientState = DerpClientState;

/// A closed-client, disconnected-client, or frame-write failure from SendPong.
#[derive(Debug)]
pub enum DerpPongSendError {
    ClientClosed,
    NotConnected,
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

/// A closed-client, disconnected-client, or frame-write failure from SendPing.
#[derive(Debug)]
pub enum DerpPingSendError {
    ClientClosed,
    ClientNotConnected,
    Write(StreamWriteFrameError),
}

impl fmt::Display for DerpPingSendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientClosed => f.write_str("derphttp.Client closed"),
            Self::ClientNotConnected => f.write_str("client not connected"),
            Self::Write(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl Error for DerpPingSendError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Write(error) => Some(error),
            Self::ClientClosed | Self::ClientNotConnected => None,
        }
    }
}

/// State gate for `derphttp.Client.SendPing` and `SendPong`.
///
/// This gate snapshots caller-supplied state and releases its lock before writing,
/// matching the pinned methods' state-check boundary. It never connects, reconnects,
/// cancels work, or closes the transport; the owner remains responsible for keeping
/// state synchronized with the actual client lifecycle.
pub struct DerphttpSendGate<W> {
    writer: Arc<DerpSendWriter<W>>,
    state: Mutex<DerpClientState>,
}

impl<W> DerphttpSendGate<W> {
    pub fn new(writer: Arc<DerpSendWriter<W>>, state: DerpClientState) -> Self {
        Self { writer, state: Mutex::new(state) }
    }

    fn lock_state(&self) -> MutexGuard<'_, DerpClientState> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn state(&self) -> DerpClientState {
        *self.lock_state()
    }

    pub fn mark_connected(&self) -> Result<(), DerpPongSendError> {
        let mut state = self.lock_state();
        if *state == DerpClientState::Closed {
            return Err(DerpPongSendError::ClientClosed);
        }
        *state = DerpClientState::Connected;
        Ok(())
    }

    pub fn mark_disconnected(&self) {
        let mut state = self.lock_state();
        if *state != DerpClientState::Closed {
            *state = DerpClientState::Disconnected;
        }
    }

    pub fn mark_closed(&self) -> Result<(), DerpPongSendError> {
        let mut state = self.lock_state();
        if *state == DerpClientState::Closed {
            return Err(DerpPongSendError::ClientClosed);
        }
        *state = DerpClientState::Closed;
        Ok(())
    }

    fn send_state(&self) -> DerpClientState {
        self.state()
    }
}

impl<W: Write> DerphttpSendGate<W> {
    /// Sends a Ping only when connected; it does not connect or reconnect.
    pub fn send_ping(&self, data: [u8; 8]) -> Result<(), DerpPingSendError> {
        match self.send_state() {
            DerpClientState::Connected => {}
            DerpClientState::Disconnected => return Err(DerpPingSendError::ClientNotConnected),
            DerpClientState::Closed => return Err(DerpPingSendError::ClientClosed),
        }
        self.writer.send_ping(data).map_err(DerpPingSendError::Write)
    }

    /// Sends a best-effort Pong only when connected; it does not reconnect.
    pub fn send_pong(&self, data: [u8; 8]) -> Result<(), DerpPongSendError> {
        match self.send_state() {
            DerpClientState::Connected => {}
            DerpClientState::Disconnected => return Err(DerpPongSendError::NotConnected),
            DerpClientState::Closed => return Err(DerpPongSendError::ClientClosed),
        }
        self.writer.send_pong(data).map_err(DerpPongSendError::Write)
    }
}

/// Compatibility alias for the previously introduced SendPong-only gate.
pub type DerpPongSendGate<W> = DerphttpSendGate<W>;

struct PongSignal {
    ready: Mutex<bool>,
    changed: Condvar,
}

impl PongSignal {
    fn new() -> Self {
        Self { ready: Mutex::new(false), changed: Condvar::new() }
    }

    fn lock_ready(&self) -> MutexGuard<'_, bool> {
        self.ready.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn signal(&self) {
        let should_notify = {
            let mut ready = self.lock_ready();
            if *ready {
                false
            } else {
                *ready = true;
                true
            }
        };
        if should_notify {
            self.changed.notify_one();
        }
    }
}

/// A one-shot notification that a matching DERP Pong was received.
pub struct PongResponseWaiter(Arc<PongSignal>);

impl PongResponseWaiter {
    /// Waits for the registered Pong, returning false if the duration expires.
    pub fn wait_timeout(&self, timeout: Duration) -> bool {
        let Some(deadline) = Instant::now().checked_add(timeout) else {
            let mut ready = self.0.lock_ready();
            while !*ready {
                ready = self.0.changed.wait(ready).unwrap_or_else(|poisoned| poisoned.into_inner());
            }
            return true;
        };

        let mut ready = self.0.lock_ready();
        loop {
            if *ready {
                return true;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let (next_ready, result) =
                self.0.changed.wait_timeout(ready, remaining).unwrap_or_else(|poisoned| poisoned.into_inner());
            ready = next_ready;
            if result.timed_out() && !*ready {
                return false;
            }
        }
    }
}

/// Tracks outstanding Ping identifiers for the pinned fork's Pong dispatch.
///
/// Registering a duplicate identifier replaces the prior waiter, matching the
/// fork's map assignment. A matching Pong signals and removes the current waiter.
pub struct DerpPongResponseRegistry {
    ping_out: Mutex<HashMap<[u8; 8], Arc<PongSignal>>>,
}

impl Default for DerpPongResponseRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl DerpPongResponseRegistry {
    pub fn new() -> Self {
        Self { ping_out: Mutex::new(HashMap::new()) }
    }

    fn lock_ping_out(&self) -> MutexGuard<'_, HashMap<[u8; 8], Arc<PongSignal>>> {
        self.ping_out.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Registers a Ping identifier and returns its one-shot response waiter.
    pub fn register_ping(&self, data: [u8; 8]) -> PongResponseWaiter {
        let signal = Arc::new(PongSignal::new());
        self.lock_ping_out().insert(data, Arc::clone(&signal));
        PongResponseWaiter(signal)
    }

    /// Removes a pending Ping identifier, if present.
    pub fn unregister_ping(&self, data: [u8; 8]) {
        self.lock_ping_out().remove(&data);
    }

    /// Signals and removes a registered matching Pong; returns false if unmatched.
    pub fn handle_pong(&self, data: [u8; 8]) -> bool {
        let mut ping_out = self.lock_ping_out();
        let Some(signal) = ping_out.get(&data).cloned() else {
            return false;
        };
        signal.signal();
        ping_out.remove(&data);
        true
    }
}

/// Filters registered matching Pongs from an already-created DERP receive session.
///
/// Matching Pongs wake their registered waiter and are consumed; unmatched Pongs
/// and all other recognized messages are returned. This is only the response
/// dispatch loop of `RecvDetail`, not the connection-generation or error-reconnect
/// lifecycle around it.
pub struct DerphttpPongFilter<R, W> {
    receiver: DerpClientRecvSession<R, W>,
    pong_responses: DerpPongResponseRegistry,
}

impl<R, W> DerphttpPongFilter<R, W> {
    pub fn new(receiver: DerpClientRecvSession<R, W>) -> Self {
        Self { receiver, pong_responses: DerpPongResponseRegistry::new() }
    }

    /// Returns the registry used by this receive filter.
    pub fn pong_responses(&self) -> &DerpPongResponseRegistry {
        &self.pong_responses
    }
}

impl<R: RecvDeadlineReader, W: Write> DerphttpPongFilter<R, W> {
    /// Returns the next message other than a registered matching Pong.
    pub fn recv_next(&mut self) -> Result<ReceivedMessage, RecvSessionError> {
        loop {
            match self.receiver.recv_next()? {
                ReceivedMessage::Pong(data) if self.pong_responses.handle_pong(data) => {}
                message => return Ok(message),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Read, Write};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use crate::derp::{
        write_frame, DerpClientRecvSession, DerpSendWriter, FrameHeader, ReceivedMessage, RecvDeadlineReader,
        FRAME_KEEP_ALIVE, FRAME_PING, FRAME_PONG,
    };
    use crate::{NodePrivate, NodePublic};

    use super::{DerpClientState, DerpPongResponseRegistry, DerphttpPongFilter, DerphttpSendGate};

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

    fn pong_wire(data: [u8; 8]) -> Vec<u8> {
        let mut wire = Vec::new();
        write_frame(&mut wire, FRAME_PONG, &data).unwrap();
        wire
    }

    fn make_filter(wire: Vec<u8>) -> DerphttpPongFilter<MemoryReader, Vec<u8>> {
        let client_private =
            NodePrivate::from_text("privkey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let receiver = DerpClientRecvSession::new(
            MemoryReader(Cursor::new(wire)),
            client_private,
            NodePublic::from_raw32([0x42; 32]),
            Arc::new(DerpSendWriter::new(Vec::new(), None)),
        );
        DerphttpPongFilter::new(receiver)
    }

    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedWriter {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(input);
            Ok(input.len())
        }

        fn flush(&mut self) -> io::Result<()> {
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

    fn make_send_gate(state: DerpClientState, bytes: Arc<Mutex<Vec<u8>>>) -> DerphttpSendGate<SharedWriter> {
        DerphttpSendGate::new(Arc::new(DerpSendWriter::new(SharedWriter(bytes), None)), state)
    }

    #[test]
    fn matching_pong_is_consumed_and_the_registration_is_removed_once() {
        let ping = *b"pingdata";
        let mut wire = pong_wire(ping);
        wire.extend_from_slice(&pong_wire(ping));
        write_frame(&mut wire, FRAME_KEEP_ALIVE, &[]).unwrap();
        let mut filter = make_filter(wire);
        let waiter = filter.pong_responses().register_ping(ping);

        assert_eq!(filter.recv_next().unwrap(), ReceivedMessage::Pong(ping));
        assert!(waiter.wait_timeout(Duration::ZERO));
        assert_eq!(filter.recv_next().unwrap(), ReceivedMessage::KeepAlive);
    }

    #[test]
    fn unmatched_pong_is_returned_to_the_caller() {
        let ping = *b"pingdata";
        let mut filter = make_filter(pong_wire(ping));

        assert_eq!(filter.recv_next().unwrap(), ReceivedMessage::Pong(ping));
    }

    #[test]
    fn duplicate_ping_identifier_replaces_the_previous_waiter() {
        let registry = DerpPongResponseRegistry::new();
        let ping = *b"pingdata";
        let first = registry.register_ping(ping);
        let second = registry.register_ping(ping);

        assert!(registry.handle_pong(ping));
        assert!(!first.wait_timeout(Duration::ZERO));
        assert!(second.wait_timeout(Duration::ZERO));
        assert!(!registry.handle_pong(ping));
    }

    #[test]
    fn unregistering_ping_leaves_pong_unmatched() {
        let registry = DerpPongResponseRegistry::new();
        let ping = *b"pingdata";
        let waiter = registry.register_ping(ping);
        registry.unregister_ping(ping);

        assert!(!registry.handle_pong(ping));
        assert!(!waiter.wait_timeout(Duration::ZERO));
    }

    #[test]
    fn send_ping_gate_returns_exact_disconnected_error_without_reconnecting() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let gate = make_send_gate(DerpClientState::Disconnected, Arc::clone(&bytes));

        assert_eq!(gate.send_ping(*b"pingdata").unwrap_err().to_string(), "client not connected");
        assert_eq!(gate.state(), DerpClientState::Disconnected);
        assert!(bytes.lock().unwrap().is_empty());
    }

    #[test]
    fn send_ping_gate_returns_closed_error_without_writing() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let gate = make_send_gate(DerpClientState::Closed, Arc::clone(&bytes));

        assert_eq!(gate.send_ping(*b"pingdata").unwrap_err().to_string(), "derphttp.Client closed");
        assert!(bytes.lock().unwrap().is_empty());
    }

    #[test]
    fn connected_send_ping_writes_the_exact_frame() {
        let ping = *b"pingdata";
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let gate = make_send_gate(DerpClientState::Connected, Arc::clone(&bytes));

        gate.send_ping(ping).unwrap();
        let mut expected = FrameHeader { frame_type: FRAME_PING, frame_len: 8 }.encode().to_vec();
        expected.extend_from_slice(&ping);
        assert_eq!(*bytes.lock().unwrap(), expected);
    }

    #[test]
    fn send_ping_writer_error_is_preserved_without_changing_connection_state() {
        let writer = Arc::new(DerpSendWriter::new(FailingWriter, None));
        let gate = DerphttpSendGate::new(writer, DerpClientState::Connected);
        let error = gate.send_ping(*b"pingdata").unwrap_err();

        assert_eq!(error.to_string(), "write failed");
        assert!(std::error::Error::source(&error).is_some());
        assert_eq!(gate.state(), DerpClientState::Connected);
    }
}
