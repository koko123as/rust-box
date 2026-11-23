//! Narrow pure-Rust slices from the pinned fork's `derphttp.Client`.
//!
//! This module gates `SendPing` and `SendPong` on caller-supplied connection state,
//! dispatches registered Pong responses, and filters only matching Pong messages
//! from an already-created DERP receive session. Its bounded Ping helper models a
//! five-second maximum deadline and an explicit cancellation token, but not Go
//! scheduler select parity. It does not connect or reconnect, assign connection
//! generations, close transports, or implement the complete `derphttp.Client` lifecycle.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::io::Write;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use rand::rand_core::OsRng;
use rand::TryRngCore;

use crate::derp::{
    DerpClientRecvSession, DerpSendWriter, ReceivedMessage, RecvDeadlineReader, RecvSessionError, StreamWriteFrameError,
};

/// Maximum wait in the pinned fork's high-level `derphttp.Client.Ping` operation.
pub const DERP_PING_MAX_WAIT: Duration = Duration::from_secs(5);

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

/// Failure from the bounded high-level Ping helper.
#[derive(Debug)]
pub enum DerphttpPingError {
    Entropy(String),
    Send(DerpPingSendError),
    Cancelled,
    DeadlineExceeded,
    DeadlineOverflow,
}

impl fmt::Display for DerphttpPingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entropy(error) => write!(f, "DERP Ping randomness unavailable: {error}"),
            Self::Send(error) => fmt::Display::fmt(error, f),
            Self::Cancelled => f.write_str("context canceled"),
            Self::DeadlineExceeded => f.write_str("context deadline exceeded"),
            Self::DeadlineOverflow => f.write_str("DERP Ping deadline overflow"),
        }
    }
}

impl Error for DerphttpPingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Send(error) => Some(error),
            Self::Entropy(_) | Self::Cancelled | Self::DeadlineExceeded | Self::DeadlineOverflow => None,
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

/// Computes the high-level Ping deadline: the earlier of the caller deadline and
/// the pinned fork's fixed five-second maximum.
fn ping_deadline(start: Instant, caller_deadline: Option<Instant>) -> Option<Instant> {
    let maximum = start.checked_add(DERP_PING_MAX_WAIT)?;
    Some(caller_deadline.map_or(maximum, |deadline| deadline.min(maximum)))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PongSignalState {
    Pending,
    Pong,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PongWaitOutcome {
    Pong,
    Cancelled,
    DeadlineExceeded,
}

struct PongSignal {
    state: Mutex<PongSignalState>,
    changed: Condvar,
}

impl PongSignal {
    fn new() -> Self {
        Self { state: Mutex::new(PongSignalState::Pending), changed: Condvar::new() }
    }

    fn lock_state(&self) -> MutexGuard<'_, PongSignalState> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn transition(&self, next: PongSignalState) {
        let should_notify = {
            let mut state = self.lock_state();
            if *state == PongSignalState::Pending {
                *state = next;
                true
            } else {
                false
            }
        };
        if should_notify {
            self.changed.notify_one();
        }
    }

    fn signal(&self) {
        self.transition(PongSignalState::Pong);
    }

    fn cancel(&self) {
        self.transition(PongSignalState::Cancelled);
    }

    fn wait_until(&self, deadline: Option<Instant>) -> PongWaitOutcome {
        let mut state = self.lock_state();
        loop {
            match *state {
                PongSignalState::Pong => return PongWaitOutcome::Pong,
                PongSignalState::Cancelled => return PongWaitOutcome::Cancelled,
                PongSignalState::Pending => {}
            }

            let Some(deadline) = deadline else {
                state = self.changed.wait(state).unwrap_or_else(|poisoned| poisoned.into_inner());
                continue;
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return PongWaitOutcome::DeadlineExceeded;
            }
            let (next, result) =
                self.changed.wait_timeout(state, remaining).unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next;
            if result.timed_out() && *state == PongSignalState::Pending {
                return PongWaitOutcome::DeadlineExceeded;
            }
        }
    }
}

#[derive(Default)]
struct PingCancellationState {
    cancelled: bool,
    waiters: Vec<Weak<PongSignal>>,
}

/// A cloneable cancellation signal for a DERP Ping wait.
///
/// Cancelling wakes every currently subscribed Ping; it does not close or reconnect
/// the transport. A Ping still sends its frame before observing this signal.
#[derive(Clone, Default)]
pub struct DerpPingCancellationToken {
    state: Arc<Mutex<PingCancellationState>>,
}

impl DerpPingCancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock_state(&self) -> MutexGuard<'_, PingCancellationState> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Marks the token cancelled and wakes all outstanding Ping waiters.
    pub fn cancel(&self) {
        let mut state = self.lock_state();
        if state.cancelled {
            return;
        }
        state.cancelled = true;
        for waiter in state.waiters.drain(..) {
            if let Some(waiter) = waiter.upgrade() {
                waiter.cancel();
            }
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.lock_state().cancelled
    }

    fn register(&self, waiter: &Arc<PongSignal>) {
        let mut state = self.lock_state();
        state.waiters.retain(|waiter| waiter.strong_count() != 0);
        if state.cancelled {
            waiter.cancel();
        } else {
            state.waiters.push(Arc::downgrade(waiter));
        }
    }
}

/// A one-shot notification that a matching DERP Pong was received.
pub struct PongResponseWaiter(Arc<PongSignal>);

impl PongResponseWaiter {
    /// Waits for the registered Pong, returning false if the duration expires.
    pub fn wait_timeout(&self, timeout: Duration) -> bool {
        self.0.wait_until(Instant::now().checked_add(timeout)) == PongWaitOutcome::Pong
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

struct PingRegistrationGuard {
    registry: Arc<DerpPongResponseRegistry>,
    data: [u8; 8],
}

impl Drop for PingRegistrationGuard {
    fn drop(&mut self) {
        self.registry.unregister_ping(self.data);
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
    pong_responses: Arc<DerpPongResponseRegistry>,
}

impl<R, W> DerphttpPongFilter<R, W> {
    pub fn new(receiver: DerpClientRecvSession<R, W>) -> Self {
        Self { receiver, pong_responses: Arc::new(DerpPongResponseRegistry::new()) }
    }

    /// Returns the registry used by this receive filter.
    pub fn pong_responses(&self) -> &DerpPongResponseRegistry {
        &self.pong_responses
    }

    /// Creates a Ping helper sharing this receive filter's response registry.
    ///
    /// A separate receive loop must call `recv_next` while Ping is waiting, and the
    /// supplied send gate must target the same DERP client.
    pub fn ping_client<S>(&self, send_gate: Arc<DerphttpSendGate<S>>) -> DerphttpPingClient<S> {
        DerphttpPingClient { send_gate, pong_responses: Arc::clone(&self.pong_responses) }
    }
}

/// A bounded high-level Ping sender sharing the receive filter's Pong registry.
///
/// `ping_until` registers an OS-random eight-byte identifier before sending, then
/// waits until the matching Pong or the earlier of the caller deadline and the
/// pinned five-second maximum. `ping_with_cancellation` also wakes on a caller-owned
/// cancellation token; a separate receive loop must dispatch Pongs through the filter.
pub struct DerphttpPingClient<W> {
    send_gate: Arc<DerphttpSendGate<W>>,
    pong_responses: Arc<DerpPongResponseRegistry>,
}

impl<W: Write> DerphttpPingClient<W> {
    /// Sends one Ping and waits for its matching Pong until the capped deadline.
    ///
    /// This convenience method does not take a cancellation token. As in the pinned
    /// Go path, the connection must already be active and another receive loop must
    /// process the paired filter concurrently.
    pub fn ping_until(&self, caller_deadline: Option<Instant>) -> Result<(), DerphttpPingError> {
        let mut rng = OsRng;
        self.ping_with_context_and_rng(caller_deadline, None, &mut rng)
    }

    /// Sends one Ping and waits for its Pong, caller deadline, or cancellation.
    ///
    /// Even an already-cancelled token is observed only after the Ping frame is
    /// sent, matching the pinned fork's send-before-select order. A send error wins.
    pub fn ping_with_cancellation(
        &self,
        caller_deadline: Option<Instant>,
        cancellation: &DerpPingCancellationToken,
    ) -> Result<(), DerphttpPingError> {
        let mut rng = OsRng;
        self.ping_with_context_and_rng(caller_deadline, Some(cancellation), &mut rng)
    }

    #[cfg(test)]
    fn ping_until_with_rng<R: TryRngCore>(
        &self,
        caller_deadline: Option<Instant>,
        rng: &mut R,
    ) -> Result<(), DerphttpPingError>
    where
        R::Error: fmt::Display,
    {
        self.ping_with_context_and_rng(caller_deadline, None, rng)
    }

    fn ping_with_context_and_rng<R: TryRngCore>(
        &self,
        caller_deadline: Option<Instant>,
        cancellation: Option<&DerpPingCancellationToken>,
        rng: &mut R,
    ) -> Result<(), DerphttpPingError>
    where
        R::Error: fmt::Display,
    {
        let deadline = ping_deadline(Instant::now(), caller_deadline).ok_or(DerphttpPingError::DeadlineOverflow)?;
        let mut data = [0u8; 8];
        rng.try_fill_bytes(&mut data).map_err(|error| DerphttpPingError::Entropy(error.to_string()))?;

        let waiter = self.pong_responses.register_ping(data);
        if let Some(cancellation) = cancellation {
            cancellation.register(&waiter.0);
        }
        let _registration = PingRegistrationGuard { registry: Arc::clone(&self.pong_responses), data };
        self.send_gate.send_ping(data).map_err(DerphttpPingError::Send)?;

        match waiter.0.wait_until(Some(deadline)) {
            PongWaitOutcome::Pong => Ok(()),
            PongWaitOutcome::Cancelled => Err(DerphttpPingError::Cancelled),
            PongWaitOutcome::DeadlineExceeded => Err(DerphttpPingError::DeadlineExceeded),
        }
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
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};

    use rand::TryRngCore;

    use crate::derp::{
        write_frame, DerpClientRecvSession, DerpSendWriter, FrameHeader, ReceivedMessage, RecvDeadlineReader,
        FRAME_KEEP_ALIVE, FRAME_PING, FRAME_PONG,
    };
    use crate::{NodePrivate, NodePublic};

    use super::{
        ping_deadline, DerpClientState, DerpPingCancellationToken, DerpPongResponseRegistry, DerphttpPingClient,
        DerphttpPongFilter, DerphttpSendGate, DERP_PING_MAX_WAIT,
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

    #[derive(Clone)]
    struct RecordingWriter(Arc<(Mutex<Vec<u8>>, Condvar)>);

    impl Write for RecordingWriter {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            let (bytes, changed) = &*self.0;
            bytes.lock().unwrap().extend_from_slice(input);
            changed.notify_one();
            Ok(input.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn wait_for_wire(shared: &Arc<(Mutex<Vec<u8>>, Condvar)>, expected_len: usize) -> Vec<u8> {
        let deadline = Instant::now() + Duration::from_secs(2);
        let (bytes, changed) = &**shared;
        let mut bytes = bytes.lock().unwrap();
        while bytes.len() < expected_len {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "Ping frame was not fully written before test deadline");
            let (next, result) = changed.wait_timeout(bytes, remaining).unwrap();
            bytes = next;
            assert!(!result.timed_out() || bytes.len() >= expected_len);
        }
        bytes.clone()
    }

    struct FixedPingRng([u8; 8]);

    impl TryRngCore for FixedPingRng {
        type Error = std::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(u32::from_le_bytes(self.0[..4].try_into().unwrap()))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(u64::from_le_bytes(self.0))
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
            for (index, byte) in destination.iter_mut().enumerate() {
                *byte = self.0[index % self.0.len()];
            }
            Ok(())
        }
    }

    struct FailingPingRng;

    impl TryRngCore for FailingPingRng {
        type Error = io::Error;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Err(io::Error::other("entropy unavailable"))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Err(io::Error::other("entropy unavailable"))
        }

        fn try_fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), Self::Error> {
            Err(io::Error::other("entropy unavailable"))
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

    fn make_ping_client(
        filter: &DerphttpPongFilter<MemoryReader, Vec<u8>>,
        state: DerpClientState,
        writer: impl Write + 'static,
    ) -> DerphttpPingClient<impl Write + 'static> {
        let send_gate = Arc::new(DerphttpSendGate::new(Arc::new(DerpSendWriter::new(writer, None)), state));
        filter.ping_client(send_gate)
    }

    #[test]
    fn high_level_ping_waits_for_pong_received_by_the_paired_filter() {
        let challenge = *b"fixed123";
        let mut wire = pong_wire(challenge);
        write_frame(&mut wire, FRAME_KEEP_ALIVE, &[]).unwrap();
        let mut filter = make_filter(wire);
        let output = Arc::new((Mutex::new(Vec::new()), Condvar::new()));
        let ping_client = make_ping_client(&filter, DerpClientState::Connected, RecordingWriter(Arc::clone(&output)));

        let ping_task = std::thread::spawn(move || {
            let mut rng = FixedPingRng(challenge);
            ping_client.ping_until_with_rng(None, &mut rng)
        });
        let bytes = wait_for_wire(&output, 13);
        let mut expected = FrameHeader { frame_type: FRAME_PING, frame_len: 8 }.encode().to_vec();
        expected.extend_from_slice(&challenge);
        assert_eq!(bytes, expected);
        assert_eq!(filter.recv_next().unwrap(), ReceivedMessage::KeepAlive);
        assert!(ping_task.join().unwrap().is_ok());
    }

    #[test]
    fn high_level_ping_deadline_returns_context_deadline_error_and_unregisters() {
        let challenge = *b"fixed123";
        let filter = make_filter(Vec::new());
        let output = Arc::new(Mutex::new(Vec::new()));
        let ping_client = make_ping_client(&filter, DerpClientState::Connected, SharedWriter(Arc::clone(&output)));
        let mut rng = FixedPingRng(challenge);

        let error = ping_client.ping_until_with_rng(Some(Instant::now()), &mut rng).unwrap_err();
        assert_eq!(error.to_string(), "context deadline exceeded");
        assert!(!filter.pong_responses().handle_pong(challenge));
        let mut expected = FrameHeader { frame_type: FRAME_PING, frame_len: 8 }.encode().to_vec();
        expected.extend_from_slice(&challenge);
        assert_eq!(*output.lock().unwrap(), expected);
    }

    #[test]
    fn high_level_ping_entropy_failure_is_closed_before_registration_or_write() {
        let filter = make_filter(Vec::new());
        let output = Arc::new(Mutex::new(Vec::new()));
        let ping_client = make_ping_client(&filter, DerpClientState::Connected, SharedWriter(Arc::clone(&output)));

        let error = ping_client.ping_until_with_rng(None, &mut FailingPingRng).unwrap_err();
        assert_eq!(error.to_string(), "DERP Ping randomness unavailable: entropy unavailable");
        assert!(output.lock().unwrap().is_empty());
        assert!(!filter.pong_responses().handle_pong([0; 8]));
    }

    #[test]
    fn high_level_ping_send_error_is_preserved_and_registration_removed() {
        let challenge = *b"fixed123";
        let filter = make_filter(Vec::new());
        let output = Arc::new(Mutex::new(Vec::new()));
        let ping_client = make_ping_client(&filter, DerpClientState::Disconnected, SharedWriter(Arc::clone(&output)));
        let cancellation = DerpPingCancellationToken::new();
        cancellation.cancel();
        let mut rng = FixedPingRng(challenge);

        let error = ping_client.ping_with_context_and_rng(None, Some(&cancellation), &mut rng).unwrap_err();
        assert_eq!(error.to_string(), "client not connected");
        assert!(output.lock().unwrap().is_empty());
        assert!(!filter.pong_responses().handle_pong(challenge));
    }

    #[test]
    fn high_level_ping_deadline_is_capped_at_five_seconds_and_respects_earlier_deadline() {
        let start = Instant::now();
        let maximum = start + DERP_PING_MAX_WAIT;
        assert_eq!(ping_deadline(start, None), Some(maximum));
        assert_eq!(ping_deadline(start, Some(maximum + Duration::from_secs(1))), Some(maximum));
        let earlier = start + Duration::from_secs(3);
        assert_eq!(ping_deadline(start, Some(earlier)), Some(earlier));
    }

    #[test]
    fn high_level_ping_cancellation_wakes_waiter_and_unregisters() {
        let challenge = *b"fixed123";
        let filter = make_filter(Vec::new());
        let output = Arc::new((Mutex::new(Vec::new()), Condvar::new()));
        let ping_client = make_ping_client(&filter, DerpClientState::Connected, RecordingWriter(Arc::clone(&output)));
        let cancellation = DerpPingCancellationToken::new();
        let task_cancellation = cancellation.clone();

        let ping_task = std::thread::spawn(move || {
            let mut rng = FixedPingRng(challenge);
            ping_client.ping_with_context_and_rng(None, Some(&task_cancellation), &mut rng)
        });
        let bytes = wait_for_wire(&output, 13);
        let mut expected = FrameHeader { frame_type: FRAME_PING, frame_len: 8 }.encode().to_vec();
        expected.extend_from_slice(&challenge);
        assert_eq!(bytes, expected);

        cancellation.cancel();
        assert!(cancellation.is_cancelled());
        assert_eq!(ping_task.join().unwrap().unwrap_err().to_string(), "context canceled");
        assert!(!filter.pong_responses().handle_pong(challenge));
    }

    #[test]
    fn already_cancelled_ping_still_sends_before_returning_context_error() {
        let challenge = *b"fixed123";
        let filter = make_filter(Vec::new());
        let output = Arc::new(Mutex::new(Vec::new()));
        let ping_client = make_ping_client(&filter, DerpClientState::Connected, SharedWriter(Arc::clone(&output)));
        let cancellation = DerpPingCancellationToken::new();
        cancellation.cancel();
        let mut rng = FixedPingRng(challenge);

        let error = ping_client.ping_with_context_and_rng(None, Some(&cancellation), &mut rng).unwrap_err();
        assert_eq!(error.to_string(), "context canceled");
        let mut expected = FrameHeader { frame_type: FRAME_PING, frame_len: 8 }.encode().to_vec();
        expected.extend_from_slice(&challenge);
        assert_eq!(*output.lock().unwrap(), expected);
        assert!(!filter.pong_responses().handle_pong(challenge));
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
