//! Narrow pure-Rust behavior from the pinned fork's `derphttp.Client.RecvDetail`.
//!
//! This module dispatches registered Pong responses and filters only matching
//! Pong messages from an already-created DERP receive session. It does not connect
//! or reconnect, assign connection generations, close transports, or implement the
//! complete `derphttp.Client` lifecycle.

use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::derp::{DerpClientRecvSession, ReceivedMessage, RecvDeadlineReader, RecvSessionError};

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
    use std::io::{self, Cursor, Read};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use crate::derp::{
        write_frame, DerpClientRecvSession, DerpSendWriter, ReceivedMessage, RecvDeadlineReader, FRAME_KEEP_ALIVE,
        FRAME_PONG,
    };
    use crate::{NodePrivate, NodePublic};

    use super::{DerpPongResponseRegistry, DerphttpPongFilter};

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
}
