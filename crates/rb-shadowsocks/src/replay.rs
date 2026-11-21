//! Replay protection of 2022: the salt filter of TCP requests (sing
//! `replay.NewSimple`) and the packet id window of UDP sessions
//! (sing-shadowsocks `SlidingWindow`).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Remembers salts for `timeout` (sing `replay.SimpleFilter`).
pub struct SaltFilter {
    timeout: Duration,
    inner: Mutex<(Instant, HashMap<Vec<u8>, Instant>)>,
}

impl SaltFilter {
    pub fn new(timeout: Duration) -> Self {
        SaltFilter { timeout, inner: Mutex::new((Instant::now(), HashMap::new())) }
    }

    /// Whether `salt` is new; remembers it.
    pub fn check(&self, salt: &[u8]) -> bool {
        let now = Instant::now();
        let mut guard = self.inner.lock().unwrap();
        let (last_clean, pool) = &mut *guard;
        let exists = if now.duration_since(*last_clean) > self.timeout {
            pool.retain(|_, added| now.duration_since(*added) <= self.timeout);
            *last_clean = now;
            pool.contains_key(salt)
        } else {
            pool.get(salt).is_some_and(|added| now.duration_since(*added) <= self.timeout)
        };
        if !exists {
            pool.insert(salt.to_vec(), now);
        }
        !exists
    }
}

const BLOCK_BIT_LOG: u64 = 6;
const BLOCK_BITS: u64 = 1 << BLOCK_BIT_LOG;
const RING_BLOCKS: u64 = 1 << 7;
const BLOCK_MASK: u64 = RING_BLOCKS - 1;
const BIT_MASK: u64 = BLOCK_BITS - 1;
const WINDOW_SIZE: u64 = (RING_BLOCKS - 1) * BLOCK_BITS;

/// A sliding window of packet ids (WireGuard's replay filter, as
/// sing-shadowsocks `SlidingWindow`).
#[derive(Clone)]
pub struct SlidingWindow {
    last: u64,
    ring: [u64; RING_BLOCKS as usize],
}

impl Default for SlidingWindow {
    fn default() -> Self {
        SlidingWindow { last: 0, ring: [0; RING_BLOCKS as usize] }
    }
}

impl SlidingWindow {
    /// Whether `counter` may be accepted.
    pub fn check(&self, counter: u64) -> bool {
        if counter > self.last {
            return true;
        }
        if self.last - counter > WINDOW_SIZE {
            return false;
        }
        let block = (counter >> BLOCK_BIT_LOG) & BLOCK_MASK;
        let bit = counter & BIT_MASK;
        (self.ring[block as usize] >> bit) & 1 == 0
    }

    /// Marks `counter` seen (after [`check`](Self::check)).
    pub fn add(&mut self, counter: u64) {
        let block = counter >> BLOCK_BIT_LOG;
        if counter > self.last {
            let mut last_block = self.last >> BLOCK_BIT_LOG;
            let diff = (block - last_block).min(RING_BLOCKS);
            for _ in 0..diff {
                last_block = (last_block + 1) & BLOCK_MASK;
                self.ring[last_block as usize] = 0;
            }
            self.last = counter;
        }
        let block = block & BLOCK_MASK;
        let bit = counter & BIT_MASK;
        self.ring[block as usize] |= 1 << bit;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window() {
        let mut window = SlidingWindow::default();
        assert!(window.check(0));
        window.add(0);
        assert!(!window.check(0));
        assert!(window.check(1));
        window.add(5000);
        assert!(window.check(4000));
        assert!(!window.check(5000));
        window.add(4999);
        assert!(!window.check(4999));
        // Behind the window.
        window.add(10_000);
        assert!(!window.check(10_000 - WINDOW_SIZE - 1));
        assert!(window.check(10_000 - WINDOW_SIZE));
    }

    #[test]
    fn salts() {
        let filter = SaltFilter::new(Duration::from_secs(60));
        assert!(filter.check(b"a"));
        assert!(!filter.check(b"a"));
        assert!(filter.check(b"b"));
    }
}
