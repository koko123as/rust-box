//! A controller factory that can switch Hysteria2 congestion control after HTTP/3 authentication.
use std::any::Any;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::connection::RttEstimator;
use crate::{Duration, Instant};

use super::{BrutalConfig, Controller, ControllerFactory, ControllerMetrics, CubicConfig, PacketNumberSpace};

/// A Hysteria2 congestion-controller factory whose mode can be selected after authentication.
///
/// The provisional controller is Quinn's default Cubic controller. Calling
/// [`Self::select_brutal`] switches existing controllers on their next control
/// callback, without restarting the QUIC connection.
#[derive(Clone)]
pub struct Hysteria2NegotiatedConfig {
    selection: Arc<Mutex<ControllerMode>>,
}

impl Hysteria2NegotiatedConfig {
    /// Selects Hysteria2 Brutal with a target rate in bytes per second.
    pub fn select_brutal(&self, bytes_per_second: u64) -> Result<(), &'static str> {
        if bytes_per_second == 0 {
            return Err("Hysteria2 Brutal bandwidth must be non-zero");
        }
        *lock_unpoisoned(&self.selection) = ControllerMode::Brutal { bytes_per_second };
        Ok(())
    }

    /// Selects Hysteria2's pinned sing-quic BBR-meta2 standard profile.
    pub fn select_meta2(&self) {
        *lock_unpoisoned(&self.selection) = ControllerMode::Meta2;
    }
}

impl Default for Hysteria2NegotiatedConfig {
    fn default() -> Self {
        Self { selection: Arc::new(Mutex::new(ControllerMode::PreAuth)) }
    }
}

impl ControllerFactory for Hysteria2NegotiatedConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        let mode = ControllerMode::PreAuth;
        Box::new(Hysteria2NegotiatedController {
            selection: self.selection.clone(),
            state: Mutex::new(ControllerState { mode, current_mtu, inner: build_controller(mode, now, current_mtu) }),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControllerMode {
    PreAuth,
    Brutal { bytes_per_second: u64 },
    Meta2,
}

struct ControllerState {
    mode: ControllerMode,
    current_mtu: u16,
    inner: Box<dyn Controller>,
}

struct Hysteria2NegotiatedController {
    selection: Arc<Mutex<ControllerMode>>,
    state: Mutex<ControllerState>,
}

impl Hysteria2NegotiatedController {
    fn refresh(&self, now: Instant) -> MutexGuard<'_, ControllerState> {
        let selected = *lock_unpoisoned(&self.selection);
        let mut state = lock_unpoisoned(&self.state);
        if state.mode != selected {
            let current_mtu = state.current_mtu;
            state.inner = build_controller(selected, now, current_mtu);
            state.mode = selected;
        }
        state
    }
}

fn build_controller(mode: ControllerMode, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
    match mode {
        ControllerMode::PreAuth => Arc::new(CubicConfig::default()).build(now, current_mtu),
        ControllerMode::Brutal { bytes_per_second } => {
            let config = BrutalConfig::new(bytes_per_second).expect("selected Brutal rate must be non-zero");
            Arc::new(config).build(now, current_mtu)
        }
        ControllerMode::Meta2 => Box::new(super::hysteria2_meta2::Hysteria2Meta2::new(now, current_mtu)),
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Controller for Hysteria2NegotiatedController {
    fn on_packet_sent(
        &mut self,
        space: PacketNumberSpace,
        packet_number: u64,
        sent: Instant,
        bytes: u64,
        congestion_controlled_bytes: u64,
        ack_eliciting: bool,
        bytes_in_flight: u64,
        app_limited: bool,
    ) {
        self.refresh(sent).inner.on_packet_sent(
            space,
            packet_number,
            sent,
            bytes,
            congestion_controlled_bytes,
            ack_eliciting,
            bytes_in_flight,
            app_limited,
        );
    }

    fn on_packet_acked(
        &mut self,
        space: PacketNumberSpace,
        packet_number: u64,
        ack_time: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.refresh(ack_time).inner.on_packet_acked(space, packet_number, ack_time, sent, bytes, app_limited, rtt);
    }

    fn on_packet_lost(
        &mut self,
        space: PacketNumberSpace,
        packet_number: u64,
        loss_time: Instant,
        sent: Instant,
        bytes: u64,
        ack_eliciting: bool,
        bytes_in_flight: u64,
    ) {
        self.refresh(loss_time).inner.on_packet_lost(
            space,
            packet_number,
            loss_time,
            sent,
            bytes,
            ack_eliciting,
            bytes_in_flight,
        );
    }

    fn on_rtt_update(&mut self, rtt: &RttEstimator) {
        self.refresh(Instant::now()).inner.on_rtt_update(rtt);
    }

    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.refresh(now).inner.on_sent(now, bytes, last_packet_number);
    }

    fn on_ack(&mut self, now: Instant, sent: Instant, bytes: u64, app_limited: bool, rtt: &RttEstimator) {
        self.refresh(now).inner.on_ack(now, sent, bytes, app_limited, rtt);
    }

    fn on_end_acks(&mut self, now: Instant, in_flight: u64, app_limited: bool, largest_packet_num_acked: Option<u64>) {
        self.refresh(now).inner.on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(&mut self, now: Instant, sent: Instant, persistent: bool, lost_bytes: u64) {
        self.refresh(now).inner.on_congestion_event(now, sent, persistent, lost_bytes);
    }

    fn on_congestion_event_batch_end(
        &mut self,
        now: Instant,
        prior_in_flight: u64,
        current_in_flight: u64,
        space: PacketNumberSpace,
    ) {
        self.refresh(now).inner.on_congestion_event_batch_end(now, prior_in_flight, current_in_flight, space);
    }

    fn on_packet_space_pruned(&mut self, space: PacketNumberSpace, least_unacked: u64) {
        self.refresh(Instant::now()).inner.on_packet_space_pruned(space, least_unacked);
    }

    fn on_packet_space_discarded(&mut self, space: PacketNumberSpace) {
        self.refresh(Instant::now()).inner.on_packet_space_discarded(space);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        let mut state = self.refresh(Instant::now());
        state.current_mtu = new_mtu;
        state.inner.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        self.refresh(Instant::now()).inner.window()
    }

    fn pacing_delay(&self, now: Instant, bytes: u64, mtu: u16) -> Option<Duration> {
        self.refresh(now).inner.pacing_delay(now, bytes, mtu)
    }

    fn metrics(&self) -> ControllerMetrics {
        self.refresh(Instant::now()).inner.metrics()
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        let state = lock_unpoisoned(&self.state);
        Box::new(Self {
            selection: self.selection.clone(),
            state: Mutex::new(ControllerState {
                mode: state.mode,
                current_mtu: state.current_mtu,
                inner: state.inner.clone_box(),
            }),
        })
    }

    fn initial_window(&self) -> u64 {
        self.refresh(Instant::now()).inner.initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::congestion::{ControllerFactory, CubicConfig};
    use crate::{Duration, Instant};

    use super::Hysteria2NegotiatedConfig;

    #[test]
    fn negotiated_factory_switches_existing_controller_to_brutal() {
        let now = Instant::now();
        let config = Arc::new(Hysteria2NegotiatedConfig::default());
        let controller = config.clone().build(now, 1200);
        let cubic_window = Arc::new(CubicConfig::default()).build(now, 1200).initial_window();
        assert_eq!(controller.initial_window(), cubic_window);

        config.select_brutal(1_000_000).unwrap();
        assert_eq!(controller.initial_window(), 10_240);
        assert_eq!(controller.pacing_delay(now, 1200, 1200), Some(Duration::ZERO));
    }

    #[test]
    fn negotiated_factory_switches_existing_controller_to_meta2_standard() {
        let now = Instant::now();
        let config = Arc::new(Hysteria2NegotiatedConfig::default());
        let controller = config.clone().build(now, 1200);

        config.select_meta2();
        assert_eq!(controller.initial_window(), 32 * 1200);
        assert_eq!(controller.metrics().congestion_window, 32 * 1200);
    }

    #[test]
    fn negotiated_factory_rejects_zero_brutal_rate() {
        let config = Hysteria2NegotiatedConfig::default();
        assert!(config.select_brutal(0).is_err());
    }
}
