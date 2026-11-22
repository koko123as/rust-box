//! Hysteria2's Brutal congestion controller, matching sing-quic's
//! `hysteria/congestion/{brutal,pacer}.go` behavior.
use super::{Controller, ControllerFactory, ControllerMetrics, PacketNumberSpace};
use crate::connection::RttEstimator;
use crate::{Duration, Instant};
use std::any::Any;
use std::sync::Arc;

const PACKET_INFO_SLOT_COUNT: usize = 5;
const MIN_SAMPLE_COUNT: u64 = 50;
const MIN_ACK_RATE: f64 = 0.8;
const CONGESTION_WINDOW_MULTIPLIER: f64 = 2.0;
const MAX_BURST_PACKETS: u64 = 10;
const MAX_BURST_PACING_DELAY: Duration = Duration::from_millis(4);
const MIN_PACING_DELAY: Duration = Duration::from_millis(1);
const RTT_UNAVAILABLE_WINDOW: u64 = 10_240;
const NANOS_PER_SECOND: u128 = 1_000_000_000;

/// Factory configuration for Hysteria2's fixed-bandwidth Brutal controller.
///
/// `bytes_per_second` is the local target rate after Hysteria2's auth
/// negotiation has selected the effective transmit bandwidth.
#[derive(Debug, Clone)]
pub struct BrutalConfig {
    bytes_per_second: u64,
}

impl BrutalConfig {
    /// Creates a Brutal controller factory for a non-zero transmit rate.
    pub fn new(bytes_per_second: u64) -> Result<Self, &'static str> {
        if bytes_per_second == 0 {
            return Err("Hysteria2 Brutal bandwidth must be non-zero");
        }
        Ok(Self { bytes_per_second })
    }

    /// Returns the configured target rate in bytes per second.
    pub fn bytes_per_second(&self) -> u64 {
        self.bytes_per_second
    }
}

impl ControllerFactory for BrutalConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(BrutalController::new(self.bytes_per_second, now, current_mtu))
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct PacketInfo {
    timestamp: Option<u64>,
    ack_count: u64,
    loss_count: u64,
}

#[derive(Clone)]
struct BrutalController {
    bytes_per_second: u64,
    max_datagram_size: u64,
    ack_rate: f64,
    sample_epoch: Instant,
    packet_info_slots: [PacketInfo; PACKET_INFO_SLOT_COUNT],
    smoothed_rtt: Option<Duration>,
    budget_at_last_sent: u64,
    last_sent_time: Option<Instant>,
}

impl BrutalController {
    fn new(bytes_per_second: u64, now: Instant, current_mtu: u16) -> Self {
        let mut controller = Self {
            bytes_per_second: bytes_per_second.max(1),
            max_datagram_size: u64::from(current_mtu.max(1)),
            ack_rate: 1.0,
            sample_epoch: now,
            packet_info_slots: [PacketInfo::default(); PACKET_INFO_SLOT_COUNT],
            smoothed_rtt: None,
            budget_at_last_sent: 0,
            last_sent_time: None,
        };
        controller.budget_at_last_sent = controller.max_burst_size();
        controller
    }

    fn bandwidth(&self) -> u64 {
        ((self.bytes_per_second as f64 / self.ack_rate).max(1.0)) as u64
    }

    fn timestamp(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.sample_epoch).as_secs()
    }

    fn record_ack(&mut self, now: Instant) {
        self.record_packet_info(now, true);
    }

    fn record_loss(&mut self, now: Instant) {
        self.record_packet_info(now, false);
    }

    fn record_packet_info(&mut self, now: Instant, acked: bool) {
        let timestamp = self.timestamp(now);
        let slot = &mut self.packet_info_slots[(timestamp % PACKET_INFO_SLOT_COUNT as u64) as usize];
        if slot.timestamp != Some(timestamp) {
            *slot = PacketInfo { timestamp: Some(timestamp), ack_count: 0, loss_count: 0 };
        }
        if acked {
            slot.ack_count = slot.ack_count.saturating_add(1);
        } else {
            slot.loss_count = slot.loss_count.saturating_add(1);
        }
        self.update_ack_rate(timestamp);
    }

    fn update_ack_rate(&mut self, timestamp: u64) {
        let oldest_included = timestamp.saturating_sub(PACKET_INFO_SLOT_COUNT as u64);
        let (mut ack_count, mut loss_count) = (0u64, 0u64);
        for slot in self.packet_info_slots {
            if slot.timestamp.is_some_and(|sample_time| sample_time >= oldest_included) {
                ack_count = ack_count.saturating_add(slot.ack_count);
                loss_count = loss_count.saturating_add(slot.loss_count);
            }
        }
        let total_count = ack_count.saturating_add(loss_count);
        self.ack_rate = if total_count < MIN_SAMPLE_COUNT {
            1.0
        } else {
            (ack_count as f64 / total_count as f64).clamp(MIN_ACK_RATE, 1.0)
        };
    }

    fn max_burst_size(&self) -> u64 {
        let rate_limited_burst = (MAX_BURST_PACING_DELAY.as_nanos() * u128::from(self.bandwidth()) / NANOS_PER_SECOND)
            .min(u128::from(u64::MAX)) as u64;
        let packet_burst = MAX_BURST_PACKETS.saturating_mul(self.max_datagram_size);
        rate_limited_burst.max(packet_burst)
    }

    fn budget(&self, now: Instant) -> u64 {
        let max_budget = self.max_burst_size();
        let Some(last_sent_time) = self.last_sent_time else {
            return max_budget;
        };
        let elapsed_nanos = now.saturating_duration_since(last_sent_time).as_nanos();
        let replenished =
            (u128::from(self.bandwidth()) * elapsed_nanos / NANOS_PER_SECOND).min(u128::from(u64::MAX)) as u64;
        self.budget_at_last_sent.saturating_add(replenished).min(max_budget)
    }

    fn delay_until_budget(&self, now: Instant, bytes: u64) -> Duration {
        let budget = self.budget(now);
        if budget >= bytes {
            return Duration::ZERO;
        }
        let bandwidth = u128::from(self.bandwidth());
        let deficit = u128::from(bytes - budget);
        let numerator = deficit.saturating_mul(NANOS_PER_SECOND);
        let wait_nanos = numerator
            .saturating_add(bandwidth.saturating_sub(1))
            .checked_div(bandwidth)
            .unwrap_or(u128::MAX)
            .min(u128::from(u64::MAX)) as u64;
        Duration::from_nanos(wait_nanos).max(MIN_PACING_DELAY)
    }
}

impl Controller for BrutalController {
    fn on_packet_sent(
        &mut self,
        _space: PacketNumberSpace,
        _packet_number: u64,
        sent: Instant,
        bytes: u64,
        _ack_eliciting: bool,
        _bytes_in_flight: u64,
        _app_limited: bool,
    ) {
        let budget = self.budget(sent);
        self.budget_at_last_sent = budget.saturating_sub(bytes);
        self.last_sent_time = Some(sent);
    }

    fn on_packet_acked(
        &mut self,
        _space: PacketNumberSpace,
        _packet_number: u64,
        ack_time: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        _rtt: &RttEstimator,
    ) {
        self.record_ack(ack_time);
    }

    fn on_packet_lost(
        &mut self,
        _space: PacketNumberSpace,
        _packet_number: u64,
        loss_time: Instant,
        _sent: Instant,
        _bytes: u64,
        _ack_eliciting: bool,
        _bytes_in_flight: u64,
    ) {
        self.record_loss(loss_time);
    }

    fn on_rtt_update(&mut self, rtt: &RttEstimator) {
        self.smoothed_rtt = rtt.smoothed();
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.max_datagram_size = u64::from(new_mtu.max(1));
    }

    fn window(&self) -> u64 {
        let Some(smoothed_rtt) = self.smoothed_rtt else {
            return RTT_UNAVAILABLE_WINDOW;
        };
        ((self.bytes_per_second as f64 * smoothed_rtt.as_secs_f64() * CONGESTION_WINDOW_MULTIPLIER / self.ack_rate)
            .min(u64::MAX as f64)) as u64
    }

    fn pacing_delay(&self, now: Instant, bytes: u64, _mtu: u16) -> Option<Duration> {
        Some(self.delay_until_budget(now, bytes))
    }

    fn metrics(&self) -> ControllerMetrics {
        ControllerMetrics {
            congestion_window: self.window(),
            ssthresh: None,
            pacing_rate: Some(self.bandwidth().saturating_mul(8)),
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        RTT_UNAVAILABLE_WINDOW
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_window_and_pacer_match_hysteria_brutal_defaults() {
        let now = Instant::now();
        let controller = BrutalController::new(1_000_000, now, 1200);
        assert_eq!(controller.initial_window(), RTT_UNAVAILABLE_WINDOW);
        assert_eq!(controller.window(), RTT_UNAVAILABLE_WINDOW);
        assert_eq!(controller.max_burst_size(), 12_000);
        assert_eq!(controller.pacing_delay(now, 1200, 1200), Some(Duration::ZERO));
    }

    #[test]
    fn pacer_replenishes_at_target_rate_with_minimum_delay() {
        let now = Instant::now();
        let mut controller = BrutalController::new(1_000_000, now, 1200);
        controller.on_packet_sent(PacketNumberSpace::Data, 0, now, 12_000, true, 12_000, false);
        assert_eq!(controller.pacing_delay(now, 1200, 1200), Some(Duration::from_micros(1200)));
        assert_eq!(controller.pacing_delay(now + Duration::from_millis(2), 1200, 1200), Some(Duration::ZERO));
    }

    #[test]
    fn ack_rate_uses_minimum_sample_and_eighty_percent_floor() {
        let now = Instant::now();
        let mut controller = BrutalController::new(1_000_000, now, 1200);
        for _ in 0..10 {
            controller.record_ack(now);
        }
        for _ in 0..39 {
            controller.record_loss(now);
        }
        assert_eq!(controller.ack_rate, 1.0, "49 observations are below the sample threshold");
        controller.record_loss(now);
        assert_eq!(controller.ack_rate, MIN_ACK_RATE, "50 observations activate the ACK-rate floor");
    }

    #[test]
    fn ack_rate_expires_samples_older_than_five_seconds() {
        let now = Instant::now();
        let mut controller = BrutalController::new(1_000_000, now, 1200);
        for _ in 0..25 {
            controller.record_ack(now);
            controller.record_loss(now);
        }
        assert_eq!(controller.ack_rate, MIN_ACK_RATE);
        controller.record_ack(now + Duration::from_secs(6));
        assert_eq!(controller.ack_rate, 1.0);
    }

    #[test]
    fn factory_rejects_zero_bandwidth() {
        assert!(BrutalConfig::new(0).is_err());
        assert_eq!(BrutalConfig::new(8_000_000).unwrap().bytes_per_second(), 8_000_000);
    }
}
