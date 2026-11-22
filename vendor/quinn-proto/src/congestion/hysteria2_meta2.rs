//! Hysteria2's BBR-meta2 standard profile, ported from the pinned sing-quic source.
//!
//! Source: sing-quic v0.7.2-0.20261020082049-7e0a5869a5f4,
//! `congestion_meta2/bbr_sender.go` (constants/profiles 24-63, state 170-317,
//! construction/MTU 321-416, send/CC event 432-608, rates/windows 610-686,
//! transitions 689-877, calculations 879-1022), `bandwidth_sampler.go`
//! (send state/sample 19-98, ACK aggregation 100-241, snapshots 282-328,
//! sampler 413-510, send/events/loss 554-727, ACK sampling 762-871),
//! `pacer.go` (11-75), and `windowed_filter.go` (9-165).
//!
//! The standard profile uses no overshoot detection, no startup ACK-height gain,
//! no overestimate-avoidance A0 points, no send-rate ACK-height limit, and no
//! full-round aggregation epoch reset. ProbeBW's randomized offset is sampled
//! from the same allowed set {0, 2..=7}. The Quinn adapter translates independent
//! packet-number spaces into a monotonic connection-local number and drains one
//! ACK/loss batch once, at the packet-event boundary.

use std::{
    any::Any,
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use rand::{RngExt, SeedableRng};
use rand_pcg::Pcg32;

use crate::{
    congestion::{Controller, ControllerFactory, ControllerMetrics, PacketNumberSpace},
    connection::RttEstimator,
    Duration, Instant,
};

const BITS_PER_SECOND: u64 = 8;
const SECOND_NANOS: u64 = 1_000_000_000;
const INFINITE_BANDWIDTH: u64 = u64::MAX;
const INITIAL_CWND_PACKETS: u64 = 32;
const MIN_CWND_PACKETS: u64 = 4;
const MAX_CWND_PACKETS: u64 = 20_000;
const MIN_PACING_BYTES_PER_SECOND: u64 = 65_536;
const MAX_PACKET_BUFFER_SIZE: u64 = 1452;
const STARTUP_GROWTH_TARGET: f64 = 1.25;
const STARTUP_ROUNDS_WITHOUT_GAIN: u64 = 3;
const STARTUP_LOSS_EVENTS: u64 = 8;
const STARTUP_LOSS_THRESHOLD: f64 = 0.02;
const BANDWIDTH_FILTER_ROUNDS: u64 = 10;
const MIN_RTT_EXPIRY: Duration = Duration::from_secs(10);
const PROBE_RTT_TIME: Duration = Duration::from_millis(200);
const MIN_PACING_DELAY: Duration = Duration::from_millis(1);
const PACER_MAX_BURST_PACKETS: u64 = 10;
const PACER_MIN_BURST_EXTRA: Duration = Duration::from_millis(1);
const PROBE_BW_PACING_GAINS: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Startup,
    Drain,
    ProbeBandwidth,
    ProbeRtt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryState {
    NotInRecovery,
    Conservation,
    Growth,
}

#[derive(Clone, Copy, Debug, Default)]
struct SendTimeState {
    valid: bool,
    app_limited: bool,
    total_bytes_sent: u64,
    total_bytes_acked: u64,
    bytes_in_flight: u64,
}

#[derive(Clone, Copy, Debug)]
struct PacketSnapshot {
    sent: Instant,
    size: u64,
    total_bytes_sent_at_last_acked: u64,
    last_acked_sent: Option<Instant>,
    last_acked_ack: Option<Instant>,
    send_state: SendTimeState,
}

#[derive(Clone, Copy, Debug, Default)]
struct PacketSample {
    bandwidth: u64,
    rtt: Option<Duration>,
    send_state: SendTimeState,
}

#[derive(Clone, Copy, Debug, Default)]
struct EventSample {
    max_bandwidth: u64,
    max_bandwidth_is_app_limited: bool,
    min_rtt: Option<Duration>,
    last_packet_send_state: SendTimeState,
    extra_acked: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct FilterEntry<T> {
    value: T,
    round: u64,
}

/// Three-candidate windowed max filter used by both Meta2 bandwidth and ACK-height
/// tracking. This is the integer-round specialization of sing-quic's filter.
#[derive(Clone, Debug)]
struct WindowedMax<T> {
    window: u64,
    estimates: [FilterEntry<T>; 3],
}

impl<T: Copy + Default + Ord> WindowedMax<T> {
    fn new(window: u64) -> Self {
        Self { window, estimates: [FilterEntry::default(); 3] }
    }

    fn best(&self) -> T {
        self.estimates[0].value
    }

    fn update(&mut self, value: T, round: u64) {
        if self.estimates[0].value == T::default()
            || value >= self.estimates[0].value
            || round.wrapping_sub(self.estimates[2].round) > self.window
        {
            let entry = FilterEntry { value, round };
            self.estimates = [entry; 3];
            return;
        }

        if value >= self.estimates[1].value {
            self.estimates[1] = FilterEntry { value, round };
            self.estimates[2] = self.estimates[1];
        } else if value >= self.estimates[2].value {
            self.estimates[2] = FilterEntry { value, round };
        }

        if round.wrapping_sub(self.estimates[0].round) > self.window {
            self.estimates[0] = self.estimates[1];
            self.estimates[1] = self.estimates[2];
            self.estimates[2] = FilterEntry { value, round };
            if round.wrapping_sub(self.estimates[0].round) > self.window {
                self.estimates[0] = self.estimates[1];
                self.estimates[1] = self.estimates[2];
            }
            return;
        }

        if self.estimates[1].value == self.estimates[0].value
            && round.wrapping_sub(self.estimates[1].round) > self.window / 4
        {
            self.estimates[1] = FilterEntry { value, round };
            self.estimates[2] = self.estimates[1];
            return;
        }

        if self.estimates[2].value == self.estimates[1].value
            && round.wrapping_sub(self.estimates[2].round) > self.window / 2
        {
            self.estimates[2] = FilterEntry { value, round };
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct AckedPacket {
    number: u64,
    bytes: u64,
}

#[derive(Clone, Copy, Debug)]
struct LostPacket {
    number: u64,
    bytes: u64,
}

#[derive(Clone, Debug)]
struct MaxAckHeightTracker {
    filter: WindowedMax<u64>,
    epoch_start: Option<Instant>,
    epoch_bytes: u64,
    epochs: u64,
}

impl MaxAckHeightTracker {
    fn new() -> Self {
        Self { filter: WindowedMax::new(BANDWIDTH_FILTER_ROUNDS), epoch_start: None, epoch_bytes: 0, epochs: 0 }
    }

    fn best(&self) -> u64 {
        self.filter.best()
    }

    fn update(&mut self, bandwidth: u64, round: u64, ack_time: Instant, bytes_acked: u64) -> u64 {
        if self.epoch_start.is_none() {
            self.start_epoch(ack_time, bytes_acked);
            return 0;
        }

        let delta = ack_time.saturating_duration_since(self.epoch_start.expect("epoch checked"));
        let expected = bytes_from_bandwidth_and_delta(bandwidth, delta);
        if self.epoch_bytes <= expected {
            self.start_epoch(ack_time, bytes_acked);
            return 0;
        }

        self.epoch_bytes = self.epoch_bytes.wrapping_add(bytes_acked);
        let extra = self.epoch_bytes.wrapping_sub(expected);
        self.filter.update(extra, round);
        extra
    }

    fn start_epoch(&mut self, now: Instant, bytes_acked: u64) {
        self.epoch_start = Some(now);
        self.epoch_bytes = bytes_acked;
        self.epochs = self.epochs.wrapping_add(1);
    }
}

/// The per-packet delivery-rate sampler. Only ack-eliciting packets contribute
/// snapshots, matching the pinned quic-go `isRetransmittable` input.
#[derive(Clone, Debug)]
struct BandwidthSampler {
    sent: BTreeMap<u64, PacketSnapshot>,
    total_bytes_sent: u64,
    total_bytes_acked: u64,
    total_bytes_lost: u64,
    total_bytes_neutered: u64,
    total_bytes_sent_at_last_acked: u64,
    last_acked_sent: Option<Instant>,
    last_acked_ack: Option<Instant>,
    last_sent_packet: Option<u64>,
    app_limited: bool,
    end_of_app_limited_phase: Option<u64>,
    total_bytes_acked_after_last_event: u64,
    ack_height: MaxAckHeightTracker,
}

impl BandwidthSampler {
    fn new() -> Self {
        Self {
            sent: BTreeMap::new(),
            total_bytes_sent: 0,
            total_bytes_acked: 0,
            total_bytes_lost: 0,
            total_bytes_neutered: 0,
            total_bytes_sent_at_last_acked: 0,
            last_acked_sent: None,
            last_acked_ack: None,
            last_sent_packet: None,
            app_limited: false,
            end_of_app_limited_phase: None,
            total_bytes_acked_after_last_event: 0,
            ack_height: MaxAckHeightTracker::new(),
        }
    }

    fn on_packet_sent(
        &mut self,
        sent: Instant,
        packet_number: u64,
        bytes: u64,
        bytes_in_flight_before: u64,
        tracked: bool,
    ) {
        debug_assert!(self.last_sent_packet.is_none_or(|last| packet_number > last));
        self.last_sent_packet = Some(packet_number);
        if !tracked {
            return;
        }

        self.total_bytes_sent = self.total_bytes_sent.wrapping_add(bytes);
        if bytes_in_flight_before == 0 {
            self.last_acked_ack = Some(sent);
            self.total_bytes_sent_at_last_acked = self.total_bytes_sent;
            self.last_acked_sent = Some(sent);
        }

        let send_state = SendTimeState {
            valid: true,
            app_limited: self.app_limited,
            total_bytes_sent: self.total_bytes_sent,
            total_bytes_acked: self.total_bytes_acked,
            bytes_in_flight: bytes_in_flight_before.wrapping_add(bytes),
        };
        self.sent.insert(
            packet_number,
            PacketSnapshot {
                sent,
                size: bytes,
                total_bytes_sent_at_last_acked: self.total_bytes_sent_at_last_acked,
                last_acked_sent: self.last_acked_sent,
                last_acked_ack: self.last_acked_ack,
                send_state,
            },
        );
    }

    fn on_packet_acked(&mut self, ack_time: Instant, packet_number: u64) -> PacketSample {
        let Some(snapshot) = self.sent.remove(&packet_number) else { return PacketSample::default() };

        self.total_bytes_acked = self.total_bytes_acked.wrapping_add(snapshot.size);
        self.total_bytes_sent_at_last_acked = snapshot.send_state.total_bytes_sent;
        self.last_acked_sent = Some(snapshot.sent);
        self.last_acked_ack = Some(ack_time);
        if self.app_limited && self.end_of_app_limited_phase.is_none_or(|end| packet_number > end) {
            self.app_limited = false;
        }

        let Some(a0_sent) = snapshot.last_acked_sent else { return PacketSample::default() };
        let Some(a0_ack) = snapshot.last_acked_ack else { return PacketSample::default() };
        let send_rate = if snapshot.sent > a0_sent {
            bandwidth_from_delta(
                snapshot.send_state.total_bytes_sent.wrapping_sub(snapshot.total_bytes_sent_at_last_acked),
                snapshot.sent.saturating_duration_since(a0_sent),
            )
        } else {
            INFINITE_BANDWIDTH
        };
        if ack_time <= a0_ack {
            return PacketSample::default();
        }

        let ack_rate = bandwidth_from_delta(
            self.total_bytes_acked.wrapping_sub(snapshot.send_state.total_bytes_acked),
            ack_time.saturating_duration_since(a0_ack),
        );
        let rtt = ack_time.saturating_duration_since(snapshot.sent);
        PacketSample {
            bandwidth: send_rate.min(ack_rate),
            rtt: (!rtt.is_zero()).then_some(rtt),
            send_state: snapshot.send_state,
        }
    }

    fn on_packet_lost(&mut self, packet_number: u64, bytes_lost: u64) -> SendTimeState {
        self.total_bytes_lost = self.total_bytes_lost.wrapping_add(bytes_lost);
        self.sent.get(&packet_number).map(|packet| packet.send_state).unwrap_or_default()
    }

    fn on_packet_neutered(&mut self, packet_number: u64) {
        if let Some(packet) = self.sent.remove(&packet_number) {
            self.total_bytes_neutered = self.total_bytes_neutered.wrapping_add(packet.size);
            debug_assert!(self.total_bytes_neutered <= self.total_bytes_sent);
        }
    }

    fn remove_packet(&mut self, packet_number: u64) {
        self.sent.remove(&packet_number);
    }

    fn on_app_limited(&mut self) {
        self.app_limited = true;
        self.end_of_app_limited_phase = self.last_sent_packet;
    }

    fn is_app_limited(&self) -> bool {
        self.app_limited
    }

    fn on_congestion_event(
        &mut self,
        ack_time: Instant,
        acked: &[AckedPacket],
        lost: &[LostPacket],
        max_bandwidth: u64,
        round_trip_count: u64,
    ) -> EventSample {
        let mut event = EventSample::default();
        let mut last_lost_state = SendTimeState::default();
        for packet in lost {
            let state = self.on_packet_lost(packet.number, packet.bytes);
            if state.valid {
                last_lost_state = state;
            }
        }

        if acked.is_empty() {
            event.last_packet_send_state = last_lost_state;
            return event;
        }

        let mut last_acked_state = SendTimeState::default();
        for packet in acked {
            let sample = self.on_packet_acked(ack_time, packet.number);
            if !sample.send_state.valid {
                continue;
            }
            last_acked_state = sample.send_state;
            if let Some(rtt) = sample.rtt {
                event.min_rtt = Some(event.min_rtt.map_or(rtt, |current| current.min(rtt)));
            }
            if sample.bandwidth > event.max_bandwidth {
                event.max_bandwidth = sample.bandwidth;
                event.max_bandwidth_is_app_limited = sample.send_state.app_limited;
            }
        }

        event.last_packet_send_state = if !last_lost_state.valid {
            last_acked_state
        } else if !last_acked_state.valid {
            last_lost_state
        } else if lost.last().is_some_and(|lost| lost.number > acked.last().expect("nonempty ACKs").number) {
            last_lost_state
        } else {
            last_acked_state
        };

        let estimate = max_bandwidth.max(event.max_bandwidth);
        let newly_acked = self.total_bytes_acked.wrapping_sub(self.total_bytes_acked_after_last_event);
        if newly_acked != 0 {
            self.total_bytes_acked_after_last_event = self.total_bytes_acked;
            // Standard Meta2 has no send-rate limit, no overestimate avoidance,
            // no forced full-round reset, and no bandwidth-increase height reduction.
            event.extra_acked = self.ack_height.update(estimate, round_trip_count, ack_time, newly_acked);
        }
        event
    }

    fn max_ack_height(&self) -> u64 {
        self.ack_height.best()
    }
}

fn bandwidth_from_delta(bytes: u64, delta: Duration) -> u64 {
    let nanos = delta.as_nanos().min(u64::MAX as u128) as u64;
    if nanos == 0 {
        return INFINITE_BANDWIDTH;
    }
    bytes.wrapping_mul(SECOND_NANOS) / nanos * BITS_PER_SECOND
}

fn bytes_from_bandwidth_and_delta(bandwidth: u64, delta: Duration) -> u64 {
    let nanos = delta.as_nanos().min(u64::MAX as u128) as u64;
    bandwidth.wrapping_mul(nanos) / (SECOND_NANOS * BITS_PER_SECOND)
}

#[derive(Clone, Debug)]
struct Meta2Pacer {
    budget_at_last_sent: u64,
    max_datagram_size: u64,
    last_sent_time: Option<Instant>,
}

impl Meta2Pacer {
    fn new(max_datagram_size: u64) -> Self {
        Self { budget_at_last_sent: PACER_MAX_BURST_PACKETS * max_datagram_size, max_datagram_size, last_sent_time: None }
    }

    fn bandwidth_bytes_per_second(pacing_rate: u64) -> u64 {
        (pacing_rate / BITS_PER_SECOND).max(MIN_PACING_BYTES_PER_SECOND)
    }

    fn max_burst_size(&self, pacing_rate: u64) -> u64 {
        let bytes_per_second = Self::bandwidth_bytes_per_second(pacing_rate);
        let interval = MIN_PACING_DELAY + PACER_MIN_BURST_EXTRA;
        let rate_burst = (interval.as_nanos().saturating_mul(bytes_per_second as u128) / SECOND_NANOS as u128)
            .min(u64::MAX as u128) as u64;
        rate_burst.max(PACER_MAX_BURST_PACKETS.saturating_mul(self.max_datagram_size))
    }

    fn budget(&self, now: Instant, pacing_rate: u64) -> u64 {
        let Some(last_sent) = self.last_sent_time else { return self.max_burst_size(pacing_rate) };
        let bytes_per_second = Self::bandwidth_bytes_per_second(pacing_rate);
        let elapsed = now.saturating_duration_since(last_sent).as_nanos();
        let added = (bytes_per_second as u128).saturating_mul(elapsed) / SECOND_NANOS as u128;
        self.budget_at_last_sent
            .saturating_add(added.min(u64::MAX as u128) as u64)
            .min(self.max_burst_size(pacing_rate))
    }

    fn on_packet_sent(&mut self, sent: Instant, bytes: u64, pacing_rate: u64) {
        let budget = self.budget(sent, pacing_rate);
        self.budget_at_last_sent = budget.saturating_sub(bytes);
        self.last_sent_time = Some(sent);
    }

    fn delay(&self, now: Instant, pacing_rate: u64) -> Duration {
        if self.budget(now, pacing_rate) >= self.max_datagram_size {
            return Duration::ZERO;
        }
        let bytes_per_second = Self::bandwidth_bytes_per_second(pacing_rate).max(1);
        let deficit = self.max_datagram_size.saturating_sub(self.budget_at_last_sent);
        let nanos = (deficit as u128)
            .saturating_mul(SECOND_NANOS as u128)
            .div_ceil(bytes_per_second as u128)
            .min(u64::MAX as u128) as u64;
        let wait = MIN_PACING_DELAY.max(Duration::from_nanos(nanos));
        self.last_sent_time.map_or(wait, |last| (last + wait).saturating_duration_since(now))
    }

    fn set_max_datagram_size(&mut self, size: u64) {
        self.max_datagram_size = size;
    }
}

#[derive(Clone, Debug)]
struct PacketMapping {
    logical_number: u64,
    tracked: bool,
    lost: bool,
}

#[derive(Clone, Copy, Debug)]
struct PendingAck {
    packet: AckedPacket,
}

#[derive(Clone, Copy, Debug)]
struct PendingLoss {
    packet: LostPacket,
}

#[derive(Clone, Debug)]
struct Meta2Sender {
    mode: Mode,
    recovery_state: RecoveryState,
    sampler: BandwidthSampler,
    max_bandwidth: WindowedMax<u64>,
    round_trip_count: u64,
    last_sent_packet: Option<u64>,
    current_round_trip_end: Option<u64>,
    num_loss_events_in_round: u64,
    bytes_lost_in_round: u64,
    min_rtt: Option<Duration>,
    min_rtt_timestamp: Option<Instant>,
    congestion_window: u64,
    initial_congestion_window: u64,
    max_congestion_window: u64,
    min_congestion_window: u64,
    pacing_rate: u64,
    pacing_gain: f64,
    congestion_window_gain: f64,
    high_gain: f64,
    high_cwnd_gain: f64,
    drain_gain: f64,
    congestion_window_gain_constant: f64,
    cycle_offset: usize,
    last_cycle_start: Option<Instant>,
    is_at_full_bandwidth: bool,
    rounds_without_bandwidth_gain: u64,
    bandwidth_at_last_round: u64,
    exiting_quiescence: bool,
    exit_probe_rtt_at: Option<Instant>,
    probe_rtt_round_passed: bool,
    last_sample_is_app_limited: bool,
    recovery_end: Option<u64>,
    recovery_window: u64,
    max_datagram_size: u64,
    bytes_in_flight: u64,
    pacer: Meta2Pacer,
    random: Pcg32,
}

impl Meta2Sender {
    fn new(now: Instant, max_datagram_size: u16) -> Self {
        let mds = u64::from(max_datagram_size.max(1));
        let initial = INITIAL_CWND_PACKETS.saturating_mul(mds);
        let maximum = MAX_CWND_PACKETS.saturating_mul(mds);
        let random = Pcg32::from_rng(&mut rand::rng());
        let mut sender = Self {
            mode: Mode::Startup,
            recovery_state: RecoveryState::NotInRecovery,
            sampler: BandwidthSampler::new(),
            max_bandwidth: WindowedMax::new(BANDWIDTH_FILTER_ROUNDS),
            round_trip_count: 0,
            last_sent_packet: None,
            current_round_trip_end: None,
            num_loss_events_in_round: 0,
            bytes_lost_in_round: 0,
            min_rtt: None,
            min_rtt_timestamp: None,
            congestion_window: initial,
            initial_congestion_window: initial,
            max_congestion_window: maximum,
            min_congestion_window: MIN_CWND_PACKETS.saturating_mul(mds),
            pacing_rate: 0,
            pacing_gain: 1.0,
            congestion_window_gain: 1.0,
            high_gain: 2.885,
            high_cwnd_gain: 2.0,
            drain_gain: 1.0 / 2.885,
            congestion_window_gain_constant: 2.0,
            cycle_offset: 0,
            last_cycle_start: Some(now),
            is_at_full_bandwidth: false,
            rounds_without_bandwidth_gain: 0,
            bandwidth_at_last_round: 0,
            exiting_quiescence: false,
            exit_probe_rtt_at: None,
            probe_rtt_round_passed: false,
            last_sample_is_app_limited: false,
            recovery_end: None,
            recovery_window: maximum,
            max_datagram_size: mds,
            bytes_in_flight: 0,
            pacer: Meta2Pacer::new(mds),
            random,
        };
        sender.enter_startup_mode();
        sender
    }

    fn min_rtt(&self, rtt_stats_min: Duration) -> Duration {
        self.min_rtt.unwrap_or_else(|| {
            if rtt_stats_min.is_zero() { Duration::from_millis(100) } else { rtt_stats_min }
        })
    }

    fn bandwidth_estimate(&self) -> u64 {
        self.max_bandwidth.best()
    }

    fn bandwidth_from_bytes(bytes: u64, rtt: Duration) -> u64 {
        bandwidth_from_delta(bytes, rtt)
    }

    fn pacing_rate(&self, rtt_stats_min: Duration) -> u64 {
        if self.pacing_rate == 0 {
            let base = Self::bandwidth_from_bytes(self.initial_congestion_window, self.min_rtt(rtt_stats_min));
            (self.high_gain * base as f64) as u64
        } else {
            self.pacing_rate
        }
    }

    fn bdp(&self, rtt_stats_min: Duration) -> u64 {
        let rtt_nanos = self.min_rtt(rtt_stats_min).as_nanos().min(u64::MAX as u128) as u64;
        rtt_nanos
            .wrapping_mul(self.bandwidth_estimate())
            .wrapping_div(BITS_PER_SECOND)
            .wrapping_div(SECOND_NANOS)
    }

    fn target_congestion_window(&self, gain: f64, rtt_stats_min: Duration) -> u64 {
        let bdp = self.bdp(rtt_stats_min);
        let window = (gain * bdp as f64) as u64;
        if window == 0 {
            (gain * self.initial_congestion_window as f64) as u64
        } else {
            window.max(self.min_congestion_window)
        }
    }

    fn probe_rtt_congestion_window(&self) -> u64 {
        self.min_congestion_window
    }

    fn window(&self) -> u64 {
        if self.mode == Mode::ProbeRtt {
            self.probe_rtt_congestion_window()
        } else if self.recovery_state != RecoveryState::NotInRecovery {
            self.congestion_window.min(self.recovery_window)
        } else {
            self.congestion_window
        }
    }

    fn enter_startup_mode(&mut self) {
        self.mode = Mode::Startup;
        self.pacing_gain = self.high_gain;
        self.congestion_window_gain = self.high_cwnd_gain;
    }

    fn enter_probe_bandwidth_mode(&mut self, now: Instant) {
        self.mode = Mode::ProbeBandwidth;
        self.congestion_window_gain = self.congestion_window_gain_constant;
        let offset = self.random.random_range(0..u16::MAX) % (PROBE_BW_PACING_GAINS.len() as u16 - 1);
        self.cycle_offset = if offset >= 1 { usize::from(offset + 1) } else { 0 };
        self.last_cycle_start = Some(now);
        self.pacing_gain = PROBE_BW_PACING_GAINS[self.cycle_offset];
    }

    fn update_round_trip_counter(&mut self, last_acked: u64) -> bool {
        if self.current_round_trip_end.is_none_or(|end| last_acked > end) {
            self.round_trip_count = self.round_trip_count.wrapping_add(1);
            self.current_round_trip_end = self.last_sent_packet;
            true
        } else {
            false
        }
    }

    fn update_recovery_state(&mut self, last_acked: u64, has_losses: bool, is_round_start: bool) {
        if !self.is_at_full_bandwidth {
            return;
        }
        if has_losses {
            self.recovery_end = self.last_sent_packet;
        }
        match self.recovery_state {
            RecoveryState::NotInRecovery if has_losses => {
                self.recovery_state = RecoveryState::Conservation;
                self.recovery_window = 0;
                self.current_round_trip_end = self.last_sent_packet;
            }
            RecoveryState::Conservation | RecoveryState::Growth => {
                if self.recovery_state == RecoveryState::Conservation && is_round_start {
                    self.recovery_state = RecoveryState::Growth;
                }
                if !has_losses && self.recovery_end.is_some_and(|end| last_acked > end) {
                    self.recovery_state = RecoveryState::NotInRecovery;
                }
            }
            RecoveryState::NotInRecovery => {}
        }
    }

    fn update_min_rtt(&mut self, now: Instant, sample: Duration) -> bool {
        let expired = self.min_rtt.is_some()
            && self.min_rtt_timestamp.is_some_and(|time| now.saturating_duration_since(time) > MIN_RTT_EXPIRY);
        if expired || self.min_rtt.is_none_or(|current| sample < current) {
            self.min_rtt = Some(sample);
            self.min_rtt_timestamp = Some(now);
        }
        expired
    }

    fn update_gain_cycle_phase(&mut self, now: Instant, prior_in_flight: u64, has_losses: bool, rtt_stats_min: Duration) {
        let min_rtt = self.min_rtt(rtt_stats_min);
        let mut advance = self.last_cycle_start.is_some_and(|start| now > start + min_rtt);
        if self.pacing_gain > 1.0
            && !has_losses
            && prior_in_flight < self.target_congestion_window(self.pacing_gain, rtt_stats_min)
        {
            advance = false;
        }
        if self.pacing_gain < 1.0
            && self.bytes_in_flight <= self.target_congestion_window(1.0, rtt_stats_min)
        {
            advance = true;
        }
        if advance {
            self.cycle_offset = (self.cycle_offset + 1) % PROBE_BW_PACING_GAINS.len();
            self.last_cycle_start = Some(now);
            // Standard profile has drain_to_target=false.
            self.pacing_gain = PROBE_BW_PACING_GAINS[self.cycle_offset];
        }
    }

    fn check_if_full_bandwidth_reached(&mut self, last_packet_state: SendTimeState) {
        if self.last_sample_is_app_limited {
            return;
        }
        let target = (self.bandwidth_at_last_round as f64 * STARTUP_GROWTH_TARGET) as u64;
        if self.bandwidth_estimate() >= target {
            self.bandwidth_at_last_round = self.bandwidth_estimate();
            self.rounds_without_bandwidth_gain = 0;
            return;
        }
        self.rounds_without_bandwidth_gain = self.rounds_without_bandwidth_gain.wrapping_add(1);
        let exit_due_to_loss = self.num_loss_events_in_round >= STARTUP_LOSS_EVENTS
            && last_packet_state.valid
            && last_packet_state.bytes_in_flight > 0
            && (self.bytes_lost_in_round as f64)
                > (last_packet_state.bytes_in_flight as f64 * STARTUP_LOSS_THRESHOLD);
        if self.rounds_without_bandwidth_gain >= STARTUP_ROUNDS_WITHOUT_GAIN || exit_due_to_loss {
            self.is_at_full_bandwidth = true;
        }
    }

    fn maybe_exit_startup_or_drain(&mut self, now: Instant, rtt_stats_min: Duration) {
        if self.mode == Mode::Startup && self.is_at_full_bandwidth {
            self.mode = Mode::Drain;
            self.pacing_gain = self.drain_gain;
            self.congestion_window_gain = self.high_cwnd_gain;
        }
        if self.mode == Mode::Drain && self.bytes_in_flight <= self.target_congestion_window(1.0, rtt_stats_min) {
            self.enter_probe_bandwidth_mode(now);
        }
    }

    fn maybe_enter_or_exit_probe_rtt(
        &mut self,
        now: Instant,
        is_round_start: bool,
        min_rtt_expired: bool,
    ) {
        if min_rtt_expired && !self.exiting_quiescence && self.mode != Mode::ProbeRtt {
            self.mode = Mode::ProbeRtt;
            self.pacing_gain = 1.0;
            self.exit_probe_rtt_at = None;
        }
        if self.mode == Mode::ProbeRtt {
            self.sampler.on_app_limited();
            if self.exit_probe_rtt_at.is_none() {
                if self.bytes_in_flight < self.probe_rtt_congestion_window() + MAX_PACKET_BUFFER_SIZE {
                    self.exit_probe_rtt_at = Some(now + PROBE_RTT_TIME);
                    self.probe_rtt_round_passed = false;
                }
            } else {
                if is_round_start {
                    self.probe_rtt_round_passed = true;
                }
                if self.exit_probe_rtt_at.is_some_and(|time| now >= time) && self.probe_rtt_round_passed {
                    self.min_rtt_timestamp = Some(now);
                    if !self.is_at_full_bandwidth {
                        self.enter_startup_mode();
                    } else {
                        self.enter_probe_bandwidth_mode(now);
                    }
                }
            }
        }
        self.exiting_quiescence = false;
    }

    fn calculate_pacing_rate(&mut self, bytes_lost: u64, rtt_stats_min: Duration) {
        let estimate = self.bandwidth_estimate();
        if estimate == 0 {
            return;
        }
        let target_rate = (self.pacing_gain * estimate as f64) as u64;
        if self.is_at_full_bandwidth {
            self.pacing_rate = target_rate;
            return;
        }
        if self.pacing_rate == 0 && !rtt_stats_min.is_zero() {
            self.pacing_rate = Self::bandwidth_from_bytes(self.initial_congestion_window, rtt_stats_min);
            return;
        }
        // Standard profile disables detect_overshooting; do not lower pacing on loss.
        let _ = bytes_lost;
        self.pacing_rate = self.pacing_rate.max(target_rate);
    }

    fn calculate_congestion_window(&mut self, bytes_acked: u64, _excess_acked: u64, rtt_stats_min: Duration) {
        if self.mode == Mode::ProbeRtt {
            return;
        }
        let mut target = self.target_congestion_window(self.congestion_window_gain, rtt_stats_min);
        if self.is_at_full_bandwidth {
            target = target.saturating_add(self.sampler.max_ack_height());
            self.congestion_window = target.min(self.congestion_window.saturating_add(bytes_acked));
        } else if self.congestion_window < target || self.sampler.total_bytes_acked < self.initial_congestion_window {
            // Standard profile disables ACK-height growth during startup.
            self.congestion_window = self.congestion_window.saturating_add(bytes_acked);
        }
        self.congestion_window = self.congestion_window.clamp(self.min_congestion_window, self.max_congestion_window);
    }

    fn calculate_recovery_window(&mut self, bytes_acked: u64, bytes_lost: u64) {
        if self.recovery_state == RecoveryState::NotInRecovery {
            return;
        }
        if self.recovery_window == 0 {
            self.recovery_window = self.bytes_in_flight.saturating_add(bytes_acked).max(self.min_congestion_window);
            return;
        }
        if self.recovery_window >= bytes_lost {
            self.recovery_window -= bytes_lost;
        } else {
            self.recovery_window = self.max_datagram_size;
        }
        if self.recovery_state == RecoveryState::Growth {
            self.recovery_window = self.recovery_window.saturating_add(bytes_acked);
        }
        self.recovery_window = self
            .recovery_window
            .max(self.bytes_in_flight.saturating_add(bytes_acked))
            .max(self.min_congestion_window);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        prior_in_flight: u64,
        acked: &[AckedPacket],
        lost: &[LostPacket],
        rtt_stats_min: Duration,
    ) {
        let total_acked_before = self.sampler.total_bytes_acked;
        let total_lost_before = self.sampler.total_bytes_lost;
        self.bytes_in_flight = prior_in_flight;
        for packet in acked {
            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(packet.bytes);
        }
        for packet in lost {
            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(packet.bytes);
        }

        let is_round_start = if let Some(last_acked) = acked.last() {
            let round_start = self.update_round_trip_counter(last_acked.number);
            self.update_recovery_state(last_acked.number, !lost.is_empty(), round_start);
            round_start
        } else {
            false
        };

        let sample = self.sampler.on_congestion_event(
            now,
            acked,
            lost,
            self.bandwidth_estimate(),
            self.round_trip_count,
        );
        if sample.last_packet_send_state.valid {
            self.last_sample_is_app_limited = sample.last_packet_send_state.app_limited;
        }
        if total_acked_before != self.sampler.total_bytes_acked
            && (!sample.max_bandwidth_is_app_limited || sample.max_bandwidth > self.bandwidth_estimate())
        {
            self.max_bandwidth.update(sample.max_bandwidth, self.round_trip_count);
        }

        let min_rtt_expired = sample.min_rtt.is_some_and(|rtt| self.update_min_rtt(now, rtt));
        let bytes_lost = self.sampler.total_bytes_lost.wrapping_sub(total_lost_before);
        if !lost.is_empty() {
            self.num_loss_events_in_round = self.num_loss_events_in_round.wrapping_add(1);
            self.bytes_lost_in_round = self.bytes_lost_in_round.wrapping_add(bytes_lost);
        }
        if self.mode == Mode::ProbeBandwidth {
            self.update_gain_cycle_phase(now, prior_in_flight, !lost.is_empty(), rtt_stats_min);
        }
        if is_round_start && !self.is_at_full_bandwidth {
            self.check_if_full_bandwidth_reached(sample.last_packet_send_state);
        }
        self.maybe_exit_startup_or_drain(now, rtt_stats_min);
        self.maybe_enter_or_exit_probe_rtt(now, is_round_start, min_rtt_expired);

        let bytes_acked = self.sampler.total_bytes_acked.wrapping_sub(total_acked_before);
        self.calculate_pacing_rate(bytes_lost, rtt_stats_min);
        self.calculate_congestion_window(bytes_acked, sample.extra_acked, rtt_stats_min);
        self.calculate_recovery_window(bytes_acked, bytes_lost);

        if is_round_start {
            self.num_loss_events_in_round = 0;
            self.bytes_lost_in_round = 0;
        }
    }

    fn set_max_datagram_size(&mut self, new_size: u64) {
        if new_size == 0 || new_size == self.max_datagram_size {
            return;
        }
        let old_size = self.max_datagram_size;
        let old_min = self.min_congestion_window;
        let old_initial = self.initial_congestion_window;
        let scale = |window: u64| -> u64 {
            ((window as u128).saturating_mul(new_size as u128) / old_size.max(1) as u128)
                .min(u64::MAX as u128) as u64
        };
        self.max_datagram_size = new_size;
        self.initial_congestion_window = scale(self.initial_congestion_window);
        self.max_congestion_window = scale(self.max_congestion_window);
        self.min_congestion_window = MIN_CWND_PACKETS.saturating_mul(new_size);
        if new_size >= old_size {
            self.congestion_window = if self.congestion_window == old_min {
                self.min_congestion_window
            } else if self.congestion_window == old_initial {
                self.initial_congestion_window
            } else {
                self.congestion_window.max(self.min_congestion_window).min(self.max_congestion_window)
            };
            self.recovery_window = self.recovery_window.max(self.min_congestion_window).min(self.max_congestion_window);
        } else {
            // Quinn can report path-MTU decreases after a black-hole event; the pinned
            // Go setter rejects decreases. Scale down as a safe path-change adaptation.
            self.congestion_window = scale(self.congestion_window).max(self.min_congestion_window).min(self.max_congestion_window);
            self.recovery_window = scale(self.recovery_window).max(self.min_congestion_window).min(self.max_congestion_window);
        }
        self.pacer.set_max_datagram_size(new_size);
    }
}

#[derive(Clone, Debug)]
pub(super) struct Hysteria2Meta2 {
    sender: Meta2Sender,
    rtt_stats_min: Duration,
    next_logical_packet_number: u64,
    packets: HashMap<(PacketNumberSpace, u64), PacketMapping>,
    pending_acked: Vec<PendingAck>,
    pending_lost: Vec<PendingLoss>,
    connection_app_limited: bool,
}

impl Hysteria2Meta2 {
    pub(super) fn new(now: Instant, current_mtu: u16) -> Self {
        Self {
            sender: Meta2Sender::new(now, current_mtu),
            rtt_stats_min: Duration::ZERO,
            next_logical_packet_number: 1,
            packets: HashMap::new(),
            pending_acked: Vec::new(),
            pending_lost: Vec::new(),
            connection_app_limited: false,
        }
    }

    fn observe_app_limited(&mut self, app_limited: bool, bytes_in_flight: u64) {
        if app_limited && !self.connection_app_limited && bytes_in_flight < self.sender.window() {
            self.sender.sampler.on_app_limited();
        }
        self.connection_app_limited = app_limited;
    }

    fn new_logical_packet_number(&mut self, space: PacketNumberSpace, packet_number: u64, tracked: bool) -> u64 {
        let logical_number = self.next_logical_packet_number;
        self.next_logical_packet_number = self.next_logical_packet_number.wrapping_add(1);
        self.sender.last_sent_packet = Some(logical_number);
        self.packets.insert((space, packet_number), PacketMapping { logical_number, tracked, lost: false });
        logical_number
    }

    fn flush_batch(&mut self, now: Instant, prior_in_flight: u64, current_in_flight: u64) {
        if !self.pending_acked.is_empty() || !self.pending_lost.is_empty() {
            self.pending_acked.sort_by_key(|packet| packet.packet.number);
            self.pending_lost.sort_by_key(|packet| packet.packet.number);
            let acked = self.pending_acked.iter().map(|packet| packet.packet).collect::<Vec<_>>();
            let lost = self.pending_lost.iter().map(|packet| packet.packet).collect::<Vec<_>>();
            self.sender.on_congestion_event(now, prior_in_flight, &acked, &lost, self.rtt_stats_min);
            self.pending_acked.clear();
            self.pending_lost.clear();
        }
        // Packets sent before authentication use Quinn's provisional controller;
        // untracked ACK-only packets can also be in flight. Keep the model exact.
        self.sender.bytes_in_flight = current_in_flight;
    }
}

impl Controller for Hysteria2Meta2 {
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
        let tracked = ack_eliciting && congestion_controlled_bytes != 0;
        let logical = self.new_logical_packet_number(space, packet_number, tracked);
        let bytes_in_flight_before = bytes_in_flight.saturating_sub(congestion_controlled_bytes);
        self.observe_app_limited(app_limited, bytes_in_flight_before);
        if bytes_in_flight_before == 0 && self.sender.sampler.is_app_limited() {
            self.sender.exiting_quiescence = true;
        }
        self.sender.bytes_in_flight = bytes_in_flight;
        self.sender.pacer.on_packet_sent(sent, bytes, self.sender.pacing_rate(self.rtt_stats_min));
        self.sender.sampler.on_packet_sent(sent, logical, bytes, bytes_in_flight_before, tracked);
    }

    fn on_packet_acked(
        &mut self,
        space: PacketNumberSpace,
        packet_number: u64,
        _ack_time: Instant,
        _sent: Instant,
        bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.rtt_stats_min = rtt.min();
        if let Some(mapping) = self.packets.remove(&(space, packet_number)) {
            self.pending_acked.push(PendingAck { packet: AckedPacket { number: mapping.logical_number, bytes } });
        }
    }

    fn on_packet_lost(
        &mut self,
        space: PacketNumberSpace,
        packet_number: u64,
        _loss_time: Instant,
        _sent: Instant,
        bytes: u64,
        _ack_eliciting: bool,
        _bytes_in_flight: u64,
    ) {
        if let Some(mapping) = self.packets.get_mut(&(space, packet_number)) {
            if !mapping.lost {
                mapping.lost = true;
                self.pending_lost.push(PendingLoss { packet: LostPacket { number: mapping.logical_number, bytes } });
            }
        }
    }

    fn on_rtt_update(&mut self, rtt: &RttEstimator) {
        self.rtt_stats_min = rtt.min();
    }

    fn on_end_acks(&mut self, _now: Instant, in_flight: u64, app_limited: bool, _largest_acked: Option<u64>) {
        self.observe_app_limited(app_limited, in_flight);
    }

    fn on_congestion_event(&mut self, _now: Instant, _sent: Instant, _persistent: bool, _lost_bytes: u64) {
        // Per-packet loss callbacks are buffered and consumed once at batch-end.
    }

    fn on_congestion_event_batch_end(
        &mut self,
        now: Instant,
        prior_in_flight: u64,
        current_in_flight: u64,
        _space: PacketNumberSpace,
    ) {
        self.flush_batch(now, prior_in_flight, current_in_flight);
    }

    fn on_packet_space_pruned(&mut self, space: PacketNumberSpace, least_unacked: u64) {
        let obsolete = self
            .packets
            .keys()
            .filter(|(packet_space, packet_number)| *packet_space == space && *packet_number < least_unacked)
            .copied()
            .collect::<Vec<_>>();
        for key in obsolete {
            if let Some(mapping) = self.packets.remove(&key) {
                self.sender.sampler.remove_packet(mapping.logical_number);
            }
        }
    }

    fn on_packet_space_discarded(&mut self, space: PacketNumberSpace) {
        let discarded = self
            .packets
            .keys()
            .filter(|(packet_space, _)| *packet_space == space)
            .copied()
            .collect::<Vec<_>>();
        for key in discarded {
            if let Some(mapping) = self.packets.remove(&key) {
                if mapping.tracked && !mapping.lost {
                    self.sender.sampler.on_packet_neutered(mapping.logical_number);
                } else {
                    self.sender.sampler.remove_packet(mapping.logical_number);
                }
            }
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.sender.set_max_datagram_size(u64::from(new_mtu));
    }

    fn window(&self) -> u64 {
        self.sender.window()
    }

    fn pacing_delay(&self, now: Instant, _bytes: u64, _mtu: u16) -> Option<Duration> {
        Some(self.sender.pacer.delay(now, self.sender.pacing_rate(self.rtt_stats_min)))
    }

    fn metrics(&self) -> ControllerMetrics {
        ControllerMetrics {
            congestion_window: self.window(),
            ssthresh: None,
            pacing_rate: Some(self.sender.pacing_rate(self.rtt_stats_min)),
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.sender.initial_congestion_window
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl ControllerFactory for Hysteria2Meta2 {
    fn build(self: Arc<Self>, _now: Instant, _current_mtu: u16) -> Box<dyn Controller> {
        Box::new((*self).clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_profile_initial_windows_use_packet_counts() {
        let now = Instant::now();
        let controller = Hysteria2Meta2::new(now, 1200);
        assert_eq!(controller.initial_window(), 32 * 1200);
        assert_eq!(controller.sender.min_congestion_window, 4 * 1200);
        assert_eq!(controller.sender.max_congestion_window, 20_000 * 1200);
        assert_eq!(controller.sender.mode, Mode::Startup);
        assert_eq!(controller.sender.pacing_gain, 2.885);
        assert_eq!(controller.sender.congestion_window_gain, 2.0);
    }

    #[test]
    fn probe_bandwidth_random_offset_never_uses_drain_index() {
        let now = Instant::now();
        let mut sender = Meta2Sender::new(now, 1200);
        for _ in 0..64 {
            sender.enter_probe_bandwidth_mode(now);
            assert!(sender.cycle_offset == 0 || (2..=7).contains(&sender.cycle_offset));
        }
    }

    #[test]
    fn probe_rtt_uses_pinned_packet_buffer_allowance() {
        let now = Instant::now();
        let sender = Meta2Sender::new(now, 1200);
        assert_eq!(sender.probe_rtt_congestion_window() + MAX_PACKET_BUFFER_SIZE, 6252);
    }

    #[test]
    fn bandwidth_conversion_preserves_bit_rate_units() {
        assert_eq!(bandwidth_from_delta(1000, Duration::from_secs(1)), 8000);
        assert_eq!(bytes_from_bandwidth_and_delta(8000, Duration::from_secs(1)), 1000);
    }

    #[test]
    fn mtu_updates_rescale_packet_sized_windows_including_a_path_decrease() {
        let now = Instant::now();
        let mut sender = Meta2Sender::new(now, 1200);

        sender.set_max_datagram_size(1400);
        assert_eq!(sender.initial_congestion_window, 32 * 1400);
        assert_eq!(sender.congestion_window, 32 * 1400);
        assert_eq!(sender.min_congestion_window, 4 * 1400);

        // Quinn may report a smaller MTU after black-hole detection; the pinned Go
        // setter rejects this transition, while this adapter scales its windows.
        sender.set_max_datagram_size(1000);
        assert_eq!(sender.initial_congestion_window, 32 * 1000);
        assert_eq!(sender.congestion_window, 32 * 1000);
        assert_eq!(sender.min_congestion_window, 4 * 1000);
        assert_eq!(sender.max_congestion_window, 20_000 * 1000);
    }

    #[test]
    fn pacer_refills_a_depleted_bucket_at_the_configured_rate() {
        let now = Instant::now();
        let mut pacer = Meta2Pacer::new(1200);
        pacer.on_packet_sent(now, 12_000, 8_000_000);

        assert_eq!(pacer.delay(now, 8_000_000), Duration::from_micros(1200));
        assert_eq!(pacer.delay(now + Duration::from_millis(1), 8_000_000), Duration::from_micros(200));
        assert_eq!(pacer.delay(now + Duration::from_micros(1200), 8_000_000), Duration::ZERO);
    }

    #[test]
    fn sampler_tracks_ack_and_loss_by_logical_number() {
        let now = Instant::now();
        let later = now + Duration::from_millis(10);
        let mut sampler = BandwidthSampler::new();
        sampler.on_packet_sent(now, 1, 1200, 0, true);
        sampler.on_packet_sent(later, 2, 1200, 1200, true);
        let event = sampler.on_congestion_event(
            later + Duration::from_millis(10),
            &[AckedPacket { number: 1, bytes: 1200 }, AckedPacket { number: 2, bytes: 1200 }],
            &[],
            0,
            0,
        );
        assert!(event.last_packet_send_state.valid);
        assert!(sampler.total_bytes_acked >= 1200);
    }

    #[test]
    fn sampler_keeps_send_state_app_limited_until_a_later_packet_is_acked() {
        let now = Instant::now();
        let mut sampler = BandwidthSampler::new();
        sampler.on_packet_sent(now, 1, 1200, 0, true);
        sampler.on_app_limited();
        sampler.on_packet_sent(now + Duration::from_millis(10), 2, 1200, 1200, true);

        let event = sampler.on_congestion_event(
            now + Duration::from_millis(20),
            &[AckedPacket { number: 1, bytes: 1200 }, AckedPacket { number: 2, bytes: 1200 }],
            &[],
            0,
            0,
        );
        assert!(event.last_packet_send_state.valid);
        assert!(event.last_packet_send_state.app_limited);
        assert!(!sampler.is_app_limited());

        sampler.on_packet_sent(now + Duration::from_millis(30), 3, 1200, 0, true);
        assert!(!sampler.sent[&3].send_state.app_limited);
    }

    #[test]
    fn packet_number_mapping_is_unique_across_spaces() {
        let mut controller = Hysteria2Meta2::new(Instant::now(), 1200);
        let initial = controller.new_logical_packet_number(PacketNumberSpace::Initial, 0, true);
        let handshake = controller.new_logical_packet_number(PacketNumberSpace::Handshake, 0, true);
        let data = controller.new_logical_packet_number(PacketNumberSpace::Data, 0, true);
        assert!(initial < handshake && handshake < data);
    }

    #[test]
    fn packet_space_pruning_and_discard_remove_only_obsolete_sampler_state() {
        let now = Instant::now();
        let mut controller = Hysteria2Meta2::new(now, 1200);
        controller.on_packet_sent(PacketNumberSpace::Initial, 0, now, 1200, 1200, true, 1200, false);
        controller.on_packet_sent(PacketNumberSpace::Data, 0, now, 1200, 1200, true, 2400, false);
        let initial = controller.packets[&(PacketNumberSpace::Initial, 0)].logical_number;
        let data = controller.packets[&(PacketNumberSpace::Data, 0)].logical_number;

        controller.on_packet_space_pruned(PacketNumberSpace::Initial, 1);
        assert!(!controller.sender.sampler.sent.contains_key(&initial));
        assert!(controller.sender.sampler.sent.contains_key(&data));

        controller.on_packet_space_discarded(PacketNumberSpace::Data);
        assert!(!controller.sender.sampler.sent.contains_key(&data));
        assert_eq!(controller.sender.sampler.total_bytes_neutered, 1200);
    }

    #[test]
    fn ack_batches_from_distinct_packet_spaces_share_one_logical_number_line() {
        let now = Instant::now();
        let mut controller = Hysteria2Meta2::new(now, 1200);
        controller.on_packet_sent(PacketNumberSpace::Initial, 0, now, 1200, 1200, true, 1200, false);
        controller.on_packet_sent(PacketNumberSpace::Data, 0, now, 1200, 1200, true, 2400, false);
        let rtt = RttEstimator::new(Duration::from_millis(100));

        controller.on_packet_acked(
            PacketNumberSpace::Initial,
            0,
            now + Duration::from_millis(10),
            now,
            1200,
            false,
            &rtt,
        );
        controller.on_congestion_event_batch_end(
            now + Duration::from_millis(10),
            2400,
            1200,
            PacketNumberSpace::Initial,
        );
        assert_eq!(controller.sender.sampler.total_bytes_acked, 1200);
        assert_eq!(controller.sender.bytes_in_flight, 1200);

        controller.on_packet_acked(
            PacketNumberSpace::Data,
            0,
            now + Duration::from_millis(20),
            now,
            1200,
            false,
            &rtt,
        );
        controller.on_congestion_event_batch_end(
            now + Duration::from_millis(20),
            1200,
            0,
            PacketNumberSpace::Data,
        );
        assert_eq!(controller.sender.sampler.total_bytes_acked, 2400);
        assert_eq!(controller.sender.bytes_in_flight, 0);
        assert!(controller.packets.is_empty());
    }

    #[test]
    fn empty_batch_syncs_flight_bytes_from_quinn_after_untracked_acks() {
        let now = Instant::now();
        let mut controller = Hysteria2Meta2::new(now, 1200);
        controller.sender.bytes_in_flight = 2400;

        controller.on_congestion_event_batch_end(now, 2400, 0, PacketNumberSpace::Data);

        assert_eq!(controller.sender.bytes_in_flight, 0);
    }

    #[test]
    fn pacing_hook_uses_meta2_bucket_instead_of_quinn_pacer() {
        let controller = Hysteria2Meta2::new(Instant::now(), 1200);
        assert!(controller.pacing_delay(Instant::now(), 1200, 1200).is_some());
    }
}
