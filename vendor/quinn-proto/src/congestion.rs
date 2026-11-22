//! Logic for controlling the rate at which data is sent

use crate::connection::RttEstimator;
use crate::{Duration, Instant};
use std::any::Any;
use std::sync::Arc;

mod bbr;
mod cubic;
mod hysteria2;
mod hysteria_brutal;
mod new_reno;

pub use bbr::{Bbr, BbrConfig};
pub use cubic::{Cubic, CubicConfig};
pub use hysteria2::Hysteria2NegotiatedConfig;
pub use hysteria_brutal::BrutalConfig;
pub use new_reno::{NewReno, NewRenoConfig};

/// QUIC packet number space, without exposing Quinn's internal space identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum PacketNumberSpace {
    /// Initial packet number space.
    Initial,
    /// Handshake packet number space.
    Handshake,
    /// Application Data packet number space (including 0-RTT).
    Data,
}

/// Common interface for different congestion controllers
pub trait Controller: Send + Sync {
    /// A tracked packet was sent. `bytes_in_flight` is sampled after accounting for it.
    #[allow(unused_variables)]
    fn on_packet_sent(
        &mut self,
        space: PacketNumberSpace,
        packet_number: u64,
        sent: Instant,
        bytes: u64,
        ack_eliciting: bool,
        bytes_in_flight: u64,
        app_limited: bool,
    ) {
    }
    /// A packet was acknowledged in its packet number space.
    #[allow(unused_variables)]
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
    }
    /// A packet was declared lost. `bytes_in_flight` is sampled before removing it.
    #[allow(unused_variables)]
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
    }
    /// The path's smoothed RTT estimate was updated after processing an ACK.
    #[allow(unused_variables)]
    fn on_rtt_update(&mut self, rtt: &RttEstimator) {}
    /// One or more packets were just sent
    #[allow(unused_variables)]
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {}

    /// Packet deliveries were confirmed
    ///
    /// `app_limited` indicates whether the connection was blocked on outgoing
    /// application data prior to receiving these acknowledgements.
    #[allow(unused_variables)]
    fn on_ack(&mut self, now: Instant, sent: Instant, bytes: u64, app_limited: bool, rtt: &RttEstimator) {}

    /// Packets are acked in batches, all with the same `now` argument. This indicates one of those batches has completed.
    #[allow(unused_variables)]
    fn on_end_acks(&mut self, now: Instant, in_flight: u64, app_limited: bool, largest_packet_num_acked: Option<u64>) {}

    /// Packets were deemed lost or marked congested
    ///
    /// `in_persistent_congestion` indicates whether all packets sent within the persistent
    /// congestion threshold period ending when the most recent packet in this batch was sent were
    /// lost.
    /// `lost_bytes` indicates how many bytes were lost. This value will be 0 for ECN triggers.
    fn on_congestion_event(&mut self, now: Instant, sent: Instant, is_persistent_congestion: bool, lost_bytes: u64);

    /// The known MTU for the current network path has been updated
    fn on_mtu_update(&mut self, new_mtu: u16);

    /// Number of ack-eliciting bytes that may be in flight
    fn window(&self) -> u64;

    /// Optionally provide a pacing delay for the next datagram.
    ///
    /// `None` preserves Quinn's built-in pacer. `Some(Duration::ZERO)` explicitly
    /// allows the datagram immediately and skips that pacer; a positive duration
    /// delays transmission by that amount. `bytes` is the planned datagram size,
    /// and `mtu` is the current path MTU.
    #[allow(unused_variables)]
    fn pacing_delay(&self, now: Instant, bytes: u64, mtu: u16) -> Option<Duration> {
        None
    }

    /// Retrieve implementation-specific metrics used to populate `qlog` traces when they are enabled
    fn metrics(&self) -> ControllerMetrics {
        ControllerMetrics { congestion_window: self.window(), ssthresh: None, pacing_rate: None }
    }

    /// Duplicate the controller's state
    fn clone_box(&self) -> Box<dyn Controller>;

    /// Initial congestion window
    fn initial_window(&self) -> u64;

    /// Returns Self for use in down-casting to extract implementation details
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

/// Common congestion controller metrics
#[derive(Default)]
#[non_exhaustive]
pub struct ControllerMetrics {
    /// Congestion window (bytes)
    pub congestion_window: u64,
    /// Slow start threshold (bytes)
    pub ssthresh: Option<u64>,
    /// Pacing rate (bits/s)
    pub pacing_rate: Option<u64>,
}

/// Constructs controllers on demand
pub trait ControllerFactory {
    /// Construct a fresh `Controller`
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller>;
}

const BASE_DATAGRAM_SIZE: u64 = 1200;

#[cfg(test)]
mod tests {
    use super::{Controller, NewReno, NewRenoConfig};
    use crate::Instant;
    use std::sync::Arc;

    #[test]
    fn controller_pacing_hook_defaults_to_builtin_pacer() {
        let now = Instant::now();
        let controller = NewReno::new(Arc::new(NewRenoConfig::default()), now, 1200);

        assert_eq!(controller.pacing_delay(now, 1200, 1200), None);
    }
}
