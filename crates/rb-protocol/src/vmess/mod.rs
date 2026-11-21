//! The `vmess` inbound and outbound (sing-box `protocol/vmess`) with the
//! wire format of sing-vmess: the AEAD and legacy (alterId) headers, the
//! body securities and chunk options, TCP, UDP (plain, packetaddr, XUDP)
//! and mux requests.

pub mod codec;
mod inbound;
mod outbound;
pub mod protocol;
pub mod session;
pub mod stream;

pub use inbound::VmessInbound;
pub use outbound::{VmessOutbound, VmessPacketEncoding};

#[cfg(test)]
mod tests;
