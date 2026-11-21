//! The `vless` inbound and outbound (sing-box `protocol/vless`) with the
//! wire format of sing-vmess `vless`: TCP, UDP (plain, packetaddr, XUDP)
//! and `xtls-rprx-vision`.

pub(crate) mod inbound;
pub mod mux;
mod outbound;
pub mod packet;
pub mod protocol;
pub mod vision;

pub use inbound::VlessInbound;
pub use outbound::{PacketEncoding, VlessOutbound};
