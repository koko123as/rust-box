//! Protocols, mirroring sing-box `protocol/`: the `socks`, `http` and
//! `mixed` inbounds (`protocol/{socks,http,mixed}`, with the wire formats of
//! `sing/protocol/{socks,http}`) and the `direct` and `block` outbounds.

pub mod http;
pub mod inbound;
pub mod outbound;
pub mod socks;

pub use inbound::{ProxyInbound, ProxyKind};
pub use outbound::{Block, Direct};
