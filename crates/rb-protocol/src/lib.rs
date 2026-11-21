//! Protocols, mirroring sing-box `protocol/`: the `socks`, `http` and
//! `mixed` inbounds (`protocol/{socks,http,mixed}`, with the wire formats of
//! `sing/protocol/{socks,http}`; TLS on `http` and `mixed`) and the `direct`,
//! `block`, `socks` and `http` outbounds.

pub mod http;
pub mod inbound;
pub mod outbound;
pub mod proxy_outbound;
pub mod socks;

pub use inbound::{ProxyInbound, ProxyKind};
pub use outbound::{Block, Direct};
pub use proxy_outbound::{HttpOutbound, SocksOutbound};
