//! Protocols, mirroring sing-box `protocol/`: the `socks`, `http` and
//! `mixed` inbounds (`protocol/{socks,http,mixed}`, with the wire formats of
//! `sing/protocol/{socks,http}`; TLS on `http` and `mixed`), the
//! `shadowsocks` inbound and outbound (with UDP over TCP) and the `direct`,
//! `block`, `socks` and `http` outbounds.

pub mod http;
pub mod inbound;
pub mod outbound;
pub mod proxy_outbound;
pub mod shadowsocks;
pub mod socks;
pub mod uot;

pub use inbound::{ProxyInbound, ProxyKind};
pub use outbound::{Block, Direct};
pub use proxy_outbound::{HttpOutbound, SocksOutbound};
pub use shadowsocks::{ShadowsocksInbound, ShadowsocksOutbound};
