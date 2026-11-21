//! Protocols, mirroring sing-box `protocol/`: the `socks`, `http` and
//! `mixed` inbounds (`protocol/{socks,http,mixed}`, with the wire formats of
//! `sing/protocol/{socks,http}`; TLS on `http` and `mixed`), the
//! `shadowsocks` inbound and outbound (with UDP over TCP) and the `direct`,
//! `block`, `socks` and `http` outbounds, and the `trojan`, `vless` and
//! `vmess` inbounds and outbounds.

pub mod framed;
pub mod http;
pub mod inbound;
pub mod outbound;
pub mod proxy_outbound;
pub mod shadowsocks;
pub mod socks;
pub mod trojan;
pub mod uot;
pub mod vless;
pub mod vmess;

pub use inbound::{ProxyInbound, ProxyKind};
pub use outbound::{Block, Direct};
pub use proxy_outbound::{HttpOutbound, SocksOutbound};
pub use shadowsocks::{ShadowsocksInbound, ShadowsocksOutbound};
pub use trojan::{TrojanInbound, TrojanOutbound};
pub use vless::{VlessInbound, VlessOutbound};
pub use vmess::{VmessInbound, VmessOutbound};
