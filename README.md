# rust-box

A Rust reimplementation of a universal proxy platform, modeled on
[sing-box](https://github.com/SagerNet/sing-box) v1.14.4: the same JSON
configuration format and the same architecture (inbounds → router → outbounds,
with a DNS router), written from the sing-box source and documentation.

rust-box is not affiliated with or endorsed by sing-box or SagerNet. It is
licensed GPL-3.0-or-later, like sing-box (see `LICENSE` and `COPYING`).

## Status

Milestone 1, the core path, is in place:

| Area | Implemented | sing-box reference |
|---|---|---|
| Configuration | sing-box JSON for the sections below; unknown fields and sections rust-box lacks are rejected with their path | `option/` |
| Inbounds | `mixed`, `socks` (4, 4a, 5 CONNECT, users), `http` (CONNECT and plain requests, Basic auth) | `protocol/{mixed,socks,http}` |
| Outbounds | `direct` (with `domain_resolver`), `block` | `protocol/{direct,block}` |
| Route rules | default and logical rules; `inbound`, `ip_version`, `network`, `auth_user`, `protocol`, `domain*`, `ip_cidr`, `ip_is_private`, `source_*`, `port`, `port_range`, `invert`; sing-box's grouping (address items OR'd, groups AND'd) | `route/rule/` |
| Rule actions | `route`, `reject`, `sniff` (tls, http, bittorrent, ssh), `resolve` | `route/route.go` |
| DNS | `local`, `udp`, `tcp` servers; rules (`domain*`, `query_type`, `inbound`, ...) with `route` and `reject`; `final`, `strategy`, cache | `dns/` |
| CLI | `run`, `check`, `version` | `cmd/sing-box` |

Not yet: UDP (SOCKS5 UDP ASSOCIATE), TUN, encrypted protocols
(Shadowsocks, VMess, VLESS, Trojan, Hysteria2, TUIC, ...), TLS, rule-sets,
DNS over TLS/HTTPS/QUIC, FakeIP, Clash API. See `docs/roadmap.md` and the
architecture analysis in `docs/singbox-architecture.md`.

## Build and run

```sh
cargo build --release
./target/release/rust-box check -c examples/config.json
./target/release/rust-box run -c examples/config.json
```

## Layout

| Crate | Role |
|---|---|
| `rb-config` | configuration model and parsing |
| `rb-adapter` | core types and traits: `Socksaddr`, `InboundContext`, `Inbound`, `Outbound`, `ConnectionRouter`, `DnsResolver` |
| `rb-rule` | rule matching shared by route and DNS rules |
| `rb-dns` | DNS transports, DNS router, cache |
| `rb-route` | router: rule walk, actions, sniffing, relaying |
| `rb-protocol` | inbound and outbound protocols |
| `rust-box` | the box (assembly, start, close) and the command |
