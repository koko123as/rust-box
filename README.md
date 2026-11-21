# rust-box

A Rust reimplementation of a universal proxy platform, modeled on
[sing-box](https://github.com/SagerNet/sing-box) v1.14.4: the same JSON
configuration format and the same architecture (inbounds → router → outbounds,
with a DNS router), written from the sing-box source and documentation.

rust-box is not affiliated with or endorsed by sing-box or SagerNet. It is
licensed GPL-3.0-or-later, like sing-box (see `LICENSE` and `COPYING`).

## Status

Milestones 1 (the core path), 2 (UDP), 3 (dial options and outbound
plumbing) and 4 (rule-sets) are in place:

| Area | Implemented | sing-box reference |
|---|---|---|
| Configuration | sing-box JSON for the sections below; unknown fields and sections rust-box lacks are rejected with their path | `option/` |
| Inbounds | `mixed`, `socks` (4, 4a, 5 CONNECT and UDP ASSOCIATE, users, `udp_timeout`), `http` (CONNECT and plain requests, Basic auth) | `protocol/{mixed,socks,http}` |
| Inbounds: listen fields | `listen` (default `127.0.0.1`), `listen_port`, `bind_interface`, `routing_mark`, `reuse_addr`, `netns`, `tcp_fast_open`, `tcp_multi_path`, `tcp_keep_alive*`, `udp_timeout`, `udp_fragment`, `detour` (hand-over to another inbound); legacy fields rejected as in v1.14.4 | `option/inbound.go`, `common/listener` |
| Outbounds | `direct` (TCP and UDP, happy-eyeballs with `fallback_delay`), `block` | `protocol/{direct,block}` |
| Dial fields | all of `shared/dial`: `detour`, `bind_interface`, `inet4/6_bind_address`, `bind_address_no_port`, `protect_path`, `routing_mark`, `reuse_addr`, `netns`, `connect_timeout`, `tcp_fast_open`, `tcp_multi_path`, keep-alive, `udp_fragment`, `domain_resolver`, `fallback_delay`, deprecated `domain_strategy`, `network_strategy`/`network_type`/`fallback_network_type` (no effect, as in sing-box's command line); on `direct` and on `udp`/`tcp` DNS servers; `route.default_interface`, `route.default_mark` | `option/outbound.go`, `common/dialer` |
| UDP | packet connections routed through the rules (`network: udp`), idle timeouts (inbound `udp_timeout`, route `udp_timeout`, protocol defaults), domain unmapping, `udp_connect`, a UDP NAT table | `route/conn.go`, `sing/common/udpnat2` |
| Route rules | default and logical rules; `inbound`, `ip_version`, `network`, `auth_user`, `protocol`, `domain*`, `ip_cidr`, `ip_is_private`, `source_*`, `port`, `port_range`, `rule_set`, `rule_set_ip_cidr_match_source`, `invert`; sing-box's grouping (address items OR'd, groups AND'd) | `route/rule/` |
| Rule-sets | `route.rule_set`: `inline`, `local` (reloaded when the file changes) and `remote` (HTTP and HTTPS, gzip, ETag / 304, `update_interval`, `download_detour`), `source` (versions 1–5) and `binary` (SRS); headless rules with the domain succinct set and AdGuard matchers; `rule_set` items in route and DNS rules, DNS legacy mode and the update validation | `route/rule_set*.go`, `common/srs`, `common/convertor/adguard` |
| Certificates | top-level `certificate`: `store` `system` (default), `mozilla`, `chrome`, `none`; `certificate`, `certificate_path`, `certificate_directory_path` (watched) | `common/certificate` |
| Rule actions | `route`, `route-options`, `bypass`, `reject`, `hijack-dns`, `sniff` (tls, http, quic, dns, stun, bittorrent, dtls, ssh, rdp, ntp), `resolve` | `route/route.go`, `common/sniff` |
| Route options | `override_address`, `override_port` (TCP and UDP, replies mapped back), `fallback_delay`, `udp_connect`, `udp_timeout`, `udp_disable_domain_unmapping`, `tls_fragment`, `tls_fragment_fallback_delay`, `tls_record_fragment` | `route/route.go`, `common/tlsfragment` |
| DNS | `local`, `udp`, `tcp` servers; rules (`domain*`, `query_type`, `inbound`, `rule_set`, ...) with `route` and `reject`; `final`, `strategy`, cache | `dns/` |
| CLI | `run`, `check`, `version`; `rule-set compile`, `decompile`, `format`, `upgrade`, `merge`, `match`, `convert` (AdGuard) | `cmd/sing-box` |

Not yet: TUN, encrypted protocols (Shadowsocks, VMess, VLESS, Trojan,
Hysteria2, TUIC, ...), TLS, DNS over TLS/HTTPS/QUIC, FakeIP, Clash
API and `tls_spoof`. The `network_strategy` family of fields (dial fields,
route option, `route.default_network_*`) only works with a platform
interface in sing-box's graphical clients; rust-box handles them as
sing-box's command line does: accepted without effect, with the same
conflict checks. Platform support: the Linux-only socket options
(`bind_interface`, `routing_mark`, `netns`, `bind_address_no_port`,
`tcp_fast_open`) work on Linux and Android and are refused elsewhere; see
the table in `docs/roadmap.md`. See `docs/roadmap.md` (with the known
differences of each milestone) and the architecture analysis in
`docs/singbox-architecture.md`.

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
| `rb-adapter` | core types and traits: `Socksaddr`, `InboundContext`, `Inbound`, `Outbound`, `PacketConn`, `ConnectionRouter`, `DnsResolver` |
| `rb-common` | shared data structures: the domain succinct set and AdGuard matcher, IP sets, varbin, Go-style JSON output |
| `rb-rule` | rule matching shared by route and DNS rules, headless rules, the `rule_set` item |
| `rb-rule-set` | inline, local and remote rule-sets, the HTTP(S) download client |
| `rb-fswatch` | file watching (`common/fswatch`) |
| `rb-certificate` | the certificate store (`common/certificate`) |
| `rb-dialer` | dialing and listening: the dial and listen fields, happy-eyeballs, the detour dialer, TCP Fast Open, TLS fragmentation |
| `rb-dns` | DNS transports, DNS router, cache |
| `rb-route` | router: rule walk, actions, sniffing, relaying (TCP and UDP), `hijack-dns`, UDP NAT |
| `rb-protocol` | inbound and outbound protocols |
| `rust-box` | the box (assembly, start, close) and the command |
