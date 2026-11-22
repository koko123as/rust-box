# Roadmap

Ordered by dependency, following the porting order in the sing-box
architecture analysis (`docs/singbox-architecture.md`, section 11.2). Each
milestone is one pull request with tests; the configuration stays sing-box
v1.14.4 compatible, and a field rust-box does not implement is an error, never
silently ignored.

1. **Core path** (done): config, socks/http/mixed inbounds, direct/block
   outbounds, route rules and actions (route, reject, sniff, resolve), DNS
   (local/udp/tcp, rules, cache).
2. **UDP** (done): SOCKS5 UDP ASSOCIATE in `socks` and `mixed`, UDP in
   `direct` (and `block`), packet-connection routing through the same rules
   (`route/conn.go` `NewPacketConnection`), UDP NAT table, `udp_timeout`
   (inbound field and route option, protocol timeouts), the `route-options`
   action with `udp_connect`, `udp_timeout` and
   `udp_disable_domain_unmapping`, packet sniffers (dns, quic, stun,
   bittorrent, dtls, ntp) and stream sniffers dns and rdp, `hijack-dns` over
   UDP and TCP.
3. **Dial options and outbound plumbing** (done): every dial field
   (`shared/dial`) in a new crate `rb-dialer` — `detour` (DNS servers),
   `bind_interface`, `inet4_bind_address`, `inet6_bind_address`,
   `bind_address_no_port`, `protect_path`, `routing_mark`, `reuse_addr`,
   `netns`, `connect_timeout`, `tcp_fast_open`, `tcp_multi_path`,
   `disable_tcp_keep_alive`, `tcp_keep_alive`, `tcp_keep_alive_interval`,
   `udp_fragment`, `domain_resolver` (string and object, with
   `rewrite_ttl`), `fallback_delay` and the deprecated `domain_strategy`;
   `route.default_interface` and `route.default_mark`; happy-eyeballs in
   `direct`; the route options `override_address`, `override_port`,
   `fallback_delay`, `tls_fragment`, `tls_fragment_fallback_delay`,
   `tls_record_fragment` on `route`, `route-options` and `bypass`; the
   listen fields (`shared/listen`) including the inbound `detour`; HTTP
   proxy keep-alive. Dial fields are also accepted on `udp` and `tcp` DNS
   servers.
4. **Rule-sets** (done): inline, local and remote `source`/`binary` (SRS)
   rule-sets (`rb-rule-set`), headless rules, `rule_set` items in route and
   DNS rules, the DNS router's legacy mode and rule-set update validation,
   file watching (`rb-fswatch`), the top-level `certificate` store
   (`rb-certificate`) for HTTPS downloads, and the `rule-set` commands
   (`compile`, `decompile`, `format`, `upgrade`, `merge`, `match`,
   `convert`).
5. **TLS and first encrypted protocols** (done): rustls client/server, `shadowsocks`
   (AEAD and 2022), `trojan`, `vless`, `vmess`, `socks`/`http` outbounds,
   multiplex (`sing-mux`).
6. **DNS**: DoT, DoH, DoQ/DoH3, `hosts`, `fakeip`, `predefined`, `evaluate`,
   `match_response`.
7. **V2Ray transports and QUIC protocols**: WebSocket, HTTP/2, gRPC,
   HTTPUpgrade; `hysteria2`, `tuic`.
8. **TUN**: Linux and Android TUN, a user-space TCP/IP stack, auto_route, the
   platform interface for Android VpnService.
9. **Management**: Clash API, cache file, selector/urltest groups.
10. **Heavy endpoints** (evaluated separately): WireGuard, Tailscale, naive,
    uTLS/REALITY fingerprints.

## Known differences in milestone 1

- ~~`direct` tries resolved addresses one after another~~: fixed in
  milestone 3 (happy-eyeballs).
- ~~A plain HTTP proxy request is forwarded with `Connection: close`~~:
  fixed in milestone 3 (keep-alive client connections).
- The `local` DNS server uses the system resolver (getaddrinfo), which
  reports no TTL; answers are cached for 10 seconds.
- `reject` with `method: drop` closes the connection like `default`.

## Known differences in milestone 2

- SOCKS5 UDP packets with a non-zero `FRAG` field are dropped (RFC 1928
  allows a server without reassembly to); sing-box ignores the field and
  treats such a packet as whole.
- The `direct` outbound resolves every domain destination of a UDP session
  through DNS and reports replies from each resolved address as the domain
  (unless `udp_disable_domain_unmapping`); sing-box resolves and maps back
  only the session's first destination.
- `hijack-dns`: A and AAAA answers are built from the addresses the DNS
  router returns (rules, strategy and cache as for lookups), so CNAME
  records and the upstream's other sections and EDNS options are not passed
  through; other query types are forwarded as they are to the selected
  `udp`/`tcp` server and not cached, and the `local` server answers them
  with NOTIMP. Responses are not truncated to the client's UDP size
  (sing-box `TruncateDNSMessage`).
- DNS rules see the inbound, source, user and network of a hijacked query,
  not its destination.
- The QUIC sniffer reads the server name only: there is no client
  detection (chromium, firefox, safari, quic-go), so the `client` rule item
  is not supported yet. At most 8 packets are read while sniffing a UDP
  session.
- The UDP NAT table (`rb_route::nat`) has no user yet: the SOCKS5 inbound
  gives each UDP ASSOCIATE its own socket and session, as sing-box does; the
  table is for the inbounds that share a socket (`direct`, `shadowsocks`,
  `tun`). `udp_fragment` was not supported (added in milestone 3).

## Milestone 3: platform support of the dial and listen fields

| Field | Linux | Android | other platforms |
|---|---|---|---|
| `bind_interface` (dial and listen), `route.default_interface` | `SO_BINDTOIFINDEX`, else `SO_BINDTODEVICE` | same | refused (sing-box also supports macOS and Windows) |
| `routing_mark` (dial and listen), `route.default_mark` | `SO_MARK`, needs `CAP_NET_ADMIN` | same | refused (sing-box: Linux only) |
| `bind_address_no_port` | `IP_BIND_ADDRESS_NO_PORT` | same | refused (sing-box: Linux only) |
| `netns` (dial and listen) | `setns` on a helper thread, needs `CAP_SYS_ADMIN` | same | refused (sing-box: Linux only) |
| `tcp_fast_open` (dial) | lazy connect, data in the SYN (`MSG_FASTOPEN`) | same | refused (sing-box also macOS, Windows, FreeBSD) |
| `tcp_fast_open` (listen) | `TCP_FASTOPEN` queue 4096 | same | refused |
| `tcp_multi_path` | `IPPROTO_MPTCP`, plain TCP when the kernel has none | same | plain TCP (as Go) |
| `udp_fragment` | `IP_MTU_DISCOVER` / `IPV6_MTU_DISCOVER` | same | system default |
| `protect_path` | `SCM_RIGHTS` over a Unix socket | same | refused off Unix |
| `reuse_addr` | `SO_REUSEADDR` + `SO_REUSEPORT` | same | `SO_REUSEADDR` |
| `tcp_keep_alive*`, `disable_tcp_keep_alive` | `TCP_KEEPIDLE`, `TCP_KEEPINTVL`, count 9 (Go's default) | same | idle time only |

`network_strategy`, `network_type` and `fallback_network_type` (dial fields),
the `network_strategy` route option and `route.default_network_strategy`,
`default_network_type`, `default_fallback_network_type` and
`default_fallback_delay` only take effect in sing-box's graphical clients,
through their platform interface with `auto_detect_interface`. rust-box has
no platform interface yet (milestone 8) and handles them exactly as sing-box
v1.14.4's command line does (an exception to "never silently ignore"
approved by the user):

- They are parsed and validated (`unknown network strategy`, `unknown
  interface type`) and otherwise have no effect; neither sing-box nor
  rust-box logs anything about them.
- `dialer.NewDefault`: with `bind_interface`, `inet4_bind_address`,
  `inet6_bind_address` or `tcp_fast_open`, a dialer fails with sing-box's
  message "`network_strategy` is conflict with `bind_interface`,
  `inet4_bind_address`, `inet6_bind_address` and `tcp_fast_open`" when
  `network_strategy` is set, or when `network_type` is set with neither
  `fallback_network_type` (an explicit `[]` counts as set, `null` does not)
  nor `fallback_delay` (Go's operator precedence). A dialer with `detour`
  is not checked, as sing-box builds no default dialer for it. rust-box
  reports this when the configuration loads, with the field path.
- `route.NewNetworkManager`: `default_network_strategy` fails with
  "`default_network_strategy` is conflict with `default_interface`" or
  "`auto_detect_interface` is required by `default_network_strategy`".
- The `network_strategy` route option reaches sing-box's default dialer only
  through `direct`'s resolving dialer, which dials IP destinations without
  it (`resolveParallelNetworkDialer.DialParallelInterface`); other outbounds
  do not read it. So it has no effect in either program.

## Known differences in milestone 3

- The platform network fields (`network_strategy` and the others above)
  behave as in sing-box's command line: accepted without effect, with its
  conflict checks (the first version of this milestone rejected them).
- Rejected with their path rather than implemented: the route options
  `tls_spoof` and `tls_spoof_method` (raw-socket injection),
  `domain_resolver.client_subnet`, and the `network_namespaces`
  section (so `netns` takes a name under `/var/run/netns` or a path, not a
  namespace tag).
- `domain_resolver.disable_optimistic_cache` is accepted; rust-box has no
  optimistic cache, so it is always in effect.
- References are checked when the configuration loads: an inbound
  `detour`, a DNS server `detour` (including sing-box's "detour to an empty
  direct outbound makes no sense") and an `inet4_bind_address` /
  `inet6_bind_address` of the wrong family. sing-box reports these on the
  first connection that uses them.
- `listen` now defaults to `127.0.0.1`, as in sing-box's listener code
  (`Listen.Build(127.0.0.1)`); milestones 1 and 2 used `0.0.0.0`.
- Behaviors kept from v1.14.4 on purpose: `tcp_multi_path` only applies to
  the IPv4 dialer (sing-box enables MPTCP on `dialer4` only; listeners use
  it for both families); the route option `fallback_delay` is a plain number
  of nanoseconds (`uint32` cast to `time.Duration`), so `"300ms"` is a type
  error; `tls_fragment` cuts the ClientHello once inside the first label of
  the server name (the label list is cut down by the number of dots) and
  turns `TCP_NODELAY` off afterwards; `udp_fragment` has no effect on the
  `socks`, `http` and `mixed` inbounds, whose UDP sockets sing-box opens
  without it; inbound `detour` hands TCP connections over but a SOCKS5 UDP
  association fails with "inbound detour is not UDP injectable", as these
  inbounds are not UDP-injectable in sing-box either.
- `tcp_fast_open`: a destination port of a server-first protocol (SMTP,
  IMAP, POP3) is connected at once instead of on the first write (sing-box
  achieves the same by writing an empty first packet); when the kernel
  refuses Fast Open the connection falls back to a plain connect.
- `bypass` routes like `route` when it names an outbound and is skipped
  otherwise; its kernel-level meaning for `auto_redirect` pre-matching
  needs a TUN (milestone 8).
- HTTP proxy, plain requests: each request is a routed connection of its
  own and the client connection stays open with `HTTP/1.1` and
  `Proxy-Connection: keep-alive`, as in sing-box. Differences from Go's
  HTTP client underneath sing-box: no `User-Agent` is added when the client
  sent none; header names and order are passed as received instead of
  canonicalized and sorted; an absolute `https://` target is answered with
  502 (sing-box would make the TLS connection itself); a request body the
  upstream did not read to its end closes the client connection (sing-box
  discards up to 256 KiB to keep it open); the `407` realm is `rust-box`.
  As in sing-box, `X-Forwarded-For` replaces the source address (port 0)
  for routing, so `source_*` rules can be steered by the client.
- `protect_path` talks to the protector synchronously on the dialing
  thread, as sing-box's control function does.
- Not ported: sing-box's connection tracking and power reports in the
  default dialer, and the `direct` outbound's check against connecting back
  into a TUN range.

## Known differences in milestone 4

The `rule-set` commands were compared with the real sing-box v1.14.4 binary
(`crates/rust-box/tests/rule_set_cli.rs`, fixtures written by sing-box in
`crates/rust-box/tests/data/rule-set`): the decompressed `.srs` content of
`compile` and `convert`, and the output of `decompile`, `format`, `upgrade`,
`merge` and `match`, are byte-identical. The compressed `.srs` bytes differ,
since Go's and Rust's zlib encoders produce different (equally valid)
streams.

- No cache file (milestone 9): remote rule-sets are downloaded at every
  start instead of being restored from `cache.db`, and rule-sets are not
  reference-counted (a rule-set no rule uses is still loaded and updated).
- The remote `http_client` option and the top-level `http_clients` section
  are rejected as not supported yet; the deprecated `download_detour` is
  honored (with sing-box's deprecation warning).
- `process_*`, `package_name*`, `network_type`, `network_is_expensive`,
  `network_is_constrained`, `wifi_ssid`/`wifi_bssid` and the interface
  address items are parsed, written to and read from SRS, but never match:
  rust-box has no process searcher and no platform interface yet. As in
  sing-box, `rule-set match` leaves the network items out (no network
  manager outside a box).
- The DNS rule actions and items of later milestones (`match_response`,
  `evaluate`, `respond`) are not implemented.
- Empty lists follow sing-box's decoder: `"domain": []` is the same as an
  unset field, and a rule list made only of empty rules (`[{}]`,
  `[{"domain":[]}]`) is no list at all, while an empty rule next to a real
  one fails with "missing conditions".
- Error and log wording: errors are printed as `Error: ...` (anyhow) rather
  than logrus' `FATAL[0000] ...`, and `upgrade` prints a plain
  `INFO[0000] already up-to-date`; Go's JSON decoder messages are mimicked
  for the common cases only.
- `-c` is not a global flag: it is accepted before or after `run`/`check`,
  so that `rule-set merge` can have its own `-c` (in sing-box the
  subcommand flag shadows the persistent one).

## Known differences in milestone 5

TLS is rustls 0.23 (ring) instead of Go's crypto/tls. The shadowsocks,
trojan, vless, vmess and sing-mux wire formats were checked against vectors
generated by the Go libraries (`testdata/generate*`) and against the real
sing-box v1.14.4 binary in both directions (`SING_BOX_BIN`).

- TLS 1.0 and 1.1 are not supported (rustls implements 1.2 and 1.3 only);
  `min_version`/`max_version` below 1.2 are errors. CBC cipher suites,
  P-521 and X25519MLKEM768 are rejected, as are `utls`, `reality`, `ech`,
  `acme`, `ktls`, `certificate_provider` and `spoof`.
- A TLS handshake fails when client and server ALPN lists have no overlap;
  Go's server continues without ALPN.
- Proxy outbounds (trojan, vless, vmess and the like) send their request
  header when the connection is dialed; sing-box waits up to 300 ms for the
  first payload to coalesce with it.
- UDP NAT sessions follow rust-box's NAT table lifetime (`udp_timeout`)
  rather than each protocol's own per-session timers.
- `xtls-rprx-vision` padding bytes are zero; Go pads with whatever stale
  bytes are in its buffer.
- With `packetaddr`, the inbound routes the whole packet session by the
  destination of its first packet.
- `multiplex.brutal` is rejected: TCP Brutal needs `setsockopt` on the raw
  TCP socket, which is not reachable through rust-box's boxed stream layers
  (TLS, Vision, protocol framing). The inbound still answers a client's
  brutal exchange with "brutal is not enabled by the server", as sing-box
  does when brutal is off.
- vmess AEAD UDP never sends an empty packet; sing-vmess would send a sealed
  empty chunk.
- A mux stream whose routing fails is closed without sing-mux's error
  status.
- Log wording: multiplexed connections log "outbound connection to" rather
  than "outbound multiplex connection to", and mux stream lines are not
  prefixed with the user.
- After the client half-closes, rust-box half-closes every outbound and
  keeps the download open; sing-box closes outbounds that cannot half-close
  (such as shadowsocks) entirely.
- vmess tests inject a clock into the AEAD timestamp check; the runtime uses
  real time, as sing-vmess does.

## Known differences in milestone 6

- FakeIP address/domain mappings and allocation cursors live only in process
  memory. They are not saved to or restored from `experimental.cache_file`;
  that persistence work is deferred to milestone 9.
- On Windows, the default hosts path is built from `%SystemRoot%\\System32\\Drivers\\etc\\hosts`;
  sing-box uses `GetSystemDirectory`. WOW64 path behavior may therefore differ
  and has not been verified on Windows.
- The full workspace suite passed, including its existing sing-box CLI/proxy
  interoperability cases, but there is no dedicated DNS transport-to-transport
  interoperability test against sing-box v1.14.4. DoT/DoH/DoQ/DoH3 transport
  tests use local fixtures; live public resolvers and non-Linux platforms have
  not been verified.

## Known differences in milestone 7

Milestone 7 is complete. The final workspace run with the pinned sing-box
v1.14.4 binary passed 400 tests, with 0 failures and 1 ignored doc test; the
Hysteria2, TUIC and V2Ray-transport interoperability cases passed. The four PR
CI jobs (fmt/clippy/test, MSRV 1.88, x86_64 Linux release and aarch64 Android
release) also passed. Unsupported configuration is rejected with its field
path rather than silently ignored.

- Hysteria2 outbound supports Brutal negotiation but rejects BBR-meta2;
  Hysteria2 inbound accepts both Brutal and Meta2. Hysteria2 obfuscation
  (`obfs`), `masquerade`, `realm`, inbound `detour`, outbound port hopping
  (`server_ports`, `hop_interval`, `hop_interval_max`), `bbr_profile` and
  `brutal_debug` are not implemented. The outbound also requires
  `disable_chrome_parrot: true`; Chrome-parrot behavior is not implemented.
- TUIC supports default/cubic congestion control and native UDP DATAGRAM
  relay on the outbound, but not `zero_rtt_handshake`, `udp_over_stream`,
  `udp_relay_mode: quic`, `bbr` or `new_reno` congestion control.
- High-packet-loss or high-latency networks, extreme MTUs, long-duration
  runs and high-concurrency load were not part of this milestone's
  verification.

## Known differences in milestone 8

- **User-space stack.** sing-tun's `gvisor`, `system` and `mixed` stacks are
  replaced by one stack of rust-box's own (`rb-netstack`): TCP on smoltcp
  0.12, UDP and ICMP written for rust-box. smoltcp was chosen over a custom
  TCP because it is a maintained pure-Rust TCP/IP implementation (no C, no
  Go), builds on Rust 1.88 (0.12 is its last release for 1.88; 0.13 needs
  1.91), and runs entirely in memory, so the stack is tested without a TUN
  or privileges. gVisor itself has no Rust port; a from-scratch TCP would
  carry far more risk than the TCP state machine smoltcp already has.
  `stack` accepts `system`, `gvisor` and `mixed` and runs the same stack for
  each; another value fails at start with `unknown stack: <value>`, as in
  sing-box.
- The TCP handshake with the client completes before the outbound connects;
  a connection whose outbound then fails is closed (a rejected one is reset
  at once, before the handshake, as in sing-box).
- ICMP: echo requests to any address the rules do not refuse are answered
  by the stack itself; rust-box does not forward pings through an outbound,
  and route rules have no `icmp` network, so pings are not pre-matched.
- Packets the stack drops: IPv4 fragments, IPv6 packets with extension
  headers before the transport header, and destinations that are not
  global unicast (as sing-tun's system stack).
- `loopback_address` (system stack only in sing-tun) is refused as not
  supported.
- auto_route on Linux installs the same routes, gateways and policy rules as
  sing-tun (verified against vectors generated from sing-tun's own code and,
  as root, against the kernel state sing-box v1.14.4 leaves for the same
  options), over rtnetlink without a netlink library. systemd-resolved is
  configured with `resolvectl` as sing-tun does; its `flush-caches` on
  network changes is not ported.
- Not implemented, refused with the field path and "is not supported by
  rust-box yet": `netns`, `auto_redirect` and its marks, `nfqueue` and
  fallback rule index (the nftables mode), `exclude_mptcp`,
  `include_mac_address`, `exclude_mac_address`, `route_address_set`,
  `route_exclude_address_set`, `loopback_address`. sing-box accepts these at
  `check`. The meaning of `bypass` that only exists under `auto_redirect` is
  therefore not available either; elsewhere `bypass` behaves as before.
- `dns_mode` takes any string, as in sing-box; on Linux every mode but
  `disabled` behaves the same.
- Android: without a platform interface, `include_package`,
  `exclude_package` and `include_android_user` fail at start (rust-box does
  not read `packages.xml`); with one, they are passed to the platform in
  its TUN options. The Android rule that lets another VPN's traffic through
  is ported but never installed, since rust-box cannot tell that another
  VPN is running.
- Platform interface (`rb-platform`): a Rust trait with the parts of
  libbox's `PlatformInterface` the TUN and the dialer use (open the TUN,
  protect a socket, the default interface and its monitor, the interface
  list). There are no gomobile or other FFI bindings, and a VpnService
  client has only been exercised with an in-process fake.
- `route.auto_detect_interface` now takes effect: sockets are protected by
  the platform, or bound (`SO_BINDTODEVICE`) to the default interface,
  which rust-box reads from `/proc/net/route` and `/proc/net/ipv6_route`
  instead of following netlink route updates. Dialers with their own bind
  address or interface are left alone. `network_strategy` and the other
  network type fields still have no effect.
- The `direct` outbound's check against dialing back into a TUN range is
  made when it dials (TCP) or opens its socket (UDP), as sing-box does, for
  the ranges of TUN interfaces rust-box itself started.
- `multiplex.brutal` stays unsupported: it needs the `tcp-brutal` kernel
  module (absent on CI and on stock Android kernels) and a `setsockopt` on
  the raw TCP socket under the multiplexed connection; rust-box can reach
  that socket only when no TLS or other layer sits between, so it would
  work for a fraction of configurations and be untestable in CI.
- Tests that need root are skipped unless `RB_TUN_TEST=1`
  (`crates/rust-box/tests/tun.rs`); the stack, rules and netlink encoding
  are covered by in-memory tests.
