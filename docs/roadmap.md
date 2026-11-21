# Roadmap

Ordered by dependency, following the porting order in the sing-box
architecture analysis (`docs/singbox-architecture.md`, section 11.2). Each
milestone is one pull request with tests; the configuration stays sing-box
v1.14.4 compatible, and a field rust-box does not implement is an error, never
silently ignored.

1. **Core path** (done): config, socks/http/mixed inbounds, direct/block
   outbounds, route rules and actions (route, reject, sniff, resolve), DNS
   (local/udp/tcp, rules, cache).
2. **UDP**: SOCKS5 UDP ASSOCIATE, UDP NAT table and timeouts (`route/conn.go`
   `NewPacketConnection`), `udp_timeout`, DNS sniffing and `hijack-dns`.
3. **Dial options and outbound plumbing**: `detour`, `bind_interface`,
   `routing_mark`, `tcp_fast_open`, happy-eyeballs (`fallback_delay`),
   `route-options`, `bypass`.
4. **Rule-sets**: inline, local and remote `source`/`binary` (SRS) rule-sets,
   `rule_set` rule items.
5. **TLS and first encrypted protocols**: rustls client/server, `shadowsocks`
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

- `direct` tries resolved addresses one after another; sing-box races them
  with `fallback_delay` (happy-eyeballs).
- A plain HTTP proxy request is forwarded with `Connection: close`, so each
  request uses its own upstream connection; sing-box keeps the client
  connection alive across requests.
- The `local` DNS server uses the system resolver (getaddrinfo), which
  reports no TTL; answers are cached for 10 seconds.
- `reject` with `method: drop` closes the connection like `default`.
