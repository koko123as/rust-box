# Local `quinn-proto` patch

This directory vendors the upstream `quinn-proto` 0.11.19 source crate (the version selected by the workspace's pinned `quinn` 0.11.12 dependency). Upstream licenses are retained in `LICENSE-APACHE` and `LICENSE-MIT`; the package manifest and original registry manifest are retained for provenance.

The local path patch exists because strict sing-quic Hysteria2 congestion-control behavior needs packet-level congestion feedback and a controller-owned pacing deadline, which the unmodified Quinn `Controller` interface does not expose. Any local changes must preserve the existing built-in controllers and be covered by tests. This fork is not a claim of Hysteria2 compatibility by itself.
