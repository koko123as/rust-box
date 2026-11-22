# Rustls fork origin

This directory is the controlled M10 fork baseline of the Rustls crate.

- Upstream package: `rustls` 0.23.46 from crates.io.
- Cargo registry archive SHA-256: `48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf` (the original lockfile checksum before applying the local path override).
- The baseline source is copied from the published 0.23.46 crate without code changes. Upstream license files and source notices are retained.
- The workspace root `[patch.crates-io]` entry redirects all compatible workspace consumers to this path. Keep the fork's package name/version unchanged so Tokio-Rustls and Quinn share one Rustls type identity.

Subsequent M10 modifications must be isolated in reviewed commits, preserve the 0.23.46 baseline as the reference, and prove behavior with byte-level ClientHello and complete handshake tests. Do not update this fork to another upstream Rustls release without an explicit compatibility review.

## Local M10 patches

- Add a typed ClientHello codec for the Chrome 133 ALPS codepoint `0x44cd` (uTLS v1.8.7 `ApplicationSettingsExtensionNew`), with exact wire-byte and round-trip tests. The field defaults to absent and is not enabled by the standard TLS client configuration. This codec-only patch is not a completed uTLS profile and must not be reported as compatibility.
