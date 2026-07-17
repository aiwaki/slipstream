# Slipstream Windows Adapter

This crate is the first Windows platform boundary around `slipstream-core`.
Version 1 is deliberately a no-network harness: it verifies signed policies,
executes activation and recovery reducers through injected effects, consumes
StatusV2, and classifies traffic without calling Windows or touching the host.

`RecordingWindowsEffects` is the deterministic fake used by contract tests.
Native service, process, DNS, proxy, VPN, packet, and installer effects belong
in later modules and must keep the v1 harness available for regression tests.
The rollback boundary is explicitly atomic: durable commit and runtime
activation must either both succeed or leave the current policy active.

```bash
cargo test --locked --manifest-path crates/slipstream-windows-adapter/Cargo.toml
cargo clippy --locked --manifest-path crates/slipstream-windows-adapter/Cargo.toml \
  --all-targets -- -D warnings
```

The adapter executes `contracts/platform-adapter-v1.json` plus the existing
routing, recovery, StatusV2, manifest, signed-bundle, and activation contracts.
