# Slipstream Windows Adapter

This crate is the first Windows platform boundary around `slipstream-core`.
Its routing v1 module is deliberately a no-network harness: it verifies signed
policies, executes activation and recovery reducers through injected effects,
consumes StatusV2, and classifies traffic without touching the host.

`RecordingWindowsEffects` is the deterministic fake used by contract tests.
The isolated `service_lifecycle::v1` module adds transactional install, explicit
start/stop, bounded crash recovery, and fail-forward uninstall semantics behind
`WindowsServiceEffects`. Durable stop or uninstall intent is written before
service actions, is bound to the exact service identity and executable hash,
and cannot be weakened into background recovery. A crash attempt is persisted
before restart and reset only after readiness, so controller restarts cannot
erase the recovery budget. Unknown or foreign services produce no destructive
effects. Failed installation is compensated and must finish with an explicit
absence proof.

`service_observer::v1` adds the first native boundary. On Windows,
`WindowsScmObserver` opens the local Service Control Manager with query-only
rights and reads only the exact `dev.slipstream.service` name, status, process
ID, and configured binary command. Only the native service-not-found result is
reported as absent; access, decoding, and query failures remain errors. The
observer does not infer ownership, hash or execute the binary, or mutate the
service.

Native service mutation, process, storage, DNS, proxy, VPN, packet, and
installer effects belong in later modules and must keep the v1 recording
harnesses available for regression tests. Policy rollback remains explicitly
atomic: durable commit and runtime activation must either both succeed or leave
the current policy active.

```bash
cargo test --locked --manifest-path crates/slipstream-windows-adapter/Cargo.toml
cargo clippy --locked --manifest-path crates/slipstream-windows-adapter/Cargo.toml \
  --all-targets -- -D warnings
```

The adapter executes `contracts/platform-adapter-v1.json`,
`contracts/windows-service-lifecycle-v1.json`,
`contracts/windows-service-observer-v1.json`, and the existing routing,
recovery, StatusV2, manifest, signed-bundle, and activation contracts.
