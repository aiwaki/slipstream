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

`service_ownership::v1` is a pure proof boundary between that observation and
the lifecycle. Its machine-level record binds the exact canonical SCM command
to an absolute executable path, lowercase SHA-256, and positive generation.
The result is `owned` only when a separate adapter has already proven the record
owner-only, the SCM state is stable, and the observed command, opened path, and
hash all match. Missing or inaccessible evidence stays `unknown`; mismatches
are `foreign`. The model reads no files and calls no native or network API.

On Windows, `WindowsServiceOwnershipCollector` supplies that proof without
mutating the machine. It locates `Slipstream/service-owner-v1.json` below the
system `ProgramData` known folder, opens it with reparse traversal disabled,
checks the final handle path and regular-file identity, and accepts write access
only for LocalSystem or built-in Administrators. The bounded strict-v1 JSON is
read from that same handle. A present service's executable is opened the same
way and SHA-256 is computed before the handle is released. Missing,
inaccessible, ambiguous, or permissively writable evidence cannot become
`owned`.

`service_payload` implements only the native `StagePayload` and
`RemoveOwnedPayload` effects. It accepts a source only when the exact opened
regular-file handle hashes to the lifecycle identity, creates owner-only
non-reparse directories and pending files, flushes each file, and renames on the
same volume with write-through semantics. The executable is committed first;
the strict owner record is the final commit marker. The read-only collector then
reopens both paths and must reproduce the exact identity. Failure compensation
marks only handles created by that transaction for deletion, while an existing
foreign or ambiguous path is never replaced.

Native SCM mutation, process, durable lifecycle-state, DNS, proxy, VPN, packet,
and installer effects belong in later modules and must keep the v1 recording
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
`contracts/windows-service-observer-v1.json`,
`contracts/windows-service-ownership-v1.json`, and the existing routing,
recovery, StatusV2, manifest, signed-bundle, and activation contracts.
