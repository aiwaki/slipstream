# Slipstream Windows Adapter

This crate is the first Windows platform boundary around `slipstream-core`.
Its routing v1 module is deliberately a no-network harness: it verifies signed
policies, executes activation and recovery reducers through injected effects,
consumes StatusV2, and classifies traffic without touching the host.

`RecordingWindowsEffects` is the deterministic fake used by contract tests.
The separate `data_plane::v1` module freezes the worker/request/session boundary
before any native Windows network API is admitted. It validates the complete
`slipstream-core` policy result against the chosen backend, so Discord and
YouTube accept only local-bypass/local-engine requests and cannot acquire a
Geph edge. Requests, first-payload deadlines, cancellation acknowledgements,
shutdown, resets, and late completions are pure events that emit ordered
commands through an injected effect boundary.

`RecordingWindowsDataPlaneEffects` owns deterministic fake resources and
rejects duplicate opens, closes, first-payload marks, and outcomes. First
payload proves that the selected backend became usable; it does not declare a
long-lived relay successful. A later reset after partial payload is therefore
recorded as a stream failure, while caller or shutdown cancellation records no
backend failure. Cancellation and worker shutdown are bounded, resources close
exactly once before a terminal outcome, and a late completion cannot resurrect
a cancelled or stopped session. Monotonic session IDs keep stale events from
targeting a later request that reuses an external request ID, while a bounded,
deterministically pruned terminal history prevents a long-running service from
growing state without limit. The reducer itself opens no socket and reads or
mutates no DNS, proxy, PAC, or VPN state.

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

`service_lifecycle_state` implements the separate native filesystem effects for
`PersistIntent`, `CommitInstall`, and `ClearActiveInstallRecord`. Intent and
active-install records are strict, bounded, owner-only, and committed through a
flushed pending file. A surviving pending file is interruption evidence, not
cleanup permission. Active install requires matching running intent and exact
staged-payload ownership; clearing it requires an absent tombstone and verifies
that the exact record disappeared. Unknown or inconsistent evidence blocks all
later service-manager mutation. Stable state is only a prerequisite for a
separate action-specific ownership gate, not authorization by itself.

`service_scm` adds that action-specific gate and the isolated native effects for
`RegisterService`, `StartOwnedService`, `StopOwnedService`, and
`UnregisterOwnedService`. Every call recollects stable lifecycle state and the
exact staged payload. Existing services are observed through the same handle
that carries only the required mutation right plus query rights. Registration
requires exact absence; start, stop, and removal require a stable exact-owned
service, with uninstall and install-compensation tombstones handled explicitly.
No process, DNS, proxy, PAC, VPN, socket, or packet API is present.

`service_native` composes durable state, payload, and SCM effects while holding
the shared operation lock once per lifecycle action. Readiness and stopped-state
proofs bind to the exact staged identity. Unregister closes its delete handles
and waits for the exact service name to disappear before payload removal is
allowed. If a failure is reported after active-install commit, compensation
keeps the exact identity in the absent tombstone and defers clearing the active
record until both SCM and payload absence are proven. A disposable service
fixture exercises install, stop, start, crash recovery, uninstall, and that
post-commit compensation path in Windows CI.

`service_controller` is the production-facing command boundary. It acquires the
same machine-wide operation lock before collecting durable lifecycle and live
SCM/ownership evidence, reconstructs actionable state only when those domains
agree on the exact owned identity, and holds the lock through reducer execution
and every native effect. Fresh and terminal absence remain idempotent; installing
an already-running identical service is a no-op. Foreign, unknown, interrupted,
or inconsistent evidence never becomes cleanup authority. A disposable CI gate
executes install, a failed and then successful bounded crash restart, and
uninstall through separate controller processes.

`service_host` makes that boundary executable without adding a data plane. The
same production binary enters SCM mode only with exact `--service`; management
uses explicit `manage install|start|stop|recover|uninstall` commands and emits a
versioned JSON result. Install hashes the current executable before the existing
payload transaction reopens and independently verifies it. The service reports
the bounded `START_PENDING -> RUNNING -> STOP_PENDING -> STOPPED` sequence and
accepts both stop and shutdown controls. It opens no socket, discovers no other
process, and performs no DNS, proxy, PAC, VPN, or packet operation. A separate
Windows CI process exercises repeatable install, stop, restart, and uninstall
through the real SCM.

The next Windows step composes the production service host with an injected
no-network worker through this data-plane contract. SCM `RUNNING` must follow
worker readiness, and stop/shutdown must preserve bounded cancellation before
the host reports `STOPPED`. Native networking and installer integration remain
later steps and must keep every v1 recording harness available for regression
tests. Policy rollback remains explicitly atomic: durable commit and runtime
activation must either both succeed or leave the current policy active.

```bash
cargo test --locked --manifest-path crates/slipstream-windows-adapter/Cargo.toml
cargo clippy --locked --manifest-path crates/slipstream-windows-adapter/Cargo.toml \
  --all-targets --all-features -- -D warnings
```

The adapter executes `contracts/platform-adapter-v1.json`,
`contracts/windows-service-lifecycle-v1.json`,
`contracts/windows-service-observer-v1.json`,
`contracts/windows-service-ownership-v1.json`,
`contracts/windows-service-lifecycle-state-v1.json`,
`contracts/windows-service-scm-gate-v1.json`,
`contracts/windows-service-host-v1.json`,
`contracts/windows-data-plane-v1.json`, and the existing routing, recovery,
StatusV2, manifest, signed-bundle, and activation contracts.
