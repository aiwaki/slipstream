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

`direct_connector::v1` is the first native networking primitive admitted behind
that boundary. Its opaque plan can be created only after the complete direct
request is revalidated against the active policy tables. The endpoint must be
an already-selected canonical IPv4 or IPv6 address; the connector never resolves
a hostname or chooses a route. Initial and subsequent client payloads, read
chunks, queues, connect time, and first-payload time are bounded. The worker
thread owns the TCP stream until clean close, reset, caller cancellation,
deadline, or shutdown, and maps each result back to the existing data-plane
event with the exact request/session identity.

`WindowsDirectDataPlaneEffects` stages one validated opaque plan before
`StartSession`, rejects every non-direct backend, and owns the connector until
`CloseSession` precedes the normalized outcome. Its retained plans and outcomes
are bounded. A loopback fixture qualifies connect, first payload, partial-payload
reset, cancellation, deadline, shutdown, and the real reducer/effect chain on
Windows CI. The production SCM host still has no request ingress and retains its
no-network effect until a later composition supplies numeric endpoint evidence
and an adapter-owned client stream.

`direct_ingress::v1` is that ownership and relay boundary, but not an OS packet
capture source. It accepts only fresh `original_destination` evidence bound to
the exact reducer-issued session, request ID, numeric endpoint, and one
non-cloneable owned client `TcpStream`. Connector preload is forbidden: every
upstream byte must come from that stream. Backend bytes reach the data-plane
reducer only after the full chunk has been written to the client, so a queued
or stalled response cannot falsely prove first payload.

`WindowsDirectIngressDataPlaneEffects` stages the client and opaque connector
plan before `StartSession`, restores both if native worker startup fails, and
owns the relay until close precedes outcome. Client and backend reads, both
queues, retained state, and backpressure intervals are bounded. A client EOF or
write stall cancels without manufacturing a backend failure; an upstream stall
is an explicit backend reset. Deterministic relay-state tests qualify the exact
first-delivery and no-progress deadlines without depending on Windows TCP
buffer sizing or autotuning. Native loopback qualification covers the actual
owned relay, client-first close, reset after delivered payload, cancellation,
first-payload delivery, and shutdown. Closed cancellation bookkeeping is
bounded and drops first-payload markers.

`capture_source::v1` freezes the separate ownership lifecycle above direct
ingress without choosing a Windows interception technology. One staged native
stream is represented by an opaque one-shot resource ID. The source reports a
fresh canonical numeric original destination to an external admission
authority, retains ownership while admission is pending, and hands the stream
to direct ingress only after the exact direct request is independently granted
and revalidated. It does not derive hostnames or select routes or backends.

Invalid, rejected, expired, startup-racing, and shutdown-racing captures close
exactly once. A failed handoff retains source ownership for retry or explicit
compensation. Absolute connector deadlines cannot be rebased by late admission,
and a duplicate token cannot close the existing tracked stream. Stop prevents
new admission before bounded drain; startup and
shutdown have force-stop paths, effect batches resume from exact cursors, and
terminal history is bounded. `RecordingWindowsCaptureSourceEffects` proves
these rules without a socket or native API. The production SCM host does not
compose this module and remains no-network.

`packet_adapter::v1` is the active no-own-driver packet boundary. It admits
only the pinned official Wintun 0.14.1 AMD64 or ARM64 artifact after exact
archive, license, DLL, PE-machine, Authenticode publisher, signer, and
timestamp evidence. It can prepare only fresh policy-bound public `/32` or
`/128` candidate routes for `local_bypass` or `geo_exit`; protected hosts are
reclassified through the active tables, the resolver evidence must name that
canonical host, and the selected address must occur in the same answer set.
Resolver evidence is opaque and cannot be deserialized or constructed outside
the adapter boundary. IPv6
admission is conservative global-unicast only and rejects IANA
special-purpose space. A second pure gate requires an opaque complete binding
snapshot for the exact destination. Partial DNS observations fail closed; the
candidate host must be present, all hosts must be canonical, sorted and unique,
and every binding must select the same route class and strategy. Evidence lives
for at most 30 seconds and carries a collector generation. Neither the route
plan nor the conflict admission permits a route-table mutation. Feasibility
review showed that read-only DNS cannot produce the claimed complete boundary,
so v1 is frozen and no native conflict issuer or route effect may be built from
it. A separately versioned capture-only contract must pass its own safety gates
before DLL loading, adapter/route ownership, packet-stack integration, or
rollback work begins. This module cannot load a DLL, create an adapter, install
a route, or touch system DNS, proxy, PAC, VPN, or the production service host.

The `wfp_*::v1` modules preserve a now-superseded own-driver research path for
compatibility and future reference; they are not the Windows shipping plan.
`wfp_capture::v1` freezes that WFP driver/service data boundary while
remaining pure Rust. Its fixed 128-byte context is manually encoded with an
explicit version, lengths, byte order, TCP family, original remote/local
endpoints, service generation, exact target PID, capture-instance ID, and
service executable SHA-256. IPv4 padding and reserved bytes must be zero;
unsafe original destinations, stale identity, ordinary loopback connections
without context, non-owned listeners, and missing or oversized redirect
records are rejected with stable error codes.

The validated capture and redirect-record plan are non-cloneable. Each capture
carries the monotonic connection ID issued by capture-source v1. Handoff
revalidates a complete direct-ingress request against active policy, then
requires its exact connection ID and endpoint; a concurrent connection to the
same address cannot borrow that admission. A mismatch returns the capture
intact, while success exposes the opaque records first and produces the opaque
ingress/connect plan only after the caller marks those records applied. This
models the required
`SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS`-before-bind/connect ordering without
calling Winsock. Direct connector v1 is unchanged, and the production service
host does not compose this module.

`wfp_runtime::v1` freezes the surrounding lifecycle as another pure reducer.
It registers kernel callouts before starting the exact owned listeners, then
admits provider, sublayer, management callouts, provider context, and V4/V6
filters only as one failure-atomic dynamic-session command. A stop or runtime
fault emits dynamic-session close as its sole first action. After closure, an
exact service/capture identity, reducer-issued monotonic runtime generation,
and session generation gate the owned-filter inspection.

Listener stop, bounded accepted-stream drain, and kernel-callout unregister are
unreachable until both filters are proven absent. If either filter is still
visible, the reducer retains the listener and callouts and schedules another
inspection; it never creates the unavailable-callout blackhole that motivated
this ordering. Drain deadline force-close and unregister form one resumable
effect batch, so a later failure cannot replay an already committed stream
close. An accepted stream above the configured bound receives its own exact,
retryable reject effect and never enters runtime state. The recording effect
validates resource order and stale-event binding for each exact runtime attempt
without WFP, Winsock, a driver, or production-host composition.

`wfp_session::v1` is the first native WFP management boundary behind that
reducer. It freezes seven fixed owned object keys and a separate 128-byte
provider context that binds the exact service, runtime, session, target PID,
dual-stack loopback listeners, executable hash, and TCP/443 capture scope. The
controller refuses an atomic session command until the same runtime binding has
successful kernel-registration and listener-readiness proofs; those proofs
cannot be replaced in place. It also refuses listener stop or kernel unregister
until an inspection bound to the last attempted session generation proves both
exact filter keys absent.

On Windows, `WindowsFwpmManagementApi` opens an ephemeral dynamic engine
session and can add the provider, sublayer, V4/V6 management callouts, general
provider context, and terminating V4/V6 filters in one transaction. Every
partial failure aborts the transaction and closes the session; there is no
delete-by-key recovery. CI currently qualifies only an empty begin/abort/close
cycle and exact filter absence. It intentionally does not commit live filters
until a disposable driver has registered both matching kernel callouts, because
an unavailable terminating callout can block matching traffic. The production
SCM host does not import this module.

`worker_host::v1` composes that reducer with `WindowsServiceHostRuntimeV1`
without changing either frozen contract. Worker readiness precedes SCM
`RUNNING`; startup failure produces a nonzero `STOPPED`; and host-owned stop or
shutdown reports `STOP_PENDING`, drives bounded cancellation, then permits
`STOPPED` only after `ReportWorkerStopped`. Its recording effect also exposes an
exact resume cursor, so a successful worker-ready report or SCM status update is
not replayed after a later command fails.

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

`service_host` makes that boundary executable without adding native networking.
The same production binary enters SCM mode only with exact `--service`; management
uses explicit `manage install|start|stop|recover|uninstall` commands and emits a
versioned JSON result. Install hashes the current executable before the existing
payload transaction reopens and independently verifies it. The service reports
the bounded `START_PENDING -> RUNNING -> STOP_PENDING -> STOPPED` sequence and
accepts both stop and shutdown controls. It opens no socket, discovers no other
process, and performs no DNS, proxy, PAC, VPN, or packet operation. A separate
Windows CI process exercises repeatable install, stop, restart, and uninstall
through the real SCM. In service mode it consumes the pure worker-host
composition through an injected no-network effect, so worker readiness gates
`RUNNING` and both stop controls preserve the bounded data-plane shutdown order.

An OS interception source, additional backends, and installer integration
remain later steps and must keep every v1 recording harness available for
regression tests. The worker
reclassifies normalized hosts through the active validated
policy tables instead of trusting caller-supplied route metadata. Every effect
command must fail before mutation or complete fully; reducer state is committed
only after the whole command batch, and failures expose the exact cursor for a
non-replaying resume. Policy rollback remains explicitly atomic: durable commit
and runtime activation must either both succeed or leave the current policy
active.

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
`contracts/windows-data-plane-v1.json`, `contracts/windows-worker-host-v1.json`,
`contracts/windows-direct-connector-v1.json`,
`contracts/windows-direct-ingress-v1.json`,
`contracts/windows-capture-source-v1.json`,
`contracts/windows-wfp-capture-v1.json`,
`contracts/windows-wfp-runtime-v1.json`,
`contracts/windows-wfp-session-v1.json`,
and the existing routing, recovery, StatusV2, manifest, signed-bundle, and
activation contracts.
