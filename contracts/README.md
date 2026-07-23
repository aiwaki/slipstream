# Routing Contracts

These versioned JSON vectors are the language-neutral behavior contract for
Slipstream routing decisions and bounded recovery primitives.

- `routing-policy-v1.json` maps representative hostnames to their normalized
  policy result.
- `recovery-v1.json` maps normalized connection outcomes and reducer context to
  ordered recovery actions.
- `address-attempts-v1.json` defines deterministic IPv4/IPv6 candidate ordering,
  staggered starts, concurrency bounds, deadlines, winner selection, and loser
  cancellation.
- `route-circuit-v1.json` defines a circuit breaker scoped by service group,
  route class, and backend, including bounded half-open probes.
- `route-circuit-registry-v1.json` defines deterministic TTL/LRU storage for
  non-default circuit state without changing route selection.
- `connection-race-v1.json` composes those primitives as a pure command/event
  state machine and executes them through scripted resolver and connector
  adapters without touching the network.
- `status-v2-v1.json` freezes one complete privacy-bounded StatusV2 payload and
  its legacy tray projection, including additive-field preservation.
- `route-policy-manifest-v1.json` freezes manifest normalization, structured
  validation failures, bounded input limits, and effective first-match
  protection for local-bypass and direct-first domains.
- `route-policy-bundle-v1.json` freezes Python-compatible canonical bytes,
  SHA-256 identity, Ed25519 verification, and structured envelope failures.
- `route-policy-activation-v1.json` freezes compare-and-swap trial activation,
  health acceptance, rejection restore, stale-event protection, and one-level
  rollback for already-verified policy identities.
- `platform-adapter-v1.json` freezes the first no-network adapter boundary:
  verified policy activation, fake-effect ordering, compensation, StatusV2
  consumption, and recovery dispatch. Windows is the first implementation;
  later adapters consume the same contract before adding native effects.
- `windows-service-lifecycle-v1.json` freezes the Windows service boundary before
  native service-manager code exists: exact owned identity, transactional
  install compensation, intent-first stop/uninstall, bounded crash recovery,
  same-identity install idempotence, final-state verification, and refusal to
  mutate foreign or unknown services.
- `windows-service-observer-v1.json` freezes conservative SCM state mapping for
  the read-only native Windows observer. It never infers ownership and exposes a
  process ID only for a stable running state.
- `windows-service-ownership-v1.json` freezes the proof required before a
  Windows service may be treated as owned. An owner-only record, canonical SCM
  command, exact executable path, SHA-256, positive generation, and stable SCM
  state must all agree; incomplete evidence is unknown and mismatched evidence
  is foreign.
- `windows-service-lifecycle-state-v1.json` freezes strict durable intent and
  active-install records plus interruption, identity, and tombstone barriers.
- `windows-service-scm-gate-v1.json` freezes the action-specific authorization
  for exact registration, start, stop, and removal. Stable state and staged
  payload evidence are prerequisites; foreign, transitional, or mismatched
  service evidence always refuses mutation.
- `windows-service-host-v1.json` freezes the production host command surface,
  structured management results, and bounded SCM shutdown sequence. The same
  binary runs only as exact `--service` or explicit `manage` commands, installs
  from its currently opened executable identity, and has no networking or
  process-discovery surface.
- `windows-data-plane-v1.json` freezes the first Windows worker and session
  boundary as pure commands and events. It reclassifies each normalized host
  through the active validated policy tables instead of trusting caller route
  metadata, validates the backend before effects, keeps session resources
  adapter-owned until bounded cancellation completes, distinguishes first
  payload from terminal stream success, assigns monotonic session identities,
  retains only bounded terminal history, and emits one normalized outcome after
  resource close. Its failure vectors resume multi-command effect batches from
  an exact cursor without replaying already-completed commands.
- `windows-worker-host-v1.json` composes that data-plane reducer with the SCM
  host without adding a native or network effect. Worker readiness is the only
  path to `RUNNING`; host-owned stop or shutdown reports `STOP_PENDING` before
  cancellation and cannot report `STOPPED` until the worker is terminal.
  Startup failure, graceful drain, forced deadline, late completion, repeated
  stop, and interrupted effect batches are language-neutral vectors.
- `windows-direct-connector-v1.json` admits the first Windows native networking
  primitive. It accepts only an already-authorized direct session plus a
  numeric endpoint, freezes bounded buffer and deadline validation, and maps
  connector events back to the data-plane reducer without resolving names or
  selecting another route.
- `windows-direct-ingress-v1.json` binds that connector to one adapter-owned
  client stream and fresh original-destination evidence. It forbids preloaded
  bytes, counts backend payload only after client delivery, bounds both relay
  directions, and maps client close to cancellation rather than a fabricated
  backend failure.
- `windows-capture-source-v1.json` freezes the technology-neutral source above
  direct ingress. It owns each accepted stream under a one-shot resource token,
  offers only fresh numeric original-destination evidence to an external
  admission authority, hands off only a separately admitted direct request,
  and closes every unhanded stream under bounded startup, admission, and
  shutdown paths. It does not choose an interception API.
- `windows-packet-adapter-v1.json` freezes the no-own-driver Windows packet
  boundary. It admits only the pinned official Wintun AMD64/ARM64 binaries
  after exact package, DLL, PE-machine, Authenticode publisher, signer, and
  timestamp evidence. Its candidate route plans require one canonical policy
  host and a selected destination present in the same fresh resolver evidence.
  That evidence is an opaque, non-deserializable capability; IPv6 candidates
  are limited to reviewed
  global-unicast space. Its separate shared-destination gate rejects partial,
  stale, oversized, non-canonical, unsorted, or policy-incompatible binding
  snapshots. Compatible evidence is collector-issued, generation-bound, and
  short-lived. Plans and conflict admissions are not native authorization. The
  complete-DNS premise was rejected after feasibility review, so v1 is frozen
  and no native issuer or route effect may be built from it. Default routes and
  system DNS/proxy/PAC/VPN mutation are impossible. It does not load the DLL,
  install a route, or compose production traffic.
- `windows-packet-capture-v2.json` freezes the capture-only feasibility
  boundary above a future packet source. Every flow carries a nonzero capture
  generation and flow identity plus at most five seconds of in-band TLS SNI or
  QUIC Initial hostname evidence. The active policy may classify only
  `local_bypass` or `geo_exit`; direct, unknown, opaque, ECH, malformed, stale,
  mismatched, or unsafe observations remain direct passthrough. Classification
  is not backend authorization. The contract has no DLL loading, adapter,
  route, socket, DNS, proxy, PAC, VPN, or production-host effect, and keeps all
  native loop, activation, expiry, rollback, coexistence, and architecture
  qualification gates closed.
- `windows-packet-egress-v1.json` freezes the pure outbound loop-avoidance
  admission below that capture boundary. A plan requires short-lived route
  evidence observed before capture plus an exact owned capture-route activation
  that moves the baseline epoch to the active epoch. The activation, plan, and
  current state must retain the same capture generation, destination, exact
  host prefix, and capture-interface LUID/index; a later route change
  invalidates the plan. Stable egress LUID-to-index identity, source family,
  and a containing baseline route prefix are also required. The capture
  interface is always rejected. IPv4 special-purpose ranges, including the
  deprecated `192.88.99.0/24` 6to4 relay block, fail closed. IPv6 destinations
  fail closed against the frozen 2025-10-10 IANA
  global-unicast allocation snapshot, including unallocated and special-purpose
  space. The positive allocation list is intersected with the frozen 2025-10-09
  special-purpose registry, so assigned but non-global ORCHIDv2 and DET
  prefixes also fail closed. The currently selected source address must still
  exactly match the baseline before a plan is emitted. IPv4 records the
  `IP_UNICAST_IF` value in network byte order while IPv6
  records the `IPV6_UNICAST_IF` value in host byte order. This does not
  call either socket option, trust JSON as native evidence, query or mutate a
  route, classify an external VPN, or compose the production host; those remain
  separate disposable AMD64/ARM64 gates.
- `windows-packet-flow-v1.json` freezes the pure forwarding seam after capture
  classification and outbound-route admission. Its opaque admission binds one
  capture generation, flow ID, monotonic data-plane session ID, transport,
  destination, active policy result, backend, and evidence lifetime. The pure
  state retains only ordered frame identities and byte counts; a future effect
  must retain immutable payload bytes under the same flow/direction/sequence
  identity until delivery is acknowledged. Per-direction byte and frame bounds
  plus a validated aggregate budget prevent tiny-frame memory amplification.
  High/low watermarks pause and resume only the producing side, while idle and sustained
  backpressure deadlines close only that owned flow. TCP half-closes propagate
  only after the preceding queue drains, UDP datagram boundaries remain
  distinct, resets clear both queues, and terminal history is bounded and
  ABA-safe. Pruning terminal detail retains a separate captured-flow owner
  tombstone; only monotonic retirement of an inactive capture generation may
  discard it, and that retirement high-watermark rejects delayed reopen. Backend
  bytes reach data-plane v1 only after confirmed client
  delivery; an expired or capacity-rejected open cancels its not-yet-owned
  session. Commands otherwise report connector lifecycle back into data-plane
  v1. This contract performs no packet reconstruction, socket,
  adapter, route, DNS, proxy, PAC, VPN, process, or service effect and is not
  composed into the production host.
- `windows-wfp-capture-v1.json` preserves the superseded WFP driver/service
  research wire without invoking WFP or opening a socket. Its fixed 128-byte
  context binds original IPv4/IPv6 endpoints to the exact owned service
  generation, PID, instance, and executable hash. Accepted loopback streams
  require that context plus bounded opaque redirect records and a source-issued
  connection ID. A one-shot type-state handoff consumes an
  active-policy-validated direct-ingress request with the same connection
  identity and exposes its outbound endpoint only after those records are
  marked applied.
- `windows-wfp-runtime-v1.json` freezes the pure lifecycle immediately above
  those future effects. Kernel callouts precede exact listener readiness and
  one atomic dynamic-session transaction. Session close is the first stop
  action; listener stop, bounded stream drain, and kernel unregister remain
  blocked until exact owned-filter absence is observed. Filter presence keeps
  the safety listener and callouts alive and schedules another proof instead of
  tearing down underneath a terminating filter.

Python's pure implementations live in `spike/routing_policy.py` and
`spike/routing_recovery.py`, with address and circuit models beside them. Rust
implements the shared primitives in `crates/slipstream-core`; the macOS tray is
an adapter and may re-export core modules during migration. Python and Rust
execute the same files. Version 1 is append-only: correct an objectively invalid
vector in place, but introduce behavior changes as a new contract version so
platform adapters can migrate deliberately.

The contracts describe pure decisions only. They do not perform DNS queries,
open sockets, mutate PF, or change external DNS, proxy, PAC, or VPN state.
The Windows adapter's routing and lifecycle reducers remain effect-free by
construction. Its target-scoped native observer is read-only. The separate SCM
effect can mutate only `dev.slipstream.service`, requests only action-specific
rights, rechecks the opened service handle, and first consumes protected
lifecycle state plus exact staged-payload evidence. It has no process or
networking surface. Owner-only record, ACL, and executable hash evidence remain
adapter responsibilities; JSON content cannot assert its own trustworthiness.
The production-facing service controller holds the shared machine-wide lock
from evidence collection through reducer and native-effect completion, so
controller restarts cannot split authorization from mutation.
The production service host reports `START_PENDING`, `RUNNING`, `STOP_PENDING`,
and `STOPPED` through SCM and accepts both stop and system-shutdown controls.
Those reports consume the pure worker-host composition: the injected
no-network worker must report readiness before `RUNNING`, and both stop paths
flow through bounded data-plane shutdown before `STOPPED`.
Windows CI invokes its management commands through separate processes and
proves repeated install, stop, start, and uninstall remain idempotent.
The Windows data-plane contract still performs no network operation. Its
recording effect proves that resources close exactly once before an outcome,
caller and shutdown cancellation are not backend failures, partial payload
followed by reset remains a stream failure, and late completions cannot
resurrect terminal sessions. Caller policy metadata is checked against the
active trusted classifier. Every individual native effect must be
failure-atomic; reducer state is committed only after the full command batch,
and a failed batch resumes from its returned cursor. Native networking must
preserve this contract.
The signed-bundle contract contains one deterministic test public key and
signature. It is not a production trust key and does not enable remote policy
fetch or application.
The activation contract emits ordered data-only adapter actions. It does not
fetch, verify, persist, or apply a manifest itself. A trial and rollback are
bound to the expected active SHA-256, while every health result is bound to the
current candidate SHA-256 and reducer-issued monotonic trial generation. A late
result therefore cannot commit either a different policy or a newer retry of
the same policy content.
The manifest contract also rejects `geo_exit` entries in the earlier
`static_routes` table and any geo-exit suffix that overlaps a protected domain.
It validates the route selected by table order, not merely the presence of a
later correct entry, including more-specific static subdomains inside a
protected suffix family.
The connection-race contract gates its request-local circuit before emitting
`resolve`, records one result for the whole logical request rather than one per
IP, and ignores adapter completions after a terminal result. The Python I/O
adapter executes those commands inside an already-selected backend. Persistent
runtime state is a separate bounded registry above that adapter: a full local
strategy ladder, proven Smart DNS attempt, or verified owned Geph attempt is one
backend outcome. Unknown and direct traffic remain one-shot.
