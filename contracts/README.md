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
