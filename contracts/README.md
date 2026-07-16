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

Python's pure implementations live in `spike/routing_policy.py` and
`spike/routing_recovery.py`, with address and circuit models beside them. Rust
implements the shared primitives in `crates/slipstream-core`; the macOS tray is
an adapter and may re-export core modules during migration. Python and Rust
execute the same files. Version 1 is append-only: correct an objectively invalid
vector in place, but introduce behavior changes as a new contract version so
platform adapters can migrate deliberately.

The contracts describe pure decisions only. They do not perform DNS queries,
open sockets, mutate PF, or change external DNS, proxy, PAC, or VPN state.
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
