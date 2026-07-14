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

Python's pure implementations live in `spike/routing_policy.py` and
`spike/routing_recovery.py`, with address and circuit models beside them.
Rust mirrors the new primitives in `app-tauri/src-tauri/src/`. Python and Rust
execute the same files. Version 1 is append-only: correct an objectively invalid
vector in place, but introduce behavior changes as a new contract version so
platform adapters can migrate deliberately.

The contracts describe pure decisions only. They do not perform DNS queries,
open sockets, mutate PF, or change external DNS, proxy, PAC, or VPN state.
