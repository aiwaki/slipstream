# Routing Contracts

These versioned JSON vectors are the language-neutral behavior contract for
Slipstream policy classification and safe recovery reduction.

- `routing-policy-v1.json` maps representative hostnames to their normalized
  policy result.
- `recovery-v1.json` maps normalized connection outcomes and reducer context to
  ordered recovery actions.

Python and Rust tests consume the same files. Version 1 is append-only: correct
an objectively invalid vector in place, but introduce behavior changes as a new
contract version so platform adapters can migrate deliberately.

The contracts describe pure decisions only. They do not perform DNS queries,
open sockets, mutate PF, or change external DNS, proxy, PAC, or VPN state.
