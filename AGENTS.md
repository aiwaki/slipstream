# Agent Instructions

@/Users/aiwaki/.codex/RTK.md

## Code Discovery

Prefer codebase-memory-mcp graph tools over grep/glob/file search for code
discovery:

1. `search_graph`
2. `trace_path`
3. `get_code_snippet`
4. `query_graph`
5. `get_architecture`

Fall back to text search for string literals, configs, docs, or when graph
tools are unavailable. If the live MCP transport fails with `Transport closed`,
use the same graph backend through:

```bash
rtk /Users/aiwaki/.local/bin/codebase-memory-mcp cli list_projects
```

## Project Knowledge

Before routing, diagnostics, or documentation work, read:

- `docs/README.md` for the documentation map.
- `docs/DECISIONS.md` for active routing and knowledge-capture invariants.
- `docs/ROUTING_RESEARCH.md` for prior routing investigations.

Repo docs are the source of truth for project knowledge. Record important or
near-important findings in the appropriate repo doc:

- `docs/ROUTING_RESEARCH.md` for routing, external repo, and network findings.
- `docs/DECISIONS.md` for stable project decisions and invariants.
- `docs/TROUBLESHOOTING.md` for repeated user symptoms and checks.

Use Codex memory only for durable user preferences, cross-session working rules,
and pointers to repo docs. Do not duplicate long investigations in memory.

## Routing Invariants

- Discord and YouTube/googlevideo stay on local bypass/desync, not Geph.
- Geph is reserved for geo-exit cases where a service rejects the user's Russian
  IP address.
- Do not globally block QUIC/UDP.
- Do not mutate external DNS, VPN, PAC, or proxy settings. Detect and warn only.
