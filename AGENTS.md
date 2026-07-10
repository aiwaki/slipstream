# Agent Notes

@/Users/aiwaki/.codex/RTK.md

## Start Here

- Read `docs/README.md` before docs, routing, release, or troubleshooting work.
- Read `docs/DECISIONS.md` before changing routing policy, canaries, Geph, DNS,
  proxy, PAC, or VPN behavior.
- Keep root README files short and user-facing. Put project knowledge in `docs/`.

## Code Discovery

- Prefer codebase-memory-mcp graph tools for code discovery:
  `search_graph`, `get_code_snippet`, and `search_code`.
- If the graph transport fails with `Transport closed`, record the fallback in
  repo docs when relevant and use narrow `rtk rg` / `rtk sed` searches.
- Use grep-style search for string literals, config values, generated files, and
  non-code docs.
- Use context-mode for large logs, status dumps, or broad file summaries so raw
  output stays out of the chat context.

## Routing Invariants

- Discord and YouTube/googlevideo stay on local bypass. Never route them through
  Geph, including `updates.discord.com` and `gateway.discord.gg`.
- Geph is only for geo-exit cases where the service rejects Russian IPs.
- Do not globally block QUIC or UDP/443.
- Do not mutate external DNS, proxy, PAC, VPN, or user-managed DNS such as
  `xbox-dns.ru`; detect and warn only.

## Knowledge Capture

- Use `docs/ROUTING_RESEARCH.md` for routing investigations, external repo
  findings, and network behavior.
- Use `docs/DECISIONS.md` for stable decisions and invariants.
- Use `docs/TROUBLESHOOTING.md` for repeated user-visible symptoms and checks.
- Keep Codex memory compact; repo docs are the project source of truth.

## Git And PR Hygiene

- Prefer regular `git push`/`git fetch`. If Git transport hangs but GitHub API is
  healthy, verify the remote branch with `gh pr view` / `gh api` before using an
  API fallback.
- Do not rewrite PR history to hide an equivalent commit SHA mismatch. Confirm
  tree equality, CI status, and PR head before continuing.
- Keep work in PR branches by default; avoid pushing directly to `main`.
