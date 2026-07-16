# Agent Notes

@/Users/aiwaki/.codex/RTK.md

## Start Here

- After automatic context compaction, task resume, or a bare "continue"
  request, read `docs/CURRENT_STATE.md` and verify it against the current
  worktree, merged/open PRs, and required CI before choosing work.
- Read `docs/README.md` before docs, routing, release, or troubleshooting work.
- Read `docs/DECISIONS.md` before changing routing policy, canaries, Geph, DNS,
  proxy, PAC, or VPN behavior.
- Keep root README files short and user-facing. Put project knowledge in `docs/`.

## Resume And Continuity

- Conversation summaries, milestone labels, and `docs/CURRENT_STATE.md` are
  navigation aids, not proof. Current source, git state, PR state, and matching
  CI evidence are authoritative.
- Never continue from a claimed milestone number alone. Reconcile every
  incomplete gate in `docs/CURRENT_STATE.md` with current evidence first.
- Prefer executing the next verified action over restating the roadmap. Update
  `docs/CURRENT_STATE.md` in the same PR when that action or milestone status
  changes.
- Do not repeat work after compaction. Check whether its branch, PR, equivalent
  tree, or merge already exists before editing.

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
  `xbox-dns.ru`. Its app-owned direct DoH fallback is allowed only for one
  exact unknown host after a local failure; it never changes resolver settings
  or sends Discord/YouTube through Geph.

## Knowledge Capture

- Use `docs/ROUTING_RESEARCH.md` for routing investigations, external repo
  findings, and network behavior.
- Use `docs/DECISIONS.md` for stable decisions and invariants.
- Use `docs/TROUBLESHOOTING.md` for repeated user-visible symptoms and checks.
- Use `docs/CURRENT_STATE.md` only for the compact evidence checkpoint, open
  gates, and next verified action; keep detailed investigations in their
  existing topic documents.
- Keep Codex memory compact; repo docs are the project source of truth.

## Git And PR Hygiene

- Prefer regular `git push`/`git fetch`. If Git transport hangs but GitHub API is
  healthy, verify the remote branch with `gh pr view` / `gh api` before using an
  API fallback.
- Do not rewrite PR history to hide an equivalent commit SHA mismatch. Confirm
  tree equality, CI status, and PR head before continuing.
- Keep work in PR branches by default; avoid pushing directly to `main`.
