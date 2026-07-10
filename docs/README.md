# Documentation Map

This directory is the repo-first knowledge base for Slipstream. Keep user-facing
setup in the root README files; keep engineering decisions, investigations, and
support notes here.

## Start Here

| Need | Read |
|---|---|
| Current implementation order | [ROADMAP.md](ROADMAP.md) |
| Active routing invariants and decisions | [DECISIONS.md](DECISIONS.md) |
| Operational checks and repeated user symptoms | [TROUBLESHOOTING.md](TROUBLESHOOTING.md) |
| Resilience model and known limits | [RESILIENCE.md](RESILIENCE.md) |
| Routing research and external repo findings | [ROUTING_RESEARCH.md](ROUTING_RESEARCH.md) |
| Icon and visual identity brief | [ICON_BRIEF.md](ICON_BRIEF.md) |
| Bundled component licenses | [../THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) |
| Agent workflow notes | [../AGENTS.md](../AGENTS.md) |
| Older implementation plans and specs | [plans/](plans/) and [specs/](specs/) |

## Knowledge Capture Rules

- Put stable project decisions in [DECISIONS.md](DECISIONS.md).
- Put routing investigations, external repo findings, and network-behavior notes
  in [ROUTING_RESEARCH.md](ROUTING_RESEARCH.md).
- Put repeated support symptoms and concrete checks in
  [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
- Put roadmap changes in [ROADMAP.md](ROADMAP.md), not in research notes.
- Keep root README files short and user-facing.

## Agent Memory Policy

Repo docs are the source of truth for project knowledge. Codex memory should only
store durable user preferences, cross-session working rules, and critical
invariants that help an agent find the right repo doc. Do not duplicate long
investigations in memory.
