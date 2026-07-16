# Documentation Map

This directory is the repo-first knowledge base for Slipstream. Keep user-facing
setup in the root README files; keep engineering decisions, investigations, and
support notes here.

## Start Here

| Need | Read |
|---|---|
| Local setup, safe tests, and build instructions | [../DEVELOPMENT.md](../DEVELOPMENT.md) |
| System boundaries and data flow | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Contribution workflow | [../CONTRIBUTING.md](../CONTRIBUTING.md) |
| Private vulnerability reporting and security scope | [../SECURITY.md](../SECURITY.md) |
| Current evidence checkpoint and next verified action | [CURRENT_STATE.md](CURRENT_STATE.md) |
| Current implementation order | [ROADMAP.md](ROADMAP.md) |
| Active routing invariants and decisions | [DECISIONS.md](DECISIONS.md) |
| Operational checks and repeated user symptoms | [TROUBLESHOOTING.md](TROUBLESHOOTING.md) |
| Resilience model and known limits | [RESILIENCE.md](RESILIENCE.md) |
| Release channels, tags, and artifacts | [RELEASES.md](RELEASES.md) |
| Deterministic data-plane regression gate | [TRAFFIC_CONTRACTS.md](TRAFFIC_CONTRACTS.md) |
| Language-neutral routing and recovery contracts | [../contracts/README.md](../contracts/README.md) |
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
- Keep the compaction/resume checkpoint in
  [CURRENT_STATE.md](CURRENT_STATE.md); update it whenever a PR changes the
  verified next action or milestone status.
- Keep root README files short and user-facing.
- Review `README.md`, `README.en.md`, repository About/topics, and the Releases
  page together for every tagged app release and whenever installation,
  platform support, or user-visible routing behavior changes. Avoid
  version-specific churn when a stable description is enough.

## Agent Memory Policy

Repo docs are the source of truth for project knowledge. Codex memory should only
store durable user preferences, cross-session working rules, and critical
invariants that help an agent find the right repo doc. Do not duplicate long
investigations in memory.
