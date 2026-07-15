# Architecture

Slipstream separates routing decisions from platform-specific interception and
process ownership. The current product adapter targets macOS Apple Silicon.

## Components

| Component | Responsibility |
|---|---|
| Tauri tray | User settings, status, diagnostics, updates, and installation orchestration |
| Python daemon | Connection classification, route selection, health reduction, recovery, and macOS data plane |
| Private PF anchor | Scoped TCP interception owned only by Slipstream |
| Local bypass engine | DPI-oriented strategies that preserve the user's external IP |
| Owned Geph sidecar | Foreign exit for explicitly classified geo-exit services |
| Telegram proxy | Local proxy offered when Telegram cannot connect directly |
| JSON contracts | Shared policy and recovery vectors consumed by Python and Rust tests |

The tray is not part of the packet path. A tray crash must not change routing
ownership, and daemon recovery must not depend on a visible menu-bar process.

## Route Model

| Route | Backend rule |
|---|---|
| `direct_passthrough` | Connect without Slipstream bypassing |
| `local_bypass` | Use local DPI handling; never promote Discord or YouTube to Geph |
| `geo_exit` | Use only a verified owned Geph process; never substitute an external process |
| `unknown` | Collect bounded evidence before changing policy |

External DNS, proxy, PAC, and VPN configuration is observed only. Slipstream
does not rewrite or disable user-managed network settings.

## Contracts And Adapters

Policy classification and recovery decisions are represented as language-neutral
fixtures in [`contracts/`](../contracts/README.md). Platform adapters own socket,
process, firewall, and lifecycle calls. This boundary allows future Windows,
Android, Linux, and feasibility-gated iOS adapters to reuse policy behavior
without copying macOS PF logic.

Operational invariants live in [DECISIONS.md](DECISIONS.md), failure behavior in
[RESILIENCE.md](RESILIENCE.md), and the implementation sequence in
[ROADMAP.md](ROADMAP.md).
