# Slipstream — Icon Brief

For a designer / Claude design. We need **two** icons.

## What Slipstream is
A native macOS **menu-bar app** that quietly bypasses DPI censorship (TSPU) so
Discord, YouTube and other blocked sites work again — no VPN, automatic, calm.
Core technique: splitting/fragmenting the TLS handshake so the censor can't read
it. Name "Slipstream" = the low-drag draft behind a moving object; here it's
traffic *slipping through* the wall.

## Personality
Apple-grade, calm, confident, minimal. Geometric, single concept, instantly
readable. Not edgy/hacker, not loud. Think Things / Bear / Tailscale tray icons.

## Deliverable 1 — Menu-bar (status) glyph
- **Template image** (monochrome, tint-adaptive — macOS recolors it for light/
  dark/active). No color, no gradients. Single line weight.
- Crisp at **16–18 pt** (so ~36px @2x). Must read at tiny size.
- Three states (same glyph, different fill/treatment):
  - **Active** — energized/filled (bypass running)
  - **Dormant** — muted (a VPN is up; we step aside) — e.g. a moon/zzz variant
  - **Off** — outline or slashed
- Format: SVG + a 1x/2x PDF or PNG set, plus optionally an SF-Symbols-style
  single-path glyph.

## Deliverable 2 — App icon (Dock/DMG/Finder)
- Full color, **1024×1024**, macOS rounded-square (squircle) with subtle depth,
  per Apple HIG. A small set of sizes for `.icns` (16…1024).
- Same concept as the glyph, richer.

## Concept (recommended)
**"The slip."** A clean horizontal *current/flow line* that **splits into two**
and slips past a vertical **barrier** (the censorship wall). The split nods
directly to our TLS-record fragmentation; the flow continuing past the wall = the
bypass. Minimal, geometric, one idea.
- Menu-bar glyph: just the splitting flow line passing a thin bar.
- App icon: the same, with a soft aurora/gradient backdrop (cool blues/teal),
  the flow line crisp white.

## Alternatives (if "the slip" doesn't land)
1. **Paper plane / arrow** slipping through a narrow gap in a wall.
2. **Double chevron »** that bends/flows around a bar — speed + passing-through.
3. **Keyhole of light** — a gap in a wall with a beam through it.
4. **Fish through a net** — slipping past (more playful).

## Palette (app icon)
Cool, calm, modern: teal→blue aurora, white/near-white glyph. Avoid red/alarm
colors. The menu-bar glyph stays monochrome (template).

## Name lockup (optional)
Wordmark "Slipstream" in SF Pro / a clean geometric sans, lowercase ok.
