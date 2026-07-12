# Traffic Contracts

Traffic contracts are the deterministic data-plane gate for routing changes.
They ensure that a named user journey selects the intended backend, never
selects a prohibited backend, and delivers both its first and later response
bytes through the real daemon connection handler.

## What Runs

The test harness enters `tproxy._handle_impl` with:

- a fixed, parseable TLS first-flight fixture, so SNI parsing is real rather
  than mocked;
- a fake PF original destination;
- a deterministic DNS result when the local route needs one;
- in-process local, Geph SOCKS, or direct upstream endpoints.

The policy lookup, route-class selection, first-payload forwarding, and relay
logic are production code. The harness never opens a network connection,
changes PF, or reads or writes system DNS/proxy/VPN state.

## Core Matrix

| Journey | Expected class | Required backend | Must never use |
|---|---|---|---|
| Discord updater | Local bypass | Local fake/desync | Geph |
| YouTube web/video entry | Local bypass | Local fake/desync | Geph |
| ChatGPT WebSocket | Geo exit | Owned Geph | Local desync/direct |
| Steam Store | Geo exit | Owned Geph | Local desync/direct |
| Telegram MTProto DC | Direct | Plain direct TCP | Local desync/Geph |
| Generic HTTPS host | Unknown | Local adaptive ladder | Geph |
| Geo backend unavailable | Geo exit | Pause only Slipstream's PF anchor | Local fallback |

These are representatives of routing **classes and service groups**, not a
manual list of every website. A new host normally belongs to an existing
contract. Add a new contract only when it introduces a distinct route class,
backend, payload shape, or safety rule.

## Incident Rule

Before changing routing after an incident, add or extend a contract that
reproduces the user-visible path. It must use the real handler and assert the
backend that is forbidden as well as the one that is required. Only then is a
runtime patch eligible for a preview build.

## Boundaries

A passing contract proves Slipstream's deterministic decision and relay path;
it does not prove a remote provider is currently available or that a particular
browser version has no independent issue. PF ownership, installer lifecycle,
and live endpoint health remain separate CI and release gates.
