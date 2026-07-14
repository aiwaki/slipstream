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
| ChatGPT WebSocket | Geo exit | Fresh Smart DNS proof, otherwise owned Geph | Local desync/direct |
| Steam Store | Geo exit | Owned Geph | Local desync/direct |
| Telegram raw MTProto DC | Safety passthrough | Plain direct TCP | Local desync/Geph |
| Telegram Desktop in a blocked network | Local proxy | Bundled `tg-ws-proxy` | A direct-connect guarantee |
| Generic HTTPS host | Unknown | Local adaptive ladder | Geph |
| Geo backend unavailable | Geo exit | Pause only Slipstream's PF anchor | Local fallback |

These are representatives of routing **classes and service groups**, not a
manual list of every website. A new host normally belongs to an existing
contract. Add a new contract only when it introduces a distinct route class,
backend, payload shape, or safety rule.

Smart DNS is a read-only, user-managed resolver path. For OpenAI and Anthropic,
Slipstream may use it first only after the resolver has passed a fresh payload
canary. A runtime miss falls back to owned Geph only when that backend is
verified ready; otherwise the existing geo fail-closed path pauses only
Slipstream's private PF anchor for the native retry. It never falls into local
desync, and Slipstream never changes the system DNS configuration.

Raw Telegram MTProto passthrough is defensive: the transparent handler does not
corrupt a protocol it cannot classify. It is not a claim that Telegram can
connect directly from every Russian network; the bundled local `tg-ws-proxy` is
the supported connection path when direct MTProto is blocked.

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

## Resolver And Connector Contract

`contracts/connection-race-v1.json` covers the layer below route selection and
above platform sockets. Python and Rust execute the same scripted resolver and
connector scenarios: IPv6 stall with IPv4 fallback, immediate failure release,
shared deadlines, circuit isolation, half-open recovery, and protected-route
rejection before DNS. They also deliver the deadline wake before an
exact-deadline success to prove that queue order cannot turn that success into a
timeout, while rejecting a success timestamped after the deadline. These
adapters perform no network I/O. A later runtime adapter must translate the same
commands and events without changing their ordering or circuit-accounting
semantics.
