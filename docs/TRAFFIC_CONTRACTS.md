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
scripted adapters perform no network I/O. The Python adapter in
`spike/connection_race_io.py` translates the same commands into owned async
tasks and is tested with loopback sockets for usable winner transfer, address
fallback, loser cleanup, deadline cancellation, caller cancellation, and
pre-I/O circuit rejection.

`spike/connection_probe.py` is the only production boundary from the
transparent handler into that adapter. It receives numeric addresses and an
already-selected service group, route class, backend, and complete
first-payload dialer. The race therefore chooses only an address inside one
route; it cannot choose Geph or a different strategy. A TCP connect alone is
not success: the candidate must return first server bytes. Handler contracts
cover stalled-first/healthy-second Discord and Smart DNS edges and forbid Geph
in the local case.

## Windows Data Plane V1

`contracts/windows-data-plane-v1.json` freezes the equivalent Windows boundary
before a native connector exists. A request already contains the normalized
policy result and selected backend; the worker validates that tuple before
emitting `StartSession`, so the adapter cannot silently turn local bypass into
Geph or promote unknown traffic to geo exit. Discord and YouTube mismatches are
explicit rejection vectors.

First payload is a readiness signal, not a claim that a streaming response
completed. It releases a half-open readiness gate while the session continues
relaying; a later reset after partial bytes records one normalized `stream`
failure. Stalls before payload record `first_payload`. Caller and shutdown
cancellation do not manufacture backend failures. The fake effect owns every
resource until cancellation acknowledgement or a bounded deadline, closes it
once before recording an outcome, and ignores late completions after terminal
state. Monotonic session IDs protect a reused external request ID from stale
events, and deterministic terminal pruning bounds long-lived worker state.
These vectors contain no socket, native API, or host mutation.

`contracts/route-circuit-registry-v1.json` covers the bounded state above those
request-local races. Production records one result only after a complete
protected local ladder, a proven Smart DNS attempt, or a verified owned Geph
attempt. Tests prove that individual desync failures do not open the local
circuit, Smart DNS suppression still permits the separately keyed owned-Geph
candidate, an owned-Geph half-open permit is released on the first payload of a
still-live WebSocket, and unknown hosts neither persist state nor acquire a Geph
edge.
