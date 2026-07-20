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
around native connectors. A request already contains the normalized
policy result and selected backend, but that metadata is not trusted. The worker
reclassifies the host through the active validated policy tables and validates
the complete tuple before emitting `StartSession`, so a caller cannot hide a
Discord or YouTube host behind `generic`, silently turn local bypass into Geph,
or promote unknown traffic to geo exit. Those mismatches are explicit rejection
vectors.

First payload is a readiness signal, not a claim that a streaming response
completed. It releases a half-open readiness gate while the session continues
relaying; a later reset after partial bytes records one normalized `stream`
failure. Stalls before payload record `first_payload`. Caller and shutdown
cancellation do not manufacture backend failures. The fake effect owns every
resource until cancellation acknowledgement or a bounded deadline, closes it
once before recording an outcome, and ignores late completions after terminal
state. Monotonic session IDs protect a reused external request ID from stale
events, and deterministic terminal pruning bounds long-lived worker state.
Each individual effect command is failure-atomic. Reducer state commits only
after the entire command batch succeeds; an interrupted batch returns the exact
cursor needed to resume without replaying a completed start or close. These
vectors contain no socket, native API, or host mutation.

`contracts/windows-worker-host-v1.json` composes this reducer with the pure SCM
host lifecycle. Worker readiness is recorded before `RUNNING`; `STOP_PENDING`
precedes cancellation; and `ReportWorkerStopped` precedes `STOPPED`.
Deterministic vectors cover startup failure, cancellation acknowledgement,
forced shutdown deadline, late backend completion after forced close, repeated
stop, and effect recovery without replaying the completed command prefix. The
production Windows host consumes the same composition with a no-network effect,
so SCM lifecycle qualification still admits no user traffic by itself.

`contracts/windows-direct-connector-v1.json` admits exactly one socket class:
direct TCP to an already-selected numeric IPv4 or IPv6 endpoint. Creation of
its opaque plan repeats active-policy admission and rejects non-direct backends,
including protected local-bypass and geo-exit traffic. It cannot resolve a
hostname, select another route, or inspect or mutate DNS, proxy, PAC, or VPN
state. Buffers, queues, connect time, and first-payload time are bounded; every
event retains the reducer-issued session identity. Disposable loopback tests
cover real connect, first payload through the reducer/effect chain, reset after
partial payload, caller cancellation, first-payload deadline, and shutdown.
The production host remains no-network until a later ingress boundary can
supply both trusted numeric endpoint evidence and an adapter-owned client
stream.

`contracts/windows-direct-ingress-v1.json` freezes that ownership boundary
without choosing a Windows interception technology. One non-cloneable accepted
client stream is bound to fresh `original_destination` evidence, the exact
reducer-issued session and request IDs, and the same numeric endpoint admitted
by connector v1. Preloaded connector bytes are rejected: every upstream byte
must be read from the owned client. A backend payload event is withheld until
the complete chunk has been written to the client, so first-payload health
cannot be proven by bytes that are only queued inside the adapter. The
first-payload deadline remains active until that delivery completes.

Both relay directions use fixed-size reads, bounded channels and internal
queues, bounded closed-cancellation bookkeeping, and explicit no-progress
backpressure deadlines. A client-first EOF, read failure, or downstream write
stall becomes cancellation and records no invented backend failure. An upstream
write stall is a normalized backend reset. Deterministic relay-state tests
qualify the exact first-delivery and no-progress boundaries without depending
on platform TCP buffers; native loopback qualification proves the actual owned
relay, reset, cancellation, first-payload delivery, and shutdown paths.

`contracts/windows-capture-source-v1.json` freezes the separate source above
that relay without embedding WFP, WinDivert, or any other interception
technology in the frozen reducer. A native adapter stages one accepted stream
under an opaque one-shot resource ID and reports only its canonical numeric
original destination. The reducer allocates a monotonic connection ID and
offers that evidence to an external admission authority; it does not derive a
hostname, classify policy, or select a backend. Only a separately granted
direct connector request can be rebound to the fresh evidence and handed to
direct ingress.

The source owns every stream until the handoff effect succeeds. A failed
handoff is failure-atomic and leaves the exact resource available for retry or
explicit compensation. Admission cannot rebase an already-expired connector or
first-payload deadline, and a duplicate resource token cannot close or replace
the tracked stream. Invalid, rejected, expired, startup-racing, and
shutdown-racing captures close exactly once. Stop first prevents new admission,
then closes all unhanded streams and reaches terminal state through a bounded
source-stop deadline. Effect batches expose an exact resume cursor, IDs are
monotonic, retained terminal evidence is bounded, and late events cannot
resurrect the source. The production SCM host does not compose this module and
therefore remains no-network while a native capture implementation is still
absent.

`contracts/windows-packet-adapter-v1.json` freezes the active no-own-driver
packet boundary. It admits only exact evidence for the pinned official signed
Wintun 0.14.1 AMD64/ARM64 artifacts and prepares only fresh policy-bound public
exact `/32` or `/128` candidates for `local_bypass` or `geo_exit`. Protected
hosts are reclassified through the active tables. Resolver evidence binds one
canonical host to its observed address set, and the selected destination must
belong to that set. The evidence type is opaque and non-deserializable. IPv6
candidates are conservatively limited to reviewed
global-unicast space and exclude IANA special-purpose ranges. A separate pure
admission requires a complete collector-owned binding snapshot for the exact
destination. The candidate host must occur in a bounded canonical sorted set,
and every host in that set must reclassify to the same route class and strategy.
Partial DNS observations, stale evidence, and shared direct/local/geo
destinations fail closed. The admission is generation-bound and expires at the
earlier evidence deadline. It is not native route authorization. The complete-
DNS premise was rejected after feasibility review, so v1 is frozen and no
native issuer or route effect may be built from it. The pure contract cannot
load a DLL, create an adapter, install a route, change the default route, or
touch system DNS, proxy, PAC, VPN, or production traffic.

Wintun exposes L3 packets rather than the accepted TCP stream expected by
direct-ingress and capture-source v1. A separately versioned capture-only
contract must reclassify each flow from bounded in-band evidence and preserve
direct passthrough when hostname evidence is missing or opaque. Only after its
loop, activation, expiry, and coexistence gates pass may a reviewed userspace
packet stack and backend bridge be considered; the stream contracts are not
silently reused as packet ownership proof.

`contracts/windows-packet-capture-v2.json` now freezes that pure classifier.
Each observation binds a nonzero capture generation and flow ID to a canonical
public destination and a five-second evidence window. TLS flows accept only
ClientHello SNI evidence and QUIC flows accept only Initial SNI evidence. The
hostname is normalized and reclassified through the active shared policy;
`local_bypass` and `geo_exit` are policy results, not backend authorization.
Direct, unknown, ECH, missing, malformed, mismatched, stale, and unsafe cases
all preserve direct passthrough. The module has no DLL, adapter, route, socket,
DNS, proxy, PAC, VPN, or production-host effect. Native work remains blocked on
disposable loop avoidance, activation, bounded removal, rollback, external-VPN,
AMD64, and ARM64 qualification.

The remaining `windows-wfp-*` contracts preserve the superseded own-driver
research path only. `contracts/windows-wfp-capture-v1.json` freezes that WFP
`ALE_CONNECT_REDIRECT_V4/V6` data boundary. A manually encoded 128-byte
context carries explicit magic, version and lengths; TCP family; original
remote and local endpoints; service generation; exact target PID; nonzero
capture-instance ID; and executable SHA-256. IPv4 address slots have mandatory
zero padding, reserved bytes and flags are zero, and unsafe original
destinations are rejected. Wire v1 is append-only; a layout change requires
v2.

The accepted socket must match one exact owned loopback listener and supply
both that context and nonempty bounded opaque redirect records. Generation,
PID, instance and nonzero executable hash must still match the active service
identity, and IPv4-mapped IPv6 destinations receive the same safety checks as
native IPv4. A validated capture also receives the monotonic connection ID
allocated by capture-source v1. Handoff revalidates the complete direct-ingress
request against active policy and requires its exact connection ID and endpoint,
preventing two concurrent connections to one address from exchanging an
admission. The non-cloneable capture preserves ownership after a mismatch. Its
one-shot socket-preparation boundary exposes redirect records before it exposes
the opaque ingress/connect plan, modeling the required records-before-bind or
connect order without invoking Winsock. Direct connector v1 remains frozen. The
production host still imports none of this module, and the WFP engine, callout,
filters, driver and sockets remain future native effects.

`contracts/windows-wfp-runtime-v1.json` freezes the ordering around those
future effects without implementing them. One exact service/capture identity
and reducer-issued monotonic runtime generation own each attempt. Kernel
classify callouts register first, exact V4/V6 loopback listeners become ready
second, and a single failure-atomic command may then commit the non-persistent
provider, sublayer, management callouts, provider context and filters in one
dynamic engine transaction.

An ordinary stop or runtime fault emits dynamic-session close as its only first
effect. Exact filter inspection follows the close acknowledgement. Listener
stop, accepted-stream drain and kernel-callout unregister cannot be reached
until both owned filters are absent. If either remains, the safety listener and
kernel callouts stay live and only a bounded recheck is scheduled. Once filters
are absent, listeners stop before a bounded stream drain; a drain deadline
force-closes the exact retained stream IDs before unregister. A stream accepted
above the configured bound receives an exact retryable reject effect and never
enters reducer state. Multi-command effects resume from an exact cursor. Stale
service generations, capture instances, runtime attempts, session generations
and timers are rejected. The module calls no WFP, Winsock, driver, DNS, proxy,
PAC or VPN API and remains absent from the production SCM host.

`contracts/route-circuit-registry-v1.json` covers the bounded state above those
request-local races. Production records one result only after a complete
protected local ladder, a proven Smart DNS attempt, or a verified owned Geph
attempt. Tests prove that individual desync failures do not open the local
circuit, Smart DNS suppression still permits the separately keyed owned-Geph
candidate, an owned-Geph half-open permit is released on the first payload of a
still-live WebSocket, and unknown hosts neither persist state nor acquire a Geph
edge.
