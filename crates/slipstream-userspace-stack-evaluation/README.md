# Userspace Stack Evaluation

This crate qualifies a pinned userspace IPv4/IPv6 TCP/UDP stack behind an
in-memory Layer 3 device. It is deliberately separate from
`slipstream-windows-adapter` and is not linked into the Windows service host.

Version 1 selects `smoltcp 0.13.1` for bounded evaluation. The tests prove
dual-stack TCP, UDP below the IPv6 MTU, IPv4 fragmentation and reassembly,
dual-stack UDP checksum rejection, deterministic polling, and fixed queue and
buffer limits. They also freeze the candidate's current inability to emit
oversized IPv6 datagrams: that path drops without an L3 frame and remains
ineligible for production composition.

The selected stack also does not natively reassemble IPv6 Fragment Header
input. An additive, effect-free pre-stack v1 normalizer now qualifies exact
in-order and out-of-order reconstruction with fixed assembly, payload,
fragment-count, and timeout bounds. Overlap, conflicting headers or sizes,
unsupported extension chains, and capacity exhaustion fail closed. RFC 6946
atomic fragments are reconstructed without allocating or touching reassembly
state. A completed packet reaches the selected UDP stack with its original
source endpoint; the normalizer is not composed into Windows capture or the
production service host.

The corresponding language-neutral contracts are
[`windows-userspace-stack-selection-v1.json`](../../contracts/windows-userspace-stack-selection-v1.json)
and
[`windows-userspace-stack-ipv6-fragment-input-v1.json`](../../contracts/windows-userspace-stack-ipv6-fragment-input-v1.json).

```sh
cargo test --locked --manifest-path crates/slipstream-userspace-stack-evaluation/Cargo.toml
cargo clippy --locked --manifest-path crates/slipstream-userspace-stack-evaluation/Cargo.toml --all-targets -- -D warnings
```
