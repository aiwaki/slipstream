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

The corresponding language-neutral contract is
[`windows-userspace-stack-selection-v1.json`](../../contracts/windows-userspace-stack-selection-v1.json).

```sh
cargo test --locked --manifest-path crates/slipstream-userspace-stack-evaluation/Cargo.toml
cargo clippy --locked --manifest-path crates/slipstream-userspace-stack-evaluation/Cargo.toml --all-targets -- -D warnings
```
