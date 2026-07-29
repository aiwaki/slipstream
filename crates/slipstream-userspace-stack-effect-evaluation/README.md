# Userspace Stack Effect Evaluation

This crate qualifies two additive boundaries outside the production host:

- Windows userspace byte-owner v1 to the pinned `smoltcp 0.13.1` candidate,
  using a deterministic in-memory Layer 3 pair;
- byte-owner v1 to a bounded native connector queue, using numeric loopback
  sockets only.

Selected-stack version 1 proves IPv4 and IPv6 TCP/UDP delivery in both
directions, exact tuple and flow-identity use, payload preservation, and retry
after a pre-mutation injected failure. The native connector contract proves an
atomic byte-owner handoff, exact retained TCP suffixes after partial writes,
failure-before-progress retention, one exact UDP datagram, and backend identity
revalidation before every native write. Discord and YouTube cannot select Geph,
and Geph cannot accept UDP at this boundary.

```bash
cargo test --locked --manifest-path crates/slipstream-userspace-stack-effect-evaluation/Cargo.toml
cargo clippy --locked --manifest-path crates/slipstream-userspace-stack-effect-evaluation/Cargo.toml --all-targets -- -D warnings
```

The frozen language-neutral selected-stack contract is
[`contracts/windows-userspace-stack-effect-v1.json`](../../contracts/windows-userspace-stack-effect-v1.json).
The additive
[`contracts/windows-capture-fragment-effect-v1.json`](../../contracts/windows-capture-fragment-effect-v1.json)
contract composes capture v4 classification with bounded IPv6 fragment input
only in this test crate. Retained assemblies are owned by one exact capture
generation and flow, expire no later than their five-second capture evidence,
and cannot blend or evict a same-identification assembly from another flow.
The additive
[`contracts/windows-userspace-native-connector-effect-v1.json`](../../contracts/windows-userspace-native-connector-effect-v1.json)
contract freezes the connector queue and numeric-loopback evidence. Passing
these gates does not admit the selected stack or connector into the Windows
production host. Selected-stack composition, backend reads, and disposable
AMD64/ARM64 packet-flow qualification remain separate gates.
