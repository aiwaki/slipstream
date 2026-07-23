# Userspace Stack Effect Evaluation

This crate qualifies the boundary between Windows userspace byte-owner v1 and
the pinned `smoltcp 0.13.1` candidate. Both are test-only dependencies. The
adapter enqueues an exact borrowed payload into a deterministic in-memory stack;
no Wintun, native socket, route, DNS, proxy, PAC, VPN, process, service, or
production-host effect is available.

Version 1 proves IPv4 and IPv6 TCP/UDP delivery in both directions, exact tuple
and flow-identity use, payload preservation, and retry after a pre-mutation
injected failure. A failed effect leaves the byte owner and selected stack
unchanged.

```bash
cargo test --locked --manifest-path crates/slipstream-userspace-stack-effect-evaluation/Cargo.toml
cargo clippy --locked --manifest-path crates/slipstream-userspace-stack-effect-evaluation/Cargo.toml --all-targets -- -D warnings
```

The frozen language-neutral contract is
[`contracts/windows-userspace-stack-effect-v1.json`](../../contracts/windows-userspace-stack-effect-v1.json).
Passing this gate does not admit the selected stack into the Windows production
host. Native packet effects, IPv6 fragment input, and disposable AMD64/ARM64
lifecycle qualification remain separate gates.
