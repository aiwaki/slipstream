# Python daemon

This directory contains the macOS routing daemon, its pure policy and recovery
modules, packaging configuration, tests, and archived network experiments.

| Path | Purpose |
|---|---|
| `tproxy.py` | Packaged daemon entry point and connection orchestration. |
| `routing_policy.py` | Route classification without system side effects. |
| `routing_recovery.py` | Recovery reducer and safe action selection. |
| `connection_*.py`, `route_circuit*.py` | Connection attempts, racing, and bounded circuit state. |
| `geph_backend.py`, `pf_adapter.py` | Owned Geph and private PF-anchor adapters. |
| `slipstreamd.spec`, `build_daemon.sh` | PyInstaller packaging. |
| `test_*.py` | Unit, contract, and regression tests. |

Setup, safe test commands, and build instructions are in
[`../DEVELOPMENT.md`](../DEVELOPMENT.md). Privileged lifecycle checks belong on
disposable CI runners, not on a primary workstation.

## Archived research

[`VOICEPROBE.md`](VOICEPROBE.md) documents an earlier Discord voice-plane
experiment. It is not part of the current runtime or supported routing policy.
