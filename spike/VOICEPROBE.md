# voiceprobe — archived Discord voice experiment

> [!CAUTION]
> Archived research only. This tool is not part of the current runtime,
> supported routing policy, or developer onboarding. Run it only on a disposable
> lab machine after reviewing the source.

Validates: on macOS, entitlement-free, can we observe Discord voice UDP (libpcap)
and inject low-TTL fake primes on the same 5-tuple (raw/L3 send) to unblock voice
on a DPI-throttled network, without touching Discord's own socket?

This document preserves the original experiment and its validation criteria; it
does not describe a current implementation commitment.

## Setup
```bash
cd slipstream/spike
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Unit tests (no root, no network)
```bash
pytest -v
```

## Run (needs root; scapy uses libpcap)
```bash
sudo .venv/bin/python voiceprobe.py selftest --iface en0
sudo .venv/bin/python voiceprobe.py capture  --iface en0   # join a Discord call
sudo .venv/bin/python voiceprobe.py live     --iface en0   # join a call; voice must be blocked otherwise
```
Find your interface with `route get default | grep interface`.

## Safety
This tool ONLY sniffs and emits extra decoy UDP datagrams. It does NOT modify pf,
routes, DNS, or Discord's sockets. Ctrl-C stops it instantly; nothing persists.
Blast radius is minimal — that is why this is the first step.

## Pass/Fail
- selftest PASS: injected fake observed leaving the iface with ttl=4 and the exact
  5-tuple we set.
- capture PASS: we see and correctly classify (stun / ip-discovery / rtp) outbound
  voice datagrams during a call.
- live PASS: with voice otherwise blocked, running `live` lets a Discord call
  connect and you hear other people.
- live FAIL: voice still dead → pivot voice plane to the utun fallback (spec §3).
