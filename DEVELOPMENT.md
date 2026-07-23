# Development

This guide covers local setup, unprivileged checks, and the build path for
Slipstream. Product behavior and routing decisions are documented in
[`docs/`](docs/README.md).

## Safety boundary

Slipstream's installed daemon changes privileged macOS networking state. The
local checks below do not install the daemon or modify PF, DNS, proxy, PAC, or
VPN settings.

Run PF, installed-daemon, and packaged-app lifecycle checks only on a disposable
macOS runner or test machine. Do not run daemon `--install`, `sudo` PF commands,
or lifecycle scripts on a primary workstation.

## Requirements

- macOS Apple Silicon for the complete app bundle
- Rust stable
- Node.js LTS and npm
- Python 3.13
- Xcode command-line tools

## Setup

Run the commands in this guide from the repository root unless a section says
otherwise.

```bash
python3 -m venv spike/.venv
spike/.venv/bin/python -m pip install \
  --only-binary=:all: \
  --require-hashes \
  -r spike/requirements.txt

cd app-tauri
npm ci
cd ..
```

Python dependency locks target Python 3.13. Runtime, test, and build graphs are
kept separate. To update them after editing the corresponding
`requirements-*.in` files:

```bash
PYTHON=python3.13 scripts/update_python_locks.sh
```

The update command uses pinned `pip-tools`; all three generated lock files must
be reviewed in the same change.

## Safe local checks

These checks do not require root access or modify system network state:

```bash
spike/.venv/bin/python -m pytest spike scripts -q
python3 scripts/sync_version.py --check
```

```bash
cd app-tauri/src-tauri
cargo test
```

```bash
cargo test --locked --manifest-path crates/slipstream-core/Cargo.toml
cargo test --locked --manifest-path crates/slipstream-windows-adapter/Cargo.toml
cargo test --locked --manifest-path crates/slipstream-userspace-stack-evaluation/Cargo.toml
```

The Python suite includes the language-neutral routing and recovery vectors in
[`contracts/`](contracts/README.md). Rust reads the same vectors. The userspace
stack evaluation is effect-free and does not load Wintun, open native sockets,
or mutate adapter, route, DNS, proxy, PAC, VPN, process, or service state. The
Windows adapter tests also keep capture-v4 source evidence and the pure
userspace-flow binding plus bounded payload ownership outside the production
service host. Payload staging requires the exact current packet-flow
predecessor and resulting queue delta; cleanup uses the same causal snapshot
rather than timestamp ordering. Payload effects are injected and
failure-atomic; the selected stack is still instantiated only in its separate
evaluation crate.

## Build

Build the self-contained Python daemon first:

```bash
cd spike
./build_daemon.sh
cd ..
rm -rf app-tauri/src-tauri/slipstreamd
cp -R spike/dist/slipstreamd app-tauri/src-tauri/slipstreamd
```

A complete local app build also needs the Geph sidecar at:

```text
app-tauri/src-tauri/binaries/geph5-client-aarch64-apple-darwin
```

Then build the app without updater signing:

```bash
cd app-tauri
npm ci
npm run build:local
```

Release builds use `npm run build:release` and require the updater signing
environment. The bundled Geph client is built by
[`build-geph.yml`](.github/workflows/build-geph.yml). Release tag namespaces,
channels, and published artifact contracts are documented in
[`docs/RELEASES.md`](docs/RELEASES.md).

## Privileged qualification

The main CI workflow runs the privileged checks on disposable GitHub-hosted
macOS runners:

| Gate | Source |
|---|---|
| Private PF anchor sentinel | [`scripts/pf_anchor_smoke.py`](scripts/pf_anchor_smoke.py) |
| Installed daemon lifecycle | [`scripts/pf_installed_lifecycle_smoke.py`](scripts/pf_installed_lifecycle_smoke.py) |
| Packaged app, tray crash, Chrome, and Safari lifecycle | [`.github/workflows/ci.yml`](.github/workflows/ci.yml) |

These gates require `SLIPSTREAM_DISPOSABLE_CI=1` where applicable. That marker is
a safety contract, not a convenience flag for a development machine.

## Documentation changes

- Update `README.md` and `README.en.md` together when installation, platform
  support, or user-visible routing behavior changes.
- Record stable decisions in [`docs/DECISIONS.md`](docs/DECISIONS.md).
- Record routing investigations in
  [`docs/ROUTING_RESEARCH.md`](docs/ROUTING_RESEARCH.md).
- Record repeated symptoms and checks in
  [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md).
