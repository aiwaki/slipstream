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
cargo test --locked --manifest-path crates/slipstream-userspace-stack-effect-evaluation/Cargo.toml
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
failure-atomic. A second test-only evaluation crate composes that effect
boundary with the selected stack through an in-memory Layer 3 pair; neither
crate is linked into the Windows production host.

## Build

Keep long-lived development and qualification work in a durable checkout, not
in an OS-managed temporary directory. Before replacing an installed app, retain
the exact source revision and any uncommitted diff that produced it. If a prior
worktree disappeared, an older saved branch or graph index is not proof that its
uncommitted tail is present: reconcile that tail before building a replacement.
Record the source, artifact verification result and remaining physical gates in
`docs/CURRENT_STATE.md` and the relevant investigation log.

The app scripts rebuild the self-contained Python daemon with Python 3.13,
stage it into Tauri through a temporary directory, build the final app, and run
the canonical macOS bundle verifier. That verifier checks the complete
fresh/staged/materialized bundle chain, critical binary hashes and
architectures, app identity, helper isolation, routing invariants, and the
ad-hoc signature's integrity. A tray rebuild therefore cannot silently reuse
an older frozen daemon. If `python3.13` is not on `PATH`, set
`SLIPSTREAM_PYTHON_313` to its exact executable path.

A complete local app build also needs the Geph sidecar at:

```text
app-tauri/src-tauri/binaries/geph5-client-aarch64-apple-darwin
```

Use the recorded Geph release contract and the verification sequence in
`.github/workflows/ci.yml` before staging that sidecar; neither the upstream
source crate nor a locally generated audit report substitutes for its binary
attestations. The complete version- and hash-pinned Chromium headless runtime
must also be materialized with
`scripts/materialize_chromium_headless_shell.py` into
`app-tauri/src-tauri/chromium-headless-shell`. The tracked README alone is not a
runtime. Do not use test-only resource overrides for a product build.

Then build the app without updater signing:

```bash
cd app-tauri
npm ci
npm run build:local
```

After installing that exact build, compare the built and installed app trees
and validate the schema-3 install attestation, witness, exact LaunchDaemon
plist, fresh StatusV2 heartbeat, and live `launchctl` PID/program/arguments
without opening the root-only daemon:

```bash
npm run verify:local-install
```

The command binds the attested PID to both StatusV2 and the running launchd
service. Checks that require root access to hash `/usr/local/slipstream`, prove
listener ownership, or inspect kernel PF state remain `not_run`; it does not
silently treat them as passed. The current macOS build is ad-hoc signed and
unnotarized, so this verification does not claim notarization or Gatekeeper
compatibility.

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
