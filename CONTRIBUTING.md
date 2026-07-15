# Contributing

Slipstream is still owner-driven, but focused bug reports and pull requests are
welcome.

## Before Changing Code

1. Read [DEVELOPMENT.md](DEVELOPMENT.md) for setup and safe local checks.
2. Read [docs/DECISIONS.md](docs/DECISIONS.md) before changing routing, PF,
   Geph, DNS, proxy, PAC, VPN, update, or uninstall behavior.
3. Use a public issue for reproducible bugs and design discussion. Report
   vulnerabilities through [SECURITY.md](SECURITY.md), not a public issue.

## Pull Requests

- Keep one behavioral concern per PR and explain the user-visible effect.
- Add focused tests for changed policy, recovery, lifecycle, or release logic.
- Run the safe local checks documented in
  [DEVELOPMENT.md](DEVELOPMENT.md#safe-local-checks).
- Leave privileged PF and packaged lifecycle qualification to disposable CI.
- Update `README.md` and `README.en.md` together when public behavior changes.
- Record durable routing decisions and recurring symptoms in the appropriate
  document under [docs/](docs/README.md).

Do not install or re-arm the privileged daemon on a primary workstation to
qualify a contribution.
