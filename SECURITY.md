# Security Policy

Slipstream manages privileged network routing, a private PF anchor, and owned
sidecar processes. Please report security issues privately through
[GitHub Security Advisories](https://github.com/aiwaki/slipstream/security/advisories/new).
Do not open a public issue for an unpatched vulnerability.

## Scope

Security-sensitive areas include:

- PF ownership, recovery, install, update, and uninstall behavior;
- privileged daemon and tray boundaries;
- owned Geph identity, credentials, listeners, and process lifecycle;
- update, release, artifact, and policy signature verification;
- diagnostics redaction and secret-bearing files.

Include the Slipstream version, macOS version, reproduction steps, expected and
observed behavior, and sanitized diagnostics when available. Remove account
secrets, tokens, hostnames, and other private data before attaching files.

Supported installation targets are identified in the root README and their
release notes. Archived releases are retained for traceability but do not
receive fixes.
