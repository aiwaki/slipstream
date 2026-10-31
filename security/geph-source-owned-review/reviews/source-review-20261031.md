# Fresh bounded RSA source review — 2026-10-31

**No new confirmed source defect was found in the reviewed scope. This report does not admit a release.**

The review binds SOURCE `69d5de39654dea018075469d20ea7892cc35f5af0466d19a7811ef3316b60df7` and Cargo.lock `560504e697c28f2114ec16414e5dc372e1903df986ba36792aab9a12c34631cb` (revision 4). It is a fresh manual review of the three embedded packages and the production auth/bandwidth call paths. No builds, tests, scanners, account requests, native processes or browser probes were run.

## Exact source and lock binding

All 20 embedded file bodies and all 16 source edits match retained candidate `a94d4c1d0263963f1ad8461f8f9705c64acc524e4b31588353821a18bef7d0e9`. The only SOURCE changes are `release_revision` and `lock_sha256`. The new lock replaces exactly four package blocks: rustls 0.23.45 → 0.23.46, rustls-webpki 0.103.15 → 0.103.16, webpki-roots 1.0.9 → 1.0.10, and ctutils 0.4.3 → 0.4.4. Every new block equals the corresponding C6 block; other records are unchanged. `rsa` and `blind-rsa-signatures` are absent. These are static identity checks, not Cargo/build proof.

## Per-package findings

| Package | Fresh source conclusion |
|---|---|
| `slipstream-rsa-client` | No concrete new FFI ownership defect found. Bn/Ctx/Mont/Rsa have RAII ownership; borrowed n/e stay under the owning key. Native handles do not cross await. OwnedPending contains owned bytes, cannot be cloned or serialized, and is consumed during finalization. Error paths do not publish partial signatures. |
| `mizaru2-slipstream-client` | No new protocol-authentication or serialization defect found. DER/signature/Merkle bounds apply to decoding and direct DTO use. Expected epoch, configured root and exact response DER are checked before credential publication; response mathematical key must match the pending operation. Invalid configured roots do not silently fall back to None. |
| `geph5-broker-protocol` | No new runtime adaptation defect found. Five Rust files are identical to retained upstream; the other two retain identical runtime prefixes and remove only terminal cfg(test) modules. RPC signatures remain unchanged; the manifest selects the source-owned client adapter. |

In auth, a random token precedes retrieval of the untrusted issuer key. The request-selected Plus/Free root, epoch and signature are checked before `db_write`. Bandwidth tokens are written only after successful unblind with the original configured key. A scoped search found no old RustCrypto RSA imports or RSA private-key generation/signing paths in the candidate's production Rust.

The retained auth fix uses `is_plus != currently_plus`. Hash-checked causal evidence contains two old-code failures and three patched passes: expired nonzero Plus status preserves existing Free cache, retires stale Plus cache, and an active upgrade still retires Free cache. The runtime auth copy is identical to the candidate. Tests were not repeated.

## Evidence reused, not re-executed

The JSON report binds all 20 embedded files, the five final edited root files, and 62 small retained evidence files. All hashes matched. The 9.7 MB AWS-LC archive was not rehashed in this review; its retained provenance is not presented as a new archive verification. Historical evidence includes 18 primitive/compatibility, 9 corrected independent compatibility, 6 async, 6 adapter and 11 synthetic actual-callsite checks. Their fixture aggregate differs from the current combined candidate. The invalid earlier wire-envelope run remains excluded.

Pinned AWS-LC API documentation explicitly allows a secret base for `BN_mod_exp_mont`; inversion uses `BN_mod_inverse_blinded`, and native hashing/PSS is reused. This limited API-contract review is not a complete cryptographic assurance claim.

## Boundaries before activation

- **CURRENT_AUDIT**: No current registry or native dependency security admission. Independent fresh CI audit must assess the combined source, lock, enabled features and native AWS-LC/SQLite inventory; old RSA exceptions must not be extended or used.

- **EXPIRED_POLICY**: Retained source-owned policy expired 2026-10-22; retained ancestor OSV data is historical. This fresh manual source review does not renew that policy or establish fresh advisory absence.

- **COMBINED_BUILD**: Retained compile/tests used a different aggregate lock and fixture; byte-equivalent source evidence does not prove the new combined build, exact features, target ABI or package. Current rustls/webpki/roots/ctutils blocks are preserved, but AWS-LC is newly introduced relative to C6.

- **CRYPTO_ASSURANCE**: No new side-channel, sanitizer, fuzz, custom-allocator or cross-architecture validation was run. Pinned native API contracts and bounded FFI inspection are not blanket cryptographic or memory-safety assurance.

- **ENTROPY_ABORT**: Pinned AWS-LC RNG may abort when sufficient entropy is unavailable. Packaged process containment/recovery is unqualified; returned errors are not evidence of recoverable entropy failure.

- **SECRET_COPIES**: SecretBytes/BN cleanup covers inspected owned live storage, not every caller-owned token copy, stack/register copy, allocator configuration or complete erasure.

- **BODY_ALLOCATION**: Inherited whole RPC body/JSON allocation occurs before bounded Mizaru DTO decoding. No transport body-size or JSON-depth hardening claim is made.

- **BW_CANCELLATION**: Retained cancellation checks do not establish rollback or notification recovery for a bandwidth INSERT already submitted before cancellation ahead of BW_TOKEN_SUPPLIED.notify; an actual operational failure was not reproduced.

- **KEY_POLICY**: Legacy byte-width acceptance permits 2041..4096-bit modulus widths and exponents 3/65537. This is not a new strict 2048-bit minimum or complete issuer-modulus validation. Known legacy 2049-bit blind-encoding bug is intentionally not reproduced.

- **NO_ROOT_MODE**: Absent broker_keys retains explicit inherited unauthenticated-root mode; configured invalid roots fail rather than falling back. The review does not broaden or remove that policy.

- **LIVE_QUALIFICATION**: No real account/broker traffic, installed-app interoperability, browser/site matrix, soak or release qualification was performed. Existing release gates remain required.

- **SQLITE_PROVENANCE**: Neither retained candidate SOURCE nor C6 SOURCE has a native_sqlite field. Preserve and freshly validate the independent current SQLite native provenance/inventory; do not infer a descriptor from these files.

- **LICENSE_SCOPE**: Available upstream attribution/license declarations were retained; this source review does not provide legal clearance or assert an upstream package-specific notice was recovered.

Fresh CI must independently assess registry/native dependencies and the final combined source, lock, features and provenance. This report does not approve those dependencies, renew expired source-owned policy, extend RSA exceptions, or replace the existing installed-app and release gates.

The JSON companion contains portable collection-relative references and exact hashes. Retained evidence belongs to `source-owned-actual-candidate-20261015`; those files are referenced, not bundled into these two reports.
