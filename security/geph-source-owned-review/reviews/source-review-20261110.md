# Source-owned Geph review — 2026-11-10

**The scoped review and independent source review found no new confirmed source defect. This document does not admit a release.**

This review covers the same three embedded packages as the October 31 review:
`slipstream-rsa-client`, `mizaru2-slipstream-client`, and
`geph5-broker-protocol`. SOURCE is
`69d5de39654dea018075469d20ea7892cc35f5af0466d19a7811ef3316b60df7`, and Cargo.lock is
`560504e697c28f2114ec16414e5dc372e1903df986ba36792aab9a12c34631cb`.
Both are unchanged. The JSON companion records the exact identities and checks.

## Fresh evidence

On November 10 at 14:55 UTC, the official OSV API returned HTTP 200 and an empty
JSON object for each of `mizaru2@0.2.21` and
`geph5-broker-protocol@0.4.3`. The raw responses, query bodies, timestamps, sizes,
hashes and derived ancestor inventory are retained under `osv/20261110/`.
These two queries cover the derivative ancestors; they do not scan the full
registry graph, AWS-LC, SQLite or the application.

All 20 embedded file bodies match SOURCE, the October 31 review and the retained
source copies. The five retained materialized root files also match their prior
hashes. All 69 existing evidence entries were checked by size and SHA-256,
including the AWS-LC archive. This verifies the retained bytes, not a fresh
execution of their tests. The prior evidence remains retained and dated.

## Source review

| Area | Observation |
| --- | --- |
| Native adapter | Bn, Ctx, Mont and Rsa retain RAII ownership and error-path cleanup. Borrowed modulus/exponent pointers remain tied to the owning public key. Native handles do not cross `await`. |
| Pending operation | `OwnedPending` contains owned bytes, has no clone or serialization path, and consumes its state during finalization. The response key must match the original mathematical modulus and exponent. Signature verification precedes returning credential bytes. |
| Protocol adapter | DER, representative and Merkle bounds apply during decoding and direct DTO use. Auth checks the exact response DER against the configured root and checks the requested epoch before accepting the result. Invalid configured roots return errors. |
| Production auth | Token generation precedes retrieval of an untrusted issuer key. The request-selected Free/Plus root and epoch are checked before `db_write`. The existing `is_plus != currently_plus` cache fix is unchanged. |
| Production bandwidth | The configured bandwidth key is parsed fallibly, the pending operation binds that key, and the database INSERT follows successful unblind. The previously recorded INSERT/notification cancellation limitation remains. |
| Broker protocol | The local manifest still selects the client-only adapter. This refresh changes no RPC signature, DTO, source file, feature, lock or vendor revision. |

The earlier fixture results are reused as historical evidence only. No compiler,
crypto fixture, sanitizer, fuzz, side-channel, cross-architecture, live-account,
browser or updater test was executed by this review.

## Review window and limits

The review window ends on **2026-12-10**: a 30-day maximum interval for
these unchanged source-owned adapters. Exact SOURCE, lock, descriptor and file
bindings invalidate the review when their bytes change. Any newly reported
relevant advisory or source defect requires reassessment immediately, without
waiting for that date. Current-date publication admission and the independent
fresh application/full Geph dependency audits remain mandatory. This refresh
does not renew unused expired package exceptions.

The previous limitations remain: this is not a complete cryptographic or
memory-safety assurance; AWS-LC entropy failure may abort; buffer cleanup does
not prove erasure of every caller, stack or allocator copy; whole RPC body/JSON
allocation precedes DTO bounds; bandwidth INSERT cancellation recovery is not
proven; legacy key-width/exponent policy and explicit no-root mode remain; and
the source review provides neither native SQLite provenance nor legal clearance.
The independent reviewer also verified all 16 source-edit chains and their
before/after hashes. Its structured findings and review-window assessment are
retained in the JSON companion.
