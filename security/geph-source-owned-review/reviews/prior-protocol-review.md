# Bounded protocol and callsite review

SOURCE SHA-256: `3c2cf6d98b19edf77d20f7105f20ddc509e9e1422dc137720acf7f103de51a6e`. No compile, network or scanner run.

## Finding

**P2, inherited: expired nonzero Plus expiry evicts valid Free tokens.**
`src/auth.rs:119` computes `is_plus = plus_expiry > now`, but line131
uses `plus_expiry > 0` when deciding whether to delete current/next token
cache (133–134). With `now=2000`, `plus_expiry=1000` and cached Free,
there is no account-level transition, yet both tokens are removed before
broker RPC. A later broker error loses the available fallback. This exact
logic exists in the source edit's before body too: it is not an RSA migration
regression. The expiry value returned by a real broker and association with
a user incident were not tested. A separate source repair should test this
state and use active subscription status in its cache decision.

## Reviewed boundaries

- Exact response DER is authenticated by Merkle proof, with expected epoch
  and request-selected root checked before pending finalization/cache publication.
- Configured bandwidth issuer is bound through the pending mathematical key;
  equivalent PKCS1/SPKI response encoding remains supported.
- DTO decoder bounds and wire representation match retained exact-byte adapter
  tests; protocol runtime files retain upstream behavior.
- Auth/bandwidth candidate bodies equal the successful composition fixture
  bodies after removing only the appended test helper. All12 receipt artifact
  hashes and6 independent adapter input hashes were checked.

Retained evidence covers6 adapter tests and11 synthetic real-callsite tests.
They were not rerun. No new migration-specific protocol/serialization defect
was identified; this is not blanket security clearance.

## Still unproven

Whole RPC body/JSON allocation is unbounded before DTO decode. Existing
checks also do not establish notification recovery for cancellation after a
bandwidth INSERT has been submitted but before its event is emitted. The
exact full candidate, real accounts, installed behavior, other ABIs and
cryptographic side channels remain outside this review.

Paths, exact hashes, line ranges and evidence links are in `protocol-review.json`.
