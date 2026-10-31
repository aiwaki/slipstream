# Synthetic RSA/auth fixture

These deliberately public RSA keys belong only to deterministic interoperability
tests. They are not account credentials or production keys.

The retained Geph call-site fixture and legacy signing oracle are unchanged from
the reviewed October 11 composition. The oracle has its own Cargo.lock (including
the legacy RSA implementation) and is compiled as a separate test executable. It
is never linked into, packaged with or added to the production Geph dependency
graph, SBOM or admission policy. Its private-key operations use only these public
fixture keys under the existing network/private-file-denying runtime sandbox.

The runner copies the current, hash-verified production tree and lock, changes only
four test-only insertion points (three cfg(test) items plus a broker hook), adds
this fixture module, then requires all eleven exact
positive libtest results. The current production tree is checked unchanged after
execution. The catalog binds all production inputs and all nine fixture files;
a source change requires an explicit review of this test catalog.

No historical passing log admits the current candidate. The fresh producer must
compile and run these cases with the candidate's current dependencies. This is
synthetic auth and bandwidth coverage, not a real broker/account or installed-app
qualification. The existing SQLx cancellation case is retained; native SQLite is
not activated.
