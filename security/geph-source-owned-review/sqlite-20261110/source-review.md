# Bundled SQLite repair review — 2026-11-10

The exact owned SQLx 0.8.6 manifest selects libsqlite3-sys 0.39.1, whose bundled
engine is SQLite 3.54.1. This removes the old bundled C implementation affected
by CVE-2026-119375 / RUSTSEC-2026-0459; it does not rely on a claim that a local
database or sibling WAL can never be modified by a less-trusted party.

All 51 SQLx Rust source files, both original MIT/Apache license texts and the
original manifest provenance match the retained official 0.8.6 crate archive.
The owned package has 56 files. Its only manifest changes are the exact wrapper
version, explicit `column_metadata` and `publish=false`. The root path patch
serves both normal SQLx and macro consumers. The machine report lists each file,
its hash and the bounded review method. No SQLx runtime source is edited.

The FFI inventory covers 104 explicit imports/qualified identifiers, including
types and inline helpers. No identifier is missing. Used extern declarations
and constants match after normalizing std/core C primitive aliases,
`std::option::Option` versus `core::option::Option` in ten callback declarations,
whitespace, and trailing argument/generic commas. `SQLITE_TRANSIENT` is an
inline Rust helper: its destructor sentinel and signature remain the same,
with mem/c_void references moving from std to core. This is bounded source
compatibility evidence, not a complete ABI or memory-safety proof.

Three isolated Rust tests passed: BLOB upsert/WAL reader/reopen, transaction and
column metadata behavior, and recovery after a SQL error. They assert the actual
SQLite version and source ID. The single-job spike used a separate resolved lock;
it is not a full Geph build. The production lock changes exactly two of 490
records; both macOS metadata graphs accept it with `--locked` and retain bundled
SQLite. A compiled test of that exact production closure is still required.

An independent C fixture compiled the unmodified full old/new amalgamations and
called their real `sqlite3WalReadFrame` through a deterministic synthetic VFS.
Six cases per version passed. The old positive control retains the sentinel in
the unread tail; the fixed engine zeroes it while preserving payload, bounds,
offset and I/O errors. This is not a full database-file exploit or app test.

Fresh official OSV responses for SQLx 0.8.6 and libsqlite3-sys 0.39.1 were HTTP 200
with raw `{}` bodies. The three-ancestor projection also retains the two earlier
same-day exact queries. A current full registry/native audit is still mandatory;
these direct queries make no transitive or vulnerability-free claim.

The original three package descriptors and runtime bytes are unchanged. Their
existing bounded source review is rebound to the new source/lock; all 75 prior
payloads remain unchanged and their old tests remain historical. Previous crypto,
allocation, cancellation, entropy, secret-copy, root-key and license limitations
remain. The default SQLite build drops `SQLITE_ENABLE_MEMORY_MANAGEMENT`; SQLx
does not call the affected APIs, but engine-wide behavior equivalence is not claimed.

No system SQLite or SQLCipher fallback is accepted. No Geph/app binary, broker
call, installed app or release qualification was performed for this report.
Expiry remains 2026-12-10, with exact-source invalidation and current dependency
admission still required. No exception, automatic renewal or date-only extension
was introduced. `transformations.json` binds retained local evidence to public
copies with workstation path prefixes replaced. It also records the explicit
editorial correction of the FFI method description; raw results and original
artifact hashes remain retained.
