# SQLx SQLite driver source attribution

This is sqlx-sqlite 0.8.6 from the official crates.io archive, licensed under
MIT OR Apache-2.0. The original license notices and normalized manifest are
retained unchanged. All 51 Rust source files are byte-identical to that archive.

Slipstream changes only the manifest: disable publication, pin libsqlite3-sys
to 0.39.1, and explicitly enable column_metadata required by this driver.
The official registry wrapper bundles SQLite 3.54.1, including the fix for
CVE-2026-119375. This is a local dependency override, not an upstream SQLx release.
The root crates.io patch applies to every SQLx dependency edge.
