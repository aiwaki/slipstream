# Retained source attribution and license declaration

geph5-broker-protocol 0.4.3 is a local derivative of geph5-broker-protocol 0.4.3,
published at https://crates.io/crates/geph5-broker-protocol/0.4.3 by the Geph project
(https://github.com/geph-official/geph5). Its published Cargo.toml declares ISC;
that exact manifest is retained in provenance/Cargo.toml. The package descriptor
in the enclosing SOURCE.json records the exact original crates.io archive SHA-256
and original source-file hashes. The derivative has its own descriptor/file hashes.

The upstream broker protocol source is preserved for production; terminal cfg(test) modules are omitted. The manifest selects the local client-only Mizaru derivative instead of the published server-capable mizaru2 dependency, and disables registry publication. This local package is a derivative, not the unmodified registry crate.

## License text and attribution

The published manifest declares ISC. LICENSE-ISC.txt contains the standard ISC
license text from the Open Source Initiative, retrieved on 2026-10-13:
https://opensource.org/license/isc

That file is standard license text, not a recovered package-specific upstream
notice. Its literal <YEAR> and <OWNER> placeholders are the OSI template values;
they are not attribution to a person or a claimed copyright year.

The verified geph5-broker-protocol 0.4.3 archive supplies no separate LICENSE, COPYING
or copyright file. Neither its published Cargo.toml nor Cargo.toml.orig supplies
an authors field. The original manifest is preserved verbatim in
provenance/Cargo.toml, including its license and repository declarations. No
upstream copyright holder or year has been inferred or invented.

The exact upstream archive and original file hashes remain recorded in the
enclosing SOURCE.json. This derivative preserves that provenance and the
available attribution; it does not claim that an additional upstream notice
was supplied or that license compliance received legal clearance.

The downstream packaging decision is to retain the available attribution and
supply the standard ISC text without waiting for an upstream response. This
does not change package identity, advisory assessment, source-owned review or
other release requirements. Registry dependencies retain their own notices,
including aws-lc-sys and native AWS-LC.
