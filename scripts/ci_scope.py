#!/usr/bin/env python3
"""Classify exact changed paths for the required common CI workflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import copy
import os
import re
import subprocess
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
import sys


GEPH_BOOTSTRAP_ALLOWED = frozenset(
    {
        "security/geph-dependency-audit-policy.json",
        "vendor/geph/Cargo.lock",
        "vendor/geph/SOURCE.json",
        "vendor/geph/VERSION",
        "vendor/geph/README.md",
        "scripts/geph_vendor_source.py",
        "scripts/test_geph_source_edits.py",
        "scripts/test_geph_embedded_source.py",
        # Both TLS graphs may need one coordinated source-only repair. All
        # dependency audits still run; no packaged binary is promoted here.
        "app-tauri/src-tauri/Cargo.lock",
        "docs/RELEASES.md",
        "docs/DECISIONS.md",
        "docs/CURRENT_STATE.md",
        "scripts/ci_scope.py",
        "scripts/test_ci_scope.py",
        ".github/workflows/build-geph.yml",
        "scripts/test_build_config.py",
        "scripts/run_geph_synthetic_tests.py",
        "scripts/test_run_geph_synthetic_tests.py",
        "docs/ROUTING_RESEARCH.md",
    }
)
GEPH_BOOTSTRAP_REQUIRED = frozenset(
    {
        "vendor/geph/Cargo.lock",
        "vendor/geph/SOURCE.json",
    }
)
# One reviewed RSA-only source/tooling delivery, frozen against main 9a02e262.
# An empty or partial mapping cannot authorize bootstrap.
# None denotes a file proven absent in the base tree, not an empty file.
RSA_ONLY_FILE_BINDINGS: dict[str, tuple[str | None, str]] = {
    '.gitattributes': (
        None,
        'a49cd52c99ef219da14bbad6a64b192b01265de7504c996596b12eacd5da2c28'),
    '.github/workflows/build-app.yml': (
        'c0ea37e83f5084092527a67c8802d9d35d59696099465d0ac1e919c066e9b017',
        '465acf0a1a9068388e2835a44faed7c0d30d15ceae5c634ff7be08c764685864'),
    '.github/workflows/build-geph.yml': (
        '240b05820b6b9906e3ec9b795948d2da041d5d1ef4c4fb9701ea8dbff1db0cbe',
        'f4fedc115b2148dd3dcb7f50ca33c045ebabd832770d47efba094ac66ab9a5e1'),
    '.github/workflows/ci.yml': (
        'b94c8a024f87163cb5d06a4962971307775fe3af0a547ce6f169a4ed80f5b06d',
        'fca3692d0599adeecc9941c85cdb53381e2b64cb0c01489b066902dbe2ab5a33'),
    '.github/workflows/dependency-audit.yml': (
        '709049d4b60b63a2e1d3d1150028457af1ea28c0627dc4b26c069f24fe9bb29f',
        'ed65860c0bb0ddf45ec233409f5f5f35054b73e5eed04a0adc5cdcee5432c44c'),
    'scripts/dependency_audit.py': (
        '239b2a8119a6bf20bc8ebc3862b3b6f6a0f0106ebb1d66af954dcc97369cab15',
        '37b24e37f0c746a7627d1366795b655d0f200e80d384fd612076a8908a919a8c'),
    'scripts/fixtures/geph-registry-policy-r3.json': (
        None,
        'a4c72127b018c665e8207cc01bbbbdb74012765a32127806a1e2f59e9f3c72af'),
    'scripts/fixtures/geph-rsa-auth/README.md': (
        None,
        '9f870d70345c36ed5a610f95727944f7b95e93176372530a3535e22a440ad95e'),
    'scripts/fixtures/geph-rsa-auth/account_level_fixture.rs': (
        None,
        '02d8f35c66f7215f19e35aec9ab922c0ee6ac48ea65da9cb9caf31e0e5574a90'),
    'scripts/fixtures/geph-rsa-auth/closure.json': (
        None,
        '9b19b1d0705236dfb95e85adc29c4117571082d8c85727d5e1c171aa2a167803'),
    'scripts/fixtures/geph-rsa-auth/compat-public-fixtures/e3-2048-pkcs1.der': (
        None,
        '25b5dd4b5f115246802e6c370f5755d90f66bdd9e30941f2f63ae072a23111c4'),
    'scripts/fixtures/geph-rsa-auth/compat-public-fixtures/e65537-2048-pkcs1.der': (
        None,
        'f49e22328fe35e0e91fbadb46f0d5d065f82bf68268cbf9f907e66bd358624af'),
    'scripts/fixtures/geph-rsa-auth/compat-public-fixtures/e65537-2048-private.der': (
        None,
        '1f73c05d465b65c529d1e85a2f8046cf144b2ed6723ac15c9bbd91178feb1a90'),
    'scripts/fixtures/geph-rsa-auth/compat-public-fixtures/e65537-2048-spki.der': (
        None,
        'd64f6afef53a8fbf46b5e554cee27a1912bfed4749926a9bbb7cd10e28ca26d0'),
    'scripts/fixtures/geph-rsa-auth/legacy-oracle/Cargo.lock': (
        None,
        'a982760c7bb2f70a25af3cad6178261d2bfd21a6f394c28a90d89b27bd2ef116'),
    'scripts/fixtures/geph-rsa-auth/legacy-oracle/Cargo.toml': (
        None,
        '020a6138aa70be4c6be019bd34d106750e65f7cda0faa212d50bfdf56c6a2399'),
    'scripts/fixtures/geph-rsa-auth/legacy-oracle/src/bin/sign_adapter.rs': (
        None,
        '081806af047d3032b34728c0dae6e0ecc100a48610945778acda4de2557285ed'),
    'scripts/fixtures/geph-rsa-auth/rsa_composition_tests.rs': (
        None,
        '8699e7a637445534a309f346c589dca3944681dc89326cab79347cc079731faf'),
    'scripts/fixtures/geph-rsa-removal-policy-r4.json': (
        None,
        '30cae8c4bbacfea24294bfaacc6cc8b45145e089511ebdd2c223820992907ae2'),
    'scripts/fixtures/isc-standard-license.txt': (
        None,
        '242238da85b3c2178895de4294e0a43a5394e479b318762f5b2575f0af551eee'),
    'scripts/geph_native_sqlite.py': (
        None,
        '987be399406e1b0d43d47c2d23fb8a8e5abe88c24be2e9cb8adb6f9c2858e860'),
    'scripts/geph_native_sqlite_advisories.py': (
        None,
        'a9d96deec5c85d450095dc19f9542cd1b6ca0f4bd0190815261e9fb51e89b296'),
    'scripts/geph_native_sqlite_build.py': (
        None,
        '24c1c04246b7f2d0029e47ad9638b58f9a6b02de696adfc47af0b474cd1d38bc'),
    'scripts/geph_native_sqlite_bundle.py': (
        None,
        '6c5e45553b594245d47661b048d901471137d58777afa293962cffc04edc519a'),
    'scripts/geph_rsa_fixture.py': (
        None,
        'a0039ad6a2e222ee7df4321718bd03d51d4635dd0be8ba2296c0836b29cabc58'),
    'scripts/geph_source_owned_advisories.py': (
        None,
        'e1631c585228ac6525f1e151d6bc1e476e4f7ab42fdd6dd99745627f7673423b'),
    'scripts/geph_source_owned_bundle.py': (
        None,
        '90da6d02fbb0c7f45fdbf85bccf7302baaa67458579a4f675b3770d0241ac227'),
    'scripts/geph_vendor_source.py': (
        '15afc56af39fe99eb96a3874b57e6fd6e1cb5902b676d850488608bfcca9ad76',
        'b3374b9f9183d2caa1e9bcd0e2b38a1199c60631e1d84eea4b8d693b0927767e'),
    'scripts/make_geph_vendor_sbom.py': (
        'b3ed473adc798c9eccc3a90799ec9e504c9b341e2801749d270786bf9b5420ec',
        '04e12e94b9eda9927a304510113669fb9fb2f11c45c95150c8892cbc02d70adb'),
    'scripts/make_release_sbom.py': (
        '64e16f3c30f1cd596f48fa546412c29b547d0e05f617d2478d705bc1b2c5bedc',
        '3e532b9a69f0fe1f53df4531a2fd713567528e85ea255625735d97ab7be72664'),
    'scripts/run_geph_synthetic_tests.py': (
        '0da06854b9b624ceab13e1ef5e7be26856533e1a3c95c01a894e774f6f39a547',
        'fffcfc943279b35747cc4ebb20a1d9955ac2980f84352e60e64b5e4c2f30f700'),
    'scripts/test_build_config.py': (
        'ad60740d7ab6af5f693d43c3d8b775388a788efcfc34a989142ab3380acc9be1',
        'cfb589e058c20b379367abb3269f9df6f479d0a68b163f125503c210e2fb640c'),
    'scripts/test_ci_scope.py': (
        '090ab6a24a5e9056e7986b026e54c720aa7f41863c8dd282749bc84253ccc862',
        'da8b84250d913b55b61654dba492d1d7ceef5974a06002c772a6fa76530be1da'),
    'scripts/test_dependency_audit.py': (
        '275961558beddcaaa701999d76ced2655170a855777ca97eef4eeb3836e034d5',
        'cc0b2ec2873400590d85e6121acaddebc1eee472a2df3773cefb3adfb45f90d2'),
    'scripts/test_geph_embedded_source.py': (
        None,
        '9ae61d85136dc6891a353bc3a5b7ed7736344e7e4a2d38d5c95f23999eafd0a1'),
    'scripts/test_geph_historical_policy.py': (
        '8c2df04d186288d2d3423204cfd186e24a7aa7cdda6668ebbe28f67650dc766a',
        'e3e09bc2ba362384d695ffb35e6d99ace2b6380403f1ab4c69ad883ed8ef797b'),
    'scripts/test_geph_rsa_removal_transition.py': (
        None,
        'bf2574c7d6bae36d2d4d5c64cc92437b6d146d2fd951ad54404573e7aa0fb9c1'),
    'scripts/test_geph_source_edits.py': (
        '63c487e5eccf7b854a5e8eb30d0b4dd329cacc2ceb2cd6ce080072238c923f17',
        'e79fc1dcec53ada05adc5cf49823eae8403390615adb09e86cfd8f9619e00b0c'),
    'scripts/test_geph_source_owned_advisories.py': (
        None,
        '2c42280b8a0ff960a0dca5f81f9d8153efa0c713275acdef939879bb92575feb'),
    'scripts/test_geph_source_owned_bundle.py': (
        None,
        '9297d3a795e29da0176464ad4870ed316b8fe616170060cd3290c3606b63756d'),
    'scripts/test_geph_source_owned_sbom.py': (
        None,
        'a0e8798e8c271a7c24010291b8c10d67748fc23c481cf9396964b4062e9597e7'),
    'scripts/test_geph_source_owned_workflows.py': (
        None,
        'b933f3169e4b3389bcd1fd1ecd0b61d5fe8add62176bca0a2b077b12a12bd234'),
    'scripts/test_release_audit_admission.py': (
        '0fcf6b66c9c293c56ff44153daf282ae918d4f0d7e327c652031912087af4ace',
        'd8b1c9b603812564e76f1887ca799439ed7ad62ee7fc4198ee9af13007d760a0'),
    'scripts/test_run_geph_synthetic_tests.py': (
        '632d25e003db816676e0b30326f67662d803159e0e7ae2c74a10d9d8fea0419d',
        '7ef22dfd3be19cb0c2f178140027b5d8fa8b829544e2be1f4b5321dc87a5ce4d'),
    'scripts/test_source_owned_audit_bridge.py': (
        None,
        'c004cf25a2ff8778b9aa8886e83e2ec366832e23dab00363040840155c383924'),
    'scripts/test_source_owned_review_admission.py': (
        None,
        'db66bf34b47d070b6e06189e9217ee143ad8f60c47001a60009ae009ad70b72a'),
    'scripts/test_verify_geph_source_owned_release.py': (
        None,
        'f5c49f7c426904c616a3031072ba5d32f2a2d2c6a7c9b4e01c08e33065f64b1c'),
    'scripts/verify_geph_release.py': (
        '6517d87b0ccf58c944f83f4ef53b31726e32fd843f410afdb8a2070598ced560',
        '571e65418f653cc1c3098d77568b632915e8df7cd153a20500de107b1084c4e8'),
    'security/geph-dependency-audit-policy.json': (
        'a4c72127b018c665e8207cc01bbbbdb74012765a32127806a1e2f59e9f3c72af',
        '30cae8c4bbacfea24294bfaacc6cc8b45145e089511ebdd2c223820992907ae2'),
    'security/geph-source-owned-review/archives/geph5-broker-protocol-0.4.3.crate': (
        None,
        'c0f8b70695d21757da473ffba32eeeba85f9f79708b11b54812cb77b9fc4e0d1'),
    'security/geph-source-owned-review/archives/mizaru2-0.2.21.crate': (
        None,
        'db4ea54ffedc62011081b18940996e37453bf029553b40964302f7efc5dcaff7'),
    'security/geph-source-owned-review/backend/Cargo.toml': (
        None,
        '836bac6390070d88f3c804f4212e16ca6e142f6c111795094d925470d07d6866'),
    'security/geph-source-owned-review/backend/aws-lc-sys-0.45.0.crate': (
        None,
        '9bff6c3b54fad79a2e60b8102caf565819711497c1f5f092f49508e2f5c31b27'),
    'security/geph-source-owned-review/backend/aws-lc/crypto/fipsmodule/bn/bn.c': (
        None,
        'd1dcac7dbabd174fc6413a4b20de7169a4d8908ac67a2d745d71bcfd8c5dfae8'),
    'security/geph-source-owned-review/backend/aws-lc/crypto/fipsmodule/bn/bytes.c': (
        None,
        'dc96b981cd49f7cbfd7af490c00442b7416956b2a60db1e7458f2ab698595e32'),
    'security/geph-source-owned-review/backend/aws-lc/crypto/fipsmodule/bn/ctx.c': (
        None,
        '108768c96480fd3b8ad85d08e8975f9dd6ba1f3d91756f9e717f82fd28487f46'),
    'security/geph-source-owned-review/backend/aws-lc/crypto/fipsmodule/bn/exponentiation.c': (
        None,
        'a858ca843eeabed2102e8686cc55aaffb6854176eb39f5322cd8d0278434a86e'),
    'security/geph-source-owned-review/backend/aws-lc/crypto/fipsmodule/bn/gcd.c': (
        None,
        '7ebb35b113d29f804567efef43204725224c8d806b59fdab679eb1c9cb00691e'),
    'security/geph-source-owned-review/backend/aws-lc/crypto/fipsmodule/bn/montgomery.c': (
        None,
        '073cba671b1c22ebf57dea832835a4b9e179a153326de60d8a2a0ab05753a1fc'),
    'security/geph-source-owned-review/backend/aws-lc/crypto/fipsmodule/rsa/padding.c': (
        None,
        'a2e241acc3cb29c7f0ebf5b988e07e71999955187ab0cfe5cc602a025e28a399'),
    'security/geph-source-owned-review/backend/aws-lc/crypto/mem.c': (
        None,
        '88651b6d0b7e135980f97408815e2d357b2c39eabb563e241e795792d60fc3a1'),
    'security/geph-source-owned-review/backend/aws-lc/crypto/rsa_extra/rsa_asn1.c': (
        None,
        '2c14056d37e79145ff2354f71b8f151221dc17210409ede1e00a1174fb0c5693'),
    'security/geph-source-owned-review/backend/aws-lc/include/openssl/bn.h': (
        None,
        '9c3b508aef0d12f5db09995106dc00b667c8194836e0db60bc752799ab0cf851'),
    'security/geph-source-owned-review/backend/aws-lc/include/openssl/rand.h': (
        None,
        '968775664d7e574b96a3c473e39a38f2173e9a8db1ee3decab165f236e85efc2'),
    'security/geph-source-owned-review/backend/aws-lc/include/openssl/rsa.h': (
        None,
        'd9140449f1e55ad244974b07a980d2df4eb19cc1312a73b1c7a2234d836cd889'),
    'security/geph-source-owned-review/backend/baseline/lib.rs': (
        None,
        '1131e9eee36e226e5d45ed9e0990a27a688267215f40e36bce489a865efe47da'),
    'security/geph-source-owned-review/backend/baseline/owned.rs': (
        None,
        '70f68d4b3679112aaaf2d8d17747f1ca7376ba39d9fd3692b25b825c72257642'),
    'security/geph-source-owned-review/osv/ancestors.json': (
        None,
        '7b0e770e056d71778c1665cebb32c90d55d9b164334d2ee041b052324b2a5ad2'),
    'security/geph-source-owned-review/osv/current-geph5-broker-protocol.json': (
        None,
        '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'),
    'security/geph-source-owned-review/osv/current-mizaru2.json': (
        None,
        '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'),
    'security/geph-source-owned-review/osv/current-receipt.json': (
        None,
        '9a0563eb5b126b43d14b55414b899916324c6edf6415a787238fa49124d1aad4'),
    'security/geph-source-owned-review/osv/osv-complete.json': (
        None,
        'a51eecea9afd3a26ae703ef4e3f53d44130ff161288b90b6853c3f6fbf2f0c23'),
    'security/geph-source-owned-review/osv/projection.json': (
        None,
        '32d244e23927b7316f664b613d20876424d843c579a8ab2713fdef2cb2a1bbcb'),
    'security/geph-source-owned-review/osv/receipt.json': (
        None,
        'dc370ab081e6b9ac17a818dd4322bb5e05f7f4dd6162b7705c0a971865d4485e'),
    'security/geph-source-owned-review/retained/backend-0-legacy-vector.json': (
        None,
        '071e2d2aa6bc7acf125fd5db8f83caf410ab61eb286b2e010a6de372eba0b9e7'),
    'security/geph-source-owned-review/retained/backend-1-compat-vectors.json': (
        None,
        'c7bb06db21aeafd074a312c724e1f73aa44f1730cb52cf073e98a96e809b487e'),
    'security/geph-source-owned-review/retained/backend-10-independent-fixture-review.json': (
        None,
        'e3600ce693895353545878b233b9a20ee8e8d171bf4738889adf7dc6600bb8ba'),
    'security/geph-source-owned-review/retained/backend-2-compat-prototype-test.log': (
        None,
        '224de6862aaa2ef0acbc024c68e90486fea847113e546e422907b6b7f834308d'),
    'security/geph-source-owned-review/retained/backend-3-async-independent-review-test.log': (
        None,
        'beed4b492d6708615887d1fd353b74eb2a2ae6e4fed3a4de7b70eee9dc4f23b9'),
    'security/geph-source-owned-review/retained/backend-4-async-prototype-test.log': (
        None,
        'c46d4b400bca5e2e5c470aeaeb009163dc582b9dc893fd94157bb2bd1bb407ce'),
    'security/geph-source-owned-review/retained/backend-5-compatibility-corrected-independent.log': (
        None,
        '589544c9880f2a0ca3dac06086c80ed76c5841c894cf4ea07cf8c51efdbfe62b'),
    'security/geph-source-owned-review/retained/backend-6-corrected-review-hashes.json': (
        None,
        '4d9245456b1b3493b00b8d9c01144783e0792dbb58f487afcc953116d338dd3f'),
    'security/geph-source-owned-review/retained/backend-7-compatibility.rs': (
        None,
        '70a713054f977c8ff6fb220139fcdecc1082704d0396a8cd705604025f36faa8'),
    'security/geph-source-owned-review/retained/backend-8-async_boundary.rs': (
        None,
        'edac173a4c72c5b75bf0d3558e6fd292ffc4d7649af7666acc13f7cf67a3b685'),
    'security/geph-source-owned-review/retained/backend-9-final-execution-evidence.json': (
        None,
        '1360e35958bcaa75991d5c777183ec20d0221eec29bddb48617aea82f743f3a9'),
    'security/geph-source-owned-review/retained/protocol-0-client-adapter-independent-result.json': (
        None,
        '617daf14aea0f4bc1c1378fc90e569e9d95bbd7f07d47aeddbf2f9f7204e5efc'),
    'security/geph-source-owned-review/retained/protocol-1-final-execution-evidence.json': (
        None,
        '1360e35958bcaa75991d5c777183ec20d0221eec29bddb48617aea82f743f3a9'),
    'security/geph-source-owned-review/retained/protocol-2-compat-vectors.json': (
        None,
        'c7bb06db21aeafd074a312c724e1f73aa44f1730cb52cf073e98a96e809b487e'),
    'security/geph-source-owned-review/review.json': (
        None,
        'ce1a0e85d537cf499e895f078627ef33f78e5aaa331962adb1c25d8577e18bf4'),
    'security/geph-source-owned-review/reviews/portable-evidence.json': (
        None,
        '5259f0348825871e5f7aba756d40c0ac432df773c3426625f30a2f5b0277fcfc'),
    'security/geph-source-owned-review/reviews/prior-backend-bindings.json': (
        None,
        '2559ab78fae1ce2d9613b19fc4fe24e864f16bb467fb585b1a4021ef4200eced'),
    'security/geph-source-owned-review/reviews/prior-protocol-review.json': (
        None,
        '9506a86750a02ee95f7c10da1623ecb2e88b49c3e7d9c2b9bfa296dfb3b0636c'),
    'security/geph-source-owned-review/reviews/prior-protocol-review.md': (
        None,
        '97f11694bcce60c1ac176b87857008d0d19a45f81ff9ddb199d29b1b1e4d2e90'),
    'security/geph-source-owned-review/reviews/prior-provenance.json': (
        None,
        'd88d153c8c4f1de442b6766804b10b7976960dd54a85f9c5f0bb10099ea61a99'),
    'security/geph-source-owned-review/reviews/prior-review.json': (
        None,
        'f9ae01b9b6cc0ab59a6f768822999d1d192e6540caef0e1b262cfdd0052a3956'),
    'security/geph-source-owned-review/reviews/prior-review.md': (
        None,
        '7d32c91e9f4664ee626c78ede7d0c875153c0e9dfe84d74bcf82f8c3cc90a68a'),
    'security/geph-source-owned-review/reviews/source-review-20261031.json': (
        None,
        '5410e83f7e2cc1a3cc86b13c4d34fe4cc7b348bfac8acfe35d3e61bd3ca8289a'),
    'security/geph-source-owned-review/reviews/source-review-20261031.md': (
        None,
        '1d287933a0783b2195c7fd69d4a240e16e0d5bea1987c34ba8011011b5082524'),
    'security/geph-source-owned-review/reviews/verified-reuse.json': (
        None,
        '201a5114ecbe042b5d6dcb953c977d4a473c9b3b54815b4e5ef7ba0591d805b4'),
    'security/geph-source-owned-review/sources/slipstream-vendor/aws-lc-backend/Cargo.toml': (
        None,
        '848741648ff67d659160fe0009bb783fa7f4977247c27599dd19fa721f2c4eb0'),
    'security/geph-source-owned-review/sources/slipstream-vendor/aws-lc-backend/LICENSE': (
        None,
        '418510c495b074f7466c6c3c51af379889e8c28479da0a4f2006cf08e5e60a15'),
    'security/geph-source-owned-review/sources/slipstream-vendor/aws-lc-backend/src/lib.rs': (
        None,
        'd6473d922426398c931dc1f0e9fb1c2d24ddb628d09bf09616c2bb6a2725994f'),
    'security/geph-source-owned-review/sources/slipstream-vendor/aws-lc-backend/src/owned.rs': (
        None,
        '1c81e27303f63bbd733c39936a6103e65300b7f60c4906687e814174d46b064a'),
    'security/geph-source-owned-review/sources/slipstream-vendor/geph5-broker-protocol/Cargo.toml': (
        None,
        '12f142680e648c4295f01a4ee0077cabc5ee1fcca3f96848e06a798cd2228733'),
    'security/geph-source-owned-review/sources/slipstream-vendor/geph5-broker-protocol/LICENSE-ISC.txt': (
        None,
        '242238da85b3c2178895de4294e0a43a5394e479b318762f5b2575f0af551eee'),
    'security/geph-source-owned-review/sources/slipstream-vendor/geph5-broker-protocol/SOURCE-NOTICE.md': (
        None,
        'e6ca1999ce226e4210c925ad53a8be414d4ed097fe496bdcb5d92c71296125e6'),
    'security/geph-source-owned-review/sources/slipstream-vendor/geph5-broker-protocol/provenance/Cargo.toml': (
        None,
        '5ac09cf49ffc9fc1d61a1783149c26de9c31ed81c73ef46bc0167f3889ffad0e'),
    'security/geph-source-owned-review/sources/slipstream-vendor/geph5-broker-protocol/src/bridge.rs': (
        None,
        '38432a9f53b0e9c5837687f31f6461371bd5471a38b4aba3de9c6b802c523fdb'),
    'security/geph-source-owned-review/sources/slipstream-vendor/geph5-broker-protocol/src/exit.rs': (
        None,
        '735958b9b6a2a9edc9f60c980d175927aa9f4f8f21cf69eaf3ff4237627f2434'),
    'security/geph-source-owned-review/sources/slipstream-vendor/geph5-broker-protocol/src/lib.rs': (
        None,
        '6d68ef992a055b6b2686f4e34cbbefe22c73c04325686dba44bbffa0e01fff8c'),
    'security/geph-source-owned-review/sources/slipstream-vendor/geph5-broker-protocol/src/mac.rs': (
        None,
        '85d60b9865609b98756efa62ab909d81b2b99e9d94515e8e9d00f02af4fbcaf8'),
    'security/geph-source-owned-review/sources/slipstream-vendor/geph5-broker-protocol/src/puzzle.rs': (
        None,
        '705c63b6458096795c935fcda28eacd9fbf2aa87351b48577ae093fcb985f92a'),
    'security/geph-source-owned-review/sources/slipstream-vendor/geph5-broker-protocol/src/route.rs': (
        None,
        '0fdeb37560789eb5418a23ac4ae2e149992e614702fbac1fee7082f5a47d5c08'),
    'security/geph-source-owned-review/sources/slipstream-vendor/geph5-broker-protocol/src/signed.rs': (
        None,
        '1de66fced75c78c5ce71372b2dc5200ff169cfcc6dc932559abb61ac480d27a2'),
    'security/geph-source-owned-review/sources/slipstream-vendor/mizaru-client/Cargo.toml': (
        None,
        'f5049e27e0c5593112a78fc4f382b091f37c4731ad93073710fe66a84bd2aaac'),
    'security/geph-source-owned-review/sources/slipstream-vendor/mizaru-client/LICENSE-ISC.txt': (
        None,
        '242238da85b3c2178895de4294e0a43a5394e479b318762f5b2575f0af551eee'),
    'security/geph-source-owned-review/sources/slipstream-vendor/mizaru-client/SOURCE-NOTICE.md': (
        None,
        'e820565f60826082119d890b6533a63f8f9512c5a71283284f3b71998842644a'),
    'security/geph-source-owned-review/sources/slipstream-vendor/mizaru-client/provenance/Cargo.toml': (
        None,
        '2e8b68ac17e6578854a6508a536bf82462f9cf51abb64657b1b4d808c7bf3162'),
    'security/geph-source-owned-review/sources/slipstream-vendor/mizaru-client/src/lib.rs': (
        None,
        '3aab2e8c9c1f4dce6a02ca5f716020f560c6b4e281a59c238051b90991e64bf8'),
    'vendor/geph/Cargo.lock': (
        'c941a26c6fd308f0057544166c153945ecd54456507a836c155dff8877d5e4f0',
        '560504e697c28f2114ec16414e5dc372e1903df986ba36792aab9a12c34631cb'),
    'vendor/geph/SOURCE.json': (
        'de39d92abd79787d432bcd45f074398f91dbbf3baa843401b90f7bcbb1b36286',
        '69d5de39654dea018075469d20ea7892cc35f5af0466d19a7811ef3316b60df7'),
}
RSA_ONLY_REVIEW = "security/geph-source-owned-review/review.json"
RSA_ONLY_SUPPORT_PATHS = frozenset({
    "scripts/ci_scope.py", "docs/CURRENT_STATE.md", "docs/DECISIONS.md",
    "docs/RELEASES.md",
})


def reviewed_rsa_only_delta(deltas: dict | None) -> bool:
    if not RSA_ONLY_FILE_BINDINGS or not isinstance(deltas, dict):
        return False
    if deltas.keys() != RSA_ONLY_FILE_BINDINGS.keys():
        return False
    for path, expected in RSA_ONLY_FILE_BINDINGS.items():
        pair = deltas[path]
        if not isinstance(pair, tuple) or len(pair) != 2:
            return False
        before, after = pair
        if (before is not None and not isinstance(before, bytes)) or not isinstance(after, bytes):
            return False
        actual = (None if before is None else hashlib.sha256(before).hexdigest(),
                  hashlib.sha256(after).hexdigest())
        if actual != expected:
            return False
    return True


def rsa_only_delta_from_git() -> dict | None:
    refs = (os.environ.get("BASE_SHA", ""), os.environ.get("GITHUB_SHA", ""))
    if not RSA_ONLY_FILE_BINDINGS or not all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in refs):
        return None
    try:
        trees = [set(subprocess.check_output(
            ["git", "ls-tree", "-r", "--name-only", ref, "--", *RSA_ONLY_FILE_BINDINGS],
            text=True, stderr=subprocess.DEVNULL, timeout=10).splitlines()) for ref in refs]
        if not RSA_ONLY_FILE_BINDINGS.keys() <= trees[1]:
            return None
        return {path: tuple(
            subprocess.check_output(["git", "show", f"{ref}:{path}"],
                stderr=subprocess.DEVNULL, timeout=10) if path in tree else None
            for ref, tree in zip(refs, trees)) for path in RSA_ONLY_FILE_BINDINGS}
    except (OSError, subprocess.SubprocessError):
        return None

# One producer-path repair after the r4 source contract landed. Only these two
# changed files may bootstrap; the exact same SOURCE/lock must exist at both
# refs. Main always takes the normal packaged path after the producer succeeds.
GEPH_PHYSICAL_ROOT_REQUIRED = frozenset({
    ".github/workflows/build-geph.yml", "scripts/test_geph_source_owned_workflows.py",
})
GEPH_PHYSICAL_ROOT_ALLOWED = GEPH_PHYSICAL_ROOT_REQUIRED | {
    "scripts/ci_scope.py", "scripts/test_ci_scope.py", "docs/CURRENT_STATE.md",
}
GEPH_PHYSICAL_ROOT_FILE_BINDINGS = {
    ".github/workflows/build-geph.yml": (
        "f4fedc115b2148dd3dcb7f50ca33c045ebabd832770d47efba094ac66ab9a5e1",
        "f7e49e1aac5360fc7764616b5343290819591932ec5aa57aba374cc977ebcfa7",
    ),
    "scripts/test_geph_source_owned_workflows.py": (
        "b933f3169e4b3389bcd1fd1ecd0b61d5fe8add62176bca0a2b077b12a12bd234",
        "e6ced05362b6d5500fbe92b61c407690f7fdb3b277837294ddf7561588b29351",
    ),
    "vendor/geph/SOURCE.json": (
        "69d5de39654dea018075469d20ea7892cc35f5af0466d19a7811ef3316b60df7",
        "69d5de39654dea018075469d20ea7892cc35f5af0466d19a7811ef3316b60df7",
    ),
    "vendor/geph/Cargo.lock": (
        "560504e697c28f2114ec16414e5dc372e1903df986ba36792aab9a12c34631cb",
        "560504e697c28f2114ec16414e5dc372e1903df986ba36792aab9a12c34631cb",
    ),
}


def reviewed_geph_physical_root_delta(deltas: dict | None) -> bool:
    if not GEPH_PHYSICAL_ROOT_FILE_BINDINGS or not isinstance(deltas, dict):
        return False
    if deltas.keys() != GEPH_PHYSICAL_ROOT_FILE_BINDINGS.keys():
        return False
    for path, expected in GEPH_PHYSICAL_ROOT_FILE_BINDINGS.items():
        pair = deltas[path]
        if not isinstance(pair, tuple) or len(pair) != 2 or not all(isinstance(v, bytes) for v in pair):
            return False
        if tuple(hashlib.sha256(v).hexdigest() for v in pair) != expected:
            return False
    return True


def geph_physical_root_delta_from_git() -> dict | None:
    refs = (os.environ.get("BASE_SHA", ""), os.environ.get("GITHUB_SHA", ""))
    if not all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in refs):
        return None
    try:
        return {path: tuple(subprocess.check_output(
            ["git", "show", f"{ref}:{path}"], stderr=subprocess.DEVNULL, timeout=10)
            for ref in refs) for path in GEPH_PHYSICAL_ROOT_FILE_BINDINGS}
    except (OSError, subprocess.SubprocessError):
        return None


# One coordinated delivery repair. Exact file bytes keep this from becoming a
# general app/policy exemption. Full packaged checks still run on main, after
# its producer publishes the reviewed Geph dependency; both audits run on PRs.
DELIVERY_FILE_BINDINGS = {
    '.github/workflows/dependency-audit.yml': (
        '712ded84e3de62029067b6c3549829b3ed62e3a19b510a25cee842f684313285',
        '709049d4b60b63a2e1d3d1150028457af1ea28c0627dc4b26c069f24fe9bb29f'),
    'vendor/chromium-headless-shell/SOURCE.json': (
        'bec2143e32afe1dfc128baff9183001451e3814c942140e782519d4363f49629',
        '91a914cb43c5f8a6be8d3dc2da1ca4a05c963f95938a5c4bb0ab9cd5bbf05618'),
    'app-tauri/src-tauri/src/browser_probe.rs': (
        '20ccd41ac021c5308a70eeeca70779e93a629dbb3069185ac1a87bcb52df54cb',
        '3d2b36ac1047fbc3f9cf25cc6ede2a69f104bcdeafa60371ab38177463839882'),
    'security/dependency-audit-policy.json': (
        'a3e663bdc2d5a999b9454f6cb95d35711240793d337acc3e3a7b1b32892efb16',
        'dbcab882c56bd7daec4cdc8d964f95a84359cf83c66050497cae081b01009bdd'),
    'scripts/dependency_audit.py': (
        'a73162775fe9a47f00dc302e4d91ff9d828b7e54e17aef1a96603d8f87b246eb',
        'e40869f5329103af2b595f001bfe0b9941c25422b284fa4f6b49a7ad444d4cf9'),
}
DELIVERY_TEST_PATHS = frozenset({
    "scripts/test_build_config.py",
    "scripts/test_dependency_audit.py",
    "scripts/test_materialize_chromium_headless_shell.py",
    "scripts/test_make_release_manifest.py",
    "scripts/test_verify_release_artifacts.py",
})
# Coordinate the emSign trust-store repair with the Geph producer. Every Python
# lock must carry this exact certifi-only update; installer options, unrelated
# dependencies and a partial runtime/test/build update take ordinary packaging.
PYTHON_LOCK_FILE_BINDINGS = {
    "spike/requirements-runtime.txt": (
        "dbc2159711423ff43b87f697c62ae482869bcbe8ec7b697089606a70b910f828",
        "540a6aae9d82fca17647fa052eb772ffb8e1d77b7c4f53c0513a3cca42a7fe74"),
    "spike/requirements.txt": (
        "986abfc91327d355981a05184e7b7b2f5fe6f576a84338c19c021f6bb72a5cda",
        "2c79f2c8c826eb2203dea9b765283f57b1bab894112cc65e7a4309867435a975"),
    "spike/requirements-build.txt": (
        "1192b9d29eb533db2bf29733ee494448d8c12c38a8b9c49f1e06fbda424078f9",
        "a740216126da538358eb8009447d6afc64d70819390a9c82d207be727a36179d"),
}
GEPH_BOOTSTRAP_ALLOWED = (GEPH_BOOTSTRAP_ALLOWED | DELIVERY_FILE_BINDINGS.keys()
                          | DELIVERY_TEST_PATHS | PYTHON_LOCK_FILE_BINDINGS.keys())


def reviewed_delivery_delta(deltas: dict[str, tuple[bytes, bytes]] | None) -> bool:
    if deltas is None or deltas.keys() != DELIVERY_FILE_BINDINGS.keys():
        return False
    try:
        return all(
            tuple(hashlib.sha256(value).hexdigest() for value in deltas[path]) == binding
            for path, binding in DELIVERY_FILE_BINDINGS.items()
        )
    except (TypeError, ValueError):
        return False


def delivery_delta_from_git() -> dict[str, tuple[bytes, bytes]] | None:
    refs = (os.environ.get("BASE_SHA", ""), os.environ.get("GITHUB_SHA", ""))
    if not all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in refs):
        return None
    try:
        return {
            path: tuple(subprocess.check_output(
                ["git", "show", f"{ref}:{path}"], stderr=subprocess.DEVNULL,
                timeout=10) for ref in refs)
            for path in DELIVERY_FILE_BINDINGS
        }
    except (OSError, subprocess.SubprocessError):
        return None


def reviewed_python_lock_delta(deltas: dict[str, tuple[bytes, bytes]] | None) -> bool:
    if deltas is None or deltas.keys() != PYTHON_LOCK_FILE_BINDINGS.keys():
        return False
    try:
        return all(
            tuple(hashlib.sha256(value).hexdigest() for value in deltas[path]) == binding
            for path, binding in PYTHON_LOCK_FILE_BINDINGS.items()
        )
    except (TypeError, ValueError):
        return False


def python_lock_delta_from_git() -> dict[str, tuple[bytes, bytes]] | None:
    refs = (os.environ.get("BASE_SHA", ""), os.environ.get("GITHUB_SHA", ""))
    if not all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in refs):
        return None
    try:
        return {
            path: tuple(subprocess.check_output(
                ["git", "show", f"{ref}:{path}"], stderr=subprocess.DEVNULL,
                timeout=10) for ref in refs)
            for path in PYTHON_LOCK_FILE_BINDINGS
        }
    except (OSError, subprocess.SubprocessError):
        return None


WINDOWS_PREFIXES = (
    "contracts/",
    "crates/slipstream-core/",
    "crates/slipstream-userspace-stack-evaluation/",
    "crates/slipstream-userspace-stack-effect-evaluation/",
    "crates/slipstream-windows-adapter/",
    "vendor/wintun/",
)
WINDOWS_EXACT = frozenset(
    {
        ".github/workflows/ci.yml",
        ".github/workflows/windows-packet-adapter-qualification.yml",
    }
)


@dataclass(frozen=True)
class CiScope:
    geph_bootstrap: bool
    product: bool
    windows: bool


def _validate_path(raw: str) -> str:
    if "\x00" in raw or "\n" in raw or "\r" in raw:
        raise ValueError("changed path contains a forbidden control character")
    path = PurePosixPath(raw)
    if (
        not raw
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in raw.split("/"))
    ):
        raise ValueError(f"invalid repository-relative changed path: {raw!r}")
    return raw


def _is_documentation(path: str) -> bool:
    return (
        path in {"README.md", "README.en.md"}
        or path.startswith("docs/")
        or path.endswith(".md")
    )


APP_LOCK = "app-tauri/src-tauri/Cargo.lock"
# Reviewed TLS migrations only. This is not a blanket lockfile
# exemption: any other dependency, checksum, dependency edge or metadata change
# must take the ordinary packaged-build path.
APP_LOCK_REPAIRS = (
    ("rustls", "0.23.41", "6b92b125634d9b795e7beca796cc790df15a7fb38323bf3196fda83292d06b1f",
     "0.23.45", "0d41d731c7d2f962d1ccc364cec258de3c0e93b38c2fb3ba97ac74513048d634"),
    ("rustls-webpki", "0.103.13", "61c429a8649f110dddef65e2a5ad240f747e85f7758a6bccc7e5777bd33f756e",
     "0.103.15", "f3c3cf1d8b1e7d4927e2d154c3fcb02979afb9939629c62cd9048d4f07b60ac2"),
)
APP_LOCK_REPAIR_SETS = (
    APP_LOCK_REPAIRS,
    # RUSTSEC-2026-0346/0347/0348/0349. The previous migration is already on
    # main; recognize this exact subsequent repair without admitting other
    # lockfile changes into source bootstrap.
    (("rustls", "0.23.45", "0d41d731c7d2f962d1ccc364cec258de3c0e93b38c2fb3ba97ac74513048d634",
      "0.23.46", "48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf"),),
    # The same delivery graph also repairs the five current QUIC advisories.
    # Version/checksum pairs only; dependency edges and all other bytes of the
    # parsed lock contract must still be unchanged.
    (
        ("rustls", "0.23.45", "0d41d731c7d2f962d1ccc364cec258de3c0e93b38c2fb3ba97ac74513048d634",
         "0.23.46", "48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf"),
        ("quinn-proto", "0.11.16", "2f4bfc015262b9df63c8845072ce59068853ff5872180c2ce2f13038b970e560",
         "0.11.18", "a9746dbde176634f4f2f1faf2404e30a31b2bc1e9cafb5329c95d8177a18c9fc"),
    ),
    # RUSTSEC-2026-0382/0381: certificate-validation and emSign root repair.
    # Both version/checksum changes are required, with every edge preserved.
    (
        ("rustls-webpki", "0.103.15", "f3c3cf1d8b1e7d4927e2d154c3fcb02979afb9939629c62cd9048d4f07b60ac2",
         "0.103.16", "4443b1b6d39d7c663139942cc4558262562d2c84123bb6282ef177009ca8b281"),
        ("webpki-roots", "1.0.9", "7dcd9d09a39985f5344844e66b0c530a33843579125f23e21e9f0f220850f22a",
         "1.0.10", "1c1c8e20c8a38fc7d65abfe74eb7280e4aa667e8eec8bc84996d2874810748d9"),
    ),
)


def reviewed_app_lock_repair(before: str, after: str) -> bool:
    try:
        original, actual = tomllib.loads(before), tomllib.loads(after)
        for repairs in APP_LOCK_REPAIR_SETS:
            expected = copy.deepcopy(original)
            for name, old, old_hash, new, new_hash in repairs:
                matches = [p for p in expected["package"] if p["name"] == name and p["version"] == old]
                if len(matches) != 1:
                    break
                package = matches[0]
                if package.get("checksum") != old_hash or package.get("source") != "registry+https://github.com/rust-lang/crates.io-index":
                    break
                if any(p["name"] == name and p["version"] == new
                       and p.get("source") == package["source"] for p in expected["package"]):
                    break
                package.update(version=new, checksum=new_hash)
            else:
                if actual == expected:
                    return True
        return False
    except (ValueError, KeyError, TypeError):
        return False


def app_lock_delta_from_git() -> tuple[str, str] | None:
    refs = (os.environ.get("BASE_SHA", ""), os.environ.get("GITHUB_SHA", ""))
    if not all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in refs):
        return None
    try:
        return tuple(subprocess.check_output(
            ["git", "show", f"{ref}:{APP_LOCK}"], text=True, stderr=subprocess.DEVNULL,
            timeout=10) for ref in refs)
    except (OSError, subprocess.SubprocessError):
        return None


def classify_paths(paths: list[str], *, event_name: str,
                   app_lock_delta: tuple[str, str] | None = None,
                   delivery_delta: dict[str, tuple[bytes, bytes]] | None = None,
                   python_lock_delta: dict[str, tuple[bytes, bytes]] | None = None,
                   rsa_only_delta: dict | None = None,
                   geph_physical_root_delta: dict | None = None) -> CiScope:
    if event_name not in {"pull_request", "push"}:
        raise ValueError(f"unsupported CI event: {event_name}")
    changed = {_validate_path(path) for path in paths if path}
    if not changed:
        return CiScope(geph_bootstrap=False, product=True, windows=True)
    product = any(not _is_documentation(path) for path in changed)
    windows = any(
        path in WINDOWS_EXACT or path.startswith(WINDOWS_PREFIXES)
        for path in changed
    )
    geph_bootstrap = (
        event_name == "pull_request"
        and (GEPH_BOOTSTRAP_REQUIRED.issubset(changed) or {
            "vendor/geph/SOURCE.json", "scripts/geph_vendor_source.py",
            "scripts/test_geph_source_edits.py",
        }.issubset(changed) or (
            # Existing guarded source edits may change without a lock update.
            # verify-transition still validates the exact contract/revision;
            # binary and application changes cannot enter this path.
            "vendor/geph/SOURCE.json" in changed
            and changed.issubset({
                "vendor/geph/SOURCE.json", "vendor/geph/README.md", "docs/CURRENT_STATE.md",
                "docs/DECISIONS.md", "scripts/ci_scope.py",
                "scripts/test_ci_scope.py",
            })
        ))
        and changed.issubset(GEPH_BOOTSTRAP_ALLOWED)
        and (not (changed & DELIVERY_FILE_BINDINGS.keys()) or (
            (DELIVERY_FILE_BINDINGS.keys() | DELIVERY_TEST_PATHS | GEPH_BOOTSTRAP_REQUIRED).issubset(changed)
            and reviewed_delivery_delta(delivery_delta)))
        and (not (changed & PYTHON_LOCK_FILE_BINDINGS.keys()) or (
            (PYTHON_LOCK_FILE_BINDINGS.keys() | GEPH_BOOTSTRAP_REQUIRED).issubset(changed)
            and reviewed_python_lock_delta(python_lock_delta)))
        and ("scripts/run_geph_synthetic_tests.py" not in changed or "scripts/test_run_geph_synthetic_tests.py" in changed)
        and ("scripts/geph_vendor_source.py" not in changed or "scripts/test_geph_source_edits.py" in changed)
        and (APP_LOCK not in changed or (
            app_lock_delta is not None and reviewed_app_lock_repair(*app_lock_delta)))
        and ("scripts/ci_scope.py" not in changed or "scripts/test_ci_scope.py" in changed)
        and (".github/workflows/build-geph.yml" not in changed or "scripts/test_build_config.py" in changed)
    )
    rsa_only_bootstrap = (
        event_name == "pull_request"
        and RSA_ONLY_REVIEW in RSA_ONLY_FILE_BINDINGS
        and GEPH_BOOTSTRAP_REQUIRED <= RSA_ONLY_FILE_BINDINGS.keys()
        and RSA_ONLY_FILE_BINDINGS.keys() <= changed
        and changed <= RSA_ONLY_FILE_BINDINGS.keys() | RSA_ONLY_SUPPORT_PATHS
        and reviewed_rsa_only_delta(rsa_only_delta)
    )
    physical_root_bootstrap = (
        event_name == "pull_request"
        and GEPH_PHYSICAL_ROOT_REQUIRED <= changed
        and changed <= GEPH_PHYSICAL_ROOT_ALLOWED
        and ("scripts/ci_scope.py" not in changed or "scripts/test_ci_scope.py" in changed)
        and reviewed_geph_physical_root_delta(geph_physical_root_delta)
    )
    return CiScope(
        geph_bootstrap=geph_bootstrap or rsa_only_bootstrap or physical_root_bootstrap,
        product=product,
        windows=windows,
    )


def write_github_output(path: Path, scope: CiScope) -> None:
    with path.open("a", encoding="utf-8") as output:
        output.write(f"geph_bootstrap={str(scope.geph_bootstrap).lower()}\n")
        output.write(f"product={str(scope.product).lower()}\n")
        output.write(f"windows={str(scope.windows).lower()}\n")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-name", choices=("pull_request", "push"), required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    paths = [line.rstrip("\n") for line in sys.stdin]
    delta = app_lock_delta_from_git() if args.event_name == "pull_request" and APP_LOCK in paths else None
    delivery_delta = (delivery_delta_from_git()
        if args.event_name == "pull_request" and set(paths) & DELIVERY_FILE_BINDINGS.keys() else None)
    python_lock_delta = (python_lock_delta_from_git()
        if args.event_name == "pull_request" and set(paths) & PYTHON_LOCK_FILE_BINDINGS.keys() else None)
    rsa_only_delta = (rsa_only_delta_from_git()
        if args.event_name == "pull_request" and RSA_ONLY_REVIEW in paths else None)
    physical_root_delta = (geph_physical_root_delta_from_git()
        if args.event_name == "pull_request" and GEPH_PHYSICAL_ROOT_REQUIRED <= set(paths) else None)
    scope = classify_paths(paths, event_name=args.event_name, app_lock_delta=delta,
                           delivery_delta=delivery_delta, python_lock_delta=python_lock_delta,
                           rsa_only_delta=rsa_only_delta,
                           geph_physical_root_delta=physical_root_delta)
    write_github_output(args.github_output, scope)
    print(json.dumps(asdict(scope), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
