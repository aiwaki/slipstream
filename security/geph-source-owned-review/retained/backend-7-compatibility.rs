//! Offline wire/compatibility qualification only. All token/key bytes are public
//! test fixtures; no Geph application, database, account or network code runs.
use super::*;
use serde::{Deserialize, Serialize};
use stdcode::StdcodeSerializeExt;
mod account {
    include!("../../../account_level_fixture.rs");
}
use account::AccountLevel;

// Exact field order/container shapes from mizaru2 0.2.21. Candidate wire DTOs
// remain test-only: these tests do not add a production Mizaru adapter.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct ClientToken([u8; 32]);
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct BlindedClientToken(Vec<u8>);
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct SinglePublicKey(Vec<u8>);
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
struct MerklePublicKey(blake3::Hash);
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct SingleBlindedSignature {
    used_key: Vec<u8>,
    blinded_sig: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct SingleUnblindedSignature {
    unblinded_sig: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct BlindedSignature {
    epoch: u16,
    used_key: Vec<u8>,
    merkle_branch: Vec<blake3::Hash>,
    blinded_sig: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct UnblindedSignature {
    epoch: u16,
    used_key: Vec<u8>,
    merkle_branch: Vec<blake3::Hash>,
    unblinded_sig: Vec<u8>,
}

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../../compat-vectors.json")).unwrap()
}
fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join(path),
    )
    .unwrap()
}
fn merkle_root(epoch: u16, der: &[u8], branch: &[blake3::Hash]) -> Result<[u8; 32]> {
    // Prevent an oversized proof from shifting u16 by 16 or more. <=16 keeps
    // historical shorter-branch behavior; complete issuer trees use 16 levels.
    if branch.len() > 16 {
        return Err(Error::BadLength);
    }
    let mut acc = blake3::hash(der);
    for (i, h) in branch.iter().enumerate() {
        acc = if epoch >> i & 1 == 0 {
            blake3::keyed_hash(acc.as_bytes(), h.as_bytes())
        } else {
            blake3::keyed_hash(h.as_bytes(), acc.as_bytes())
        };
    }
    Ok(*acc.as_bytes())
}
fn verify_member(root: &[u8; 32], epoch: u16, der: &[u8], branch: &[blake3::Hash]) -> Result<()> {
    if merkle_root(epoch, der, branch)? != *root {
        return Err(Error::InvalidSignature);
    }
    Ok(())
}
fn finish_response(
    pending: Pending,
    epoch: u16,
    root: &[u8; 32],
    response: BlindedSignature,
) -> Result<UnblindedSignature> {
    if response.epoch != epoch {
        return Err(Error::BadKey);
    }
    let response_key = PublicKey::from_der(&response.used_key)?;
    let (response_n, response_e) = response_key.n_e();
    let (pending_n, pending_e) = pending.key.n_e();
    // Mizaru accepts either DER container on import, while its signing side
    // emits PKCS#1. Bind this operation to the public numbers; preserve the
    // response's exact DER for the Merkle leaf and returned cache DTO.
    if unsafe { ffi::BN_cmp(response_n, pending_n) } != 0
        || unsafe { ffi::BN_cmp(response_e, pending_e) } != 0
    {
        return Err(Error::BadKey);
    }
    verify_member(root, epoch, &response.used_key, &response.merkle_branch)?;
    let signature = pending.finalize(&response.blinded_sig)?;
    Ok(UnblindedSignature {
        epoch,
        used_key: response.used_key,
        merkle_branch: response.merkle_branch,
        unblinded_sig: signature,
    })
}
fn verify_wire(root: &[u8; 32], token: &ClientToken, signature: &UnblindedSignature) -> Result<()> {
    verify_member(
        root,
        signature.epoch,
        &signature.used_key,
        &signature.merkle_branch,
    )?;
    PublicKey::from_der(&signature.used_key)?.verify(
        &token.0,
        &signature.unblinded_sig,
        Hash::Sha256,
        -2,
    )
}
fn eq_wire<T>(value: &T, expected: &Value)
where
    T: Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let bytes = unhex(expected.as_str().unwrap());
    assert_eq!(value.stdcode(), bytes);
    assert_eq!(&stdcode::deserialize::<T>(&bytes).unwrap(), value);
}

#[test]
fn spki_and_pkcs1_preserve_original_der_and_reject_trailing_or_unknown_oid() {
    let baseline = live();
    for v in vectors().as_array().unwrap() {
        let der = field(v, "used_key");
        let key = PublicKey::from_der(&der).unwrap();
        assert_eq!(key.original_der(), der);
        assert_eq!(key.width, v["size_bytes"].as_u64().unwrap() as usize);
        let mut trailing = der.clone();
        trailing.push(0);
        assert!(matches!(PublicKey::from_der(&trailing), Err(Error::BadKey)));
        assert!(matches!(
            PublicKey::from_der(&der[..der.len() - 1]),
            Err(Error::BadKey)
        ));
        if v["format"] == "spki" {
            assert!(PublicKey::from_pkcs1_der(&der).is_err());
            // Public test DER: replace rsaEncryption OID with an unknown OID.
            let oid = [
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
            ];
            let mut wrong = der.clone();
            let pos = wrong.windows(oid.len()).position(|w| w == oid).unwrap();
            wrong[pos + oid.len() - 1] = 0x7f;
            assert!(matches!(PublicKey::from_der(&wrong), Err(Error::BadKey)));
        }
    }
    assert_eq!(live(), baseline);
}
#[test]
fn spki_algorithm_identifier_requires_rsa_encryption_and_null_parameters() {
    let v = vectors();
    let original = field(&v[1], "used_key");
    let oid = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    ];
    let pos = original.windows(oid.len()).position(|w| w == oid).unwrap();
    assert_eq!(&original[pos + oid.len()..pos + oid.len() + 2], &[0x05, 0]);
    let mut octets = original.clone();
    octets[pos + oid.len()] = 0x04;
    let mut pss = original.clone();
    pss[pos + oid.len() - 1] = 0x0a;
    pss[pos + oid.len()] = 0x30;
    // This public fixture uses a two-byte outer length and one-byte algorithm
    // length. Keep DER framing valid while deleting NULL or appending an item.
    assert_eq!(&original[..2], &[0x30, 0x82]);
    assert_eq!(&original[4..6], &[0x30, 13]);
    let outer_length = u16::from_be_bytes(original[2..4].try_into().unwrap());
    let mut missing_null = original.clone();
    missing_null.drain(pos + oid.len()..pos + oid.len() + 2);
    missing_null[5] -= 2;
    missing_null[2..4].copy_from_slice(&(outer_length - 2).to_be_bytes());
    let mut extra_item = original.clone();
    extra_item.splice(pos + oid.len() + 2..pos + oid.len() + 2, [0x05, 0]);
    extra_item[5] += 2;
    extra_item[2..4].copy_from_slice(&(outer_length + 2).to_be_bytes());
    assert!(PublicKey::from_der(&original).is_ok());
    for invalid in [octets, pss, missing_null, extra_item] {
        let baseline = live();
        assert!(matches!(PublicKey::from_der(&invalid), Err(Error::BadKey)));
        assert_eq!(live(), baseline);
    }
}
#[test]
fn exponent_three_and_non_byte_aligned_keys_use_native_pss_and_roundtrip() {
    let baseline = live();
    for v in vectors().as_array().unwrap() {
        let key = PublicKey::from_der(&field(v, "used_key")).unwrap();
        let token: [u8; 32] = field(v, "token").try_into().unwrap();
        let encoded = key.encode(&token, Hash::Sha256, 0).unwrap();
        if v["actual_bits"] == 2049 {
            assert_eq!(encoded.0.len(), 257);
            assert_eq!(encoded.0[0], 0);
        }
        let pending = key.blind_token(&token).unwrap();
        let bsig = sign_fixture(
            &pending.blinded,
            &fixture(v["private_fixture"].as_str().unwrap()),
        );
        let sig = pending.finalize(&bsig).unwrap();
        key.verify(&token, &sig, Hash::Sha256, 0).unwrap();
        if v["legacy_finalize"] == "accepted" {
            assert_eq!(sig, field(v, "signature"));
        } else {
            assert_eq!(v["legacy_finalize"], "error:VerificationFailed");
            // Legacy accepts this DER but its rounded-bit blind encoder yields
            // a signature its actual-bit verifier rejects. Preserve evidence.
            let wrong = pending_from_vector(
                &key,
                encoded.0.clone(),
                &field(v, "inverse"),
                &token,
                Hash::Sha256,
            );
            assert_ne!(wrong.blinded, field(v, "blinded"));
            assert_eq!(
                wrong.finalize(&field(v, "blind_signature")),
                Err(Error::InvalidSignature)
            );
        }
    }
    assert_eq!(live(), baseline);
}
#[test]
fn cross_key_and_cross_operation_responses_never_finalize() {
    let vs = vectors();
    let a = &vs[0];
    let b = &vs[4];
    let ka = PublicKey::from_der(&field(a, "used_key")).unwrap();
    let kb = PublicKey::from_der(&field(b, "used_key")).unwrap();
    let token = [0xa5; 32];
    let baseline = live();
    let pa = ka.blind_token(&token).unwrap();
    let pb = kb.blind_token(&token).unwrap();
    let bsig = sign_fixture(
        &pb.blinded,
        &fixture(b["private_fixture"].as_str().unwrap()),
    );
    assert!(pa.finalize(&bsig).is_err());
    let signature = pb.finalize(&bsig).unwrap();
    kb.verify(&token, &signature, Hash::Sha256, -2).unwrap();
    assert!(ka.verify(&token, &signature, Hash::Sha256, -2).is_err());
    let pa = ka.blind_token(&token).unwrap();
    let pb = ka.blind_token(&token).unwrap();
    assert_ne!(pa.blinded, pb.blinded);
    let bsig = sign_fixture(
        &pa.blinded,
        &fixture(a["private_fixture"].as_str().unwrap()),
    );
    assert!(pb.finalize(&bsig).is_err());
    pa.finalize(&bsig).unwrap();
    assert_eq!(live(), baseline);
}
#[test]
fn extended_zero_and_n_plus_one_representatives_fail_in_verify_and_finalize() {
    let v = vectors();
    let v = &v[0];
    let key = PublicKey::from_der(&field(v, "used_key")).unwrap();
    let token: [u8; 32] = field(v, "token").try_into().unwrap();
    let n = Bn::new().unwrap();
    assert!(!unsafe { ffi::BN_copy(n.0.as_ptr(), key.n_e().0) }.is_null());
    ok(unsafe { ffi::BN_add_word(n.0.as_ptr(), 1) }).unwrap();
    let n_plus_one = n.bytes(key.width).unwrap();
    let mut extended = field(v, "signature");
    extended.push(0);
    let mut leading = vec![0];
    leading.extend(field(v, "signature"));
    for (value, expected) in [
        (vec![0; key.width], Error::InvalidSignature),
        (n_plus_one, Error::OutOfRange),
        (extended, Error::BadLength),
        (leading, Error::BadLength),
    ] {
        let baseline = live();
        assert_eq!(key.verify(&token, &value, Hash::Sha256, -2), Err(expected));
        let pending = key.blind_token(&token).unwrap();
        assert!(pending.finalize(&value).is_err());
        assert_eq!(live(), baseline);
    }
}
#[test]
fn mizaru_dtos_merkle_and_account_cache_cross_backend_bytes() {
    let mut candidate_output = vec![];
    for v in vectors().as_array().unwrap() {
        let der = field(v, "used_key");
        let key = PublicKey::from_der(&der).unwrap();
        let token = ClientToken(field(v, "token").try_into().unwrap());
        let pending = key.blind_token(&token.0).unwrap();
        let signed = sign_fixture(
            &pending.blinded,
            &fixture(v["private_fixture"].as_str().unwrap()),
        );
        let signature = pending.finalize(&signed).unwrap();
        let single = SingleUnblindedSignature {
            unblinded_sig: signature.clone(),
        };
        if v["legacy_finalize"] == "accepted" {
            let w = &v["stdcode"];
            eq_wire(&SinglePublicKey(der.clone()), &w["single_public_key"]);
            eq_wire(&token, &w["token"]);
            eq_wire(
                &BlindedClientToken(field(v, "blinded")),
                &w["blinded_token"],
            );
            let sb = SingleBlindedSignature {
                used_key: der.clone(),
                blinded_sig: field(v, "blind_signature"),
            };
            eq_wire(&sb, &w["single_blinded_signature"]);
            let pending = pending_from_vector(
                &key,
                key.encode(&token.0, Hash::Sha256, 0).unwrap().0.clone(),
                &field(v, "inverse"),
                &token.0,
                Hash::Sha256,
            );
            assert_eq!(pending.blinded, field(v, "blinded"));
            assert_eq!(pending.finalize(&sb.blinded_sig).unwrap(), signature);
            eq_wire(&single, &w["single_unblinded_signature"]);
            eq_wire(&(token.clone(), single), &w["single_cache"]);
            eq_wire(&AccountLevel::Free, &w["account_free"]);
            eq_wire(&AccountLevel::Plus, &w["account_plus"]);
        }
        let mut caches = vec![];
        let branch: Vec<_> = (0..16u8).map(|i| blake3::hash(&[i])).collect();
        for epoch in [0u16, 42, 65535] {
            let root = merkle_root(epoch, key.original_der(), &branch).unwrap();
            let unblinded = UnblindedSignature {
                epoch,
                used_key: der.clone(),
                merkle_branch: branch.clone(),
                unblinded_sig: signature.clone(),
            };
            verify_wire(&root, &token, &unblinded).unwrap();
            for level in [AccountLevel::Free, AccountLevel::Plus] {
                let tuple = (level, token.clone(), unblinded.clone());
                let bytes = tuple.stdcode();
                let decoded: (AccountLevel, ClientToken, UnblindedSignature) =
                    stdcode::deserialize(&bytes).unwrap();
                assert_eq!(decoded, tuple);
                if v["legacy_finalize"] == "accepted" {
                    let c = v["caches"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|c| c["epoch"] == epoch && c["level"] == serde_json::json!(level))
                        .unwrap();
                    assert_eq!(root.as_slice(), field(c, "root"));
                    eq_wire(
                        &MerklePublicKey(blake3::Hash::from(root)),
                        &c["merkle_public_key"],
                    );
                    eq_wire(&tuple, &c["bytes"]);
                    eq_wire(&unblinded, &c["unblinded_signature"]);
                    let blinded = BlindedSignature {
                        epoch,
                        used_key: der.clone(),
                        merkle_branch: branch.clone(),
                        blinded_sig: field(v, "blind_signature"),
                    };
                    eq_wire(&blinded, &c["blinded_signature"]);
                    let pending = pending_from_vector(
                        &key,
                        key.encode(&token.0, Hash::Sha256, 0).unwrap().0.clone(),
                        &field(v, "inverse"),
                        &token.0,
                        Hash::Sha256,
                    );
                    assert_eq!(
                        finish_response(pending, epoch, &root, blinded).unwrap(),
                        unblinded
                    );
                }
                caches.push(serde_json::json!({"epoch":epoch,"level":level,"cache_key":format!("conn_token_{epoch}"),"root":hex::encode(root),"bytes":hex::encode(bytes)}));
            }
        }
        candidate_output.push(serde_json::json!({"name":v["name"],"format":v["format"],"used_key":hex::encode(der),"token":hex::encode(token.0),"signature":hex::encode(signature),"caches":caches}));
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    std::fs::write(
        root.join("compat-candidate-output.json"),
        serde_json::to_vec_pretty(&candidate_output).unwrap(),
    )
    .unwrap();
}
#[test]
fn response_accepts_same_key_in_other_der_container_with_exact_response_merkle() {
    let vs = vectors();
    for (request_index, response_index) in [(0, 1), (1, 0), (4, 5), (5, 4)] {
        let request = &vs[request_index];
        let response_vector = &vs[response_index];
        let key = PublicKey::from_der(&field(request, "used_key")).unwrap();
        let token = ClientToken(field(request, "token").try_into().unwrap());
        let baseline = live();
        let pending = pending_from_vector(
            &key,
            key.encode(&token.0, Hash::Sha256, 0).unwrap().0.clone(),
            &field(request, "inverse"),
            &token.0,
            Hash::Sha256,
        );
        let epoch = 42;
        let branch: Vec<_> = (0..16u8).map(|i| blake3::hash(&[i])).collect();
        let der = field(response_vector, "used_key");
        let root = merkle_root(epoch, &der, &branch).unwrap();
        let response = BlindedSignature {
            epoch,
            used_key: der.clone(),
            merkle_branch: branch,
            blinded_sig: field(request, "blind_signature"),
        };
        let signature = finish_response(pending, epoch, &root, response).unwrap();
        assert_eq!(signature.used_key, der);
        assert_eq!(signature.unblinded_sig, field(request, "signature"));
        verify_wire(&root, &token, &signature).unwrap();
        let expected_cache = &response_vector["caches"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["epoch"] == epoch && c["level"] == "Free")
            .unwrap()["bytes"];
        eq_wire(&(AccountLevel::Free, token, signature), expected_cache);
        assert_eq!(live(), baseline);
    }
}
#[test]
fn response_der_epoch_root_and_branch_ownership_is_bound() {
    let vs = vectors();
    let a = &vs[0];
    let other_format = &vs[1];
    let der = field(a, "used_key");
    let key = PublicKey::from_der(&der).unwrap();
    let token: [u8; 32] = field(a, "token").try_into().unwrap();
    let branch: Vec<_> = (0..16u8).map(|i| blake3::hash(&[i])).collect();
    let epoch = 42u16;
    let root = merkle_root(epoch, &der, &branch).unwrap();
    let base = BlindedSignature {
        epoch,
        used_key: der.clone(),
        merkle_branch: branch.clone(),
        blinded_sig: field(a, "blind_signature"),
    };
    // Same mathematical public key in a different DER container has another leaf.
    let spki = field(other_format, "used_key");
    assert_ne!(merkle_root(epoch, &spki, &branch).unwrap(), root);
    for mode in 0..6 {
        let baseline = live();
        let mut response = base.clone();
        let mut expected_root = root;
        match mode {
            0 => response.used_key = spki.clone(),
            1 => response.epoch += 1,
            2 => response.merkle_branch.reverse(),
            3 => response.merkle_branch.push(blake3::hash(&[99])),
            4 => expected_root[0] ^= 1,
            _ => {
                // Even a trusted Merkle root cannot authorize swapping the
                // mathematical key that owns the pending blind operation.
                response.used_key = field(&vs[4], "used_key");
                expected_root = merkle_root(epoch, &response.used_key, &branch).unwrap();
            }
        }
        let pending = pending_from_vector(
            &key,
            key.encode(&token, Hash::Sha256, 0).unwrap().0.clone(),
            &field(a, "inverse"),
            &token,
            Hash::Sha256,
        );
        assert!(finish_response(pending, epoch, &expected_root, response).is_err());
        assert_eq!(live(), baseline);
    }
    assert_eq!(
        merkle_root(epoch, &der, &[blake3::hash(&[0]); 17]),
        Err(Error::BadLength)
    );
    assert_eq!(
        merkle_root(epoch, &der, &[]).unwrap(),
        *blake3::hash(&der).as_bytes()
    );
}
#[test]
fn cache_decode_rejects_trailing_truncated_or_unknown_account_level() {
    let vs = vectors();
    let row = &vs[0]["caches"][0];
    let bytes = field(row, "bytes");
    type Cache = (AccountLevel, ClientToken, UnblindedSignature);
    assert!(stdcode::deserialize::<Cache>(&bytes).is_ok());
    let mut trailing = bytes.clone();
    trailing.push(0);
    let mut wrong_level = bytes.clone();
    wrong_level[0] = 2;
    for bad in [trailing, wrong_level, bytes[..bytes.len() - 1].to_vec()] {
        assert!(stdcode::deserialize::<Cache>(&bad).is_err());
    }
    let root_bytes: [u8; 32] = field(row, "root").try_into().unwrap();
    let root = MerklePublicKey(blake3::Hash::from(root_bytes));
    let roundtrip: MerklePublicKey = stdcode::deserialize(&root.stdcode()).unwrap();
    assert_eq!(roundtrip, root);
}
