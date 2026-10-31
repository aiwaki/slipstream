//! OUTPUT-ONLY EXPERIMENT. Not a production cryptographic implementation.
//! RSA arithmetic, hashing and PSS encoding/verifying are AWS-LC operations.
//! FFI/protocol composition still requires independent security review.
use aws_lc_sys as ffi;
mod owned;
pub use owned::OwnedPending;
use std::{
    ptr::{self, NonNull},
    rc::Rc,
};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Allocation,
    BadKey,
    BadLength,
    OutOfRange,
    Backend,
    NotInvertible,
    InvalidSignature,
    RandomGeneration,
}
type Result<T> = std::result::Result<T, Error>;
fn ok(status: i32) -> Result<()> {
    if status == 1 {
        Ok(())
    } else {
        Err(Error::Backend)
    }
}

#[cfg(test)]
thread_local! {
    static LIVE_HANDLES: std::cell::Cell<isize> = const { std::cell::Cell::new(0) };
    static ALLOCATION_BUDGET: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}
fn allocation_allowed() -> Result<()> {
    #[cfg(test)]
    ALLOCATION_BUDGET.with(|budget| match budget.get() {
        Some(0) => Err(Error::Allocation),
        Some(n) => {
            budget.set(Some(n - 1));
            Ok(())
        }
        None => Ok(()),
    })?;
    Ok(())
}
fn allocated() {
    #[cfg(test)]
    LIVE_HANDLES.with(|n| n.set(n.get() + 1));
}
fn released() {
    #[cfg(test)]
    LIVE_HANDLES.with(|n| n.set(n.get() - 1));
}
struct Bn(NonNull<ffi::BIGNUM>);
impl Bn {
    fn new() -> Result<Self> {
        allocation_allowed()?;
        let ptr = NonNull::new(unsafe { ffi::BN_new() }).ok_or(Error::Allocation)?;
        allocated();
        Ok(Self(ptr))
    }
    fn read(bytes: &[u8]) -> Result<Self> {
        let value = Self::new()?;
        if unsafe { ffi::BN_bin2bn(bytes.as_ptr(), bytes.len(), value.0.as_ptr()) }.is_null() {
            return Err(Error::Backend);
        }
        Ok(value)
    }
    fn bytes(&self, width: usize) -> Result<Vec<u8>> {
        let mut out = SecretBytes(vec![0; width]);
        ok(unsafe { ffi::BN_bn2bin_padded(out.0.as_mut_ptr(), out.0.len(), self.0.as_ptr()) })?;
        Ok(std::mem::take(&mut out.0))
    }
}
impl Drop for Bn {
    fn drop(&mut self) {
        unsafe {
            ffi::BN_clear_free(self.0.as_ptr());
            released();
        }
    }
}
struct Ctx(NonNull<ffi::BN_CTX>);
impl Ctx {
    fn new() -> Result<Self> {
        allocation_allowed()?;
        let ptr = NonNull::new(unsafe { ffi::BN_CTX_new() }).ok_or(Error::Allocation)?;
        allocated();
        Ok(Self(ptr))
    }
}
impl Drop for Ctx {
    fn drop(&mut self) {
        unsafe {
            ffi::BN_CTX_free(self.0.as_ptr());
            released();
        }
    }
}
struct Mont(NonNull<ffi::BN_MONT_CTX>);
impl Mont {
    fn new(n: *const ffi::BIGNUM, ctx: &Ctx) -> Result<Self> {
        allocation_allowed()?;
        let ptr = NonNull::new(unsafe { ffi::BN_MONT_CTX_new_for_modulus(n, ctx.0.as_ptr()) })
            .ok_or(Error::Backend)?;
        allocated();
        Ok(Self(ptr))
    }
}
impl Drop for Mont {
    fn drop(&mut self) {
        unsafe {
            ffi::BN_MONT_CTX_free(self.0.as_ptr());
            released();
        }
    }
}
struct Rsa(NonNull<ffi::RSA>);
impl Rsa {
    fn adopt(ptr: *mut ffi::RSA) -> Result<Self> {
        let ptr = NonNull::new(ptr).ok_or(Error::BadKey)?;
        allocated();
        Ok(Self(ptr))
    }
}
impl Drop for Rsa {
    fn drop(&mut self) {
        unsafe {
            ffi::RSA_free(self.0.as_ptr());
            released();
        }
    }
}

// No Debug/Clone/Serialize for private message or ephemeral state.
struct SecretBytes(Vec<u8>);
impl Drop for SecretBytes {
    fn drop(&mut self) {
        unsafe {
            ffi::OPENSSL_cleanse(self.0.as_mut_ptr().cast(), self.0.len());
            #[cfg(test)]
            owned::after_cleanse(&self.0);
        }
    }
}
#[derive(Clone, Copy)]
pub enum Hash {
    Sha256,
    Sha384,
}
impl Hash {
    fn md(self) -> *const ffi::EVP_MD {
        unsafe {
            match self {
                Self::Sha256 => ffi::EVP_sha256(),
                Self::Sha384 => ffi::EVP_sha384(),
            }
        }
    }
    fn digest(self, input: &[u8]) -> Result<SecretBytes> {
        let mut out = SecretBytes(vec![0; unsafe { ffi::EVP_MD_size(self.md()) }]);
        let mut written = 0;
        ok(unsafe {
            ffi::EVP_Digest(
                input.as_ptr().cast(),
                input.len(),
                out.0.as_mut_ptr(),
                &mut written,
                self.md(),
                ptr::null_mut(),
            )
        })?;
        if written as usize != out.0.len() {
            return Err(Error::Backend);
        }
        Ok(out)
    }
}

// Rc deliberately keeps this prototype !Send / !Sync. Thread safety and shared
// RSA internal caches are not inferred from successful sequential FFI calls.
pub struct PublicKey {
    key: Rc<Rsa>,
    width: usize,
    original_der: Rc<[u8]>,
}
fn legacy_spki_algorithm(der: &[u8]) -> bool {
    // Use AWS-LC's DER framing, then require the exact legacy AlgorithmIdentifier.
    // Its general RSA decoder otherwise ignores rsaEncryption parameters and
    // also accepts RSA-PSS keys. Neither broadening is part of this migration.
    const RSA_ENCRYPTION_NULL: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    let mut input = ffi::CBS::default();
    let mut sequence = ffi::CBS::default();
    let mut algorithm = ffi::CBS::default();
    unsafe {
        ffi::CBS_init(&mut input, der.as_ptr(), der.len());
        if ffi::CBS_get_asn1(&mut input, &mut sequence, ffi::CBS_ASN1_SEQUENCE as _) != 1
            || ffi::CBS_len(&input) != 0
            || ffi::CBS_get_asn1(&mut sequence, &mut algorithm, ffi::CBS_ASN1_SEQUENCE as _) != 1
            || ffi::CBS_len(&algorithm) != RSA_ENCRYPTION_NULL.len()
        {
            return false;
        }
        // The successful parser returns a bounded borrowed slice into der;
        // the fixed, nonzero length above excludes a null/empty slice.
        std::slice::from_raw_parts(ffi::CBS_data(&algorithm), RSA_ENCRYPTION_NULL.len())
            == RSA_ENCRYPTION_NULL
    }
}
impl PublicKey {
    /// Accept the same two DER containers as legacy Mizaru, retaining exact
    /// received bytes. Merkle membership hashes the DER, not a normalized key.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        if der.len() > 800 {
            return Err(Error::BadKey);
        }
        allocation_allowed()?;
        let mut cursor = der.as_ptr();
        let parsed = unsafe { ffi::d2i_RSA_PUBKEY(ptr::null_mut(), &mut cursor, der.len() as _) };
        if !parsed.is_null() {
            let key = Rsa::adopt(parsed)?;
            if cursor != der.as_ptr().wrapping_add(der.len()) || !legacy_spki_algorithm(der) {
                return Err(Error::BadKey);
            }
            return Self::from_parsed(key, der);
        }
        Self::from_pkcs1_der(der)
    }
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self> {
        if der.len() > 800 {
            return Err(Error::BadKey);
        }
        allocation_allowed()?;
        let key = Rsa::adopt(unsafe { ffi::RSA_public_key_from_bytes(der.as_ptr(), der.len()) })?;
        Self::from_parsed(key, der)
    }
    fn from_parsed(key: Rsa, der: &[u8]) -> Result<Self> {
        let (mut n, mut e) = (ptr::null(), ptr::null());
        unsafe {
            ffi::RSA_get0_key(key.0.as_ptr(), &mut n, &mut e, ptr::null_mut());
        }
        if n.is_null() || e.is_null() {
            return Err(Error::BadKey);
        }
        let width = unsafe { ffi::RSA_size(key.0.as_ptr()) } as usize;
        let exponent = unsafe { ffi::BN_get_word(e) };
        // Legacy checks ceil(modulus_bits/8), not exact bit length. The backend
        // PSS encoder uses actual modulus bits, including its zero-leading-byte
        // branch for 2049-bit keys. Do not reproduce the legacy blind encoder's
        // rounded-bit bug by writing an alternative PSS implementation.
        if !(256..=512).contains(&width)
            || ![3, 65537].contains(&exponent)
            || unsafe { ffi::BN_is_odd(n) } != 1
        {
            return Err(Error::BadKey);
        }
        Ok(Self {
            key: Rc::new(key),
            width,
            original_der: Rc::from(der),
        })
    }
    pub fn original_der(&self) -> &[u8] {
        &self.original_der
    }
    fn n_e(&self) -> (*const ffi::BIGNUM, *const ffi::BIGNUM) {
        let (mut n, mut e) = (ptr::null(), ptr::null());
        unsafe {
            ffi::RSA_get0_key(self.key.0.as_ptr(), &mut n, &mut e, ptr::null_mut());
        }
        (n, e)
    }
    fn encode(&self, message: &[u8], hash: Hash, salt_len: i32) -> Result<SecretBytes> {
        let digest = hash.digest(message)?;
        let mut encoded = SecretBytes(vec![0; self.width]);
        ok(unsafe {
            ffi::RSA_padding_add_PKCS1_PSS_mgf1(
                self.key.0.as_ptr(),
                encoded.0.as_mut_ptr(),
                digest.0.as_ptr(),
                hash.md(),
                hash.md(),
                salt_len,
            )
        })?;
        Ok(encoded)
    }
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        hash: Hash,
        salt_len: i32,
    ) -> Result<()> {
        if signature.len() != self.width {
            return Err(Error::BadLength);
        }
        let value = Bn::read(signature)?;
        if unsafe { ffi::BN_cmp(value.0.as_ptr(), self.n_e().0) } >= 0 {
            return Err(Error::OutOfRange);
        }
        let digest = hash.digest(message)?;
        if unsafe {
            ffi::RSA_verify_pss_mgf1(
                self.key.0.as_ptr(),
                digest.0.as_ptr(),
                digest.0.len(),
                hash.md(),
                hash.md(),
                salt_len,
                signature.as_ptr(),
                signature.len(),
            )
        } == 1
        {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
    pub fn blind_token(&self, token: &[u8; 32]) -> Result<Pending> {
        self.blind_with_sampler(token, Hash::Sha256, &BackendRandom)
    }
    fn blind_with_sampler(
        &self,
        message: &[u8],
        hash: Hash,
        rng: &impl FactorSampler,
    ) -> Result<Pending> {
        let encoded = self.encode(message, hash, 0)?;
        let ctx = Ctx::new()?;
        let (n, _) = self.n_e();
        let mont = Mont::new(n, &ctx)?;
        let factor = Bn::new()?;
        rng.sample(&factor, n)?;
        let inverse = blinded_inverse(&factor, &mont, &ctx)?;
        self.blind_encoded(encoded, factor, inverse, hash, message)
    }
    fn blind_encoded(
        &self,
        encoded: SecretBytes,
        factor: Bn,
        inverse: Bn,
        hash: Hash,
        message: &[u8],
    ) -> Result<Pending> {
        let ctx = Ctx::new()?;
        let (n, e) = self.n_e();
        let mont = Mont::new(n, &ctx)?;
        let value = Bn::read(&encoded.0)?;
        // Use secret-aware inversion to check invertibility, avoiding BN_gcd
        // over the secret message. Non-invertible errors propagate to caller.
        let _invertibility = blinded_inverse(&value, &mont, &ctx)?;
        let re = Bn::new()?;
        ok(unsafe {
            ffi::BN_mod_exp_mont(
                re.0.as_ptr(),
                factor.0.as_ptr(),
                e,
                n,
                ctx.0.as_ptr(),
                mont.0.as_ptr(),
            )
        })?;
        let blinded = multiply_mod(&value, &re, &mont, &ctx)?.bytes(self.width)?;
        Ok(Pending {
            key: Self {
                key: Rc::clone(&self.key),
                width: self.width,
                original_der: Rc::clone(&self.original_der),
            },
            inverse,
            message: SecretBytes(message.to_vec()),
            hash,
            blinded,
        })
    }
}
fn blinded_inverse(a: &Bn, mont: &Mont, ctx: &Ctx) -> Result<Bn> {
    let out = Bn::new()?;
    let mut no_inverse = 0;
    if unsafe {
        ffi::BN_mod_inverse_blinded(
            out.0.as_ptr(),
            &mut no_inverse,
            a.0.as_ptr(),
            mont.0.as_ptr(),
            ctx.0.as_ptr(),
        )
    } != 1
    {
        return Err(if no_inverse == 1 {
            Error::NotInvertible
        } else {
            Error::Backend
        });
    }
    Ok(out)
}
fn multiply_mod(a: &Bn, b: &Bn, mont: &Mont, ctx: &Ctx) -> Result<Bn> {
    let am = Bn::new()?;
    let bm = Bn::new()?;
    let product = Bn::new()?;
    let out = Bn::new()?;
    ok(unsafe {
        ffi::BN_to_montgomery(am.0.as_ptr(), a.0.as_ptr(), mont.0.as_ptr(), ctx.0.as_ptr())
    })?;
    ok(unsafe {
        ffi::BN_to_montgomery(bm.0.as_ptr(), b.0.as_ptr(), mont.0.as_ptr(), ctx.0.as_ptr())
    })?;
    ok(unsafe {
        ffi::BN_mod_mul_montgomery(
            product.0.as_ptr(),
            am.0.as_ptr(),
            bm.0.as_ptr(),
            mont.0.as_ptr(),
            ctx.0.as_ptr(),
        )
    })?;
    ok(unsafe {
        ffi::BN_from_montgomery(
            out.0.as_ptr(),
            product.0.as_ptr(),
            mont.0.as_ptr(),
            ctx.0.as_ptr(),
        )
    })?;
    Ok(out)
}
trait FactorSampler {
    fn sample(&self, factor: &Bn, n: *const ffi::BIGNUM) -> Result<()>;
}
// AWS-LC's documented RNG contract aborts on insufficient entropy. A returned
// zero may still be a backend failure, but is NOT proof of a recoverable
// entropy-error path. Process-level failure containment remains unqualified.
struct BackendRandom;
impl FactorSampler for BackendRandom {
    fn sample(&self, factor: &Bn, n: *const ffi::BIGNUM) -> Result<()> {
        if unsafe { ffi::BN_rand_range_ex(factor.0.as_ptr(), 1, n) } == 1 {
            Ok(())
        } else {
            Err(Error::RandomGeneration)
        }
    }
}
pub struct Pending {
    key: PublicKey,
    inverse: Bn,
    message: SecretBytes,
    hash: Hash,
    pub blinded: Vec<u8>,
}
impl Pending {
    // Consumes operation state on both success and error; no inverse reuse.
    pub fn finalize(self, blind_signature: &[u8]) -> Result<Vec<u8>> {
        if blind_signature.len() != self.key.width {
            return Err(Error::BadLength);
        }
        let value = Bn::read(blind_signature)?;
        let (n, _) = self.key.n_e();
        if unsafe { ffi::BN_cmp(value.0.as_ptr(), n) } >= 0 {
            return Err(Error::OutOfRange);
        }
        let ctx = Ctx::new()?;
        let mont = Mont::new(n, &ctx)?;
        let mut out =
            SecretBytes(multiply_mod(&value, &self.inverse, &mont, &ctx)?.bytes(self.key.width)?);
        self.key.verify(&self.message.0, &out.0, self.hash, -2)?;
        Ok(std::mem::take(&mut out.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    fn legacy() -> Value {
        serde_json::from_str(include_str!("../../legacy-vector.json")).unwrap()
    }
    fn rfc() -> Value {
        serde_json::from_str(include_str!(
            "../../../crypto-sources/blind-rsa-signatures-0.18.0/tests/test_vectors_rfc9474.json"
        ))
        .unwrap()
    }
    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s.trim_start_matches("0x")).unwrap()
    }
    fn field(v: &Value, key: &str) -> Vec<u8> {
        unhex(v[key].as_str().unwrap())
    }
    fn key() -> PublicKey {
        PublicKey::from_pkcs1_der(&field(&legacy(), "pkcs1_der")).unwrap()
    }
    fn live() -> isize {
        LIVE_HANDLES.with(|v| v.get())
    }
    fn sign_fixture(blinded: &[u8], der: &[u8]) -> Vec<u8> {
        // Private operation exists ONLY in the test broker oracle, using
        // explicitly public test keys. It is absent from the non-test adapter.
        let rsa = Rsa::adopt(unsafe { ffi::RSA_private_key_from_bytes(der.as_ptr(), der.len()) })
            .unwrap();
        let mut out = vec![0; unsafe { ffi::RSA_size(rsa.0.as_ptr()) } as usize];
        let mut written = 0;
        ok(unsafe {
            ffi::RSA_sign_raw(
                rsa.0.as_ptr(),
                &mut written,
                out.as_mut_ptr(),
                out.len(),
                blinded.as_ptr(),
                blinded.len(),
                ffi::RSA_NO_PADDING as i32,
            )
        })
        .unwrap();
        assert_eq!(written, out.len());
        out
    }
    fn pending_from_vector(
        key: &PublicKey,
        encoded: Vec<u8>,
        inverse: &[u8],
        message: &[u8],
        hash: Hash,
    ) -> Pending {
        let ctx = Ctx::new().unwrap();
        let mont = Mont::new(key.n_e().0, &ctx).unwrap();
        let inverse = Bn::read(inverse).unwrap();
        let factor = blinded_inverse(&inverse, &mont, &ctx).unwrap();
        key.blind_encoded(SecretBytes(encoded), factor, inverse, hash, message)
            .unwrap()
    }
    #[test]
    fn salt_zero_emission_and_legacy_blind_finalize_are_exact() {
        let base = live();
        {
            let v = legacy();
            let key = key();
            let token = field(&v, "token");
            let encoded = key.encode(&token, Hash::Sha256, 0).unwrap();
            let pending = pending_from_vector(
                &key,
                encoded.0.clone(),
                &field(&v, "inverse"),
                &token,
                Hash::Sha256,
            );
            assert_eq!(pending.blinded, field(&v, "blinded"));
            assert_eq!(
                pending.finalize(&field(&v, "blind_signature")).unwrap(),
                field(&v, "signature")
            );
            key.verify(&token, &field(&v, "signature"), Hash::Sha256, 0)
                .unwrap();
        }
        assert_eq!(live(), base);
    }
    #[test]
    fn rfc_all_four_profiles_verify_and_finalize_exactly() {
        let key = key();
        for v in rfc().as_array().unwrap() {
            let message = field(v, "input_msg");
            let salt_len = field(v, "salt").len() as i32;
            key.verify(&message, &field(v, "sig"), Hash::Sha384, salt_len)
                .unwrap();
            // Recover encoded message through the backend public RSA operation.
            // This avoids hand-written PSS or special RNG interception for RFC
            // nonzero deterministic salt fixtures.
            let encoded_bn = Bn::new().unwrap();
            let sig = Bn::read(&field(v, "sig")).unwrap();
            let ctx = Ctx::new().unwrap();
            let (n, e) = key.n_e();
            let mont = Mont::new(n, &ctx).unwrap();
            ok(unsafe {
                ffi::BN_mod_exp_mont(
                    encoded_bn.0.as_ptr(),
                    sig.0.as_ptr(),
                    e,
                    n,
                    ctx.0.as_ptr(),
                    mont.0.as_ptr(),
                )
            })
            .unwrap();
            let encoded = encoded_bn.bytes(key.width).unwrap();
            if let Some(value) = v.get("encoded_msg") {
                assert_eq!(encoded, unhex(value.as_str().unwrap()));
            }
            let digest = Hash::Sha384.digest(&message).unwrap();
            assert_eq!(
                unsafe {
                    ffi::RSA_verify_PKCS1_PSS_mgf1(
                        key.key.0.as_ptr(),
                        digest.0.as_ptr(),
                        Hash::Sha384.md(),
                        Hash::Sha384.md(),
                        encoded.as_ptr(),
                        salt_len,
                    )
                },
                1
            );
            if salt_len == 0 {
                assert_eq!(key.encode(&message, Hash::Sha384, 0).unwrap().0, encoded);
            }
            let pending =
                pending_from_vector(&key, encoded, &field(v, "inv"), &message, Hash::Sha384);
            assert_eq!(pending.blinded, field(v, "blinded_msg"));
            assert_eq!(
                pending.finalize(&field(v, "blind_sig")).unwrap(),
                field(v, "sig")
            );
        }
    }
    #[test]
    fn auto_salt_preserves_legacy_acceptance_but_zero_mode_rejects_32() {
        let v = legacy();
        let key = key();
        let token = field(&v, "token");
        let sig = field(&v, "legacy_accepts_salt32_signature");
        assert_eq!(key.verify(&token, &sig, Hash::Sha256, -2), Ok(()));
        assert_eq!(key.verify(&token, &sig, Hash::Sha256, 32), Ok(()));
        assert_eq!(
            key.verify(&token, &sig, Hash::Sha256, 0),
            Err(Error::InvalidSignature)
        );
    }
    #[test]
    fn backend_random_factor_roundtrips_both_2048_and_4096_keys() {
        let public_2048 = include_bytes!("../generated-public-test-public-key-2048.der");
        let private_2048 = include_bytes!("../generated-public-test-private-key-2048.der");
        let private_4096 = include_bytes!("../rfc9474-public-test-private-key.der");
        for (key, private) in [
            (
                PublicKey::from_pkcs1_der(public_2048).unwrap(),
                private_2048.as_slice(),
            ),
            (key(), private_4096.as_slice()),
        ] {
            let mut last = None;
            for _ in 0..8 {
                let pending = key.blind_token(&[0x5a; 32]).unwrap();
                if let Some(old) = last {
                    assert_ne!(pending.blinded, old);
                }
                last = Some(pending.blinded.clone());
                let signed = sign_fixture(&pending.blinded, private);
                let sig = pending.finalize(&signed).unwrap();
                key.verify(&[0x5a; 32], &sig, Hash::Sha256, 0).unwrap();
            }
        }
    }
    #[test]
    fn finalize_rejects_length_range_mutation_and_wrong_token() {
        let key = key();
        let v = legacy();
        let token = field(&v, "token");
        let bsig = field(&v, "blind_signature");
        let wrong_n = {
            let n = key.n_e().0;
            let mut b = vec![0; key.width];
            ok(unsafe { ffi::BN_bn2bin_padded(b.as_mut_ptr(), b.len(), n) }).unwrap();
            b
        };
        let mut corrupt = bsig.clone();
        corrupt[7] ^= 1;
        for (bytes, expected) in [
            (&bsig[..bsig.len() - 1], Error::BadLength),
            (wrong_n.as_slice(), Error::OutOfRange),
            (corrupt.as_slice(), Error::InvalidSignature),
        ] {
            let pending = pending_from_vector(
                &key,
                key.encode(&token, Hash::Sha256, 0).unwrap().0.clone(),
                &field(&v, "inverse"),
                &token,
                Hash::Sha256,
            );
            let baseline = live() - 1; // pending owns one inverse Bn; key uses Rc.
            assert_eq!(pending.finalize(bytes), Err(expected));
            assert_eq!(live(), baseline);
        }
        let pending = pending_from_vector(
            &key,
            key.encode(&[7; 32], Hash::Sha256, 0).unwrap().0.clone(),
            &field(&v, "inverse"),
            &[7; 32],
            Hash::Sha256,
        );
        assert_eq!(pending.finalize(&bsig), Err(Error::InvalidSignature));
    }
    #[test]
    fn malformed_keys_and_noninvertible_values_return_errors() {
        let baseline = live();
        let mut trailing = field(&legacy(), "pkcs1_der");
        trailing.push(0);
        for der in [
            vec![],
            vec![0; 801],
            field(&legacy(), "pkcs1_der")[..120].to_vec(),
            trailing,
        ] {
            assert!(matches!(
                PublicKey::from_pkcs1_der(&der),
                Err(Error::BadKey)
            ));
            assert_eq!(live(), baseline);
        }
        let fixtures: Value =
            serde_json::from_str(include_str!("../invalid-domain-public-keys.json")).unwrap();
        for (name, der) in fixtures.as_object().unwrap() {
            assert!(
                matches!(
                    PublicKey::from_pkcs1_der(&unhex(der.as_str().unwrap())),
                    Err(Error::BadKey)
                ),
                "{name}"
            );
            assert_eq!(live(), baseline);
        }
        let key = key();
        let ctx = Ctx::new().unwrap();
        let mont = Mont::new(key.n_e().0, &ctx).unwrap();
        let factor = Bn::read(&field(&rfc()[3], "p")).unwrap();
        assert!(matches!(
            blinded_inverse(&factor, &mont, &ctx),
            Err(Error::NotInvertible)
        ));
    }
    #[test]
    fn sampler_returned_error_does_not_return_or_retain_partial_state() {
        // This injectable return error covers our ownership unwind only. It does
        // not emulate AWS-LC's fail-stop response to a real entropy shortage.
        struct FailingRandom;
        impl FactorSampler for FailingRandom {
            fn sample(&self, _: &Bn, _: *const ffi::BIGNUM) -> Result<()> {
                Err(Error::RandomGeneration)
            }
        }
        let key = key();
        let baseline = live();
        assert!(matches!(
            key.blind_with_sampler(&[1; 32], Hash::Sha256, &FailingRandom),
            Err(Error::RandomGeneration)
        ));
        assert_eq!(live(), baseline);
    }
    #[test]
    fn every_injected_allocation_error_releases_owned_backend_handles() {
        let key = key();
        let baseline = live();
        let mut failures = 0;
        let mut successes = 0;
        for limit in 0..32 {
            ALLOCATION_BUDGET.with(|v| v.set(Some(limit)));
            let result = key.blind_token(&[3; 32]);
            ALLOCATION_BUDGET.with(|v| v.set(None));
            match result {
                Err(Error::Allocation) => failures += 1,
                Ok(pending) => {
                    successes += 1;
                    drop(pending)
                }
                Err(e) => panic!("unexpected: {e:?}"),
            }
            assert_eq!(live(), baseline, "allocation budget {limit}");
        }
        assert!(failures > 12);
        assert!(successes > 0);
    }
    #[test]
    fn abandon_pending_drops_inverse_and_shared_key_owner() {
        let key = key();
        let base = live();
        let owner = Rc::downgrade(&key.key);
        let pending = key.blind_token(&[4; 32]).unwrap();
        assert_eq!(live(), base + 1);
        drop(key);
        assert!(owner.upgrade().is_some());
        drop(pending);
        assert!(owner.upgrade().is_none());
        assert_eq!(live(), base - 1);
    }
    mod async_boundary;
    mod compatibility;
}
