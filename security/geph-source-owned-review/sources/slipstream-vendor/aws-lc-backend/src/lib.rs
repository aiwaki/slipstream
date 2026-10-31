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

fn allocation_allowed() -> Result<()> {
    Ok(())
}
fn allocated() {
}
fn released() {
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

