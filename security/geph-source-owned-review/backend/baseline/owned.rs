//! Output-only byte ownership boundary. No native handle crosses an await.
use super::*;

/// In-memory, single-use blind operation. Rust derives Send from owned bytes;
/// no unsafe Send/Sync assertion, secret serialization, Clone or Debug exists.
pub struct OwnedPending {
    der: Vec<u8>,
    inverse: SecretBytes,
    message: SecretBytes,
    hash: Hash,
    blinded: Vec<u8>,
}
impl OwnedPending {
    /// Complete all native work synchronously before returning movable state.
    /// Caller remains responsible for generating a high-entropy token before
    /// trusting an issuer key and cleansing any caller-owned token copies.
    pub fn begin(der: &[u8], token: &[u8; 32]) -> Result<Self> {
        let key = PublicKey::from_der(der)?;
        let Pending {
            key: pending_key,
            inverse,
            message,
            hash,
            blinded,
        } = key.blind_token(token)?;
        let inverse_bytes = SecretBytes(inverse.bytes(pending_key.width)?);
        Ok(Self {
            der: der.to_vec(),
            inverse: inverse_bytes,
            message,
            hash,
            blinded,
        })
    }
    pub fn blinded(&self) -> &[u8] {
        &self.blinded
    }
    /// Caller must authenticate exact response DER, epoch and expected issuer
    /// before this call, and publish the credential only after success.
    /// This guard additionally binds the reply to the operation's math key.
    pub fn finalize(self, response_der: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
        let key = PublicKey::from_der(&self.der)?;
        let response_key = PublicKey::from_der(response_der)?;
        let (n, e) = key.n_e();
        let (rn, re) = response_key.n_e();
        if unsafe { ffi::BN_cmp(n, rn) } != 0 || unsafe { ffi::BN_cmp(e, re) } != 0 {
            return Err(Error::BadKey);
        }
        // The inverse is private, fixed-width and can only originate in begin;
        // there is no decoder/import API for serialized pending state.
        let inverse = Bn::read(&self.inverse.0)?;
        let pending = Pending {
            key,
            inverse,
            message: self.message,
            hash: self.hash,
            blinded: self.blinded,
        };
        pending.finalize(signature)
    }
}

#[cfg(test)]
static WITNESSES: std::sync::LazyLock<
    std::sync::Mutex<
        std::collections::BTreeMap<usize, std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    >,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::BTreeMap::new()));

#[cfg(test)]
impl OwnedPending {
    pub(crate) fn witness_cleanup(&self, counter: &std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let mut witnesses = WITNESSES.lock().unwrap();
        for bytes in [&self.inverse.0, &self.message.0] {
            assert!(witnesses
                .insert(bytes.as_ptr() as usize, counter.clone())
                .is_none());
        }
    }
}
#[cfg(test)]
pub(crate) fn after_cleanse(bytes: &[u8]) {
    // Called before Vec frees its allocation, never a use-after-free observer.
    if let Some(counter) = WITNESSES.lock().unwrap().remove(&(bytes.as_ptr() as usize)) {
        if bytes.iter().all(|byte| *byte == 0) {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}
