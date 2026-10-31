//! Output-only client adapter for the Mizaru 0.2.21 wire protocol.
//! Server key generation/signing and RustCrypto RSA are not copied here.
use serde::{Deserialize, Serialize};
use std::{fmt, marker::PhantomData, time::SystemTime};

pub use backend::OwnedPending as Pending;
pub const MAX_DER: usize = 800;
pub const MAX_REPRESENTATIVE: usize = 512;
pub const MAX_BRANCH: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Backend(backend::Error),
    InvalidMerkleProof,
    WrongEpoch,
    OversizedInput,
}
impl From<backend::Error> for Error {
    fn from(error: backend::Error) -> Self {
        Self::Backend(error)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend(error) => write!(f, "client RSA operation failed: {error:?}"),
            Self::InvalidMerkleProof => f.write_str("Merkle proof failed"),
            Self::WrongEpoch => f.write_str("wrong epoch in response"),
            Self::OversizedInput => f.write_str("client input exceeds protocol limit"),
        }
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

// Preserve serde's Vec wire representation while bounding reserve and decode.
// These private specializations only decode fixed-size u8/Hash elements.
fn bounded<'de, D, T, const MAX: usize>(deserializer: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Bounded<T, const N: usize>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const N: usize> serde::de::Visitor<'de> for Bounded<T, N> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "at most {N} items")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|n| n > N) {
                return Err(serde::de::Error::custom("sequence exceeds protocol limit"));
            }
            let mut result = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(N));
            while let Some(item) = sequence.next_element::<T>()? {
                if result.len() == N {
                    return Err(serde::de::Error::custom("sequence exceeds protocol limit"));
                }
                result.push(item);
            }
            Ok(result)
        }
    }
    deserializer.deserialize_seq(Bounded::<T, MAX>(PhantomData))
}
fn der_bytes<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
    bounded::<D, u8, MAX_DER>(d)
}
fn representative<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<u8>, D::Error> {
    bounded::<D, u8, MAX_REPRESENTATIVE>(d)
}
fn branch<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<blake3::Hash>, D::Error> {
    bounded::<D, blake3::Hash, MAX_BRANCH>(d)
}
fn validate(der: &[u8], proof: &[blake3::Hash], signature: &[u8]) -> Result<()> {
    if der.len() > MAX_DER || proof.len() > MAX_BRANCH || signature.len() > MAX_REPRESENTATIVE {
        return Err(Error::OversizedInput);
    }
    Ok(())
}

pub fn current_epoch() -> u16 {
    unix_to_epoch(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
}
pub fn unix_to_epoch(unix: u64) -> u16 {
    (unix / 86400) as u16
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientToken([u8; 32]);
impl ClientToken {
    // Same rand 0.9 CSPRNG entry point as published Mizaru. The caller must
    // generate its token before selecting an untrusted issuer key.
    pub fn random() -> Self {
        Self(rand::random())
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn blind(self, subkey_der: &[u8]) -> Result<(BlindedClientToken, Pending)> {
        let pending = Pending::begin(subkey_der, &self.0)?;
        let request = BlindedClientToken(pending.blinded().to_vec());
        Ok((request, pending))
    }
}
impl fmt::Display for ClientToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlindedClientToken(#[serde(deserialize_with = "representative")] Vec<u8>);

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct BlindedSignature {
    pub epoch: u16,
    #[serde(deserialize_with = "der_bytes")]
    pub used_key: Vec<u8>,
    #[serde(deserialize_with = "branch")]
    pub merkle_branch: Vec<blake3::Hash>,
    #[serde(deserialize_with = "representative")]
    pub blinded_sig: Vec<u8>,
}
impl BlindedSignature {
    /// AccountLevel lives in broker-protocol. The caller selects the configured
    /// root for that request level; None explicitly preserves no-root mode.
    /// Pending is consumed on every returned failure and success.
    pub fn unblind(
        self,
        pending: Pending,
        expected_epoch: u16,
        root: Option<&PublicKey>,
    ) -> Result<UnblindedSignature> {
        validate(&self.used_key, &self.merkle_branch, &self.blinded_sig)?;
        if self.epoch != expected_epoch {
            return Err(Error::WrongEpoch);
        }
        if let Some(root) = root {
            root.verify_member(self.epoch, &self.used_key, &self.merkle_branch)?;
        }
        let signature = pending.finalize(&self.used_key, &self.blinded_sig)?;
        Ok(UnblindedSignature {
            epoch: self.epoch,
            used_key: self.used_key,
            merkle_branch: self.merkle_branch,
            unblinded_sig: signature,
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct UnblindedSignature {
    pub epoch: u16,
    #[serde(deserialize_with = "der_bytes")]
    pub used_key: Vec<u8>,
    #[serde(deserialize_with = "branch")]
    pub merkle_branch: Vec<blake3::Hash>,
    #[serde(deserialize_with = "representative")]
    pub unblinded_sig: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(transparent)]
pub struct PublicKey(blake3::Hash);
impl PublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(blake3::Hash::from(bytes))
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        *self.0.as_bytes()
    }
    pub fn verify_member(&self, epoch: u16, subkey: &[u8], proof: &[blake3::Hash]) -> Result<()> {
        validate(subkey, proof, &[])?;
        let mut acc = blake3::hash(subkey);
        for (i, sibling) in proof.iter().enumerate() {
            acc = if epoch >> i & 1 == 0 {
                blake3::keyed_hash(acc.as_bytes(), sibling.as_bytes())
            } else {
                blake3::keyed_hash(sibling.as_bytes(), acc.as_bytes())
            };
        }
        if acc != self.0 {
            return Err(Error::InvalidMerkleProof);
        }
        Ok(())
    }
    pub fn blind_verify(&self, token: ClientToken, signature: &UnblindedSignature) -> Result<()> {
        validate(
            &signature.used_key,
            &signature.merkle_branch,
            &signature.unblinded_sig,
        )?;
        self.verify_member(
            signature.epoch,
            &signature.used_key,
            &signature.merkle_branch,
        )?;
        backend::PublicKey::from_der(&signature.used_key)?.verify(
            &token.0,
            &signature.unblinded_sig,
            backend::Hash::Sha256,
            -2,
        )?;
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct SinglePublicKey(#[serde(deserialize_with = "der_bytes")] Vec<u8>);
impl SinglePublicKey {
    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        backend::PublicKey::from_der(bytes)?;
        Ok(Self(bytes.to_vec()))
    }
    pub fn to_der(&self) -> &[u8] {
        &self.0
    }
    pub fn blind_verify(
        &self,
        token: ClientToken,
        signature: &SingleUnblindedSignature,
    ) -> Result<()> {
        validate(&self.0, &[], &signature.unblinded_sig)?;
        backend::PublicKey::from_der(&self.0)?.verify(
            &token.0,
            &signature.unblinded_sig,
            backend::Hash::Sha256,
            -2,
        )?;
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct SingleBlindedSignature {
    #[serde(deserialize_with = "der_bytes")]
    pub used_key: Vec<u8>,
    #[serde(deserialize_with = "representative")]
    pub blinded_sig: Vec<u8>,
}
impl SingleBlindedSignature {
    pub fn unblind(self, pending: Pending) -> Result<SingleUnblindedSignature> {
        validate(&self.used_key, &[], &self.blinded_sig)?;
        Ok(SingleUnblindedSignature {
            unblinded_sig: pending.finalize(&self.used_key, &self.blinded_sig)?,
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct SingleUnblindedSignature {
    #[serde(deserialize_with = "representative")]
    pub unblinded_sig: Vec<u8>,
}
