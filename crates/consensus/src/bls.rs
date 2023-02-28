use crate::beacon::{PUBLIC_KEY_BYTES_LEN, SIGNATURE_BYTES_LEN};
use crate::errors::Error;
use crate::internal_prelude::*;
use crate::types::{serde_hex, H256};
use core::ops::Deref;
pub use milagro_bls::AggregatePublicKey as BLSAggregatePublicKey;
pub use milagro_bls::AggregateSignature as BLSAggregateSignature;
pub use milagro_bls::PublicKey as BLSPublicKey;
pub use milagro_bls::Signature as BLSSignature;
use ssz_rs::prelude::*;
use ssz_rs::Deserialize;
use ssz_rs_derive::SimpleSerialize;

#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct PublicKey(#[serde(with = "PublicKeyBytesDef")] PublicKeyBytes);

impl PublicKey {
    pub fn from_vec(bz: Vec<u8>) -> Result<Self, Error> {
        Ok(PublicKeyBytes::from_vec(bz)?.into())
    }
}

impl Deref for PublicKey {
    type Target = PublicKeyBytes;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct PublicKeyBytes(pub Vector<u8, PUBLIC_KEY_BYTES_LEN>);

impl PublicKeyBytes {
    pub fn as_array(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        let mut array = [0u8; PUBLIC_KEY_BYTES_LEN];
        array.copy_from_slice(self.as_slice());
        array
    }

    pub fn from_vec(bz: Vec<u8>) -> Result<Self, Error> {
        if bz.len() != PUBLIC_KEY_BYTES_LEN {
            Err(Error::InvalidBLSPublicKeyLength(
                PUBLIC_KEY_BYTES_LEN,
                bz.len(),
            ))
        } else {
            Ok(Self(Vector::<u8, PUBLIC_KEY_BYTES_LEN>::from_iter(bz)))
        }
    }
}

impl Deref for PublicKeyBytes {
    type Target = Vector<u8, PUBLIC_KEY_BYTES_LEN>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<PublicKeyBytes> for PublicKey {
    fn from(pb: PublicKeyBytes) -> Self {
        Self(pb)
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(remote = "PublicKeyBytes")]
pub struct PublicKeyBytesDef(
    #[serde(with = "serde_hex")]
    #[serde(getter = "PublicKeyBytes::as_array")]
    pub [u8; PUBLIC_KEY_BYTES_LEN],
);

impl From<PublicKeyBytesDef> for PublicKeyBytes {
    fn from(value: PublicKeyBytesDef) -> Self {
        Self(Vector::<u8, PUBLIC_KEY_BYTES_LEN>::from_iter(
            value.0.into_iter(),
        ))
    }
}

impl TryFrom<PublicKey> for BLSPublicKey {
    type Error = Error;
    fn try_from(value: PublicKey) -> Result<Self, Self::Error> {
        Ok(BLSPublicKey::from_bytes(&value.0)?)
    }
}

impl From<BLSPublicKey> for PublicKey {
    fn from(value: BLSPublicKey) -> Self {
        PublicKey(PublicKeyBytes::from_vec(value.as_bytes().to_vec()).unwrap())
    }
}

impl TryFrom<PublicKey> for BLSAggregatePublicKey {
    type Error = Error;
    fn try_from(value: PublicKey) -> Result<Self, Self::Error> {
        Ok(BLSAggregatePublicKey::from_public_key(&value.try_into()?))
    }
}

impl From<BLSAggregatePublicKey> for PublicKey {
    fn from(value: BLSAggregatePublicKey) -> Self {
        BLSPublicKey { point: value.point }.into()
    }
}

#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct Signature(#[serde(with = "SignatureBytesDef")] SignatureBytes);

impl Deref for Signature {
    type Target = SignatureBytes;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct SignatureBytes(pub Vector<u8, SIGNATURE_BYTES_LEN>);

impl SignatureBytes {
    pub fn as_array(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        let mut array = [0u8; SIGNATURE_BYTES_LEN];
        array.copy_from_slice(self.as_slice());
        array
    }
}

impl Deref for SignatureBytes {
    type Target = Vector<u8, SIGNATURE_BYTES_LEN>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(remote = "SignatureBytes")]
pub struct SignatureBytesDef(
    #[serde(with = "serde_hex")]
    #[serde(getter = "SignatureBytes::as_array")]
    pub [u8; SIGNATURE_BYTES_LEN],
);

impl From<SignatureBytesDef> for SignatureBytes {
    fn from(value: SignatureBytesDef) -> Self {
        Self(Vector::<u8, SIGNATURE_BYTES_LEN>::from_iter(
            value.0.into_iter(),
        ))
    }
}

impl TryFrom<Signature> for BLSSignature {
    type Error = Error;
    fn try_from(value: Signature) -> Result<Self, Self::Error> {
        Ok(BLSSignature::from_bytes(&value.0 .0)?)
    }
}

pub fn aggreate_public_key(keys: &[BLSPublicKey]) -> Result<BLSAggregatePublicKey, Error> {
    Ok(BLSAggregatePublicKey::into_aggregate(keys)?)
}

pub fn fast_aggregate_verify(
    pubkeys: Vec<BLSPublicKey>,
    msg: H256,
    signature: BLSSignature,
) -> Result<bool, Error> {
    let aggregate_pubkey = aggreate_public_key(&pubkeys)?;
    let aggregate_signature = BLSAggregateSignature::from_signature(&signature);

    Ok(aggregate_signature.fast_aggregate_verify_pre_aggregated(msg.as_bytes(), &aggregate_pubkey))
}

pub fn is_equal_pubkeys_and_aggreate_pub_key<const SYNC_COMMITTEE_SIZE: usize>(
    pubkeys: &Vector<PublicKey, SYNC_COMMITTEE_SIZE>,
    aggregate_pubkey: &PublicKey,
) -> Result<(), Error> {
    let pubkeys: Vec<BLSPublicKey> = pubkeys
        .iter()
        .map(|k| k.clone().try_into().unwrap())
        .collect();
    let agg_pubkey: PublicKey = aggreate_public_key(&pubkeys)?.into();
    if aggregate_pubkey == &agg_pubkey {
        Ok(())
    } else {
        Err(Error::BLSAggregatePublicKeyMismatch(
            aggregate_pubkey.clone(),
            agg_pubkey,
        ))
    }
}
