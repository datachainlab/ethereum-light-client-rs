use crate::{
    beacon::{BeaconBlockHeader, GeneralizedIndex, Slot},
    bls::{is_equal_pubkeys_and_aggreate_pub_key, PublicKey, Signature},
    errors::Error,
    internal_prelude::*,
    types::{H256, U64},
};
use ssz_rs::prelude::{Bitvector, Vector};
use ssz_rs::{Deserialize, Sized};
use ssz_rs_derive::SimpleSerialize;

pub type SyncCommitteePeriod = U64;

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#constants
/// get_generalized_index(BeaconState, 'finalized_checkpoint', 'root')
pub const FINALIZED_ROOT_INDEX: u64 = 105;
pub const FINALIZED_ROOT_DEPTH: usize = 6;
/// get_generalized_index(BeaconState, 'current_sync_committee')
pub const CURRENT_SYNC_COMMITTEE_INDEX: u64 = 54;
pub const CURRENT_SYNC_COMMITTEE_DEPTH: usize = 5;
/// get_generalized_index(BeaconState, 'next_sync_committee')
pub const NEXT_SYNC_COMMITTEE_INDEX: u64 = 55;
pub const NEXT_SYNC_COMMITTEE_DEPTH: usize = 5;

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/beacon-chain.md#synccommittee
#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct SyncCommittee<const SYNC_COMMITTEE_SIZE: usize> {
    pub pubkeys: Vector<PublicKey, SYNC_COMMITTEE_SIZE>,
    pub aggregate_pubkey: PublicKey,
}

impl<const SYNC_COMMITTEE_SIZE: usize> SyncCommittee<SYNC_COMMITTEE_SIZE> {
    pub fn validate(&self) -> Result<(), Error> {
        is_equal_pubkeys_and_aggreate_pub_key(&self.pubkeys, &self.aggregate_pubkey)
    }
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/beacon-chain.md#syncaggregate
/**
 *  sync_committee_bits: Bitvector[SYNC_COMMITTEE_SIZE]
 *  sync_committee_signature: BLSSignature
 */
#[derive(
    Clone, Debug, Default, PartialEq, Eq, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct SyncAggregate<const SYNC_COMMITTEE_SIZE: usize> {
    pub sync_committee_bits: Bitvector<SYNC_COMMITTEE_SIZE>,
    pub sync_committee_signature: Signature,
}

impl<const SYNC_COMMITTEE_SIZE: usize> SyncAggregate<SYNC_COMMITTEE_SIZE> {
    pub fn count_participants(&self) -> usize {
        self.sync_committee_bits.count_ones()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LightClientHeader {
    /// Header matching the requested beacon block root
    pub beacon: BeaconBlockHeader,
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#lightclientbootstrap
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LightClientBootstrap<const SYNC_COMMITTEE_SIZE: usize> {
    pub header: LightClientHeader,
    /// Current sync committee corresponding to `header.state_root`
    pub current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub current_sync_committee_branch: [H256; CURRENT_SYNC_COMMITTEE_DEPTH],
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#lightclientupdate
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LightClientUpdate<const SYNC_COMMITTEE_SIZE: usize> {
    /// Header attested to by the sync committee
    pub attested_header: BeaconBlockHeader,
    /// Next sync committee corresponding to `attested_header.state_root`
    pub next_sync_committee: Option<(
        SyncCommittee<SYNC_COMMITTEE_SIZE>,
        [H256; NEXT_SYNC_COMMITTEE_DEPTH],
    )>,
    /// Finalized header corresponding to `attested_header.state_root`
    pub finalized_header: (BeaconBlockHeader, [H256; FINALIZED_ROOT_DEPTH]),
    /// Sync committee aggregate signature
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    /// Slot at which the aggregate signature was created (untrusted)
    pub signature_slot: Slot,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]

pub struct LightClientFinalityUpdate<const SYNC_COMMITTEE_SIZE: usize> {
    /// Header attested to by the sync committee
    pub attested_header: LightClientHeader,
    /// Finalized header corresponding to `attested_header.state_root`
    pub finalized_header: LightClientHeader,
    pub finality_branch: [H256; FINALIZED_ROOT_DEPTH],
    /// Sync committee aggregate signature
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    /// Slot at which the aggregate signature was created (untrusted)
    pub signature_slot: Slot,
}

impl<const SYNC_COMMITTEE_SIZE: usize> From<LightClientFinalityUpdate<SYNC_COMMITTEE_SIZE>>
    for LightClientUpdate<SYNC_COMMITTEE_SIZE>
{
    fn from(value: LightClientFinalityUpdate<SYNC_COMMITTEE_SIZE>) -> Self {
        Self {
            attested_header: value.attested_header.beacon,
            next_sync_committee: None,
            finalized_header: (value.finalized_header.beacon, value.finality_branch),
            sync_aggregate: value.sync_aggregate,
            signature_slot: value.signature_slot,
        }
    }
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#get_subtree_index
pub fn get_subtree_index(generalized_index: GeneralizedIndex) -> u64 {
    generalized_index
        % 2u64
            .checked_pow((generalized_index as f64).log2().floor() as u32)
            .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        beacon::DOMAIN_SYNC_COMMITTEE,
        bls::fast_aggregate_verify,
        compute::{
            compute_domain, compute_epoch_at_slot, compute_fork_version, compute_signing_root,
        },
        config,
        context::DefaultChainContext,
        preset,
    };
    pub use milagro_bls::PublicKey as BLSPublicKey;
    use std::fs;

    #[derive(Clone, Debug, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
    struct NetworkContext {
        pub genesis_validators_root: H256,
    }

    #[test]
    fn test_light_client_update_verification() {
        let sync_committee: SyncCommittee<{ preset::mainnet::PRESET.SYNC_COMMITTEE_SIZE }> =
            serde_json::from_str(
                &fs::read_to_string("./data/mainnet_sync_committee_period_713.json").unwrap(),
            )
            .unwrap();
        assert!(sync_committee.validate().is_ok());

        let update: LightClientUpdate<{ preset::mainnet::PRESET.SYNC_COMMITTEE_SIZE }> =
            serde_json::from_str(
                &fs::read_to_string("./data/mainnet_light_client_update_slot_5841038.json")
                    .unwrap(),
            )
            .unwrap();

        let network: NetworkContext =
            serde_json::from_str(&fs::read_to_string("./data/mainnet_context.json").unwrap())
                .unwrap();

        // ensure that signing_root calculation is correct

        let ctx = DefaultChainContext::new_with_config(0.into(), config::mainnet::CONFIG);
        let fork_version =
            compute_fork_version(&ctx, compute_epoch_at_slot(&ctx, update.signature_slot));
        let domain = compute_domain(
            &ctx,
            DOMAIN_SYNC_COMMITTEE,
            Some(fork_version),
            Some(network.genesis_validators_root),
        )
        .unwrap();
        let signing_root = compute_signing_root(update.attested_header, domain).unwrap();
        let expected_signing_root: H256 = serde_json::from_str(
            &fs::read_to_string("./data/mainnet_signing_root_slot_5841037.json").unwrap(),
        )
        .unwrap();
        assert_eq!(expected_signing_root, signing_root);

        // ensure that bls verification is correct

        let participant_pubkeys: Vec<BLSPublicKey> = update
            .sync_aggregate
            .sync_committee_bits
            .iter()
            .zip(sync_committee.pubkeys.iter())
            .filter(|it| it.0 == true)
            .map(|t| t.1.clone().try_into().unwrap())
            .collect();

        let res = fast_aggregate_verify(
            participant_pubkeys,
            signing_root,
            update
                .sync_aggregate
                .sync_committee_signature
                .try_into()
                .unwrap(),
        );
        assert!(res.is_ok());
        assert!(res.unwrap());
    }
}
