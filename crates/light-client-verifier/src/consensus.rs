use crate::context::ConsensusVerificationContext;
use crate::errors::Error;
use crate::internal_prelude::*;
use crate::misbehaviour::Misbehaviour;
use crate::state::LightClientStoreReader;
use crate::updates::{ConsensusUpdate, ExecutionUpdate, LightClientBootstrap};
use core::marker::PhantomData;
use ethereum_consensus::beacon::{BeaconBlockHeader, Root, DOMAIN_SYNC_COMMITTEE};
use ethereum_consensus::bls::{fast_aggregate_verify, BLSPublicKey, BLSSignature};
use ethereum_consensus::compute::{
    compute_domain, compute_epoch_at_slot, compute_fork_version, compute_signing_root,
    compute_sync_committee_period_at_slot, hash_tree_root,
};
use ethereum_consensus::context::ChainContext;
use ethereum_consensus::execution::{
    EXECUTION_PAYLOAD_BLOCK_NUMBER_LEAF_INDEX, EXECUTION_PAYLOAD_STATE_ROOT_LEAF_INDEX,
};
use ethereum_consensus::merkle::is_valid_merkle_branch;
use ethereum_consensus::sync_protocol::{
    SyncCommittee, CURRENT_SYNC_COMMITTEE_DEPTH, CURRENT_SYNC_COMMITTEE_SUBTREE_INDEX,
    FINALIZED_ROOT_DEPTH, FINALIZED_ROOT_SUBTREE_INDEX, NEXT_SYNC_COMMITTEE_DEPTH,
    NEXT_SYNC_COMMITTEE_SUBTREE_INDEX,
};
use ethereum_consensus::types::H256;

/// SyncProtocolVerifier is a verifier of [light client sync protocol](https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncProtocolVerifier<
    const SYNC_COMMITTEE_SIZE: usize,
    const EXECUTION_PAYLOAD_TREE_DEPTH: usize,
    ST: LightClientStoreReader<SYNC_COMMITTEE_SIZE>,
>(PhantomData<ST>);

impl<
        const SYNC_COMMITTEE_SIZE: usize,
        const EXECUTION_PAYLOAD_TREE_DEPTH: usize,
        ST: LightClientStoreReader<SYNC_COMMITTEE_SIZE>,
    > SyncProtocolVerifier<SYNC_COMMITTEE_SIZE, EXECUTION_PAYLOAD_TREE_DEPTH, ST>
{
    /// validates a LightClientBootstrap
    pub fn validate_boostrap<LB: LightClientBootstrap<SYNC_COMMITTEE_SIZE>>(
        &self,
        bootstrap: &LB,
        trusted_block_root: Option<Root>,
    ) -> Result<(), Error> {
        if let Some(trusted_block_root) = trusted_block_root {
            let root = hash_tree_root(bootstrap.beacon_header().clone())?;
            if trusted_block_root != root {
                return Err(Error::TrustedRootMismatch(trusted_block_root, root));
            }
        }
        is_valid_merkle_branch(
            hash_tree_root(bootstrap.current_sync_committee().clone())?,
            &bootstrap.current_sync_committee_branch(),
            CURRENT_SYNC_COMMITTEE_DEPTH as u32,
            CURRENT_SYNC_COMMITTEE_SUBTREE_INDEX,
            bootstrap.beacon_header().state_root,
        )
        .map_err(Error::InvalidCurrentSyncCommitteeMerkleBranch)?;
        Ok(())
    }

    /// validates consensus update and execution update
    pub fn validate_updates<
        CC: ChainContext + ConsensusVerificationContext,
        CU: ConsensusUpdate<SYNC_COMMITTEE_SIZE>,
        EU: ExecutionUpdate,
    >(
        &self,
        ctx: &CC,
        store: &ST,
        consensus_update: &CU,
        execution_update: &EU,
    ) -> Result<(), Error> {
        consensus_update.validate_basic(ctx)?;
        execution_update.validate_basic()?;

        self.ensure_relevant_update(ctx, store, consensus_update)?;
        self.validate_consensus_update(ctx, store, consensus_update)?;
        self.validate_execution_update(
            consensus_update.finalized_execution_root(),
            execution_update,
        )?;
        Ok(())
    }

    /// validate a consensus update with a committee from the trusted store
    /// follow the light client protocol in the consensus spec
    pub fn validate_consensus_update<
        CC: ChainContext + ConsensusVerificationContext,
        CU: ConsensusUpdate<SYNC_COMMITTEE_SIZE>,
    >(
        &self,
        ctx: &CC,
        store: &ST,
        update: &CU,
    ) -> Result<(), Error> {
        let sync_committee = self.get_sync_committee(ctx, store, update)?;
        validate_light_client_update(ctx, store, update)?;
        verify_sync_committee_attestation(ctx, update, &sync_committee)?;
        Ok(())
    }

    /// validate an execution update with trusted/verified beacon block body
    pub fn validate_execution_update<EU: ExecutionUpdate>(
        &self,
        trusted_execution_root: Root,
        update: &EU,
    ) -> Result<(), Error> {
        is_valid_merkle_branch(
            hash_tree_root(update.state_root()).unwrap().0.into(),
            &update.state_root_branch(),
            EXECUTION_PAYLOAD_TREE_DEPTH as u32,
            EXECUTION_PAYLOAD_STATE_ROOT_LEAF_INDEX as u64,
            trusted_execution_root,
        )
        .map_err(Error::InvalidExecutionStateRootMerkleBranch)?;

        is_valid_merkle_branch(
            hash_tree_root(update.block_number()).unwrap().0.into(),
            &update.block_number_branch(),
            EXECUTION_PAYLOAD_TREE_DEPTH as u32,
            EXECUTION_PAYLOAD_BLOCK_NUMBER_LEAF_INDEX as u64,
            trusted_execution_root,
        )
        .map_err(Error::InvalidExecutionBlockNumberMerkleBranch)?;

        Ok(())
    }

    /// validates a misbehaviour with the store.
    /// it returns `Ok` if the misbehaviour is valid
    pub fn validate_misbehaviour<
        CC: ChainContext + ConsensusVerificationContext,
        CU: ConsensusUpdate<SYNC_COMMITTEE_SIZE>,
    >(
        &self,
        ctx: &CC,
        store: &ST,
        misbehaviour: Misbehaviour<SYNC_COMMITTEE_SIZE, CU>,
    ) -> Result<(), Error> {
        misbehaviour.validate_basic(ctx)?;
        let (update_1, update_2) = misbehaviour.updates();
        self.validate_consensus_update(ctx, store, &update_1)?;
        self.validate_consensus_update(ctx, store, &update_2)?;
        Ok(())
    }

    /// ensure that the consensus update is relevant
    pub fn ensure_relevant_update<CC: ChainContext, CU: ConsensusUpdate<SYNC_COMMITTEE_SIZE>>(
        &self,
        ctx: &CC,
        store: &ST,
        update: &CU,
    ) -> Result<(), Error> {
        let store_period = compute_sync_committee_period_at_slot(ctx, store.current_slot());

        let update_attested_period =
            compute_sync_committee_period_at_slot(ctx, update.attested_beacon_header().slot);
        let update_has_next_sync_committee = store.next_sync_committee().is_none()
            && (update.next_sync_committee().is_some() && update_attested_period == store_period);

        // https://github.com/ethereum/consensus-specs/blob/087e7378b44f327cdad4549304fc308613b780c3/specs/altair/light-client/sync-protocol.md#validate_light_client_update
        // assert (update_attested_slot > store.finalized_header.beacon.slot or update_has_next_sync_committee)
        if !(update.attested_beacon_header().slot > store.current_slot()
            || update_has_next_sync_committee)
        {
            return Err(Error::IrrelevantConsensusUpdates(format!(
                    "attested_beacon_header_slot={} store_slot={} update_has_next_sync_committee={} is_next_sync_committee_known={}",
                    update.attested_beacon_header().slot,
                    store.current_slot(),
                    update_has_next_sync_committee,
                    store.next_sync_committee().is_some()
                )));
        }

        // https://github.com/ethereum/consensus-specs/blob/087e7378b44f327cdad4549304fc308613b780c3/specs/altair/light-client/sync-protocol.md#process_light_client_update
        // update_has_finalized_next_sync_committee = (
        //     not is_next_sync_committee_known(store)
        //     and is_sync_committee_update(update) and is_finality_update(update) and (
        //         compute_sync_committee_period_at_slot(update.finalized_header.beacon.slot)
        //         == compute_sync_committee_period_at_slot(update.attested_header.beacon.slot)
        //     )
        // )
        let update_has_finalized_next_sync_committee = store.next_sync_committee().is_none()
            && update.next_sync_committee().is_some() // equivalent to is_sync_committee_update(update)
            && compute_sync_committee_period_at_slot(ctx, update.finalized_beacon_header().slot)
                == update_attested_period;

        // https://github.com/ethereum/consensus-specs/blob/087e7378b44f327cdad4549304fc308613b780c3/specs/altair/light-client/sync-protocol.md#process_light_client_update
        // update.finalized_header.beacon.slot > store.finalized_header.beacon.slot
        // or update_has_finalized_next_sync_committee
        if !(update_has_finalized_next_sync_committee
            || update.finalized_beacon_header().slot > store.current_slot())
        {
            return Err(Error::IrrelevantConsensusUpdates(format!(
                    "finalized_beacon_header_slot={} store_slot={} update_has_finalized_next_sync_committee={}",
                    update.finalized_beacon_header().slot, store.current_slot(), update_has_finalized_next_sync_committee
                )));
        }

        Ok(())
    }

    /// get the sync committee from the store
    pub fn get_sync_committee<CC: ChainContext, CU: ConsensusUpdate<SYNC_COMMITTEE_SIZE>>(
        &self,
        ctx: &CC,
        store: &ST,
        update: &CU,
    ) -> Result<SyncCommittee<SYNC_COMMITTEE_SIZE>, Error> {
        let store_period = compute_sync_committee_period_at_slot(ctx, store.current_slot());
        let update_signature_period =
            compute_sync_committee_period_at_slot(ctx, update.signature_slot());

        // https://github.com/ethereum/consensus-specs/blob/087e7378b44f327cdad4549304fc308613b780c3/specs/altair/light-client/sync-protocol.md#validate_light_client_update
        // # Verify sync committee aggregate signature
        // if update_signature_period == store_period:
        //     sync_committee = store.current_sync_committee
        // else:
        //     sync_committee = store.next_sync_committee
        if update_signature_period == store_period {
            Ok(store.current_sync_committee().clone())
        } else if update_signature_period == store_period + 1 {
            if let Some(next_sync_committee) = store.next_sync_committee() {
                Ok(next_sync_committee.clone())
            } else {
                Err(Error::NoNextSyncCommitteeInStore(
                    store_period.into(),
                    update_signature_period.into(),
                ))
            }
        } else {
            Err(Error::UnexpectedSingaturePeriod(
                store_period,
                update_signature_period,
                "signature period must be equal to store_period or store_period+1".into(),
            ))
        }
    }
}

/// verify a sync committee attestation
pub fn verify_sync_committee_attestation<
    const SYNC_COMMITTEE_SIZE: usize,
    CC: ChainContext + ConsensusVerificationContext,
    CU: ConsensusUpdate<SYNC_COMMITTEE_SIZE>,
>(
    ctx: &CC,
    consensus_update: &CU,
    sync_committee: &SyncCommittee<SYNC_COMMITTEE_SIZE>,
) -> Result<(), Error> {
    let participant_pubkeys: Vec<BLSPublicKey> = consensus_update
        .sync_aggregate()
        .sync_committee_bits
        .iter()
        .zip(sync_committee.pubkeys.iter())
        .filter(|it| it.0 == true)
        .map(|t| t.1.clone().try_into().unwrap())
        .collect();

    let fork_version_slot = consensus_update.signature_slot().max(1.into()) - 1;
    let fork_version = compute_fork_version(ctx, compute_epoch_at_slot(ctx, fork_version_slot))?;
    let domain = compute_domain(
        ctx,
        DOMAIN_SYNC_COMMITTEE,
        Some(fork_version),
        Some(ctx.genesis_validators_root()),
    )?;
    let signing_root =
        compute_signing_root(consensus_update.attested_beacon_header().clone(), domain)?;

    verify_bls_signatures(
        participant_pubkeys,
        signing_root,
        consensus_update
            .sync_aggregate()
            .sync_committee_signature
            .clone()
            .try_into()?,
    )
}

/// validate_light_client_update validates a light client update
///
/// NOTE: we can skip the validation of the attested header's execution payload here because we do not reference it in the light client protocol
pub fn validate_light_client_update<
    const SYNC_COMMITTEE_SIZE: usize,
    CC: ChainContext,
    ST: LightClientStoreReader<SYNC_COMMITTEE_SIZE>,
    CU: ConsensusUpdate<SYNC_COMMITTEE_SIZE>,
>(
    ctx: &CC,
    store: &ST,
    consensus_update: &CU,
) -> Result<(), Error> {
    // https://github.com/ethereum/consensus-specs/blob/087e7378b44f327cdad4549304fc308613b780c3/specs/altair/light-client/sync-protocol.md#validate_light_client_update
    // Verify that the `finality_branch`, if present, confirms `finalized_header`
    // to match the finalized checkpoint root saved in the state of `attested_header`.
    // Note that the genesis finalized checkpoint root is represented as a zero hash.
    // if not is_finality_update(update):
    //     assert update.finalized_header == LightClientHeader()
    // else:
    //     if update_finalized_slot == GENESIS_SLOT:
    //         assert update.finalized_header == LightClientHeader()
    //         finalized_root = Bytes32()
    //     else:
    //         assert is_valid_light_client_header(update.finalized_header)
    //         finalized_root = hash_tree_root(update.finalized_header.beacon)
    //     assert is_valid_normalized_merkle_branch(
    //         leaf=finalized_root,
    //         branch=update.finality_branch,
    //         gindex=finalized_root_gindex_at_slot(update.attested_header.beacon.slot),
    //         root=update.attested_header.beacon.state_root,
    //     )

    // we assume that the `finalized_beacon_header_branch`` must be non-empty
    if consensus_update.finalized_beacon_header_branch().is_empty() {
        return Err(Error::FinalizedHeaderNotFound);
    }
    let finalized_root = if consensus_update.finalized_beacon_header().slot
        == ctx.fork_parameters().genesis_slot()
    {
        if consensus_update.finalized_beacon_header() != &BeaconBlockHeader::default() {
            return Err(Error::NonEmptyBeaconHeaderAtGenesisSlot(
                ctx.fork_parameters().genesis_slot().into(),
            ));
        }
        Default::default()
    } else {
        // ensure that the finalized header is non-empty
        if consensus_update.finalized_beacon_header() == &BeaconBlockHeader::default() {
            return Err(Error::FinalizedHeaderNotFound);
        }
        consensus_update.is_valid_light_client_finalized_header()?;
        hash_tree_root(consensus_update.finalized_beacon_header().clone())?
    };
    is_valid_merkle_branch(
        finalized_root,
        &consensus_update.finalized_beacon_header_branch(),
        FINALIZED_ROOT_DEPTH as u32,
        FINALIZED_ROOT_SUBTREE_INDEX,
        consensus_update.attested_beacon_header().state_root,
    )
    .map_err(Error::InvalidFinalizedBeaconHeaderMerkleBranch)?;

    // # Verify that the `next_sync_committee`, if present, actually is the next sync committee saved in the
    // # state of the `attested_header`
    // if not is_sync_committee_update(update):
    //     assert update.next_sync_committee == SyncCommittee()
    // else:
    //     if update_attested_period == store_period and is_next_sync_committee_known(store):
    //         assert update.next_sync_committee == store.next_sync_committee
    //     assert is_valid_normalized_merkle_branch(
    //         leaf=hash_tree_root(update.next_sync_committee),
    //         branch=update.next_sync_committee_branch,
    //         gindex=next_sync_committee_gindex_at_slot(update.attested_header.beacon.slot),
    //         root=update.attested_header.beacon.state_root,
    //     )
    if let Some(update_next_sync_committee) = consensus_update.next_sync_committee() {
        let update_attested_period = compute_sync_committee_period_at_slot(
            ctx,
            consensus_update.attested_beacon_header().slot,
        );
        let store_period = compute_sync_committee_period_at_slot(ctx, store.current_slot());
        if let Some(store_next_sync_committee) = store.next_sync_committee() {
            if update_attested_period == store_period
                && store_next_sync_committee != update_next_sync_committee
            {
                return Err(Error::InconsistentNextSyncCommittee(
                    store_next_sync_committee.aggregate_pubkey.clone(),
                    update_next_sync_committee.aggregate_pubkey.clone(),
                ));
            }
        }
        is_valid_merkle_branch(
            hash_tree_root(update_next_sync_committee.clone())?,
            &consensus_update.next_sync_committee_branch().unwrap(),
            NEXT_SYNC_COMMITTEE_DEPTH as u32,
            NEXT_SYNC_COMMITTEE_SUBTREE_INDEX,
            consensus_update.attested_beacon_header().state_root,
        )
        .map_err(Error::InvalidNextSyncCommitteeMerkleBranch)?;
    } else if let Some(branch) = consensus_update.next_sync_committee_branch() {
        return Err(Error::NonEmptyNextSyncCommittee(branch.to_vec()));
    }

    Ok(())
}

pub fn verify_bls_signatures(
    pubkeys: Vec<BLSPublicKey>,
    msg: H256,
    signature: BLSSignature,
) -> Result<(), Error> {
    if fast_aggregate_verify(pubkeys, msg, signature)? {
        Ok(())
    } else {
        Err(Error::InvalidBLSSignatures)
    }
}

#[cfg(test)]
mod tests_bellatrix {
    use super::*;
    use crate::{
        context::{Fraction, LightClientContext},
        mock::MockStore,
        updates::{
            bellatrix::{ConsensusUpdateInfo, ExecutionUpdateInfo, LightClientBootstrapInfo},
            LightClientBootstrap,
        },
    };
    use ethereum_consensus::{
        beacon::Version,
        bellatrix::EXECUTION_PAYLOAD_TREE_DEPTH,
        bls::aggreate_public_key,
        config::{minimal, Config},
        fork::{ForkParameter, ForkParameters},
        preset,
        types::U64,
    };
    use std::{fs, path::PathBuf};

    const TEST_DATA_DIR: &str = "./data";

    #[test]
    fn test_bootstrap() {
        let verifier = SyncProtocolVerifier::<
            { preset::minimal::PRESET.SYNC_COMMITTEE_SIZE },
            EXECUTION_PAYLOAD_TREE_DEPTH,
            MockStore<{ preset::minimal::PRESET.SYNC_COMMITTEE_SIZE }>,
        >::default();
        let path = format!("{}/initial_state.json", TEST_DATA_DIR);
        let (bootstrap, _, _) = get_init_state(path);
        assert!(verifier.validate_boostrap(&bootstrap, None).is_ok());
    }

    #[test]
    fn test_pubkey_aggregation() {
        let path = format!("{}/initial_state.json", TEST_DATA_DIR);
        let (bootstrap, _, _) = get_init_state(path);
        let pubkeys: Vec<BLSPublicKey> = bootstrap
            .current_sync_committee()
            .pubkeys
            .iter()
            .map(|k| k.clone().try_into().unwrap())
            .collect();
        let aggregated_key = aggreate_public_key(&pubkeys).unwrap();
        let pubkey = BLSPublicKey {
            point: aggregated_key.point,
        };
        assert!(pubkey.key_validate());

        assert!(
            pubkey
                == bootstrap
                    .current_sync_committee()
                    .aggregate_pubkey
                    .clone()
                    .try_into()
                    .unwrap()
        );
    }

    #[test]
    fn test_verification() {
        let verifier = SyncProtocolVerifier::<
            { preset::minimal::PRESET.SYNC_COMMITTEE_SIZE },
            EXECUTION_PAYLOAD_TREE_DEPTH,
            MockStore<{ preset::minimal::PRESET.SYNC_COMMITTEE_SIZE }>,
        >::default();

        let (bootstrap, execution_payload_state_root, genesis_validators_root) =
            get_init_state(format!("{}/initial_state.json", TEST_DATA_DIR));
        assert!(verifier.validate_boostrap(&bootstrap, None).is_ok());

        let mut store = MockStore::new(
            bootstrap.beacon_header().clone(),
            bootstrap.current_sync_committee().clone(),
            execution_payload_state_root,
        );
        let ctx = LightClientContext::new_with_config(
            get_minimal_bellatrix_config(),
            genesis_validators_root,
            // NOTE: this is workaround. we must get the correct timestamp from beacon state.
            minimal::get_config().min_genesis_time,
            Fraction::new(2, 3),
            1729846322.into(),
        );

        let updates = [
            "light_client_update_period_5.json",
            "light_client_update_period_6.json",
            "finality_update_period_6.json",
            "light_client_update_period_7.json",
            "finality_update_period_7.json",
            "light_client_update_period_8.json",
            "finality_update_period_8.json",
            "light_client_update_period_9.json",
            "finality_update_period_9.json",
        ];

        for update in updates.into_iter() {
            let (consensus_update, execution_update) =
                get_updates(format!("{}/{}", TEST_DATA_DIR, update));
            assert!(verifier
                .validate_updates(&ctx, &store, &consensus_update, &execution_update)
                .is_ok());
            let res = store.apply_light_client_update(&ctx, &consensus_update);
            assert!(res.is_ok() && res.unwrap());
        }
    }

    // returns boostrap, execution_state_root, genesis_validators_root
    fn get_init_state(
        path: impl Into<PathBuf>,
    ) -> (
        LightClientBootstrapInfo<{ preset::minimal::PRESET.SYNC_COMMITTEE_SIZE }>,
        H256,
        H256,
    ) {
        let s = fs::read_to_string(path.into()).unwrap();
        serde_json::from_str(&s).unwrap()
    }

    fn get_updates(
        path: impl Into<PathBuf>,
    ) -> (
        ConsensusUpdateInfo<{ preset::minimal::PRESET.SYNC_COMMITTEE_SIZE }>,
        ExecutionUpdateInfo,
    ) {
        let s = fs::read_to_string(path.into()).unwrap();
        serde_json::from_str(&s).unwrap()
    }

    fn get_minimal_bellatrix_config() -> Config {
        Config {
            preset: preset::minimal::PRESET,
            fork_parameters: ForkParameters::new(
                Version([0, 0, 0, 1]),
                vec![
                    ForkParameter::new(Version([2, 0, 0, 1]), U64(0)),
                    ForkParameter::new(Version([1, 0, 0, 1]), U64(0)),
                ],
            ),
            min_genesis_time: U64(1578009600),
        }
    }
}
