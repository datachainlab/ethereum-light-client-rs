use crate::context::{ChainConsensusVerificationContext, ConsensusVerificationContext};
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
use ethereum_consensus::fork::ForkSpec;
use ethereum_consensus::merkle::is_valid_normalized_merkle_branch;
use ethereum_consensus::sync_protocol::SyncCommittee;
use ethereum_consensus::types::H256;

/// SyncProtocolVerifier is a verifier of [light client sync protocol](https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncProtocolVerifier<
    const SYNC_COMMITTEE_SIZE: usize,
    ST: LightClientStoreReader<SYNC_COMMITTEE_SIZE>,
>(PhantomData<ST>);

impl<const SYNC_COMMITTEE_SIZE: usize, ST: LightClientStoreReader<SYNC_COMMITTEE_SIZE>>
    SyncProtocolVerifier<SYNC_COMMITTEE_SIZE, ST>
{
    /// validates a LightClientBootstrap
    pub fn validate_boostrap<
        CC: ChainConsensusVerificationContext,
        LB: LightClientBootstrap<SYNC_COMMITTEE_SIZE>,
    >(
        &self,
        ctx: &CC,
        bootstrap: &LB,
        trusted_block_root: Option<Root>,
    ) -> Result<(), Error> {
        if let Some(trusted_block_root) = trusted_block_root {
            let root = hash_tree_root(bootstrap.beacon_header().clone())?;
            if trusted_block_root != root {
                return Err(Error::TrustedRootMismatch(trusted_block_root, root));
            }
        }
        let fork_spec = ctx.compute_fork_spec(bootstrap.beacon_header().slot);
        is_valid_normalized_merkle_branch(
            hash_tree_root(bootstrap.current_sync_committee().clone())?,
            &bootstrap.current_sync_committee_branch(),
            fork_spec.current_sync_committee_gindex,
            bootstrap.beacon_header().state_root,
        )
        .map_err(Error::InvalidCurrentSyncCommitteeMerkleBranch)?;
        Ok(())
    }

    /// validates consensus update and execution update
    pub fn validate_updates<
        CC: ChainConsensusVerificationContext,
        CU: ConsensusUpdate<SYNC_COMMITTEE_SIZE>,
        EU: ExecutionUpdate,
    >(
        &self,
        ctx: &CC,
        store: &ST,
        consensus_update: &CU,
        execution_update: &EU,
    ) -> Result<(), Error> {
        self.validate_consensus_update(ctx, store, consensus_update)?;
        self.validate_execution_update(
            ctx.compute_fork_spec(consensus_update.finalized_beacon_header().slot),
            consensus_update.finalized_execution_root(),
            execution_update,
        )?;
        Ok(())
    }

    /// validate a consensus update with a committee from the trusted store
    /// follow the light client protocol in the consensus spec
    pub fn validate_consensus_update<
        CC: ChainConsensusVerificationContext,
        CU: ConsensusUpdate<SYNC_COMMITTEE_SIZE>,
    >(
        &self,
        ctx: &CC,
        store: &ST,
        consensus_update: &CU,
    ) -> Result<(), Error> {
        consensus_update.validate_basic(ctx)?;
        store.ensure_relevant_update(ctx, consensus_update)?;
        let sync_committee = self.get_sync_committee(ctx, store, consensus_update)?;
        validate_light_client_update(ctx, store, consensus_update)?;
        verify_sync_committee_attestation(ctx, consensus_update, &sync_committee)?;
        Ok(())
    }

    /// validate an execution update with trusted/verified beacon block body
    pub fn validate_execution_update<EU: ExecutionUpdate>(
        &self,
        update_fork_spec: ForkSpec,
        trusted_execution_root: Root,
        execution_update: &EU,
    ) -> Result<(), Error> {
        execution_update.validate_basic()?;
        if update_fork_spec.execution_payload_gindex == 0 {
            return Err(Error::NoExecutionPayloadInBeaconBlock);
        }
        is_valid_normalized_merkle_branch(
            hash_tree_root(execution_update.state_root())
                .unwrap()
                .0
                .into(),
            &execution_update.state_root_branch(),
            update_fork_spec.execution_payload_state_root_gindex,
            trusted_execution_root,
        )
        .map_err(Error::InvalidExecutionStateRootMerkleBranch)?;

        is_valid_normalized_merkle_branch(
            hash_tree_root(execution_update.block_number())
                .unwrap()
                .0
                .into(),
            &execution_update.block_number_branch(),
            update_fork_spec.execution_payload_block_number_gindex,
            trusted_execution_root,
        )
        .map_err(Error::InvalidExecutionBlockNumberMerkleBranch)?;

        Ok(())
    }

    /// validates a misbehaviour with the store.
    /// it returns `Ok` if the misbehaviour is valid
    pub fn validate_misbehaviour<
        CC: ChainConsensusVerificationContext,
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

    /// get the sync committee from the store
    pub fn get_sync_committee<CC: ChainContext, CU: ConsensusUpdate<SYNC_COMMITTEE_SIZE>>(
        &self,
        ctx: &CC,
        store: &ST,
        update: &CU,
    ) -> Result<SyncCommittee<SYNC_COMMITTEE_SIZE>, Error> {
        let update_signature_period =
            compute_sync_committee_period_at_slot(ctx, update.signature_slot());
        if let Some(committee) = store.get_sync_committee(ctx, update_signature_period) {
            Ok(committee)
        } else {
            Err(Error::UnexpectedSingaturePeriod(
                update_signature_period,
                "store does not have the sync committee corresponding to the update signature period"
                    .into(),
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
    // ensure that suffienct participants exist
    let participants = consensus_update.sync_aggregate().count_participants();
    // from the spec: `assert sum(sync_aggregate.sync_committee_bits) >= MIN_SYNC_COMMITTEE_PARTICIPANTS`
    if participants < ctx.min_sync_committee_participants() {
        return Err(Error::LessThanMinimalParticipants(
            participants,
            ctx.min_sync_committee_participants(),
        ));
    } else if participants as u64 * ctx.signature_threshold().denominator
        < consensus_update.sync_aggregate().sync_committee_bits.len() as u64
            * ctx.signature_threshold().numerator
    {
        return Err(Error::InsufficientParticipants(
            participants as u64,
            consensus_update.sync_aggregate().sync_committee_bits.len() as u64,
        ));
    }

    let participant_pubkeys: Vec<BLSPublicKey> = consensus_update
        .sync_aggregate()
        .sync_committee_bits
        .iter()
        .zip(sync_committee.pubkeys.iter())
        .filter(|it| it.0 == true)
        .map(|t| t.1.clone().try_into().unwrap())
        .collect();

    let fork_version_slot = consensus_update.signature_slot().max(1.into()) - 1;
    let fork_version = compute_fork_version(ctx, compute_epoch_at_slot(ctx, fork_version_slot));
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
    CC: ChainConsensusVerificationContext,
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
        consensus_update.is_valid_light_client_finalized_header(ctx)?;
        hash_tree_root(consensus_update.finalized_beacon_header().clone())?
    };
    is_valid_normalized_merkle_branch(
        finalized_root,
        &consensus_update.finalized_beacon_header_branch(),
        ctx.compute_fork_spec(consensus_update.attested_beacon_header().slot)
            .finalized_root_gindex,
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
        if let Some(committee) = store.get_sync_committee(ctx, update_attested_period + 1) {
            if committee != *update_next_sync_committee {
                return Err(Error::InconsistentNextSyncCommittee(
                    committee.aggregate_pubkey.clone(),
                    update_next_sync_committee.aggregate_pubkey.clone(),
                ));
            }
        }
        is_valid_normalized_merkle_branch(
            hash_tree_root(update_next_sync_committee.clone())?,
            &consensus_update.next_sync_committee_branch().unwrap(),
            ctx.compute_fork_spec(consensus_update.attested_beacon_header().slot)
                .next_sync_committee_gindex,
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
mod tests {
    use super::*;

    mod bellatrix {
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
            bls::aggreate_public_key,
            config::{minimal, Config},
            fork::{
                altair::ALTAIR_FORK_SPEC, bellatrix::BELLATRIX_FORK_SPEC, ForkParameter,
                ForkParameters,
            },
            preset,
            types::U64,
        };
        use std::{fs, path::PathBuf};

        const TEST_DATA_DIR: &str = "./data/bellatrix";

        #[test]
        fn test_bootstrap() {
            let verifier = SyncProtocolVerifier::<
                { preset::minimal::PRESET.SYNC_COMMITTEE_SIZE },
                MockStore<{ preset::minimal::PRESET.SYNC_COMMITTEE_SIZE }>,
            >::default();
            let path = format!("{}/initial_state.json", TEST_DATA_DIR);
            let (bootstrap, _, genesis_validators_root) = get_init_state(path);
            let ctx = LightClientContext::new_with_config(
                get_minimal_bellatrix_config(),
                genesis_validators_root,
                // NOTE: this is workaround. we must get the correct timestamp from beacon state.
                minimal::get_config().min_genesis_time,
                Fraction::new(2, 3),
                1729846322.into(),
            );
            assert!(verifier.validate_boostrap(&ctx, &bootstrap, None).is_ok());
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
                MockStore<{ preset::minimal::PRESET.SYNC_COMMITTEE_SIZE }>,
            >::default();

            let (bootstrap, execution_payload_state_root, genesis_validators_root) =
                get_init_state(format!("{}/initial_state.json", TEST_DATA_DIR));
            let ctx = LightClientContext::new_with_config(
                get_minimal_bellatrix_config(),
                genesis_validators_root,
                // NOTE: this is workaround. we must get the correct timestamp from beacon state.
                minimal::get_config().min_genesis_time,
                Fraction::new(2, 3),
                1729846322.into(),
            );
            assert!(verifier.validate_boostrap(&ctx, &bootstrap, None).is_ok());

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

            let mut store = MockStore::new(
                bootstrap.beacon_header().clone(),
                bootstrap.current_sync_committee().clone(),
                execution_payload_state_root,
            );
            for update in updates.into_iter() {
                let (consensus_update, execution_update) =
                    get_updates(format!("{}/{}", TEST_DATA_DIR, update));
                assert!(verifier
                    .validate_updates(&ctx, &store, &consensus_update, &execution_update)
                    .is_ok());
                let res = store.apply_light_client_update(&ctx, &consensus_update);
                assert!(res.is_ok(), "{:?}", res);
                assert!(res.as_ref().unwrap().is_some());
                store = res.unwrap().unwrap();
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
                        ForkParameter::new(Version([1, 0, 0, 1]), U64(0), ALTAIR_FORK_SPEC),
                        ForkParameter::new(Version([2, 0, 0, 1]), U64(0), BELLATRIX_FORK_SPEC),
                    ],
                )
                .unwrap(),
                min_genesis_time: U64(1578009600),
            }
        }
    }

    mod deneb {
        use std::time::SystemTime;

        use crate::{
            context::{Fraction, LightClientContext},
            misbehaviour::{FinalizedHeaderMisbehaviour, NextSyncCommitteeMisbehaviour},
            mock::MockStore,
        };
        use ethereum_consensus::{config, types::U64};
        use utils::{
            gen_light_client_update, gen_light_client_update_with_params, MockSyncCommitteeManager,
        };

        use super::*;

        #[test]
        fn test_lc() {
            let scm = MockSyncCommitteeManager::<32>::new(1, 4);
            let ctx = LightClientContext::new_with_config(
                config::minimal::get_config(),
                Default::default(),
                Default::default(),
                Fraction::new(2, 3),
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .into(),
            );
            let period_1 = U64(1) * ctx.slots_per_epoch() * ctx.epochs_per_sync_committee_period();

            let initial_header = BeaconBlockHeader {
                slot: period_1,
                ..Default::default()
            };
            let current_sync_committee = scm.get_committee(1);
            let store = MockStore::new(
                initial_header,
                current_sync_committee.to_committee(),
                Default::default(),
            );
            let base_signature_slot = period_1 + 11;
            let base_attested_slot = base_signature_slot - 1;
            let base_finalized_epoch = base_attested_slot / ctx.slots_per_epoch();
            let dummy_execution_state_root = [1u8; 32].into();
            let dummy_execution_block_number = 1;

            {
                let update_valid = gen_light_client_update::<32, _>(
                    &ctx,
                    base_signature_slot,
                    base_attested_slot,
                    base_finalized_epoch,
                    dummy_execution_state_root,
                    dummy_execution_block_number.into(),
                    &scm,
                );
                let res = SyncProtocolVerifier::default().validate_consensus_update(
                    &ctx,
                    &store,
                    &update_valid,
                );
                assert!(res.is_ok(), "{:?}", res);
            }
            {
                let update_insufficient_attestations = gen_light_client_update_with_params(
                    &ctx,
                    base_signature_slot,
                    base_attested_slot,
                    base_finalized_epoch,
                    dummy_execution_state_root,
                    dummy_execution_block_number.into(),
                    current_sync_committee,
                    scm.get_committee(3),
                    21,
                );
                let res = SyncProtocolVerifier::default().validate_consensus_update(
                    &ctx,
                    &store,
                    &update_insufficient_attestations,
                );
                assert!(res.is_err(), "{:?}", res);
            }
            {
                let update_zero_attestations = gen_light_client_update_with_params(
                    &ctx,
                    base_signature_slot,
                    base_attested_slot,
                    base_finalized_epoch,
                    dummy_execution_state_root,
                    dummy_execution_block_number.into(),
                    current_sync_committee,
                    scm.get_committee(3),
                    0,
                );
                let res = SyncProtocolVerifier::default().validate_consensus_update(
                    &ctx,
                    &store,
                    &update_zero_attestations,
                );
                assert!(res.is_err(), "{:?}", res);
            }
            {
                //
                //                                    |
                //    +-----------+     +----------+  |  +-----------+
                //    | finalized | <-- | attested | <-- | signature |
                //    +-----------+     +----------+  |  +-----------+
                //                                    |
                //                                    |
                //                               sync committee
                //                               period boundary
                //
                let next_period_signature_slot = base_signature_slot
                    + ctx.slots_per_epoch() * ctx.epochs_per_sync_committee_period();
                let update_unknown_next_committee = gen_light_client_update::<32, _>(
                    &ctx,
                    next_period_signature_slot,
                    base_attested_slot,
                    base_finalized_epoch,
                    dummy_execution_state_root,
                    dummy_execution_block_number.into(),
                    &scm,
                );
                let res = SyncProtocolVerifier::default().validate_consensus_update(
                    &ctx,
                    &store,
                    &update_unknown_next_committee,
                );
                assert!(res.is_err(), "{:?}", res);

                let store = MockStore {
                    next_sync_committee: Some(scm.get_committee(2).to_committee()),
                    ..store.clone()
                };
                let update_valid = gen_light_client_update::<32, _>(
                    &ctx,
                    next_period_signature_slot,
                    base_attested_slot,
                    base_finalized_epoch,
                    dummy_execution_state_root,
                    dummy_execution_block_number.into(),
                    &scm,
                );
                let res = SyncProtocolVerifier::default().validate_consensus_update(
                    &ctx,
                    &store,
                    &update_valid,
                );
                assert!(res.is_ok(), "{:?}", res);
            }
            {
                //
                //                   |
                //    +-----------+  |  +----------+     +-----------+
                //    | finalized | <-- | attested | <-- | signature |
                //    +-----------+  |  +----------+     +-----------+
                //                   |
                //                   |
                //              sync committee
                //              period boundary
                //
                let next_period_signature_slot = base_signature_slot
                    + ctx.slots_per_epoch() * ctx.epochs_per_sync_committee_period();
                let next_period_attested_slot = next_period_signature_slot - 1;
                let store = MockStore {
                    next_sync_committee: Some(scm.get_committee(2).to_committee()),
                    ..store.clone()
                };
                let update_invalid_inconsistent_periods = gen_light_client_update::<32, _>(
                    &ctx,
                    next_period_signature_slot,
                    next_period_attested_slot,
                    base_finalized_epoch,
                    dummy_execution_state_root,
                    dummy_execution_block_number.into(),
                    &scm,
                );
                let res = SyncProtocolVerifier::default().validate_consensus_update(
                    &ctx,
                    &store,
                    &update_invalid_inconsistent_periods,
                );
                assert!(res.is_err(), "{:?}", res);
                if let Some(Error::InconsistentUpdatePeriod(a, b)) = res.as_ref().err() {
                    assert_eq!(a, &1.into());
                    assert_eq!(b, &2.into());
                } else {
                    panic!("unexpected error: {:?}", res);
                }
            }
        }

        #[test]
        fn test_lc_misbehaviour() {
            let scm = MockSyncCommitteeManager::<32>::new(1, 4);
            let current_sync_committee = scm.get_committee(1);
            let ctx = LightClientContext::new_with_config(
                config::minimal::get_config(),
                Default::default(),
                Default::default(),
                Fraction::new(2, 3),
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .into(),
            );
            let start_slot =
                U64(1) * ctx.slots_per_epoch() * ctx.epochs_per_sync_committee_period();

            let initial_header = BeaconBlockHeader {
                slot: start_slot,
                ..Default::default()
            };
            let store = MockStore::new(
                initial_header,
                current_sync_committee.to_committee(),
                Default::default(),
            );

            let dummy_execution_state_root = [1u8; 32].into();
            let dummy_execution_block_number = 1;
            let base_signature_slot = start_slot + 11;
            let base_attested_slot = base_signature_slot - 1;
            let base_finalized_epoch = base_attested_slot / ctx.slots_per_epoch();

            let update_1 = gen_light_client_update_with_params::<32, _>(
                &ctx,
                base_signature_slot,
                base_attested_slot,
                base_finalized_epoch,
                dummy_execution_state_root,
                dummy_execution_block_number.into(),
                current_sync_committee,
                scm.get_committee(2),
                32,
            );

            {
                let update_valid = gen_light_client_update_with_params::<32, _>(
                    &ctx,
                    base_signature_slot,
                    base_attested_slot,
                    base_finalized_epoch,
                    dummy_execution_state_root,
                    dummy_execution_block_number.into(),
                    current_sync_committee,
                    scm.get_committee(3),
                    32,
                );
                let res = SyncProtocolVerifier::default().validate_misbehaviour(
                    &ctx,
                    &store,
                    Misbehaviour::NextSyncCommittee(NextSyncCommitteeMisbehaviour {
                        consensus_update_1: update_1.clone(),
                        consensus_update_2: update_valid,
                    }),
                );
                assert!(res.is_ok(), "{:?}", res);
            }
            {
                let update_valid_different_slots = gen_light_client_update_with_params::<32, _>(
                    &ctx,
                    base_signature_slot + 1,
                    base_attested_slot + 1,
                    base_finalized_epoch,
                    dummy_execution_state_root,
                    dummy_execution_block_number.into(),
                    current_sync_committee,
                    scm.get_committee(3),
                    32,
                );
                let res = SyncProtocolVerifier::default().validate_misbehaviour(
                    &ctx,
                    &store,
                    Misbehaviour::NextSyncCommittee(NextSyncCommitteeMisbehaviour {
                        consensus_update_1: update_1.clone(),
                        consensus_update_2: update_valid_different_slots,
                    }),
                );
                assert!(res.is_ok(), "{:?}", res);
            }
            {
                let update_insufficient_attestations = gen_light_client_update_with_params::<32, _>(
                    &ctx,
                    base_signature_slot,
                    base_attested_slot,
                    base_finalized_epoch,
                    dummy_execution_state_root,
                    dummy_execution_block_number.into(),
                    current_sync_committee,
                    scm.get_committee(3),
                    21, // at least 22 is required
                );
                let res = SyncProtocolVerifier::default().validate_misbehaviour(
                    &ctx,
                    &store,
                    Misbehaviour::NextSyncCommittee(NextSyncCommitteeMisbehaviour {
                        consensus_update_1: update_1.clone(),
                        consensus_update_2: update_insufficient_attestations,
                    }),
                );
                assert!(res.is_err(), "{:?}", res);
            }
            {
                let different_period_attested_slot = base_attested_slot
                    + ctx.slots_per_epoch() * ctx.epochs_per_sync_committee_period();
                let update_different_attested_period = gen_light_client_update_with_params::<32, _>(
                    &ctx,
                    base_signature_slot,
                    different_period_attested_slot,
                    base_finalized_epoch,
                    dummy_execution_state_root,
                    dummy_execution_block_number.into(),
                    current_sync_committee,
                    scm.get_committee(3),
                    32,
                );
                let res = SyncProtocolVerifier::default().validate_misbehaviour(
                    &ctx,
                    &store,
                    Misbehaviour::NextSyncCommittee(NextSyncCommitteeMisbehaviour {
                        consensus_update_1: update_1.clone(),
                        consensus_update_2: update_different_attested_period,
                    }),
                );
                assert!(res.is_err(), "{:?}", res);
            }
            {
                let different_dummy_execution_state_root = [2u8; 32].into();
                let update_different_finalized_block = gen_light_client_update_with_params::<32, _>(
                    &ctx,
                    base_signature_slot,
                    base_attested_slot,
                    base_finalized_epoch,
                    different_dummy_execution_state_root,
                    dummy_execution_block_number.into(),
                    current_sync_committee,
                    scm.get_committee(2),
                    32,
                );
                let res = SyncProtocolVerifier::default().validate_misbehaviour(
                    &ctx,
                    &store,
                    Misbehaviour::FinalizedHeader(FinalizedHeaderMisbehaviour {
                        consensus_update_1: update_1.clone(),
                        consensus_update_2: update_different_finalized_block,
                    }),
                );
                assert!(res.is_ok(), "{:?}", res);
            }
            {
                let different_dummy_execution_state_root = [2u8; 32].into();
                let different_finalized_epoch = base_finalized_epoch - 1;
                let update_different_finalized_block = gen_light_client_update_with_params::<32, _>(
                    &ctx,
                    base_signature_slot,
                    base_attested_slot,
                    different_finalized_epoch,
                    different_dummy_execution_state_root,
                    dummy_execution_block_number.into(),
                    current_sync_committee,
                    scm.get_committee(2),
                    32,
                );
                let res = SyncProtocolVerifier::default().validate_misbehaviour(
                    &ctx,
                    &store,
                    Misbehaviour::FinalizedHeader(FinalizedHeaderMisbehaviour {
                        consensus_update_1: update_1.clone(),
                        consensus_update_2: update_different_finalized_block,
                    }),
                );
                assert!(res.is_err(), "{:?}", res);
            }
            {
                let res = SyncProtocolVerifier::default().validate_misbehaviour(
                    &ctx,
                    &store,
                    Misbehaviour::FinalizedHeader(FinalizedHeaderMisbehaviour {
                        consensus_update_1: update_1.clone(),
                        consensus_update_2: update_1.clone(),
                    }),
                );
                assert!(res.is_err(), "{:?}", res);
            }
        }
    }

    mod utils {
        use crate::updates::{ConsensusUpdateInfo, LightClientUpdate};

        use super::*;
        use ethereum_consensus::{
            beacon::{BlockNumber, Checkpoint, Epoch, Slot},
            bls::{aggreate_public_key, PublicKey, Signature},
            fork::deneb,
            merkle::MerkleTree,
            preset::mainnet::DenebBeaconBlock,
            sync_protocol::SyncAggregate,
            types::U64,
        };
        use milagro_bls::{
            AggregateSignature, PublicKey as BLSPublicKey, SecretKey as BLSSecretKey,
        };
        use ssz_rs::Vector;

        #[derive(Clone)]
        struct Validator {
            sk: BLSSecretKey,
        }

        impl Default for Validator {
            fn default() -> Self {
                Self {
                    sk: BLSSecretKey::random(&mut rand::thread_rng()),
                }
            }
        }

        impl Validator {
            pub fn sign(&self, msg: H256) -> BLSSignature {
                BLSSignature::new(msg.as_bytes(), &self.sk)
            }

            pub fn public_key(&self) -> BLSPublicKey {
                BLSPublicKey::from_secret_key(&self.sk)
            }
        }

        #[derive(Clone)]
        pub struct MockSyncCommittee<const SYNC_COMMITTEE_SIZE: usize> {
            committee: Vec<Validator>,
        }

        impl<const SYNC_COMMITTEE_SIZE: usize> MockSyncCommittee<SYNC_COMMITTEE_SIZE> {
            pub fn new() -> Self {
                let mut committee = Vec::new();
                for _ in 0..SYNC_COMMITTEE_SIZE {
                    committee.push(Validator::default());
                }
                Self { committee }
            }

            pub fn to_committee(&self) -> SyncCommittee<SYNC_COMMITTEE_SIZE> {
                let mut pubkeys = Vec::new();
                for v in self.committee.iter() {
                    pubkeys.push(v.public_key());
                }
                let aggregate_pubkey = aggreate_public_key(&pubkeys.to_vec()).unwrap();
                SyncCommittee {
                    pubkeys: Vector::from_iter(pubkeys.into_iter().map(PublicKey::from)),
                    aggregate_pubkey: PublicKey::from(aggregate_pubkey),
                }
            }

            pub fn sign_header<C: ChainConsensusVerificationContext>(
                &self,
                ctx: &C,
                signature_slot: U64,
                attested_header: BeaconBlockHeader,
                sign_num: usize,
            ) -> SyncAggregate<SYNC_COMMITTEE_SIZE> {
                let fork_version_slot = signature_slot.max(1.into()) - 1;
                let fork_version =
                    compute_fork_version(ctx, compute_epoch_at_slot(ctx, fork_version_slot));
                let domain = compute_domain(
                    ctx,
                    DOMAIN_SYNC_COMMITTEE,
                    Some(fork_version),
                    Some(ctx.genesis_validators_root()),
                )
                .unwrap();
                let signing_root = compute_signing_root(attested_header, domain).unwrap();
                self.sign(signing_root, sign_num)
            }

            pub fn sign(
                &self,
                signing_root: H256,
                sign_num: usize,
            ) -> SyncAggregate<SYNC_COMMITTEE_SIZE> {
                // let mut sigs = Vec::new();
                let mut agg_sig = AggregateSignature::new();
                let mut sg = SyncAggregate::<SYNC_COMMITTEE_SIZE>::default();
                for (i, v) in self.committee.iter().enumerate() {
                    if i < sign_num {
                        agg_sig.add(&v.sign(signing_root));
                        sg.sync_committee_bits.set(i, true);
                    } else {
                        sg.sync_committee_bits.set(i, false);
                    }
                }
                sg.sync_committee_signature =
                    Signature::try_from(agg_sig.as_bytes().to_vec()).unwrap();
                sg
            }
        }

        pub struct MockSyncCommitteeManager<const SYNC_COMMITTEE_SIZE: usize> {
            pub base_period: u64,
            pub committees: Vec<MockSyncCommittee<SYNC_COMMITTEE_SIZE>>,
        }

        impl<const SYNC_COMMITTEE_SIZE: usize> MockSyncCommitteeManager<SYNC_COMMITTEE_SIZE> {
            pub fn new(base_period: u64, n_period: u64) -> Self {
                let mut committees = Vec::new();
                for _ in 0..n_period {
                    committees.push(MockSyncCommittee::<SYNC_COMMITTEE_SIZE>::new());
                }
                Self {
                    base_period,
                    committees,
                }
            }

            pub fn get_committee(&self, period: u64) -> &MockSyncCommittee<SYNC_COMMITTEE_SIZE> {
                let idx = period - self.base_period;
                &self.committees[idx as usize]
            }
        }

        pub fn gen_light_client_update<
            const SYNC_COMMITTEE_SIZE: usize,
            C: ChainConsensusVerificationContext,
        >(
            ctx: &C,
            signature_slot: Slot,
            attested_slot: Slot,
            finalized_epoch: Epoch,
            execution_state_root: H256,
            execution_block_number: BlockNumber,
            scm: &MockSyncCommitteeManager<SYNC_COMMITTEE_SIZE>,
        ) -> ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE> {
            let signature_period = compute_sync_committee_period_at_slot(ctx, signature_slot);
            let attested_period = compute_sync_committee_period_at_slot(ctx, attested_slot);
            gen_light_client_update_with_params(
                ctx,
                signature_slot,
                attested_slot,
                finalized_epoch,
                execution_state_root,
                execution_block_number,
                scm.get_committee(signature_period.into()),
                scm.get_committee((attested_period + 1).into()),
                SYNC_COMMITTEE_SIZE,
            )
        }

        #[allow(clippy::too_many_arguments)]
        pub fn gen_light_client_update_with_params<
            const SYNC_COMMITTEE_SIZE: usize,
            C: ChainConsensusVerificationContext,
        >(
            ctx: &C,
            signature_slot: Slot,
            attested_slot: Slot,
            finalized_epoch: Epoch,
            execution_state_root: H256,
            execution_block_number: BlockNumber,
            sync_committee: &MockSyncCommittee<SYNC_COMMITTEE_SIZE>,
            next_sync_committee: &MockSyncCommittee<SYNC_COMMITTEE_SIZE>,
            sign_num: usize,
        ) -> ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE> {
            assert!(
                sign_num <= SYNC_COMMITTEE_SIZE,
                "sign_num must be less than SYNC_COMMITTEE_SIZE({})",
                SYNC_COMMITTEE_SIZE
            );
            let finalized_block = gen_finalized_beacon_block::<SYNC_COMMITTEE_SIZE, _>(
                ctx,
                finalized_epoch,
                execution_state_root,
                execution_block_number,
            );
            let finalized_root = hash_tree_root(finalized_block.clone()).unwrap();
            let (attested_block, finalized_checkpoint_branch, _, next_sync_committee_branch) =
                gen_attested_beacon_block(
                    ctx,
                    attested_slot,
                    finalized_root,
                    sync_committee.to_committee(),
                    next_sync_committee.to_committee(),
                );

            let (_, finalized_execution_branch) =
                ethereum_consensus::fork::deneb::test_utils::gen_execution_payload_proof(
                    &finalized_block.body,
                )
                .unwrap();
            let finalized_execution_root =
                hash_tree_root(finalized_block.body.execution_payload.clone())
                    .unwrap()
                    .0
                    .into();

            let attested_header = attested_block.to_header();
            let update = LightClientUpdate::<SYNC_COMMITTEE_SIZE> {
                attested_header: attested_header.clone(),
                finalized_header: (finalized_block.to_header(), finalized_checkpoint_branch),
                signature_slot,
                sync_aggregate: sync_committee.sign_header(
                    ctx,
                    signature_slot,
                    attested_header,
                    sign_num,
                ),
                next_sync_committee: Some((
                    next_sync_committee.to_committee(),
                    next_sync_committee_branch,
                )),
            };

            ConsensusUpdateInfo {
                light_client_update: update,
                finalized_execution_root,
                finalized_execution_branch,
            }
        }

        fn compute_epoch_boundary_slot<C: ChainContext>(ctx: &C, epoch: Epoch) -> Slot {
            ctx.slots_per_epoch() * epoch
        }

        pub fn gen_attested_beacon_block<const SYNC_COMMITTEE_SIZE: usize, C: ChainContext>(
            _: &C,
            attested_slot: Slot,
            finalized_header_root: H256,
            current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
            next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
        ) -> (DenebBeaconBlock, Vec<H256>, Vec<H256>, Vec<H256>) {
            let mut block = DenebBeaconBlock {
                slot: attested_slot,
                ..Default::default()
            };

            let finalized_checkpoint = Checkpoint {
                root: finalized_header_root,
                ..Default::default()
            };
            let state = DummyDenebBeaconState::<SYNC_COMMITTEE_SIZE>::new(
                attested_slot.into(),
                finalized_checkpoint,
                current_sync_committee,
                next_sync_committee,
            );
            block.state_root = state.tree().root().unwrap().into();

            let finalized_checkpoint_proof = state.generate_finalized_checkpoint();
            let current_sync_committee_proof = state.generate_current_sync_committee_proof();
            let next_sync_committee_proof = state.generate_next_sync_committee_proof();
            (
                block,
                finalized_checkpoint_proof,
                current_sync_committee_proof,
                next_sync_committee_proof,
            )
        }

        pub fn gen_finalized_beacon_block<const SYNC_COMMITTEE_SIZE: usize, C: ChainContext>(
            ctx: &C,
            finalized_epoch: Epoch,
            execution_state_root: H256,
            execution_block_number: BlockNumber,
        ) -> DenebBeaconBlock {
            let mut block = DenebBeaconBlock {
                slot: compute_epoch_boundary_slot(ctx, finalized_epoch),
                ..Default::default()
            };
            let mut body = deneb::BeaconBlockBody::default();
            body.execution_payload.state_root = execution_state_root;
            body.execution_payload.block_number = execution_block_number;
            block.body = body;
            block
        }

        pub type DummySSZType = [u8; 32];

        /// https://github.com/ethereum/consensus-specs/blob/dev/specs/capella/beacon-chain.md#beaconstate
        #[derive(Debug, Clone, Default)]
        struct DummyDenebBeaconState<const SYNC_COMMITTEE_SIZE: usize> {
            genesis_time: DummySSZType,
            genesis_validators_root: DummySSZType,
            pub slot: U64,
            fork: DummySSZType,
            latest_block_header: DummySSZType,
            block_roots: DummySSZType,
            state_roots: DummySSZType,
            historical_roots: DummySSZType,
            eth1_data: DummySSZType,
            eth1_data_votes: DummySSZType,
            eth1_deposit_index: DummySSZType,
            validators: DummySSZType,
            balances: DummySSZType,
            randao_mixes: DummySSZType,
            slashings: DummySSZType,
            previous_epoch_participation: DummySSZType,
            current_epoch_participation: DummySSZType,
            justification_bits: DummySSZType,
            previous_justified_checkpoint: DummySSZType,
            current_justified_checkpoint: DummySSZType,
            pub finalized_checkpoint: Checkpoint,
            inactivity_scores: DummySSZType,
            pub current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
            pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
            latest_execution_payload_header: DummySSZType,
            next_withdrawal_index: DummySSZType,
            next_withdrawal_validator_index: DummySSZType,
            historical_summaries: DummySSZType,
        }

        impl<const SYNC_COMMITTEE_SIZE: usize> DummyDenebBeaconState<SYNC_COMMITTEE_SIZE> {
            pub fn new(
                slot: u64,
                finalized_checkpoint: Checkpoint,
                current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
                next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
            ) -> Self {
                Self {
                    slot: slot.into(),
                    finalized_checkpoint,
                    current_sync_committee,
                    next_sync_committee,
                    ..Default::default()
                }
            }

            pub fn tree(&self) -> MerkleTree {
                use ethereum_consensus::compute::hash_tree_root;
                let tree = MerkleTree::from_leaves(
                    ([
                        self.genesis_time,
                        self.genesis_validators_root,
                        hash_tree_root(self.slot).unwrap().0,
                        self.fork,
                        self.latest_block_header,
                        self.block_roots,
                        self.state_roots,
                        self.historical_roots,
                        self.eth1_data,
                        self.eth1_data_votes,
                        self.eth1_deposit_index,
                        self.validators,
                        self.balances,
                        self.randao_mixes,
                        self.slashings,
                        self.previous_epoch_participation,
                        self.current_epoch_participation,
                        self.justification_bits,
                        self.previous_justified_checkpoint,
                        self.current_justified_checkpoint,
                        hash_tree_root(self.finalized_checkpoint.clone()).unwrap().0,
                        self.inactivity_scores,
                        hash_tree_root(self.current_sync_committee.clone())
                            .unwrap()
                            .0,
                        hash_tree_root(self.next_sync_committee.clone()).unwrap().0,
                        self.latest_execution_payload_header,
                        self.next_withdrawal_index,
                        self.next_withdrawal_validator_index,
                        self.historical_summaries,
                        Default::default(),
                        Default::default(),
                        Default::default(),
                        Default::default(),
                    ] as [_; 32])
                        .as_ref(),
                );
                tree
            }

            pub fn generate_finalized_checkpoint(&self) -> Vec<H256> {
                let br: Vec<H256> = self
                    .tree()
                    .proof(&[20])
                    .proof_hashes()
                    .iter()
                    .map(|h| H256::from_slice(h))
                    .collect();
                let node = hash_tree_root(self.finalized_checkpoint.epoch)
                    .unwrap()
                    .0
                    .into();
                let mut branch: Vec<H256> = Vec::new();
                branch.push(node);
                for b in br.iter() {
                    branch.push(*b);
                }
                branch
            }

            pub fn generate_current_sync_committee_proof(&self) -> Vec<H256> {
                self.tree()
                    .proof(&[22])
                    .proof_hashes()
                    .iter()
                    .map(|h| H256::from_slice(h))
                    .collect()
            }

            pub fn generate_next_sync_committee_proof(&self) -> Vec<H256> {
                self.tree()
                    .proof(&[23])
                    .proof_hashes()
                    .iter()
                    .map(|h| H256::from_slice(h))
                    .collect()
            }
        }
    }
}
