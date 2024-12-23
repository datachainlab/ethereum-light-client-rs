use crate::context::{ChainConsensusVerificationContext, ConsensusVerificationContext};
use crate::errors::Error;
use crate::internal_prelude::*;
use crate::misbehaviour::Misbehaviour;
use crate::state::{get_sync_committee_at_period, LightClientStoreReader};
use crate::updates::{ConsensusUpdate, ExecutionUpdate, LightClientBootstrap};
use core::marker::PhantomData;
use ethereum_consensus::beacon::{BeaconBlockHeader, Root, DOMAIN_SYNC_COMMITTEE};
use ethereum_consensus::bls::{fast_aggregate_verify, BLSPublicKey, BLSSignature};
use ethereum_consensus::compute::{
    compute_domain, compute_epoch_at_slot, compute_fork_version, compute_signing_root,
    compute_sync_committee_period_at_slot, hash_tree_root,
};
use ethereum_consensus::context::ChainContext;
use ethereum_consensus::fork::{ForkSpec, BELLATRIX_INDEX};
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
    ///
    /// If the return value is `Ok`, the update satisfies the following conditions:
    /// * the update is valid light client update:
    ///   * all merkle branches are valid
    ///   * the number of committee signatures is sufficient
    /// * the update is relevant to the store
    /// * the signature period matches the store's current or next period
    /// * the attested period matches the finalized period or finalized period + 1
    pub fn validate_consensus_update<
        CC: ChainConsensusVerificationContext,
        CU: ConsensusUpdate<SYNC_COMMITTEE_SIZE>,
    >(
        &self,
        ctx: &CC,
        store: &ST,
        consensus_update: &CU,
    ) -> Result<(), Error> {
        validate_light_client_update(ctx, store, consensus_update)?;
        let sync_committee = self.get_sync_committee(ctx, store, consensus_update)?;
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

    /// get the sync committee corresponding to the update signature period from the store
    pub fn get_sync_committee<CC: ChainContext, CU: ConsensusUpdate<SYNC_COMMITTEE_SIZE>>(
        &self,
        ctx: &CC,
        store: &ST,
        update: &CU,
    ) -> Result<SyncCommittee<SYNC_COMMITTEE_SIZE>, Error> {
        let update_signature_period =
            compute_sync_committee_period_at_slot(ctx, update.signature_slot());
        if let Some(committee) = get_sync_committee_at_period(ctx, store, update_signature_period) {
            Ok(committee)
        } else {
            Err(Error::UnexpectedSingaturePeriod(
                store.current_period(ctx),
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
    } else if participants as u64 * ctx.signature_threshold().denominator()
        < consensus_update.sync_aggregate().sync_committee_bits.len() as u64
            * ctx.signature_threshold().numerator()
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
/// NOTE: we can skip the validation of the attested header's execution payload inclusion here because we do not use it in our light client implementation.
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
    consensus_update.validate_basic(ctx)?;
    let finalized_epoch =
        compute_epoch_at_slot(ctx, consensus_update.finalized_beacon_header().slot);
    if !ctx
        .fork_parameters()
        .is_fork(finalized_epoch, BELLATRIX_INDEX)
    {
        return Err(Error::ForkNotSupported(finalized_epoch));
    }

    let current_period = store.current_period(ctx);
    let signature_period =
        compute_sync_committee_period_at_slot(ctx, consensus_update.signature_slot());
    // ensure that the update is relevant to the store
    // the `store` only has the current and next sync committee, so the signature period must match the current or next period
    if current_period != signature_period && current_period + 1 != signature_period {
        return Err(Error::StoreNotCoveredSignaturePeriod(
            current_period,
            signature_period,
        ));
    }
    store.ensure_relevant_update(ctx, consensus_update)?;

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
        if let Some(committee) =
            get_sync_committee_at_period(ctx, store, update_attested_period + 1)
        {
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

#[cfg(any(feature = "test-utils", test))]
pub mod test_utils {
    use super::*;
    use crate::updates::{ConsensusUpdateInfo, ExecutionUpdateInfo, LightClientUpdate};
    use ethereum_consensus::fork::deneb::prover::gen_execution_payload_field_proof;
    use ethereum_consensus::milagro_bls::{
        AggregateSignature, PublicKey as BLSPublicKey, SecretKey as BLSSecretKey,
    };
    use ethereum_consensus::ssz_rs::Vector;
    use ethereum_consensus::{
        beacon::{BlockNumber, Checkpoint, Epoch, Slot},
        bls::{aggreate_public_key, PublicKey, Signature},
        fork::deneb,
        merkle::MerkleTree,
        preset::minimal::DenebBeaconBlock,
        sync_protocol::SyncAggregate,
        types::U64,
    };

    #[derive(Clone)]
    struct Validator {
        sk: BLSSecretKey,
    }

    impl Validator {
        pub fn new() -> Self {
            Self {
                sk: BLSSecretKey::random(&mut rand::thread_rng()),
            }
        }

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

    impl<const SYNC_COMMITTEE_SIZE: usize> Default for MockSyncCommittee<SYNC_COMMITTEE_SIZE> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<const SYNC_COMMITTEE_SIZE: usize> MockSyncCommittee<SYNC_COMMITTEE_SIZE> {
        pub fn new() -> Self {
            let mut committee = Vec::new();
            for _ in 0..SYNC_COMMITTEE_SIZE {
                committee.push(Validator::new());
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
            sg.sync_committee_signature = Signature::try_from(agg_sig.as_bytes().to_vec()).unwrap();
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
            assert!(
                idx < self.committees.len() as u64,
                "idx: {}, len: {}",
                idx,
                self.committees.len()
            );
            &self.committees[idx as usize]
        }
    }

    #[allow(clippy::too_many_arguments)]
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
        is_update_contain_next_sync_committee: bool,
        scm: &MockSyncCommitteeManager<SYNC_COMMITTEE_SIZE>,
    ) -> (
        ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE>,
        ExecutionUpdateInfo,
    ) {
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
            is_update_contain_next_sync_committee,
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
        is_update_contain_next_sync_committee: bool,
        sign_num: usize,
    ) -> (
        ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE>,
        ExecutionUpdateInfo,
    ) {
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
                Default::default(),
                next_sync_committee.to_committee(),
            );
        let attested_header = attested_block.to_header();
        let (_, finalized_execution_branch) =
            ethereum_consensus::fork::deneb::prover::gen_execution_payload_proof(
                &finalized_block.body,
            )
            .unwrap();
        let finalized_execution_root =
            hash_tree_root(finalized_block.body.execution_payload.clone())
                .unwrap()
                .0
                .into();
        let execution_payload_header = finalized_block.body.execution_payload.clone().to_header();
        let (r, state_root_branch) =
            gen_execution_payload_field_proof(&execution_payload_header, 2).unwrap();
        let (_, block_number_branch) =
            gen_execution_payload_field_proof(&execution_payload_header, 6).unwrap();
        assert_eq!(
            r, finalized_execution_root,
            "r: {}, finalized_execution_root: {}",
            r, finalized_execution_root
        );

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
            next_sync_committee: if is_update_contain_next_sync_committee {
                Some((
                    next_sync_committee.to_committee(),
                    next_sync_committee_branch,
                ))
            } else {
                None
            },
        };

        (
            ConsensusUpdateInfo {
                light_client_update: update,
                finalized_execution_root,
                finalized_execution_branch,
            },
            ExecutionUpdateInfo {
                state_root: execution_state_root,
                state_root_branch,
                block_number: execution_block_number,
                block_number_branch,
            },
        )
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
                Fraction::new(2, 3).unwrap(),
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
                Fraction::new(2, 3).unwrap(),
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
        use super::*;
        use crate::{
            consensus::SyncProtocolVerifier,
            context::{Fraction, LightClientContext},
            misbehaviour::{FinalizedHeaderMisbehaviour, NextSyncCommitteeMisbehaviour},
            mock::MockStore,
            updates::{ConsensusUpdateInfo, LightClientUpdate},
        };
        use ethereum_consensus::{
            beacon::{Slot, Version},
            compute::hash_tree_root,
            config::{self, Config},
            fork::{
                altair::ALTAIR_FORK_SPEC,
                bellatrix::BELLATRIX_FORK_SPEC,
                capella::{self, CAPELLA_FORK_SPEC},
                deneb::{self, DENEB_FORK_SPEC},
                ForkParameter, ForkParameters,
            },
            preset,
            sync_protocol::{SyncAggregate, SyncCommittee},
            types::{H256, U64},
        };
        use hex_literal::hex;
        use serde_json::json;
        use std::time::SystemTime;
        use test_utils::{
            gen_light_client_update, gen_light_client_update_with_params, MockSyncCommitteeManager,
        };

        #[test]
        fn test_consensus_update_validation() {
            let scm = MockSyncCommitteeManager::<32>::new(1, 6);
            let ctx = LightClientContext::new_with_config(
                config::minimal::get_config(),
                Default::default(),
                Default::default(),
                Fraction::new(2, 3).unwrap(),
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .into(),
            );
            let base_store_period = 3u64;
            let base_store_slot = U64(base_store_period)
                * ctx.slots_per_epoch()
                * ctx.epochs_per_sync_committee_period();
            let base_finalized_epoch = base_store_slot / ctx.slots_per_epoch() + 1;
            let base_attested_slot = (base_finalized_epoch + 2) * ctx.slots_per_epoch();
            let base_signature_slot = base_attested_slot + 1;

            let initial_header = BeaconBlockHeader {
                slot: base_store_slot,
                ..Default::default()
            };
            let current_sync_committee = scm.get_committee(base_store_period);
            let store = MockStore::new(
                initial_header,
                current_sync_committee.to_committee(),
                Default::default(),
            );
            let dummy_execution_state_root = [1u8; 32].into();
            let dummy_execution_block_number = 1;

            {
                // valid update (store_period == finalized_period == signature_period)
                for b in [false, true] {
                    let (consensus_update, execution_update) = gen_light_client_update::<32, _>(
                        &ctx,
                        base_signature_slot,
                        base_attested_slot,
                        base_finalized_epoch,
                        dummy_execution_state_root,
                        dummy_execution_block_number.into(),
                        b,
                        &scm,
                    );
                    let res = SyncProtocolVerifier::default().validate_updates(
                        &ctx,
                        &store,
                        &consensus_update,
                        &execution_update,
                    );
                    assert!(res.is_ok(), "{:?}", res);
                }
            }
            {
                // valid update has no next sync committee branch (store_period == finalized_period == signature_period)
                let update_invalid_no_next_sync_committee_branch = {
                    let (mut update, _) = gen_light_client_update::<32, _>(
                        &ctx,
                        base_signature_slot,
                        base_attested_slot,
                        base_finalized_epoch,
                        dummy_execution_state_root,
                        dummy_execution_block_number.into(),
                        true,
                        &scm,
                    );
                    let (next_sync_committee, _) =
                        update.light_client_update.next_sync_committee.unwrap();
                    update.light_client_update.next_sync_committee =
                        Some((next_sync_committee, vec![]));
                    update
                };
                let res = SyncProtocolVerifier::default().validate_consensus_update(
                    &ctx,
                    &store,
                    &update_invalid_no_next_sync_committee_branch,
                );
                assert!(res.is_err(), "{:?}", res);
            }
            {
                let (update_insufficient_attestations, _) = gen_light_client_update_with_params(
                    &ctx,
                    base_signature_slot,
                    base_attested_slot,
                    base_finalized_epoch,
                    dummy_execution_state_root,
                    dummy_execution_block_number.into(),
                    current_sync_committee,
                    scm.get_committee(base_store_period + 1),
                    true,
                    21, // insufficient attestations. at least 22 is required.
                );
                let res = SyncProtocolVerifier::default().validate_consensus_update(
                    &ctx,
                    &store,
                    &update_insufficient_attestations,
                );
                assert!(res.is_err(), "{:?}", res);
            }
            {
                let (update_sufficient_attestations, _) = gen_light_client_update_with_params(
                    &ctx,
                    base_signature_slot,
                    base_attested_slot,
                    base_finalized_epoch,
                    dummy_execution_state_root,
                    dummy_execution_block_number.into(),
                    current_sync_committee,
                    scm.get_committee(base_store_period + 1),
                    true,
                    22, // sufficient attestations
                );
                let res = SyncProtocolVerifier::default().validate_consensus_update(
                    &ctx,
                    &store,
                    &update_sufficient_attestations,
                );
                assert!(res.is_ok(), "{:?}", res);
            }
            {
                let (update_zero_attestations, _) = gen_light_client_update_with_params(
                    &ctx,
                    base_signature_slot,
                    base_attested_slot,
                    base_finalized_epoch,
                    dummy_execution_state_root,
                    dummy_execution_block_number.into(),
                    current_sync_committee,
                    scm.get_committee(base_store_period + 1),
                    true,
                    0, // insufficient attestations. at least 22 is required.
                );
                let res = SyncProtocolVerifier::default().validate_consensus_update(
                    &ctx,
                    &store,
                    &update_zero_attestations,
                );
                assert!(res.is_err(), "{:?}", res);
            }
            {
                let (mut update_invalid_finalized_header_branch, _) =
                    gen_light_client_update::<32, _>(
                        &ctx,
                        base_signature_slot,
                        base_attested_slot,
                        base_finalized_epoch,
                        dummy_execution_state_root,
                        dummy_execution_block_number.into(),
                        true,
                        &scm,
                    );
                // set invalid finalized header branch
                update_invalid_finalized_header_branch
                    .light_client_update
                    .finalized_header
                    .1[2] = H256::default();
                let res = SyncProtocolVerifier::default().validate_consensus_update(
                    &ctx,
                    &store,
                    &update_invalid_finalized_header_branch,
                );
                assert!(res.is_err(), "{:?}", res);

                update_invalid_finalized_header_branch
                    .light_client_update
                    .finalized_header
                    .1 = vec![];
                let res = SyncProtocolVerifier::default().validate_consensus_update(
                    &ctx,
                    &store,
                    &update_invalid_finalized_header_branch,
                );
                assert!(res.is_err(), "{:?}", res);
            }
            {
                let (mut update_invalid_finalized_execution_branch, _) =
                    gen_light_client_update::<32, _>(
                        &ctx,
                        base_signature_slot,
                        base_attested_slot,
                        base_finalized_epoch,
                        dummy_execution_state_root,
                        dummy_execution_block_number.into(),
                        true,
                        &scm,
                    );
                update_invalid_finalized_execution_branch.finalized_execution_branch[0] =
                    H256::default();
                let res = SyncProtocolVerifier::default().validate_consensus_update(
                    &ctx,
                    &store,
                    &update_invalid_finalized_execution_branch,
                );
                assert!(res.is_err(), "{:?}", res);
                update_invalid_finalized_execution_branch.finalized_execution_branch = vec![]; // empty branch
                let res = SyncProtocolVerifier::default().validate_consensus_update(
                    &ctx,
                    &store,
                    &update_invalid_finalized_execution_branch,
                );
                assert!(res.is_err(), "{:?}", res);
            }
            {
                //
                //                   |
                //    +-----------+  |  +-----------+     +-----------+     +-----------+
                //    |   store   | <-- | finalized | <-- | attested  | <-- | signature |
                //    +-----------+  |  +-----------+     +-----------+     +-----------+
                //                   |
                //                   |
                //              sync committee
                //              period boundary
                //
                let next_period = U64(base_store_period) + 1;
                let finalized_epoch = next_period * ctx.epochs_per_sync_committee_period();
                let attested_slot = (finalized_epoch + 2) * ctx.slots_per_epoch();
                let signature_slot = attested_slot + 1;
                let (update, _) = gen_light_client_update(
                    &ctx,
                    signature_slot,
                    attested_slot,
                    finalized_epoch,
                    dummy_execution_state_root,
                    dummy_execution_block_number.into(),
                    true,
                    &scm,
                );
                let res = SyncProtocolVerifier::default()
                    .validate_consensus_update(&ctx, &store, &update);
                assert!(res.is_err(), "{:?}", res);

                let store = MockStore {
                    next_sync_committee: Some(scm.get_committee(next_period.into()).to_committee()),
                    ..store.clone()
                };
                let res = SyncProtocolVerifier::default()
                    .validate_consensus_update(&ctx, &store, &update);
                assert!(res.is_ok(), "{:?}", res);
            }
            {
                //
                //                   |  |
                //    +-----------+  |  |   +-----------+     +-----------+     +-----------+
                //    |   store   | <------ | finalized | <-- | attested  | <-- | signature |
                //    +-----------+  |  |   +-----------+     +-----------+     +-----------+
                //                   |  |
                //                   |  |
                //               sync committee
                //               period boundary
                //
                let next_next_period = U64(base_store_period + 2);
                let finalized_epoch = next_next_period * ctx.epochs_per_sync_committee_period();
                let attested_slot = (finalized_epoch + 2) * ctx.slots_per_epoch();
                let signature_slot = attested_slot + 1;
                let (update, _) = gen_light_client_update(
                    &ctx,
                    signature_slot,
                    attested_slot,
                    finalized_epoch,
                    dummy_execution_state_root,
                    dummy_execution_block_number.into(),
                    true,
                    &scm,
                );
                let res = SyncProtocolVerifier::default()
                    .validate_consensus_update(&ctx, &store, &update);
                assert!(res.is_err(), "{:?}", res);
                let store = MockStore {
                    next_sync_committee: Some(
                        scm.get_committee(base_store_period + 1).to_committee(),
                    ),
                    ..store.clone()
                };
                let res = SyncProtocolVerifier::default()
                    .validate_consensus_update(&ctx, &store, &update);
                assert!(res.is_err(), "{:?}", res);
            }
            {
                //
                //                   |
                //    +-----------+  |  +-----------+     +-----------+     +-----------+
                //    | finalized | <-- |   store   | <-- | attested  | <-- | signature |
                //    +-----------+  |  +-----------+     +-----------+     +-----------+
                //                   |
                //                   |
                //              sync committee
                //              period boundary
                //
                let prev_period = U64(base_store_period - 1);
                let finalized_epoch = prev_period * ctx.epochs_per_sync_committee_period();
                let attested_slot =
                    (U64(base_store_period) * ctx.epochs_per_sync_committee_period() + 2)
                        * ctx.slots_per_epoch();
                let signature_slot = attested_slot + 1;
                let (update, _) = gen_light_client_update(
                    &ctx,
                    signature_slot,
                    attested_slot,
                    finalized_epoch,
                    dummy_execution_state_root,
                    dummy_execution_block_number.into(),
                    true,
                    &scm,
                );
                let res = SyncProtocolVerifier::default()
                    .validate_consensus_update(&ctx, &store, &update);
                assert!(res.is_ok(), "{:?}", res);

                // the store cannot apply the finalized header whose period is `store_period-1`
                let res = store.apply_light_client_update(&ctx, &update);
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
                let (update_unknown_next_committee, _) = gen_light_client_update::<32, _>(
                    &ctx,
                    next_period_signature_slot,
                    base_attested_slot,
                    base_finalized_epoch,
                    dummy_execution_state_root,
                    dummy_execution_block_number.into(),
                    true,
                    &scm,
                );
                let res = SyncProtocolVerifier::default().validate_consensus_update(
                    &ctx,
                    &store,
                    &update_unknown_next_committee,
                );
                assert!(res.is_err(), "{:?}", res);

                let store = MockStore {
                    next_sync_committee: Some(
                        scm.get_committee(base_store_period + 1).to_committee(),
                    ),
                    ..store.clone()
                };
                let (update_valid, _) = gen_light_client_update::<32, _>(
                    &ctx,
                    next_period_signature_slot,
                    base_attested_slot,
                    base_finalized_epoch,
                    dummy_execution_state_root,
                    dummy_execution_block_number.into(),
                    true,
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
                    next_sync_committee: Some(
                        scm.get_committee(base_store_period + 1).to_committee(),
                    ),
                    ..store.clone()
                };
                let (update_not_finalized_next_sync_committee, _) = gen_light_client_update::<32, _>(
                    &ctx,
                    next_period_signature_slot,
                    next_period_attested_slot,
                    base_finalized_epoch,
                    dummy_execution_state_root,
                    dummy_execution_block_number.into(),
                    true,
                    &scm,
                );
                let res = SyncProtocolVerifier::default().validate_consensus_update(
                    &ctx,
                    &store,
                    &update_not_finalized_next_sync_committee,
                );
                assert!(res.is_ok(), "{:?}", res);
                let res = store
                    .apply_light_client_update(&ctx, &update_not_finalized_next_sync_committee);
                assert!(res.is_ok(), "{:?}", res);
                let new_store = res.unwrap().unwrap();
                // committees not changed
                assert_eq!(
                    store.current_sync_committee,
                    new_store.current_sync_committee
                );
                assert_eq!(store.next_sync_committee, new_store.next_sync_committee);
            }
        }

        #[test]
        fn test_misbehaviour_validation() {
            let scm = MockSyncCommitteeManager::<32>::new(1, 5);
            let current_sync_committee = scm.get_committee(1);
            let ctx = LightClientContext::new_with_config(
                config::minimal::get_config(),
                Default::default(),
                Default::default(),
                Fraction::new(2, 3).unwrap(),
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .into(),
            );

            let base_store_period = 3u64;
            let base_store_slot = U64(base_store_period)
                * ctx.slots_per_epoch()
                * ctx.epochs_per_sync_committee_period();
            let base_finalized_epoch = base_store_slot / ctx.slots_per_epoch() + 1;
            let base_attested_slot = (base_finalized_epoch + 2) * ctx.slots_per_epoch();
            let base_signature_slot = base_attested_slot + 1;

            let initial_header = BeaconBlockHeader {
                slot: base_store_slot,
                ..Default::default()
            };
            let store = MockStore::new(
                initial_header,
                current_sync_committee.to_committee(),
                Default::default(),
            );

            let dummy_execution_state_root = [1u8; 32].into();
            let dummy_execution_block_number = 1;

            let (update_1, _) = gen_light_client_update_with_params::<32, _>(
                &ctx,
                base_signature_slot,
                base_attested_slot,
                base_finalized_epoch,
                dummy_execution_state_root,
                dummy_execution_block_number.into(),
                current_sync_committee,
                scm.get_committee(base_store_period + 1),
                true,
                32,
            );

            {
                let (update_valid, _) = gen_light_client_update_with_params::<32, _>(
                    &ctx,
                    base_signature_slot,
                    base_attested_slot,
                    base_finalized_epoch,
                    dummy_execution_state_root,
                    dummy_execution_block_number.into(),
                    current_sync_committee,
                    scm.get_committee(base_store_period + 2), // `base_store_period+1` is really correct
                    true,
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
                let (update_valid_different_slots, _) = gen_light_client_update_with_params::<32, _>(
                    &ctx,
                    base_signature_slot + 1,
                    base_attested_slot + 1,
                    base_finalized_epoch,
                    dummy_execution_state_root,
                    dummy_execution_block_number.into(),
                    current_sync_committee,
                    scm.get_committee(base_store_period + 2), // `base_store_period+1` is really correct
                    true,
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
                let (update_insufficient_attestations, _) =
                    gen_light_client_update_with_params::<32, _>(
                        &ctx,
                        base_signature_slot,
                        base_attested_slot,
                        base_finalized_epoch,
                        dummy_execution_state_root,
                        dummy_execution_block_number.into(),
                        current_sync_committee,
                        scm.get_committee(base_store_period + 2), // `base_store_period+1` is really correct
                        true,
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
                let (update_different_attested_period, _) =
                    gen_light_client_update_with_params::<32, _>(
                        &ctx,
                        base_signature_slot,
                        different_period_attested_slot,
                        base_finalized_epoch,
                        dummy_execution_state_root,
                        dummy_execution_block_number.into(),
                        current_sync_committee,
                        scm.get_committee(base_store_period + 2), // `base_store_period+1` is really correct
                        true,
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
                let attested_slot = (base_finalized_epoch + ctx.epochs_per_sync_committee_period())
                    * ctx.slots_per_epoch();
                let signature_slot = attested_slot + 1;
                let (update_not_finalized_next_sync_committee, _) =
                    gen_light_client_update_with_params::<32, _>(
                        &ctx,
                        signature_slot,
                        attested_slot,
                        base_finalized_epoch,
                        dummy_execution_state_root,
                        dummy_execution_block_number.into(),
                        current_sync_committee,
                        scm.get_committee(base_store_period + 2), // `base_store_period+1` is really correct
                        true,
                        32,
                    );
                let res = SyncProtocolVerifier::default().validate_misbehaviour(
                    &ctx,
                    &store,
                    Misbehaviour::NextSyncCommittee(NextSyncCommitteeMisbehaviour {
                        consensus_update_1: update_1.clone(),
                        consensus_update_2: update_not_finalized_next_sync_committee,
                    }),
                );
                assert!(res.is_err(), "{:?}", res);
            }
            {
                let different_dummy_execution_state_root = [2u8; 32].into();
                let (update_different_finalized_block, _) =
                    gen_light_client_update_with_params::<32, _>(
                        &ctx,
                        base_signature_slot,
                        base_attested_slot,
                        base_finalized_epoch,
                        different_dummy_execution_state_root,
                        dummy_execution_block_number.into(),
                        current_sync_committee,
                        scm.get_committee(base_store_period + 1),
                        true,
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
                let (update_different_finalized_block, _) =
                    gen_light_client_update_with_params::<32, _>(
                        &ctx,
                        base_signature_slot,
                        base_attested_slot,
                        different_finalized_epoch,
                        different_dummy_execution_state_root,
                        dummy_execution_block_number.into(),
                        current_sync_committee,
                        scm.get_committee(base_store_period + 1),
                        true,
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

        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        pub struct CapellaLightClientUpdateResponse<
            const SYNC_COMMITTEE_SIZE: usize,
            const BYTES_PER_LOGS_BLOOM: usize,
            const MAX_EXTRA_DATA_BYTES: usize,
        > {
            pub version: String,
            pub data: CapellaLightClientUpdateData<
                SYNC_COMMITTEE_SIZE,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
            >,
        }

        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        pub struct CapellaLightClientUpdateData<
            const SYNC_COMMITTEE_SIZE: usize,
            const BYTES_PER_LOGS_BLOOM: usize,
            const MAX_EXTRA_DATA_BYTES: usize,
        > {
            pub attested_header:
                capella::LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
            pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
            pub next_sync_committee_branch: Vec<H256>,
            pub finalized_header:
                capella::LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
            pub finality_branch: Vec<H256>,
            pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
            pub signature_slot: Slot,
        }

        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        pub struct DenebLightClientUpdateResponse<
            const SYNC_COMMITTEE_SIZE: usize,
            const BYTES_PER_LOGS_BLOOM: usize,
            const MAX_EXTRA_DATA_BYTES: usize,
        > {
            pub version: String,
            pub data: DenebLightClientUpdateData<
                SYNC_COMMITTEE_SIZE,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
            >,
        }

        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        pub struct DenebLightClientUpdateData<
            const SYNC_COMMITTEE_SIZE: usize,
            const BYTES_PER_LOGS_BLOOM: usize,
            const MAX_EXTRA_DATA_BYTES: usize,
        > {
            pub attested_header:
                deneb::LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
            pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
            pub next_sync_committee_branch: Vec<H256>,
            pub finalized_header:
                deneb::LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
            pub finality_branch: Vec<H256>,
            pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
            pub signature_slot: Slot,
        }

        #[test]
        fn test_fork_capella_to_deneb() {
            let capella_update = json!({"data":{"attested_header":{"beacon":{"slot":"32","proposer_index":"1","parent_root":"0xa952bb65fcc838ee68484f992465c698a9f39a3d176d2efce39498029e14d81d","state_root":"0x65857cfd776497d9d6b140db71fe544ee1faa1fd45c7f7ad039974d156c7cc61","body_root":"0x3ee77fe35d61f5e0a855553eefc680f9afd10e1caf218f3881eb35d09887ebe9"},"execution":{"parent_hash":"0x5846bfa3df8bda4aab8358245639dfbda18e2d5ecccdfc20803cba9584465a77","fee_recipient":"0xa89F47C6b463f74d87572b058427dA0A13ec5425","state_root":"0x5043e1f7add17b9c0ee2420aaf092b3658e3aaf8926978f6288c3c7b1620e2b6","receipts_root":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","logs_bloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prev_randao":"0x8b98023e0f1f56845ac7ae1202b29fafbfb52688ac4ebd7ec1ca46f6b54fe6fc","block_number":"32","gas_limit":"77537520","gas_used":"0","timestamp":"1731542295","extra_data":"0xd883010e0b846765746888676f312e32332e31856c696e7578","base_fee_per_gas":"16616323","block_hash":"0x33f4957fe2d9ad025edbc041f3dd8d2fea6a220f8c220f2e6602a414df01a18d","transactions_root":"0x7ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede1","withdrawals_root":"0x28ba1834a3a7b657460ce79fa3a1d909ab8828fd557659d4d0554a9bdbc0ec30"},"execution_branch":["0x2c1a6d388d1fbd48b38a38b4af84e23c812c3c97a206d4209ffe736a009db7d7","0x336488033fe5f3ef4ccc12af07b9370b92e553e35ecb4a337a1b1c0e4afe1e0e","0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71","0xc41e001b7e589a6e8ab5f131cd70415de6af7b5da08f34beea18e9336a51bc8b"]},"next_sync_committee":{"pubkeys":["0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b"],"aggregate_pubkey":"0x82c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f7"},"next_sync_committee_branch":["0xb41b2aeacf51807bfe5a7ea6fd8c5ff3896089c97aacfeac555ce61d1a27caf7","0x0abfe55dc63653324dbeeb24b5b4fd0e37e2ea4fa444344868cb92dcca17466d","0x4299b429db51464240b620e5f90edba292ddf5cf16cb27f0b1e0b2295ff94b85","0x877ea31550fb9321993ff478e3f6b557ac20c6df8478cff23a3a4ca56c33c00d","0xab5a0e8c8c9dc64e2a2dcb3d7e677a0fe21c70698894d432e9e338da2b39b57d"],"finalized_header":{"beacon":{"slot":"16","proposer_index":"3","parent_root":"0xd5e464e9379d28778240fb23fbe232c0e167bd2771df78e6bbf7ebdd5409161b","state_root":"0xc870e08b6408a20f93363224ff203291c886572edc7ede99889ca40aa8453f63","body_root":"0x503657b0cf998ec0597e0ede2ff39f149fd1ec9061c1ee1b223c222ba709ec09"},"execution":{"parent_hash":"0x0e8442d30528ae01b4b352666bf119b03dce8441259d4c80b862f9a924fb3ccc","fee_recipient":"0xa89F47C6b463f74d87572b058427dA0A13ec5425","state_root":"0xcec8779a9457d1310f5472512f30587cedf8f0d3f3011d28cb0c711638033f0b","receipts_root":"0xf1c43f20a855fcb1ddd12b17b581955caac114c1ec29bde0aa40b84f4146e655","logs_bloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prev_randao":"0xdee938fc8b437a622d85397aae68ee496ff3e3952ecc4309b84d72cdd6231a05","block_number":"16","gas_limit":"78759137","gas_used":"3605005","timestamp":"1731542199","extra_data":"0xd883010e0b846765746888676f312e32332e31856c696e7578","base_fee_per_gas":"133815416","block_hash":"0x7692f54ab4dffc15a7c4677f13591d7ca7d2fb95397602e956eac1065ad7e283","transactions_root":"0x7bdae9ce5b11558e0c9fbd784891671e42fae38d8f20ac09b52368c5f067565e","withdrawals_root":"0x28ba1834a3a7b657460ce79fa3a1d909ab8828fd557659d4d0554a9bdbc0ec30"},"execution_branch":["0xb8ff848573e63374e72ea51e8a534e3bac0db23a472cff4ab3e30fee9a2b66ed","0x336488033fe5f3ef4ccc12af07b9370b92e553e35ecb4a337a1b1c0e4afe1e0e","0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71","0xec3943341428231e3e21e2e21b455efa16e757d241236334afa61bfd6e6f3a16"]},"finality_branch":["0x0200000000000000000000000000000000000000000000000000000000000000","0x86220a2d72000ffb901cf75bf2918181ffea3c6567a573566d8c826e9e567493","0x48e466f527fdc91af6cb33c88eb33aa0b02d2701bd633af8d544e9049b56d8d3","0x4299b429db51464240b620e5f90edba292ddf5cf16cb27f0b1e0b2295ff94b85","0x877ea31550fb9321993ff478e3f6b557ac20c6df8478cff23a3a4ca56c33c00d","0xab5a0e8c8c9dc64e2a2dcb3d7e677a0fe21c70698894d432e9e338da2b39b57d"],"sync_aggregate":{"sync_committee_bits":"0xffffffff","sync_committee_signature":"0xb64139bfd6e066b032b0144542feaa0dd4fd93f52789c0fb4009f3a6311866820e3a4b353bfdb44793c3ef615330c6a800b96379e8d4df07f34314f58d5c070eb6d5e3fc792ba61211d8507f6684de55fdd64e108b0b7e2630366d7c242f21d3"},"signature_slot":"33"},"version":"capella"});
            let deneb_update = json!({"data":{"attested_header":{"beacon":{"slot":"80","proposer_index":"0","parent_root":"0xf0b88978879826d2f516499b2984b9b0057e63e48277812df89d1a6aed9c6d73","state_root":"0xd25dbd249d10d20c685f56db9ca81e09d327ef207db25563051285ef30c2ba60","body_root":"0xecf2e60a2b3eeb27795787782055a9517d08ba2afae22956a5bff9adee400e90"},"execution":{"parent_hash":"0x0713856af8bf4f021256b888fd6256322777993df64f46c42636870be07767a6","fee_recipient":"0xa89F47C6b463f74d87572b058427dA0A13ec5425","state_root":"0x5043e1f7add17b9c0ee2420aaf092b3658e3aaf8926978f6288c3c7b1620e2b6","receipts_root":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","logs_bloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prev_randao":"0x35cbf063513bb38075dd1c75520aff746544bfbdb4f52ae456fa114b4f4b650e","block_number":"80","gas_limit":"73985196","gas_used":"0","timestamp":"1731542583","extra_data":"0xd883010e0b846765746888676f312e32332e31856c696e7578","base_fee_per_gas":"27350","block_hash":"0x79f98638247d4a26a293634d121deeba1a2d714235f1b67b4356a698913c5f07","transactions_root":"0x7ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede1","withdrawals_root":"0x28ba1834a3a7b657460ce79fa3a1d909ab8828fd557659d4d0554a9bdbc0ec30","blob_gas_used":"0","excess_blob_gas":"0"},"execution_branch":["0x5cb415a4e685451cc5ef23fee8b32455ec0eb3abfc3488f11ec3ff64815b840f","0x6c6dd63656639d153a2e86a9cab291e7a26e957ad635fec872d2836e92340c23","0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71","0xb2dc71374ec596dc11ec78d093dac227bebe0173ed095cf9d4f75cdbf575de54"]},"next_sync_committee":{"pubkeys":["0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b"],"aggregate_pubkey":"0x82c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f7"},"next_sync_committee_branch":["0xb41b2aeacf51807bfe5a7ea6fd8c5ff3896089c97aacfeac555ce61d1a27caf7","0xf3bfc0455d774cadb156ca04ca7a40c0d8153439290288126d6966705a0980bd","0x94fb3f3144deeeeaa109258b8a7ebdf3e9d8a7aa09629dfae0255d44305f1e23","0x03625ae8db8bf9cfd4c7b1ca2bb474964133355f5e9e08c6898733aeafdc64a0","0xecf2d63c6f46d35a119d0543e60b6ec893b053352f402527422e30c1449b4f60"],"finalized_header":{"beacon":{"slot":"64","proposer_index":"0","parent_root":"0x734d27a31ed234878ae162971d1d9fba94a35acc5752e8ce1c7950108ebc7f30","state_root":"0x02dd2b440dc6ce122abbfcf8a1dbcb9a61c08e52cca833706ca362c65d033584","body_root":"0xc19f72663c490ab639fbad1c77017c8d11b2eed7ec19a5b10ba696d8bac42114"},"execution":{"parent_hash":"0x1d8637dedc28e5dea176a1cf2a35e2df1a819cee4b63bec979e5057d02987108","fee_recipient":"0xa89F47C6b463f74d87572b058427dA0A13ec5425","state_root":"0x5043e1f7add17b9c0ee2420aaf092b3658e3aaf8926978f6288c3c7b1620e2b6","receipts_root":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","logs_bloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prev_randao":"0x004a94617a1433e947d00863b2c0cbef76534b1d82876e0487d2ad31e2802542","block_number":"64","gas_limit":"75150842","gas_used":"0","timestamp":"1731542487","extra_data":"0xd883010e0b846765746888676f312e32332e31856c696e7578","base_fee_per_gas":"231633","block_hash":"0x73a7190351f0ce292a70b9dd16b48225fbc3955a49b114ad5f251b7f55a5e0f3","transactions_root":"0x7ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede1","withdrawals_root":"0x28ba1834a3a7b657460ce79fa3a1d909ab8828fd557659d4d0554a9bdbc0ec30","blob_gas_used":"0","excess_blob_gas":"0"},"execution_branch":["0x36a44a5a9865ec43ee618980061e94d1af10a002247cfbfc0f798eab9bbfa616","0x6c6dd63656639d153a2e86a9cab291e7a26e957ad635fec872d2836e92340c23","0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71","0x46b8b1cbff1d4d574bc0eb3e6d1ee475e5356ccc8bc0dc476ca25041a3172eec"]},"finality_branch":["0x0800000000000000000000000000000000000000000000000000000000000000","0x86220a2d72000ffb901cf75bf2918181ffea3c6567a573566d8c826e9e567493","0xfcb9109e3e60252fff6f02e7746207ad9170ec62b5854cc6cf675cebc51161ba","0x94fb3f3144deeeeaa109258b8a7ebdf3e9d8a7aa09629dfae0255d44305f1e23","0x03625ae8db8bf9cfd4c7b1ca2bb474964133355f5e9e08c6898733aeafdc64a0","0xecf2d63c6f46d35a119d0543e60b6ec893b053352f402527422e30c1449b4f60"],"sync_aggregate":{"sync_committee_bits":"0xffffffff","sync_committee_signature":"0x86104ec9e005a343db9469b8b850372f182fce75a32b7c926601849059705e13daa50caf3f75e2ce8e05e8d218912f180d1e1d8d8a6f69a2a26ff526365e6953c8a9875eae7cc1d021725f3f2e2cf094b5246f5ceb38b59e12af90260687d6ce"},"signature_slot":"81"},"version":"deneb"});

            let capella_update: CapellaLightClientUpdateResponse<32, 256, 32> =
                serde_json::from_value(capella_update).unwrap();
            let deneb_update: DenebLightClientUpdateResponse<32, 256, 32> =
                serde_json::from_value(deneb_update).unwrap();

            let valid_ctx = LightClientContext::new_with_config(
                Config {
                    preset: preset::minimal::PRESET,
                    fork_parameters: ForkParameters::new(
                        Version([0, 0, 0, 1]),
                        vec![
                            ForkParameter::new(Version([1, 0, 0, 1]), U64(0), ALTAIR_FORK_SPEC),
                            ForkParameter::new(Version([2, 0, 0, 1]), U64(0), BELLATRIX_FORK_SPEC),
                            ForkParameter::new(Version([3, 0, 0, 1]), U64(0), CAPELLA_FORK_SPEC),
                            ForkParameter::new(Version([4, 0, 0, 1]), U64(8), DENEB_FORK_SPEC),
                        ],
                    )
                    .unwrap(),
                    min_genesis_time: U64(1578009600),
                },
                H256::from_slice(
                    hex!("acac7566fdf384a1ada45c01dcf9030d7eb0e1e5f5302659101d0b2a5bb59092")
                        .as_ref(),
                ),
                1731420304.into(),
                Fraction::new(2, 3).unwrap(),
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .into(),
            );
            let invalid_ctx = LightClientContext::new_with_config(
                Config {
                    preset: preset::minimal::PRESET,
                    fork_parameters: ForkParameters::new(
                        Version([0, 0, 0, 1]),
                        vec![
                            ForkParameter::new(Version([1, 0, 0, 1]), U64(0), ALTAIR_FORK_SPEC),
                            ForkParameter::new(Version([2, 0, 0, 1]), U64(0), BELLATRIX_FORK_SPEC),
                            ForkParameter::new(Version([3, 0, 0, 1]), U64(0), CAPELLA_FORK_SPEC),
                            ForkParameter::new(Version([4, 0, 0, 1]), U64(0), DENEB_FORK_SPEC),
                        ],
                    )
                    .unwrap(),
                    min_genesis_time: U64(1578009600),
                },
                H256::from_slice(
                    hex!("acac7566fdf384a1ada45c01dcf9030d7eb0e1e5f5302659101d0b2a5bb59092")
                        .as_ref(),
                ),
                1731420304.into(),
                Fraction::new(2, 3).unwrap(),
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .into(),
            );

            let store = {
                let mut store = MockStore::new(
                    capella_update.data.finalized_header.beacon.clone(),
                    capella_update.data.next_sync_committee.clone(), // period0's committee is same as period1
                    Default::default(),                              // dummy
                );
                store.next_sync_committee = Some(capella_update.data.next_sync_committee.clone());
                store
            };

            {
                let consensus_update = ConsensusUpdateInfo {
                    light_client_update: LightClientUpdate {
                        attested_header: capella_update.data.attested_header.beacon,
                        next_sync_committee: Some((
                            capella_update.data.next_sync_committee.clone(),
                            capella_update.data.next_sync_committee_branch.clone(),
                        )),
                        finalized_header: (
                            capella_update.data.finalized_header.beacon,
                            capella_update.data.finality_branch.clone(),
                        ),
                        sync_aggregate: capella_update.data.sync_aggregate,
                        signature_slot: capella_update.data.signature_slot,
                    },
                    finalized_execution_root: hash_tree_root(
                        capella_update.data.finalized_header.execution,
                    )
                    .unwrap(),
                    finalized_execution_branch: capella_update
                        .data
                        .finalized_header
                        .execution_branch,
                };
                let res = SyncProtocolVerifier::default().validate_consensus_update(
                    &valid_ctx,
                    &store,
                    &consensus_update,
                );
                assert!(res.is_ok(), "{:?}", res);
                let res = SyncProtocolVerifier::default().validate_consensus_update(
                    &invalid_ctx,
                    &store,
                    &consensus_update,
                );
                assert!(res.is_err(), "{:?}", res);
            }
            {
                let consensus_update = ConsensusUpdateInfo {
                    light_client_update: LightClientUpdate {
                        attested_header: deneb_update.data.attested_header.beacon,
                        next_sync_committee: Some((
                            deneb_update.data.next_sync_committee.clone(),
                            deneb_update.data.next_sync_committee_branch.clone(),
                        )),
                        finalized_header: (
                            deneb_update.data.finalized_header.beacon,
                            deneb_update.data.finality_branch.clone(),
                        ),
                        sync_aggregate: deneb_update.data.sync_aggregate,
                        signature_slot: deneb_update.data.signature_slot,
                    },
                    finalized_execution_root: hash_tree_root(
                        deneb_update.data.finalized_header.execution,
                    )
                    .unwrap(),
                    finalized_execution_branch: deneb_update.data.finalized_header.execution_branch,
                };
                let res = SyncProtocolVerifier::default().validate_consensus_update(
                    &valid_ctx,
                    &store,
                    &consensus_update,
                );
                assert!(res.is_ok(), "{:?}", res);
            }
        }
    }

    mod electra {
        use crate::{
            consensus::SyncProtocolVerifier,
            context::{Fraction, LightClientContext},
            mock::MockStore,
            updates::{ConsensusUpdateInfo, LightClientUpdate},
        };
        use ethereum_consensus::{
            beacon::{Slot, Version},
            compute::hash_tree_root,
            config::Config,
            fork::{
                altair::ALTAIR_FORK_SPEC,
                bellatrix::BELLATRIX_FORK_SPEC,
                capella::CAPELLA_FORK_SPEC,
                deneb::DENEB_FORK_SPEC,
                electra::{self, ELECTRA_FORK_SPEC},
                ForkParameter, ForkParameters,
            },
            preset,
            sync_protocol::{SyncAggregate, SyncCommittee},
            types::{H256, U64},
        };
        use hex_literal::hex;
        use serde_json::json;
        use std::time::SystemTime;

        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        pub struct LightClientUpdateResponse<
            const SYNC_COMMITTEE_SIZE: usize,
            const BYTES_PER_LOGS_BLOOM: usize,
            const MAX_EXTRA_DATA_BYTES: usize,
        > {
            pub version: String,
            pub data: LightClientUpdateData<
                SYNC_COMMITTEE_SIZE,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
            >,
        }

        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        pub struct LightClientUpdateData<
            const SYNC_COMMITTEE_SIZE: usize,
            const BYTES_PER_LOGS_BLOOM: usize,
            const MAX_EXTRA_DATA_BYTES: usize,
        > {
            pub attested_header:
                electra::LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
            pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
            pub next_sync_committee_branch: Vec<H256>,
            pub finalized_header:
                electra::LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
            pub finality_branch: Vec<H256>,
            pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
            pub signature_slot: Slot,
        }

        #[test]
        fn test_electra_update_validation() {
            let data = json!([{"data":{"attested_header":{"beacon":{"slot":"80","proposer_index":"2","parent_root":"0xc478ce4223c3345116c47e627379b4c18a24679481612727f54224b60f0924ba","state_root":"0x37ac7935d29e970710b9e777b7e5d91b3e4eb45d080adfe3678f88df87bd27e7","body_root":"0x8f8c8d6abfd6d0e72718e5cc8c34ed99fa407d4a3e2e126f4f373dba08138b27"},"execution":{"parent_hash":"0xb7452c7f7f73a3aeabd11ea46b6c7e2ebb3fb1a7321f13c7311666dd55852cc2","fee_recipient":"0xa89F47C6b463f74d87572b058427dA0A13ec5425","state_root":"0xde116fb056732e28005b7f2f6362a375150e3da8a871f6eaca39a0ec060075dc","receipts_root":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","logs_bloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prev_randao":"0x644e51edcd3e5206109ac3f50f4816c96b785624761733394cce34c72ce97474","block_number":"80","gas_limit":"73985196","gas_used":"0","timestamp":"1731420784","extra_data":"0xd883010e0c846765746888676f312e32332e32856c696e7578","base_fee_per_gas":"27370","block_hash":"0x204042fa52acd657819696450daaaafeaa6238b81fc049b4333146d43434f814","transactions_root":"0x7ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede1","withdrawals_root":"0x28ba1834a3a7b657460ce79fa3a1d909ab8828fd557659d4d0554a9bdbc0ec30","blob_gas_used":"0","excess_blob_gas":"0"},"execution_branch":["0x9f6d5e9a1cdddac70868a7f82ce79d3f07911dde6a7441a85a5cab2a7ac50085","0x6c6dd63656639d153a2e86a9cab291e7a26e957ad635fec872d2836e92340c23","0x60826dbec0252c937b31eee64acdb1e334aa120f8c860f3de894b6d9be9d1737","0x1ce581e460685c761fc37bad2e852d6c5708a0cb894335d6cd75c7e2cdabdd88"]},"next_sync_committee":{"pubkeys":["0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c"],"aggregate_pubkey":"0x881d222b887a0188eab3a4829f4ba1b947afbb14a37f23bc1b09216268a8c60854cae8a9a7b9a447a7ce7e88a44646ad"},"next_sync_committee_branch":["0xeab4a7a54f4594e7172ccb2086a5b2d916ed2474773d48fa819e71ff7fd36498","0x4046f7db4be4754f0909477f8b4811a2cb18d0cb0b88cc1dacad10b760cf1814","0x572fffcc0741b3c95323ffa0217bbe6bcc6edfe6b832943b0f601b63fa5cb6ae","0xef911751d41e2cb9f4d7e4bee966947685fd329e7115efeeaf672ccd054b446b","0x6711cbb84a80bf4b8fbdd8cebe2dd3a2a813b9170c162c4d87cefcb79bb2bad4","0x953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a"],"finalized_header":{"beacon":{"slot":"64","proposer_index":"2","parent_root":"0x2ef4a5b4ae533517995b68e35ae31775ba9ac221b50ab762e5661326e998c6fb","state_root":"0xd718d5f0480998c282c88dc275f916dd56ea4e80c0b2358c1b1f0019896cbbb5","body_root":"0x5f86881d358e275004969e63ce088a5a1f6bd7f8d8d35c8996e89e72cee78d44"},"execution":{"parent_hash":"0xc0f67837cea15531bb28104dedefa25765134f674186e62c81657e4ce7b7fb71","fee_recipient":"0xa89F47C6b463f74d87572b058427dA0A13ec5425","state_root":"0xde116fb056732e28005b7f2f6362a375150e3da8a871f6eaca39a0ec060075dc","receipts_root":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","logs_bloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prev_randao":"0x5d1642b26bd5368eb73530a862cf7a12426e718ac7c5dc8ca6832cc76a806b9a","block_number":"64","gas_limit":"75150842","gas_used":"0","timestamp":"1731420688","extra_data":"0xd883010e0c846765746888676f312e32332e32856c696e7578","base_fee_per_gas":"231790","block_hash":"0xf13c9a2cf0089115ab9699860be616f96e46c0549e4d2bcdcbd0d7a33c05df5b","transactions_root":"0x7ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede1","withdrawals_root":"0x28ba1834a3a7b657460ce79fa3a1d909ab8828fd557659d4d0554a9bdbc0ec30","blob_gas_used":"0","excess_blob_gas":"0"},"execution_branch":["0x46711de535a492319b7c19a252e8152aa8302591fcc9550c60e3b8484c9c854c","0x6c6dd63656639d153a2e86a9cab291e7a26e957ad635fec872d2836e92340c23","0x60826dbec0252c937b31eee64acdb1e334aa120f8c860f3de894b6d9be9d1737","0x9da22bc8298cc09b761020d6f31be8d1aa592d983630d9a1b5bf66fd1c234335"]},"finality_branch":["0x0800000000000000000000000000000000000000000000000000000000000000","0x86220a2d72000ffb901cf75bf2918181ffea3c6567a573566d8c826e9e567493","0x1a1d518ef5295452ec357d6f063f089b1d2b371b940c20c8f0f8424894d8a6d0","0x572fffcc0741b3c95323ffa0217bbe6bcc6edfe6b832943b0f601b63fa5cb6ae","0xef911751d41e2cb9f4d7e4bee966947685fd329e7115efeeaf672ccd054b446b","0x6711cbb84a80bf4b8fbdd8cebe2dd3a2a813b9170c162c4d87cefcb79bb2bad4","0x953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a"],"sync_aggregate":{"sync_committee_bits":"0xffffffff","sync_committee_signature":"0xac848cd9412ee24f5cbcc541361f9d127ac9ebc905f0ec67e726485ff895d509a3ab9f06c666e35e130c4b1391830f5c1533a6e1c1f2bbea7bae64ce21a2c69166a0edd8bb34afce676989626e8bc2cdc8bba896b10fb30e73554f6052155d4f"},"signature_slot":"81"},"version":"electra"},{"data":{"attested_header":{"beacon":{"slot":"144","proposer_index":"0","parent_root":"0x9e296701b9891cdef2b0c65210bca3d365a53a8d36665edda1bc8899d77d1dcb","state_root":"0xcae6a42025aecf48b70abcb87f2b89c0fc961c311a6d382dd99e2fbfb9d08df8","body_root":"0xd3a2beb23a2e0631ab497a5b70a9a5e197056f3445dd77f26082059f9535116e"},"execution":{"parent_hash":"0xa539cbaef57f4c86ab523d8ab3f72e06f76f7fe01e565891945a215074e6a0e3","fee_recipient":"0xa89F47C6b463f74d87572b058427dA0A13ec5425","state_root":"0xde116fb056732e28005b7f2f6362a375150e3da8a871f6eaca39a0ec060075dc","receipts_root":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","logs_bloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prev_randao":"0xc0e1e00889967b494afe8d44e59967c41945884228f9dcbff75cbdad9d06df02","block_number":"144","gas_limit":"69500628","gas_used":"0","timestamp":"1731421168","extra_data":"0xd883010e0c846765746888676f312e32332e32856c696e7578","base_fee_per_gas":"9","block_hash":"0xddf2e7681e437f01180f6e8cec70921bae38decb8682e2e68153cf8439789db3","transactions_root":"0x7ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede1","withdrawals_root":"0x28ba1834a3a7b657460ce79fa3a1d909ab8828fd557659d4d0554a9bdbc0ec30","blob_gas_used":"0","excess_blob_gas":"0"},"execution_branch":["0x42b6087e510f2f392b75faf0b6344f35856b6f637cfd3e2f8f3ef6ec50f4da15","0x6c6dd63656639d153a2e86a9cab291e7a26e957ad635fec872d2836e92340c23","0x60826dbec0252c937b31eee64acdb1e334aa120f8c860f3de894b6d9be9d1737","0xcc5a70db4f0fe72b187cd010cbd8d0f29e1fbc6b9072b062cd1d7a240a2920f7"]},"next_sync_committee":{"pubkeys":["0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e","0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b"],"aggregate_pubkey":"0xad140cfada110829569b1c1102c74c84fe2ce097fa7cce128b3174c12a9255b247dee99491fbd52d6591743a0fafed4e"},"next_sync_committee_branch":["0x2ed66fe705188bb88425bcf10879e9e58fdc894ab5324aea228e2fd6667dc898","0x0e521c1407a761f63eeea88ee607ac82af00b3562bd5aaa09b64263cb5b512f0","0x423733fd0ef9e89921cad0e8c4b8dd8fe0afd290a7c7389f49f9d1b1864fc450","0xddf9b0801e380ede4f51843267d3e11c084801ddd303fe6b65e5a5979269a0c6","0x1112067594716c340a1c50737a5916654ecf573daf435f6efd8521d3711ce2bb","0x953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a"],"finalized_header":{"beacon":{"slot":"128","proposer_index":"1","parent_root":"0x5d22192d8a204f30bfb4b9834b33c8bbbc6fda8e4f65dbb443755a8f59643d58","state_root":"0x8d2f20c8e71308d9c00a84b19b89b6796a8823990f3ed01898a077e23eb0bb27","body_root":"0x947690090787f644cad858c09724841283739fece1c4a78414bc10f614ce9e23"},"execution":{"parent_hash":"0x59aae856c9c526f4723a5c298756d8934ab7a2245ccf1770be5c977450635ba0","fee_recipient":"0xa89F47C6b463f74d87572b058427dA0A13ec5425","state_root":"0xde116fb056732e28005b7f2f6362a375150e3da8a871f6eaca39a0ec060075dc","receipts_root":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","logs_bloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prev_randao":"0x7a94d1a0a36f2322daea0310f90c909855f93085916218df84208c15da4b6be2","block_number":"128","gas_limit":"70595621","gas_used":"0","timestamp":"1731421072","extra_data":"0xd883010e0c846765746888676f312e32332e32856c696e7578","base_fee_per_gas":"49","block_hash":"0x73744f33faec476c04fd9a2ee832fd3ae4fc50fc2a6c2feb14e5f1083040c4c8","transactions_root":"0x7ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede1","withdrawals_root":"0x28ba1834a3a7b657460ce79fa3a1d909ab8828fd557659d4d0554a9bdbc0ec30","blob_gas_used":"0","excess_blob_gas":"0"},"execution_branch":["0x8e85ebb032667a0fd5a434b3aa17cccf0e32e45b045970a2200d647133e5a8cd","0x6c6dd63656639d153a2e86a9cab291e7a26e957ad635fec872d2836e92340c23","0x60826dbec0252c937b31eee64acdb1e334aa120f8c860f3de894b6d9be9d1737","0x5060e8a414c24398c3dbf8327fd3cd6ac7669743596e0917b225d3c0fd4cfd1e"]},"finality_branch":["0x1000000000000000000000000000000000000000000000000000000000000000","0x86220a2d72000ffb901cf75bf2918181ffea3c6567a573566d8c826e9e567493","0x61046ece5bc124eaca970582081a9c317376948ac04f6826a54f3fd9bd5a2e64","0x423733fd0ef9e89921cad0e8c4b8dd8fe0afd290a7c7389f49f9d1b1864fc450","0xddf9b0801e380ede4f51843267d3e11c084801ddd303fe6b65e5a5979269a0c6","0x1112067594716c340a1c50737a5916654ecf573daf435f6efd8521d3711ce2bb","0x953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a"],"sync_aggregate":{"sync_committee_bits":"0xffffffff","sync_committee_signature":"0xae5ac4800796fa0cd0b808826433c40f35251cea233657f2a9c4e8d38703cd4b7647e00646ec0a550b9bdde517c8f02a0abfc97a997a8a019e39aa93b6bf50fdd78fe9fd89a5598d2ed08957519d37bcb12eeaf930dfdb13756435a736539767"},"signature_slot":"145"},"version":"electra"}]);
            let res: Vec<LightClientUpdateResponse<32, 256, 32>> =
                serde_json::from_value(data).unwrap();
            let period_1_update = res[0].data.clone();
            let period_2_update = res[1].data.clone();

            let mut store = MockStore::new(
                period_1_update.finalized_header.beacon.clone(),
                period_1_update.next_sync_committee.clone(), // period1's committee is same as period2
                Default::default(),                          // dummy
            );
            store.next_sync_committee = Some(period_1_update.next_sync_committee.clone());
            let ctx = LightClientContext::new_with_config(
                get_config(),
                H256::from_slice(
                    hex!("acac7566fdf384a1ada45c01dcf9030d7eb0e1e5f5302659101d0b2a5bb59092")
                        .as_ref(),
                ),
                1731420304.into(),
                Fraction::new(2, 3).unwrap(),
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .into(),
            );
            let consensus_update = ConsensusUpdateInfo {
                light_client_update: LightClientUpdate {
                    attested_header: period_2_update.attested_header.beacon,
                    next_sync_committee: Some((
                        period_2_update.next_sync_committee.clone(),
                        period_2_update.next_sync_committee_branch.clone(),
                    )),
                    finalized_header: (
                        period_2_update.finalized_header.beacon,
                        period_2_update.finality_branch.clone(),
                    ),
                    sync_aggregate: period_2_update.sync_aggregate,
                    signature_slot: period_2_update.signature_slot,
                },
                finalized_execution_root: hash_tree_root(
                    period_2_update.finalized_header.execution,
                )
                .unwrap(),
                finalized_execution_branch: period_2_update.finalized_header.execution_branch,
            };
            let res = SyncProtocolVerifier::default().validate_consensus_update(
                &ctx,
                &store,
                &consensus_update,
            );
            assert!(res.is_ok(), "{:?}", res);
        }

        fn get_config() -> Config {
            Config {
                preset: preset::minimal::PRESET,
                fork_parameters: ForkParameters::new(
                    Version([0, 0, 0, 1]),
                    vec![
                        ForkParameter::new(Version([1, 0, 0, 1]), U64(0), ALTAIR_FORK_SPEC),
                        ForkParameter::new(Version([2, 0, 0, 1]), U64(0), BELLATRIX_FORK_SPEC),
                        ForkParameter::new(Version([3, 0, 0, 1]), U64(0), CAPELLA_FORK_SPEC),
                        ForkParameter::new(Version([4, 0, 0, 1]), U64(0), DENEB_FORK_SPEC),
                        ForkParameter::new(Version([5, 0, 0, 1]), U64(0), ELECTRA_FORK_SPEC),
                    ],
                )
                .unwrap(),
                min_genesis_time: U64(1578009600),
            }
        }
    }
}
