use crate::context::ConsensusVerificationContext;
use crate::errors::Error;
use crate::internal_prelude::*;
use ethereum_consensus::{
    beacon::{BeaconBlockHeader, Slot, BLOCK_BODY_EXECUTION_PAYLOAD_LEAF_INDEX},
    merkle::is_valid_merkle_branch,
    sync_protocol::{
        SyncAggregate, SyncCommittee, CURRENT_SYNC_COMMITTEE_DEPTH, EXECUTION_PAYLOAD_DEPTH,
        FINALIZED_ROOT_DEPTH, NEXT_SYNC_COMMITTEE_DEPTH,
    },
    types::{H256, U64},
};
pub mod bellatrix;
pub mod capella;
pub mod deneb;

pub trait LightClientBootstrap<const SYNC_COMMITTEE_SIZE: usize>:
    core::fmt::Debug + Clone + PartialEq + Eq
{
    fn beacon_header(&self) -> &BeaconBlockHeader;
    fn current_sync_committee(&self) -> &SyncCommittee<SYNC_COMMITTEE_SIZE>;
    fn current_sync_committee_branch(&self) -> [H256; CURRENT_SYNC_COMMITTEE_DEPTH];
}

/// ConsensusUpdate is an update info of the consensus layer corresponding to a specific light client update
pub trait ConsensusUpdate<const SYNC_COMMITTEE_SIZE: usize>:
    core::fmt::Debug + Clone + PartialEq + Eq
{
    fn attested_beacon_header(&self) -> &BeaconBlockHeader;

    fn next_sync_committee(&self) -> Option<&SyncCommittee<SYNC_COMMITTEE_SIZE>>;
    fn next_sync_committee_branch(&self) -> Option<[H256; NEXT_SYNC_COMMITTEE_DEPTH]>;

    fn finalized_beacon_header(&self) -> &BeaconBlockHeader;
    fn finalized_beacon_header_branch(&self) -> [H256; FINALIZED_ROOT_DEPTH];

    fn finalized_execution_root(&self) -> H256;
    fn finalized_execution_branch(&self) -> [H256; EXECUTION_PAYLOAD_DEPTH];

    fn sync_aggregate(&self) -> &SyncAggregate<SYNC_COMMITTEE_SIZE>;
    fn signature_slot(&self) -> Slot;

    /// ref. https://github.com/ethereum/consensus-specs/blob/087e7378b44f327cdad4549304fc308613b780c3/specs/altair/light-client/sync-protocol.md#is_valid_light_client_header
    /// NOTE: There are no validation for the execution payload, so you should implement it if the update contains the execution payload.
    fn is_valid_light_client_finalized_header(&self) -> Result<(), Error> {
        is_valid_merkle_branch(
            self.finalized_execution_root(),
            &self.finalized_execution_branch(),
            EXECUTION_PAYLOAD_DEPTH as u32,
            BLOCK_BODY_EXECUTION_PAYLOAD_LEAF_INDEX as u64,
            self.finalized_beacon_header().body_root.clone(),
        )
        .map_err(Error::InvalidFinalizedExecutionPayload)
    }

    fn validate_basic<C: ConsensusVerificationContext>(&self, ctx: &C) -> Result<(), Error> {
        // ensure that sync committee's aggreated key matches pubkeys
        if let Some(next_sync_committee) = self.next_sync_committee() {
            next_sync_committee.validate()?;
        }

        // ensure that the order of slots is consistent
        // equivalent to:
        // `assert current_slot >= update.signature_slot > update_attested_slot >= update_finalized_slot``
        // from the spec: https://github.com/ethereum/consensus-specs/blob/087e7378b44f327cdad4549304fc308613b780c3/specs/altair/light-client/sync-protocol.md?plain=1#L380
        if !(ctx.current_slot() >= self.signature_slot()
            && self.signature_slot() > self.attested_beacon_header().slot
            && self.attested_beacon_header().slot >= self.finalized_beacon_header().slot)
        {
            return Err(Error::InconsistentSlotOrder(
                ctx.current_slot(),
                self.signature_slot(),
                self.attested_beacon_header().slot,
                self.finalized_beacon_header().slot,
            ));
        }

        // ensure that suffienct participants exist

        let participants = self.sync_aggregate().count_participants();
        // from the spec: `assert sum(sync_aggregate.sync_committee_bits) >= MIN_SYNC_COMMITTEE_PARTICIPANTS`
        if participants < ctx.min_sync_committee_participants() {
            return Err(Error::LessThanMinimalParticipants(
                participants,
                ctx.min_sync_committee_participants(),
            ));
        } else if participants as u64 * ctx.signature_threshold().denominator
            < self.sync_aggregate().sync_committee_bits.len() as u64
                * ctx.signature_threshold().numerator
        {
            return Err(Error::InsufficientParticipants(
                participants as u64,
                self.sync_aggregate().sync_committee_bits.len() as u64,
            ));
        }

        Ok(())
    }
}

// TODO multiproof support
/// ExecutionUpdate is an update info of the execution layer
pub trait ExecutionUpdate: core::fmt::Debug + Clone + PartialEq + Eq {
    fn state_root(&self) -> H256;
    fn state_root_branch(&self) -> Vec<H256>;
    fn block_number(&self) -> U64;
    fn block_number_branch(&self) -> Vec<H256>;

    fn validate_basic(&self) -> Result<(), Error> {
        Ok(())
    }
}
