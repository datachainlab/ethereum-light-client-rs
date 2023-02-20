use crate::context::ConsensusVerificationContext;
use crate::errors::Error;
use crate::internal_prelude::*;
use core::ops::Deref;
use ethereum_consensus::{
    beacon::{BeaconBlockHeader, Slot},
    sync_protocol::{
        LightClientUpdate, SyncAggregate, SyncCommittee, FINALIZED_ROOT_DEPTH,
        NEXT_SYNC_COMMITTEE_DEPTH,
    },
    types::{H256, U64},
};

/// ConsensusUpdate is an update info of the consensus layer corresponding to a specific light client update
pub trait ConsensusUpdate<const SYNC_COMMITTEE_SIZE: usize>:
    core::fmt::Debug + Clone + PartialEq + Eq
{
    fn attested_header(&self) -> &BeaconBlockHeader;

    fn next_sync_committee(&self) -> Option<&SyncCommittee<SYNC_COMMITTEE_SIZE>>;
    fn next_sync_committee_branch(&self) -> Option<[H256; NEXT_SYNC_COMMITTEE_DEPTH]>;

    fn finalized_header(&self) -> &BeaconBlockHeader;
    fn finalized_header_branch(&self) -> [H256; FINALIZED_ROOT_DEPTH];

    fn sync_aggregate(&self) -> &SyncAggregate<SYNC_COMMITTEE_SIZE>;
    fn signature_slot(&self) -> Slot;

    fn validate_basic<C: ConsensusVerificationContext>(&self, ctx: &C) -> Result<(), Error> {
        // ensure that the finalized header is non-empty
        if self.finalized_header() == &BeaconBlockHeader::default() {
            return Err(Error::FinalizedHeaderNotFound);
        }

        // ensure that sync committee's aggreated key matches pubkeys
        if let Some(next_sync_committee) = self.next_sync_committee() {
            next_sync_committee.validate()?;
        }

        // ensure that the order of slots is consistent
        if !(ctx.current_slot() >= self.signature_slot()
            && self.signature_slot() > self.attested_header().slot
            && self.attested_header().slot >= self.finalized_header().slot)
        {
            return Err(Error::InconsistentSlotOrder(
                ctx.current_slot(),
                self.signature_slot(),
                self.attested_header().slot,
                self.finalized_header().slot,
            ));
        }

        // ensure that suffienct participants exist

        let participants = self.sync_aggregate().count_participants();
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
    fn payload_root(&self) -> H256;
    fn payload_branch(&self) -> Vec<H256>;
    fn state_root(&self) -> H256;
    fn state_root_branch(&self) -> Vec<H256>;
    fn block_number(&self) -> U64;
    fn block_number_branch(&self) -> Vec<H256>;

    fn validate_basic(&self) -> Result<(), Error> {
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct ConsensusUpdateInfo<const SYNC_COMMITTEE_SIZE: usize>(
    pub LightClientUpdate<SYNC_COMMITTEE_SIZE>,
);

impl<const SYNC_COMMITTEE_SIZE: usize> Deref for ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE> {
    type Target = LightClientUpdate<SYNC_COMMITTEE_SIZE>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> ConsensusUpdate<SYNC_COMMITTEE_SIZE>
    for ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE>
{
    fn attested_header(&self) -> &BeaconBlockHeader {
        &self.attested_header
    }
    fn next_sync_committee(&self) -> Option<&SyncCommittee<SYNC_COMMITTEE_SIZE>> {
        self.next_sync_committee.as_ref().map(|c| &c.0)
    }
    fn next_sync_committee_branch(&self) -> Option<[H256; NEXT_SYNC_COMMITTEE_DEPTH]> {
        self.next_sync_committee.as_ref().map(|c| c.1.clone())
    }
    fn finalized_header(&self) -> &BeaconBlockHeader {
        &self.finalized_header.0
    }
    fn finalized_header_branch(&self) -> [H256; FINALIZED_ROOT_DEPTH] {
        self.finalized_header.1.clone()
    }
    fn sync_aggregate(&self) -> &SyncAggregate<SYNC_COMMITTEE_SIZE> {
        &self.sync_aggregate
    }
    fn signature_slot(&self) -> Slot {
        self.signature_slot
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExecutionUpdateInfo {
    pub payload_root: H256,
    pub payload_branch: Vec<H256>,
    pub state_root: H256,
    pub state_root_branch: Vec<H256>,
    pub block_number: U64,
    pub block_number_branch: Vec<H256>,
}

impl ExecutionUpdate for ExecutionUpdateInfo {
    fn payload_root(&self) -> H256 {
        self.payload_root.clone()
    }

    fn payload_branch(&self) -> Vec<H256> {
        self.payload_branch.clone()
    }

    fn state_root(&self) -> H256 {
        self.state_root.clone()
    }

    fn state_root_branch(&self) -> Vec<H256> {
        self.state_root_branch.clone()
    }

    fn block_number(&self) -> U64 {
        self.block_number
    }

    fn block_number_branch(&self) -> Vec<H256> {
        self.block_number_branch.clone()
    }
}
