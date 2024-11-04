use crate::{errors::Error, updates::ConsensusUpdate};
use ethereum_consensus::{
    context::ChainContext,
    sync_protocol::{SyncCommittee, SyncCommitteePeriod},
};

pub trait LightClientStoreReader<const SYNC_COMMITTEE_SIZE: usize> {
    /// Returns the sync committee for the given period.
    fn get_sync_committee<CC: ChainContext>(
        &self,
        ctx: &CC,
        period: SyncCommitteePeriod,
    ) -> Option<SyncCommittee<SYNC_COMMITTEE_SIZE>>;

    /// Returns a error indicating whether the update is relevant to the light client store.
    ///
    /// This method should be used to determine whether the update should be applied to the store.
    fn ensure_relevant_update<CC: ChainContext, C: ConsensusUpdate<SYNC_COMMITTEE_SIZE>>(
        &self,
        ctx: &CC,
        update: &C,
    ) -> Result<(), Error>;
}
