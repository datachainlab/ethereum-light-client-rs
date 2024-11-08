use crate::{errors::Error, updates::ConsensusUpdate};
use ethereum_consensus::{
    context::ChainContext,
    sync_protocol::{SyncCommittee, SyncCommitteePeriod},
};

pub trait LightClientStoreReader<const SYNC_COMMITTEE_SIZE: usize> {
    /// Returns the current sync committee period
    fn current_period<CC: ChainContext>(&self, ctx: &CC) -> SyncCommitteePeriod;

    /// Returns the current sync committee corresponding to the current period if available
    fn current_sync_committee(&self) -> Option<SyncCommittee<SYNC_COMMITTEE_SIZE>>;

    /// Returns the next sync committee corresponding to the next period if available
    fn next_sync_committee(&self) -> Option<SyncCommittee<SYNC_COMMITTEE_SIZE>>;

    /// Returns the sync committee corresponding to the given signature period if available
    fn get_sync_committee<CC: ChainContext>(
        &self,
        ctx: &CC,
        signature_period: SyncCommitteePeriod,
    ) -> Option<SyncCommittee<SYNC_COMMITTEE_SIZE>> {
        let current_period = self.current_period(ctx);
        let next_period = current_period + 1;
        if signature_period == current_period {
            self.current_sync_committee()
        } else if signature_period == next_period {
            self.next_sync_committee()
        } else {
            None
        }
    }

    /// Returns a error indicating whether the update is relevant to the light client store.
    ///
    /// This method should be used to determine whether the update should be applied to the store.
    fn ensure_relevant_update<CC: ChainContext, C: ConsensusUpdate<SYNC_COMMITTEE_SIZE>>(
        &self,
        _ctx: &CC,
        _update: &C,
    ) -> Result<(), Error> {
        Ok(())
    }
}
