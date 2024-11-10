use crate::context::ConsensusVerificationContext;
use crate::state::LightClientStoreReader;
use crate::updates::ConsensusUpdate;
use ethereum_consensus::compute::compute_sync_committee_period_at_slot;
use ethereum_consensus::context::ChainContext;
use ethereum_consensus::sync_protocol::SyncCommittee;
use ethereum_consensus::{
    beacon::{BeaconBlockHeader, Slot},
    types::H256,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MockStore<const SYNC_COMMITTEE_SIZE: usize> {
    pub latest_finalized_header: BeaconBlockHeader,
    pub latest_execution_root: H256,
    pub current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub next_sync_committee: Option<SyncCommittee<SYNC_COMMITTEE_SIZE>>,
}

impl<const SYNC_COMMITTEE_SIZE: usize> MockStore<SYNC_COMMITTEE_SIZE> {
    pub fn new(
        header: BeaconBlockHeader,
        current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
        execution_state_root: H256,
    ) -> Self {
        Self {
            latest_finalized_header: header,
            latest_execution_root: execution_state_root,
            current_sync_committee,
            next_sync_committee: None,
        }
    }

    /// CONTRACT: `apply_light_client_update` must be called after `SyncProtocolVerifier::validate_consensus_update()`
    pub fn apply_light_client_update<
        CC: ChainContext + ConsensusVerificationContext,
        CU: ConsensusUpdate<SYNC_COMMITTEE_SIZE>,
    >(
        &self,
        ctx: &CC,
        consensus_update: &CU,
    ) -> Result<Option<Self>, crate::errors::Error> {
        let mut new_store = self.clone();
        let store_period =
            compute_sync_committee_period_at_slot(ctx, self.latest_finalized_header.slot);
        let finalized_period = compute_sync_committee_period_at_slot(
            ctx,
            consensus_update.finalized_beacon_header().slot,
        );

        if store_period == finalized_period {
            // store_period == finalized_period <= attested_period <= signature_period
            if consensus_update.has_finalized_next_sync_committee(ctx) {
                // finalized_period == attested_period
                new_store.next_sync_committee = consensus_update.next_sync_committee().cloned();
            }
        } else if store_period + 1 == finalized_period {
            // store_period + 1 == finalized_period == attested_period == signature_period
            debug_assert_eq!(
                compute_sync_committee_period_at_slot(
                    ctx,
                    consensus_update.attested_beacon_header().slot
                ),
                finalized_period
            );
            debug_assert_eq!(
                compute_sync_committee_period_at_slot(ctx, consensus_update.signature_slot()),
                finalized_period
            );

            if let Some(committee) = self.next_sync_committee.as_ref() {
                new_store.current_sync_committee = committee.clone();
                new_store.next_sync_committee = consensus_update.next_sync_committee().cloned();
            } else {
                return Err(crate::errors::Error::CannotRotateNextSyncCommittee(
                    store_period,
                    finalized_period,
                ));
            }
        } else {
            return Err(crate::errors::Error::UnexpectedFinalizedPeriod(
                store_period,
                finalized_period,
                "finalized period must be equal to store_period or store_period+1".into(),
            ));
        };
        if consensus_update.finalized_beacon_header().slot > self.latest_finalized_header.slot {
            new_store.latest_finalized_header = consensus_update.finalized_beacon_header().clone();
        }
        if self != &new_store {
            Ok(Some(new_store))
        } else {
            Ok(None)
        }
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> LightClientStoreReader<SYNC_COMMITTEE_SIZE>
    for MockStore<SYNC_COMMITTEE_SIZE>
{
    fn current_period<CC: ChainContext>(&self, ctx: &CC) -> Slot {
        compute_sync_committee_period_at_slot(ctx, self.latest_finalized_header.slot)
    }

    fn current_sync_committee(&self) -> Option<SyncCommittee<SYNC_COMMITTEE_SIZE>> {
        Some(self.current_sync_committee.clone())
    }

    fn next_sync_committee(&self) -> Option<SyncCommittee<SYNC_COMMITTEE_SIZE>> {
        self.next_sync_committee.clone()
    }

    fn ensure_relevant_update<CC: ChainContext, C: ConsensusUpdate<SYNC_COMMITTEE_SIZE>>(
        &self,
        _ctx: &CC,
        _update: &C,
    ) -> Result<(), crate::errors::Error> {
        // every update is relevant
        Ok(())
    }
}
