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

    pub fn current_period<CC: ChainContext>(&self, ctx: &CC) -> Slot {
        compute_sync_committee_period_at_slot(ctx, self.latest_finalized_header.slot)
    }

    pub fn apply_light_client_update<
        CC: ChainContext + ConsensusVerificationContext,
        CU: ConsensusUpdate<SYNC_COMMITTEE_SIZE>,
    >(
        &mut self,
        ctx: &CC,
        consensus_update: &CU,
    ) -> Result<bool, crate::errors::Error> {
        let store_period =
            compute_sync_committee_period_at_slot(ctx, self.latest_finalized_header.slot);
        let attested_period = compute_sync_committee_period_at_slot(
            ctx,
            consensus_update.attested_beacon_header().slot,
        );

        let mut updated = if store_period == attested_period {
            if let Some(committee) = consensus_update.next_sync_committee() {
                self.next_sync_committee = Some(committee.clone());
                true
            } else {
                false
            }
        } else if store_period + 1 == attested_period {
            if let Some(committee) = self.next_sync_committee.as_ref() {
                self.current_sync_committee = committee.clone();
                self.next_sync_committee = consensus_update.next_sync_committee().cloned();
                true
            } else {
                return Err(crate::errors::Error::CannotRotateNextSyncCommittee(
                    store_period,
                    attested_period,
                ));
            }
        } else {
            return Err(crate::errors::Error::UnexpectedAttestedPeriod(
                store_period,
                attested_period,
                "attested period must be equal to store_period or store_period+1".into(),
            ));
        };
        if consensus_update.finalized_beacon_header().slot > self.latest_finalized_header.slot {
            self.latest_finalized_header = consensus_update.finalized_beacon_header().clone();
            updated = true;
        }
        Ok(updated)
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> LightClientStoreReader<SYNC_COMMITTEE_SIZE>
    for MockStore<SYNC_COMMITTEE_SIZE>
{
    fn get_sync_committee<CC: ethereum_consensus::context::ChainContext>(
        &self,
        ctx: &CC,
        period: ethereum_consensus::sync_protocol::SyncCommitteePeriod,
    ) -> Option<SyncCommittee<SYNC_COMMITTEE_SIZE>> {
        let current_period = self.current_period(ctx);
        if period == current_period {
            Some(self.current_sync_committee.clone())
        } else if period == current_period + 1 {
            self.next_sync_committee.clone()
        } else {
            None
        }
    }

    fn ensure_relevant_update<CC: ChainContext, CU: ConsensusUpdate<SYNC_COMMITTEE_SIZE>>(
        &self,
        ctx: &CC,
        update: &CU,
    ) -> Result<(), crate::errors::Error> {
        update.ensure_consistent_update_period(ctx)
    }
}
