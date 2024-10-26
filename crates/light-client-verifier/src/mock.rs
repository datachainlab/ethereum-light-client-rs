use crate::context::ConsensusVerificationContext;
use crate::state::{should_update_sync_committees, LightClientStoreReader};
use crate::updates::ConsensusUpdate;
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

    pub fn apply_light_client_update<
        CC: ChainContext + ConsensusVerificationContext,
        CU: ConsensusUpdate<SYNC_COMMITTEE_SIZE>,
    >(
        &mut self,
        ctx: &CC,
        consensus_update: &CU,
    ) -> Result<bool, crate::errors::Error> {
        let (current_committee, next_committee) =
            should_update_sync_committees(ctx, self, consensus_update)?;
        let mut updated = false;
        if let Some(committee) = current_committee {
            self.current_sync_committee = committee.clone();
            updated = true;
        }
        if let Some(committee) = next_committee {
            self.next_sync_committee = committee.cloned();
            updated = true;
        }
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
    fn current_slot(&self) -> Slot {
        self.latest_finalized_header.slot
    }

    fn current_sync_committee(&self) -> &SyncCommittee<SYNC_COMMITTEE_SIZE> {
        &self.current_sync_committee
    }

    fn next_sync_committee(&self) -> Option<&SyncCommittee<SYNC_COMMITTEE_SIZE>> {
        self.next_sync_committee.as_ref()
    }
}
