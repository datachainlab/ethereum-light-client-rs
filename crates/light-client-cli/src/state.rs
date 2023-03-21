use ethereum_consensus::{
    beacon::{BeaconBlockHeader, Slot},
    bellatrix::ExecutionPayloadHeader,
    compute::hash_tree_root,
    sync_protocol::{LightClientBootstrap, SyncCommittee},
    types::{H256, U64},
};
use ethereum_light_client_verifier::{
    state::{SyncCommitteeKeeper, SyncCommitteeView},
    updates::ExecutionUpdate,
};

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LightClientStore<
    const SYNC_COMMITTEE_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
> {
    pub latest_finalized_header: BeaconBlockHeader,
    pub latest_execution_payload_header:
        ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    pub current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub next_sync_committee: Option<SyncCommittee<SYNC_COMMITTEE_SIZE>>,
}

impl<
        const SYNC_COMMITTEE_SIZE: usize,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
    > LightClientStore<SYNC_COMMITTEE_SIZE, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
{
    pub fn from_bootstrap(
        bootstrap: LightClientBootstrap<SYNC_COMMITTEE_SIZE>,
        latest_execution_payload_header: ExecutionPayloadHeader<
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ) -> Self {
        Self {
            latest_finalized_header: bootstrap.beacon_header,
            latest_execution_payload_header,
            current_sync_committee: bootstrap.current_sync_committee,
            next_sync_committee: None,
        }
    }
}

impl<
        const SYNC_COMMITTEE_SIZE: usize,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
    > SyncCommitteeView<SYNC_COMMITTEE_SIZE>
    for LightClientStore<SYNC_COMMITTEE_SIZE, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
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

impl<
        const SYNC_COMMITTEE_SIZE: usize,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
    > SyncCommitteeKeeper<SYNC_COMMITTEE_SIZE>
    for LightClientStore<SYNC_COMMITTEE_SIZE, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
{
    fn set_finalized_header(&mut self, header: BeaconBlockHeader) {
        self.latest_finalized_header = header;
    }

    fn set_current_sync_committee(
        &mut self,
        current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    ) {
        self.current_sync_committee = current_sync_committee;
    }

    fn set_next_sync_committee(
        &mut self,
        next_sync_committee: Option<SyncCommittee<SYNC_COMMITTEE_SIZE>>,
    ) {
        self.next_sync_committee = next_sync_committee;
    }
}

impl<
        const SYNC_COMMITTEE_SIZE: usize,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
    > LightClientStore<SYNC_COMMITTEE_SIZE, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
{
    pub fn apply_execution_update(
        &mut self,
        execution_update: ExecutionUpdateInfo<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    ) -> Result<bool, ethereum_light_client_verifier::errors::Error> {
        if self.latest_execution_payload_header != execution_update.execution_payload_header {
            self.latest_execution_payload_header = execution_update.execution_payload_header;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExecutionUpdateInfo<const BYTES_PER_LOGS_BLOOM: usize, const MAX_EXTRA_DATA_BYTES: usize>
{
    pub execution_payload_header:
        ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    pub payload_branch: Vec<H256>,
    pub state_root: H256,
    pub state_root_branch: Vec<H256>,
    pub block_number: U64,
    pub block_number_branch: Vec<H256>,
}

impl<const BYTES_PER_LOGS_BLOOM: usize, const MAX_EXTRA_DATA_BYTES: usize> ExecutionUpdate
    for ExecutionUpdateInfo<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
{
    fn payload_root(&self) -> H256 {
        hash_tree_root(self.execution_payload_header.clone())
            .unwrap()
            .0
            .into()
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
