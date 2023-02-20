use ethereum_consensus::beacon::{BeaconBlock, BeaconBlockHeader, Checkpoint, Root, Slot};
use ethereum_consensus::bls::Signature;
use ethereum_consensus::sync_protocol::{
    LightClientBootstrap, LightClientFinalityUpdate, LightClientHeader, LightClientUpdate,
    SyncAggregate, SyncCommittee, FINALIZED_ROOT_DEPTH, NEXT_SYNC_COMMITTEE_DEPTH,
};
use ethereum_consensus::types::{H256, U64};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenesisDataResponse {
    pub data: GenesisData,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenesisData {
    pub genesis_validators_root: Root,
    pub genesis_time: U64,
    pub genesis_fork_version: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BeaconBlockResponse<
    const MAX_PROPOSER_SLASHINGS: usize,
    const MAX_VALIDATORS_PER_COMMITTEE: usize,
    const MAX_ATTESTER_SLASHINGS: usize,
    const MAX_ATTESTATIONS: usize,
    const DEPOSIT_CONTRACT_TREE_DEPTH: usize,
    const MAX_DEPOSITS: usize,
    const MAX_VOLUNTARY_EXITS: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
    const MAX_BYTES_PER_TRANSACTION: usize,
    const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
    const SYNC_COMMITTEE_SIZE: usize,
> {
    pub data: BeaconBlockMessage<
        MAX_PROPOSER_SLASHINGS,
        MAX_VALIDATORS_PER_COMMITTEE,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        DEPOSIT_CONTRACT_TREE_DEPTH,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        SYNC_COMMITTEE_SIZE,
    >,
    pub version: String,
    pub execution_optimistic: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BeaconBlockMessage<
    const MAX_PROPOSER_SLASHINGS: usize,
    const MAX_VALIDATORS_PER_COMMITTEE: usize,
    const MAX_ATTESTER_SLASHINGS: usize,
    const MAX_ATTESTATIONS: usize,
    const DEPOSIT_CONTRACT_TREE_DEPTH: usize,
    const MAX_DEPOSITS: usize,
    const MAX_VOLUNTARY_EXITS: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
    const MAX_BYTES_PER_TRANSACTION: usize,
    const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
    const SYNC_COMMITTEE_SIZE: usize,
> {
    pub message: BeaconBlock<
        MAX_PROPOSER_SLASHINGS,
        MAX_VALIDATORS_PER_COMMITTEE,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        DEPOSIT_CONTRACT_TREE_DEPTH,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        SYNC_COMMITTEE_SIZE,
    >,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BeaconBlockRootResponse {
    pub data: BeaconBlockRoot,
    pub execution_optimistic: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BeaconBlockRoot {
    pub root: Root,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BeaconHeaderResponse {
    pub data: BeaconHeaderData,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BeaconHeaderData {
    pub root: Root,
    pub canonical: bool,
    pub header: BeaconHeaderSignature,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BeaconHeaderSignature {
    pub message: BeaconBlockHeader,
    pub signature: Signature,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FinalityCheckpointsResponse {
    pub data: FinalityCheckpoints,
    pub execution_optimistic: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FinalityCheckpoints {
    pub previous_justified: Checkpoint,
    pub current_justified: Checkpoint,
    pub finalized: Checkpoint,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LightClientFinalityUpdateResponse<const SYNC_COMMITTEE_SIZE: usize> {
    pub data: LightClientFinalityUpdate<SYNC_COMMITTEE_SIZE>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LightClientBootstrapResponse<const SYNC_COMMITTEE_SIZE: usize> {
    pub data: LightClientBootstrap<SYNC_COMMITTEE_SIZE>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LightClientUpdatesResponse<const SYNC_COMMITTEE_SIZE: usize>(
    pub Vec<LightClientUpdateResponse<SYNC_COMMITTEE_SIZE>>,
);

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LightClientUpdateResponse<const SYNC_COMMITTEE_SIZE: usize> {
    pub version: String,
    pub data: LightClientUpdateData<SYNC_COMMITTEE_SIZE>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LightClientUpdateData<const SYNC_COMMITTEE_SIZE: usize> {
    pub attested_header: LightClientHeader,
    pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub next_sync_committee_branch: [H256; NEXT_SYNC_COMMITTEE_DEPTH],
    pub finalized_header: LightClientHeader,
    pub finality_branch: [H256; FINALIZED_ROOT_DEPTH],
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    pub signature_slot: Slot,
}

impl<const SYNC_COMMITTEE_SIZE: usize> From<LightClientUpdateData<SYNC_COMMITTEE_SIZE>>
    for LightClientUpdate<SYNC_COMMITTEE_SIZE>
{
    fn from(value: LightClientUpdateData<SYNC_COMMITTEE_SIZE>) -> Self {
        let next_sync_committee = if value.next_sync_committee == Default::default() {
            None
        } else {
            Some((value.next_sync_committee, value.next_sync_committee_branch))
        };
        Self {
            attested_header: value.attested_header.beacon,
            next_sync_committee,
            finalized_header: (value.finalized_header.beacon, value.finality_branch),
            sync_aggregate: value.sync_aggregate,
            signature_slot: value.signature_slot,
        }
    }
}
