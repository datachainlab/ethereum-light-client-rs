use super::ForkSpec;
use crate::{
    beacon::{BeaconBlockHeader, Slot},
    internal_prelude::*,
    sync_protocol::{SyncAggregate, SyncCommittee},
    types::H256,
};

/// https://github.com/ethereum/consensus-specs/blob/master/specs/gloas/light-client/sync-protocol.md#new-constants
/// EIP-7688 turns BeaconState into a progressive container, so the state gindices
/// are not inherited from Electra; EIP-7732 moves the execution commitment into
/// signed_execution_payload_bid, which gives a new block body gindex.
pub const GLOAS_FORK_SPEC: ForkSpec = ForkSpec {
    // FINALIZED_ROOT_GINDEX_GLOAS
    finalized_root_gindex: 735,
    // CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS
    current_sync_committee_gindex: 2945,
    // NEXT_SYNC_COMMITTEE_GINDEX_GLOAS
    next_sync_committee_gindex: 2946,
    // Gloas uses execution_block_hash_gindex instead of execution_payload_gindex
    // The merkle proof verifies execution_block_hash (not hash_tree_root(execution)) against body_root
    execution_payload_gindex: 0,
    // Not used in Gloas (RLP verification instead of SSZ merkle proofs)
    execution_payload_state_root_gindex: 0,
    execution_payload_block_number_gindex: 0,
    // EXECUTION_BLOCK_HASH_GINDEX_GLOAS = 2856
    // get_generalized_index(BeaconBlockBody, 'signed_execution_payload_bid', 'message', 'parent_block_hash')
    execution_block_hash_gindex: 2856,
};

/// LightClientHeader for Gloas (spec-compliant)
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/gloas/light-client/sync-protocol.md
///
/// Unlike previous forks, Gloas LightClientHeader contains only execution_block_hash
/// instead of the full ExecutionPayloadHeader. The client must fetch ExecutionPayloadHeader
/// from the Execution Layer using this hash.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LightClientHeader {
    /// Header matching the requested beacon block root
    pub beacon: BeaconBlockHeader,
    /// Execution block hash (signed_execution_payload_bid.message.parent_block_hash)
    pub execution_block_hash: H256,
    /// Merkle branch proving execution_block_hash within BeaconBlockBody
    pub execution_branch: Vec<H256>,
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#lightclientbootstrap
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LightClientBootstrap<const SYNC_COMMITTEE_SIZE: usize> {
    pub header: LightClientHeader,
    /// Current sync committee corresponding to `beacon_header.state_root`
    pub current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub current_sync_committee_branch: Vec<H256>,
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#lightclientupdate
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LightClientUpdate<const SYNC_COMMITTEE_SIZE: usize> {
    /// Header attested to by the sync committee
    pub attested_header: LightClientHeader,
    /// Next sync committee corresponding to `attested_header.state_root`
    pub next_sync_committee: Option<(SyncCommittee<SYNC_COMMITTEE_SIZE>, Vec<H256>)>,
    /// Finalized header corresponding to `attested_header.state_root`
    pub finalized_header: LightClientHeader,
    pub finality_branch: Vec<H256>,
    /// Sync committee aggregate signature
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    /// Slot at which the aggregate signature was created (untrusted)
    pub signature_slot: Slot,
}

/// Re-export ExecutionPayloadHeader from deneb for client use
/// Client fetches this from EL using execution_block_hash
pub use super::deneb::ExecutionPayloadHeader;
