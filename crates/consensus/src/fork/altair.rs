use super::ForkSpec;

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#constants
/// get_generalized_index(BeaconState, 'finalized_checkpoint', 'root')
// pub const FINALIZED_ROOT_INDEX: u64 = 105;
pub const FINALIZED_ROOT_SUBTREE_INDEX: u64 = 41;
pub const FINALIZED_ROOT_DEPTH: u32 = 6;
/// get_generalized_index(BeaconState, 'current_sync_committee')
// pub const CURRENT_SYNC_COMMITTEE_INDEX: u64 = 54;
pub const CURRENT_SYNC_COMMITTEE_SUBTREE_INDEX: u64 = 22;
pub const CURRENT_SYNC_COMMITTEE_DEPTH: u32 = 5;
/// get_generalized_index(BeaconState, 'next_sync_committee')
// pub const NEXT_SYNC_COMMITTEE_INDEX: u64 = 55;
pub const NEXT_SYNC_COMMITTEE_SUBTREE_INDEX: u64 = 23;
pub const NEXT_SYNC_COMMITTEE_DEPTH: u32 = 5;
/// get_generalized_index(BeaconBlockBody, 'execution_payload')
// pub const EXECUTION_PAYLOAD_INDEX: u64 = 25;
pub const EXECUTION_PAYLOAD_DEPTH: u32 = 4;

pub const ALTAIR_FORK_SPEC: ForkSpec = ForkSpec {
    finalized_root_depth: FINALIZED_ROOT_DEPTH,
    current_sync_committee_depth: CURRENT_SYNC_COMMITTEE_DEPTH,
    next_sync_committee_depth: NEXT_SYNC_COMMITTEE_DEPTH,
    execution_payload_depth: EXECUTION_PAYLOAD_DEPTH,
    execution_payload_tree_depth: 0,
};
