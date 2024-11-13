use super::{deneb, ForkSpec};

/// https://github.com/ethereum/consensus-specs/blob/a09d0c321550c5411557674a981e2b444a1178c0/specs/electra/light-client/sync-protocol.md#new-constants
pub const ELECTRA_FORK_SPEC: ForkSpec = ForkSpec {
    finalized_root_gindex: 169,
    current_sync_committee_gindex: 86,
    next_sync_committee_gindex: 87,
    ..deneb::DENEB_FORK_SPEC
};
