use super::Preset;
use crate::types::U64;

/// https://github.com/ethereum/consensus-specs/blob/dev/presets/mainnet
pub const PRESET: Preset = Preset {
    DEPOSIT_CONTRACT_TREE_DEPTH: 32,
    MAX_VALIDATORS_PER_COMMITTEE: 2048,

    SECONDS_PER_SLOT: U64(12),
    SLOTS_PER_EPOCH: U64(32),

    MAX_PROPOSER_SLASHINGS: 16,
    MAX_ATTESTER_SLASHINGS: 2,
    MAX_ATTESTATIONS: 128,
    MAX_DEPOSITS: 16,
    MAX_VOLUNTARY_EXITS: 16,
    MAX_BLS_TO_EXECUTION_CHANGES: 16,
    SYNC_COMMITTEE_SIZE: 512,
    EPOCHS_PER_SYNC_COMMITTEE_PERIOD: U64(256),
    MIN_SYNC_COMMITTEE_PARTICIPANTS: 1,
    UPDATE_TIMEOUT: U64(8192),

    MAX_BYTES_PER_TRANSACTION: 1073741824,
    MAX_TRANSACTIONS_PER_PAYLOAD: 1048576,
    BYTES_PER_LOGS_BLOOM: 256,
    MAX_EXTRA_DATA_BYTES: 32,
    MAX_WITHDRAWALS_PER_PAYLOAD: 16,
    MAX_BLOB_COMMITMENTS_PER_BLOCK: 4096,
};

pub type BellatrixBeaconBlock = crate::bellatrix::BeaconBlock<
    { PRESET.MAX_PROPOSER_SLASHINGS },
    { PRESET.MAX_VALIDATORS_PER_COMMITTEE },
    { PRESET.MAX_ATTESTER_SLASHINGS },
    { PRESET.MAX_ATTESTATIONS },
    { PRESET.DEPOSIT_CONTRACT_TREE_DEPTH },
    { PRESET.MAX_DEPOSITS },
    { PRESET.MAX_VOLUNTARY_EXITS },
    { PRESET.BYTES_PER_LOGS_BLOOM },
    { PRESET.MAX_EXTRA_DATA_BYTES },
    { PRESET.MAX_BYTES_PER_TRANSACTION },
    { PRESET.MAX_TRANSACTIONS_PER_PAYLOAD },
    { PRESET.SYNC_COMMITTEE_SIZE },
>;

pub type BellatrixExecutionPayloadHeader = crate::bellatrix::ExecutionPayloadHeader<
    { PRESET.BYTES_PER_LOGS_BLOOM },
    { PRESET.MAX_EXTRA_DATA_BYTES },
>;

pub type CapellaBeaconBlock = crate::capella::BeaconBlock<
    { PRESET.MAX_PROPOSER_SLASHINGS },
    { PRESET.MAX_VALIDATORS_PER_COMMITTEE },
    { PRESET.MAX_ATTESTER_SLASHINGS },
    { PRESET.MAX_ATTESTATIONS },
    { PRESET.DEPOSIT_CONTRACT_TREE_DEPTH },
    { PRESET.MAX_DEPOSITS },
    { PRESET.MAX_VOLUNTARY_EXITS },
    { PRESET.BYTES_PER_LOGS_BLOOM },
    { PRESET.MAX_EXTRA_DATA_BYTES },
    { PRESET.MAX_BYTES_PER_TRANSACTION },
    { PRESET.MAX_TRANSACTIONS_PER_PAYLOAD },
    { PRESET.MAX_WITHDRAWALS_PER_PAYLOAD },
    { PRESET.MAX_BLS_TO_EXECUTION_CHANGES },
    { PRESET.SYNC_COMMITTEE_SIZE },
>;

pub type CapellaExecutionPayloadHeader = crate::capella::ExecutionPayloadHeader<
    { PRESET.BYTES_PER_LOGS_BLOOM },
    { PRESET.MAX_EXTRA_DATA_BYTES },
>;

pub type DenebBeaconBlock = crate::deneb::BeaconBlock<
    { PRESET.MAX_PROPOSER_SLASHINGS },
    { PRESET.MAX_VALIDATORS_PER_COMMITTEE },
    { PRESET.MAX_ATTESTER_SLASHINGS },
    { PRESET.MAX_ATTESTATIONS },
    { PRESET.DEPOSIT_CONTRACT_TREE_DEPTH },
    { PRESET.MAX_DEPOSITS },
    { PRESET.MAX_VOLUNTARY_EXITS },
    { PRESET.BYTES_PER_LOGS_BLOOM },
    { PRESET.MAX_EXTRA_DATA_BYTES },
    { PRESET.MAX_BYTES_PER_TRANSACTION },
    { PRESET.MAX_TRANSACTIONS_PER_PAYLOAD },
    { PRESET.MAX_WITHDRAWALS_PER_PAYLOAD },
    { PRESET.MAX_BLS_TO_EXECUTION_CHANGES },
    { PRESET.SYNC_COMMITTEE_SIZE },
    { PRESET.MAX_BLOB_COMMITMENTS_PER_BLOCK },
>;

pub type DenebExecutionPayloadHeader = crate::deneb::ExecutionPayloadHeader<
    { PRESET.BYTES_PER_LOGS_BLOOM },
    { PRESET.MAX_EXTRA_DATA_BYTES },
>;
