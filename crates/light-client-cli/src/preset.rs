use crate::context::Context;
use ethereum_consensus::preset::{mainnet, minimal};

pub type MainnetContext = Context<
    { mainnet::PRESET.MAX_PROPOSER_SLASHINGS },
    { mainnet::PRESET.MAX_VALIDATORS_PER_COMMITTEE },
    { mainnet::PRESET.MAX_ATTESTER_SLASHINGS },
    { mainnet::PRESET.MAX_ATTESTATIONS },
    { mainnet::PRESET.DEPOSIT_CONTRACT_TREE_DEPTH },
    { mainnet::PRESET.MAX_DEPOSITS },
    { mainnet::PRESET.MAX_VOLUNTARY_EXITS },
    { mainnet::PRESET.BYTES_PER_LOGS_BLOOM },
    { mainnet::PRESET.MAX_EXTRA_DATA_BYTES },
    { mainnet::PRESET.MAX_BYTES_PER_TRANSACTION },
    { mainnet::PRESET.MAX_TRANSACTIONS_PER_PAYLOAD },
    { mainnet::PRESET.SYNC_COMMITTEE_SIZE },
>;

pub type MinimalContext = Context<
    { minimal::PRESET.MAX_PROPOSER_SLASHINGS },
    { minimal::PRESET.MAX_VALIDATORS_PER_COMMITTEE },
    { minimal::PRESET.MAX_ATTESTER_SLASHINGS },
    { minimal::PRESET.MAX_ATTESTATIONS },
    { minimal::PRESET.DEPOSIT_CONTRACT_TREE_DEPTH },
    { minimal::PRESET.MAX_DEPOSITS },
    { minimal::PRESET.MAX_VOLUNTARY_EXITS },
    { minimal::PRESET.BYTES_PER_LOGS_BLOOM },
    { minimal::PRESET.MAX_EXTRA_DATA_BYTES },
    { minimal::PRESET.MAX_BYTES_PER_TRANSACTION },
    { minimal::PRESET.MAX_TRANSACTIONS_PER_PAYLOAD },
    { minimal::PRESET.SYNC_COMMITTEE_SIZE },
>;
