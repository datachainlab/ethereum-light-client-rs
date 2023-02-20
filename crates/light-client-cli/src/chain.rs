use crate::errors::Error;
use ethereum_consensus::{
    beacon::{BeaconBlock, Epoch, Slot},
    compute::{compute_epoch_at_slot, compute_sync_committee_period},
    config::{self, Config},
    context::ChainContext,
    sync_protocol::{LightClientBootstrap, SyncCommitteePeriod},
    types::{H256, U64},
};
use lodestar_rpc::client::RPCClient;

type Result<T> = core::result::Result<T, Error>;

pub struct Chain {
    pub(crate) rpc_client: RPCClient,
}

impl Chain {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            rpc_client: RPCClient::new(endpoint),
        }
    }

    pub async fn get_beacon_block_by_slot<
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
    >(
        &self,
        slot: Slot,
    ) -> Result<
        BeaconBlock<
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
    > {
        Ok(self
            .rpc_client
            .get_beacon_block_by_slot(slot)
            .await?
            .data
            .message)
    }

    pub async fn get_finalized_info<
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
        CC: ChainContext,
    >(
        &self,
        ctx: &CC,
    ) -> Result<FinalizedInfo> {
        let checkpoints = self.rpc_client.get_finality_checkpoints().await?.data;

        let update = self
            .rpc_client
            .get_finality_update::<SYNC_COMMITTEE_SIZE>()
            .await?
            .data;
        let finalized_block = self
            .get_beacon_block_by_slot::<
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
            >(checkpoints.finalized.epoch * ctx.slots_per_epoch())
            .await?;
        let attested_finalized_block = self
            .get_beacon_block_by_slot::<
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
            >(update.finalized_header.beacon.slot)
            .await?;

        Ok(FinalizedInfo {
            latest_finalized: FinalizedPoints::from_epoch(
                ctx,
                checkpoints.finalized.epoch,
                finalized_block.body.execution_payload.block_number,
            ),
            latest_attested_finalized: FinalizedPoints::from_slot(
                ctx,
                update.finalized_header.beacon.slot,
                attested_finalized_block.body.execution_payload.block_number,
            ),
        })
    }

    pub async fn get_bootstrap<const SYNC_COMMITTEE_SIZE: usize>(
        &self,
        finalized_root: Option<H256>,
    ) -> Result<LightClientBootstrap<SYNC_COMMITTEE_SIZE>> {
        let finalized_root = if let Some(finalized_root) = finalized_root {
            finalized_root
        } else {
            self.rpc_client
                .get_finality_checkpoints()
                .await?
                .data
                .finalized
                .root
        };
        Ok(self.rpc_client.get_bootstrap(finalized_root).await?.data)
    }
}

#[derive(Debug, Clone)]
pub enum Network {
    Minimal,
    Mainnet,
    Goerli,
    Sepolia,
}

impl Network {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "minimal" => Ok(Network::Minimal),
            "mainnet" => Ok(Network::Mainnet),
            "goerli" => Ok(Network::Goerli),
            "sepolia" => Ok(Network::Sepolia),
            s => Err(Error::Other {
                description: format!("unknown network: {}", s).into(),
            }),
        }
    }

    pub fn config(&self) -> Config {
        match self {
            Network::Minimal => config::minimal::CONFIG,
            Network::Mainnet => config::mainnet::CONFIG,
            Network::Goerli => config::goerli::CONFIG,
            Network::Sepolia => config::sepolia::CONFIG,
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct FinalizedInfo {
    pub latest_finalized: FinalizedPoints,
    pub latest_attested_finalized: FinalizedPoints,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct FinalizedPoints {
    pub slot: Slot,
    pub epoch: Epoch,
    pub period: SyncCommitteePeriod,
    pub height: U64,
}

impl FinalizedPoints {
    fn from_slot<CC: ChainContext>(ctx: &CC, slot: Slot, height: U64) -> Self {
        let epoch = compute_epoch_at_slot(ctx, slot);
        Self {
            slot,
            epoch,
            period: compute_sync_committee_period(ctx, epoch),
            height,
        }
    }

    fn from_epoch<CC: ChainContext>(ctx: &CC, epoch: Epoch, height: U64) -> Self {
        Self {
            slot: epoch * ctx.slots_per_epoch(),
            epoch,
            period: compute_sync_committee_period(ctx, epoch),
            height,
        }
    }
}
