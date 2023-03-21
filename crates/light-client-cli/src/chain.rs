use crate::errors::Error;
use ethereum_consensus::{
    beacon::{Epoch, Slot},
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

    pub async fn get_bootstrap<
        const SYNC_COMMITTEE_SIZE: usize,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
    >(
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
        Ok(self
            .rpc_client
            .get_bootstrap::<SYNC_COMMITTEE_SIZE, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>(
                finalized_root,
            )
            .await?
            .data
            .into())
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
