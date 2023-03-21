use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

use crate::{
    chain::Network,
    commands::Command,
    context::Context,
    preset::{MainnetContext, MinimalContext},
};

#[derive(Debug, Parser)]
#[clap(
    name = env!("CARGO_PKG_NAME"),
    version = env!("CARGO_PKG_VERSION"),
    author = env!("CARGO_PKG_AUTHORS"),
    about = env!("CARGO_PKG_DESCRIPTION"),
)]
pub struct Cli {
    #[command(flatten)]
    pub opts: Opts,

    #[command(subcommand)]
    pub cmd: Command,
}

#[derive(Debug, Parser, Clone)]
pub struct Opts {
    #[arg(long = "home", help = "Path to home directory")]
    pub home_dir: Option<PathBuf>,

    #[arg(long = "beacon_endpoint")]
    pub beacon_endpoint: String,

    #[arg(long = "network")]
    pub network: String,
}

impl Opts {
    pub fn home_dir(&self) -> PathBuf {
        self.home_dir
            .clone()
            .unwrap_or(dirs::home_dir().unwrap())
            .join(".ethlc")
    }

    pub fn network(&self) -> Result<Network> {
        Ok(Network::from_str(&self.network)?)
    }
}

impl Cli {
    pub async fn run(self) -> Result<()> {
        let network = self.opts.network()?;
        let opts = self.opts.clone();
        match network {
            Network::Mainnet | Network::Goerli | Network::Sepolia => {
                self.run_with_context(MainnetContext::build(network, opts)?)
                    .await
            }
            Network::Minimal => {
                self.run_with_context(MinimalContext::build(network, opts)?)
                    .await
            }
        }
    }

    async fn run_with_context<
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
        self,
        ctx: Context<
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
    ) -> Result<()> {
        match self.cmd {
            Command::Init(cmd) => cmd.run(ctx).await,
            Command::Update(cmd) => cmd.run(ctx).await,
        }
    }
}
