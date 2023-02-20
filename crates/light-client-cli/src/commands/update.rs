use crate::{
    chain::Chain,
    client::{LightClient, Target},
    context::Context,
};
use anyhow::Result;
use clap::Parser;
use core::time::Duration;

#[derive(Clone, Debug, Parser, PartialEq)]
pub struct UpdateCommand {
    #[clap(long = "target")]
    target: Option<String>,
}

impl UpdateCommand {
    pub async fn run<
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
        let chain = Chain::new(ctx.beacon_endpoint());
        let target = if let Some(target) = self.target {
            Target::from_string(&ctx, &target)?
        } else {
            Target::None
        };

        let genesis = chain.rpc_client.get_genesis().await?.data;
        let lc = LightClient::new(
            ctx,
            chain,
            genesis.genesis_time,
            genesis.genesis_validators_root,
            None,
        );

        let _ = lc
            .update_until_target(target, Duration::from_secs(5))
            .await?;
        Ok(())
    }
}
