use crate::{
    chain::{Chain, FinalizedInfo},
    context::Context,
    state::LightClientStore,
};
use anyhow::Result;
use clap::Parser;

/// show the info about the latest finalized period, slot, height
#[derive(Clone, Debug, Parser, PartialEq)]
pub struct InfoCommand {}

impl InfoCommand {
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
        let current_state = ctx.get_light_client_state()?;
        let finalized = chain.get_finalized_info::<
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
        _
        >(&ctx).await?;
        println!(
            "{}",
            serde_json::to_string_pretty(&Info {
                current_state,
                finalized
            })?
        );
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct Info<
    const SYNC_COMMITTEE_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
> {
    current_state:
        LightClientStore<SYNC_COMMITTEE_SIZE, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    finalized: FinalizedInfo,
}
