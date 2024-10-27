use crate::context::Context;
use anyhow::Result;
use clap::Parser;
use lodestar_rpc::client::RPCClient;

#[derive(Clone, Debug, Parser, PartialEq)]
pub struct HeaderCommand {
    #[clap(long = "slot", help = "Slot number")]
    pub slot: Option<u64>,
}

impl HeaderCommand {
    pub async fn run<
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
        const SYNC_COMMITTEE_SIZE: usize,
    >(
        self,
        ctx: Context<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES, SYNC_COMMITTEE_SIZE>,
    ) -> Result<()> {
        let client = RPCClient::new(ctx.beacon_endpoint());
        let res = match self.slot {
            Some(slot) => client.get_beacon_header_by_slot(slot.into()).await?,
            None => {
                let res = client.get_finality_update::<
                    SYNC_COMMITTEE_SIZE,
                    BYTES_PER_LOGS_BLOOM,
                    MAX_EXTRA_DATA_BYTES,
                >().await?;
                client
                    .get_beacon_header_by_slot(res.data.finalized_header.beacon.slot)
                    .await?
            }
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&res.data.header.message)?
        );
        Ok(())
    }
}
