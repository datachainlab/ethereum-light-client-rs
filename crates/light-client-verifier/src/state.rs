use crate::{errors::Error, updates::ConsensusUpdate};
use ethereum_consensus::{
    beacon::Slot, compute::compute_sync_committee_period_at_slot, context::ChainContext,
    sync_protocol::SyncCommittee,
};

pub trait LightClientStoreReader<const SYNC_COMMITTEE_SIZE: usize> {
    /// Returns the finalized slot based on the light client update.
    fn current_slot(&self) -> Slot;
    /// Returns the current sync committee based on the light client update.
    fn current_sync_committee(&self) -> &SyncCommittee<SYNC_COMMITTEE_SIZE>;
    /// Returns the next sync committee based on the light client update.
    fn next_sync_committee(&self) -> Option<&SyncCommittee<SYNC_COMMITTEE_SIZE>>;
}

/// Returns the new current and next sync committees based on the state and the consensus update.
///
/// If the current sync committee should be updated, the new current sync committee is returned.
/// If the next sync committee should be updated, the new next sync committee is returned.
/// ref. https://github.com/ethereum/consensus-specs/blob/087e7378b44f327cdad4549304fc308613b780c3/specs/altair/light-client/sync-protocol.md#apply_light_client_update
pub fn should_update_sync_committees<
    's,
    'u,
    const SYNC_COMMITTEE_SIZE: usize,
    CC: ChainContext,
    S: LightClientStoreReader<SYNC_COMMITTEE_SIZE>,
    CU: ConsensusUpdate<SYNC_COMMITTEE_SIZE>,
>(
    ctx: &CC,
    state: &'s S,
    consensus_update: &'u CU,
) -> Result<
    (
        // new current sync committee
        Option<&'s SyncCommittee<SYNC_COMMITTEE_SIZE>>,
        // new next sync committee
        Option<Option<&'u SyncCommittee<SYNC_COMMITTEE_SIZE>>>,
    ),
    Error,
> {
    let store_period = compute_sync_committee_period_at_slot(ctx, state.current_slot());
    let update_finalized_period =
        compute_sync_committee_period_at_slot(ctx, consensus_update.finalized_beacon_header().slot);

    if store_period != update_finalized_period && store_period + 1 != update_finalized_period {
        return Err(Error::InvalidFinalizedPeriod(
            store_period,
            update_finalized_period,
            "finalized period must be equal to store_period or store_period+1".into(),
        ));
    }

    if let Some(store_next_sync_committee) = state.next_sync_committee() {
        if update_finalized_period == store_period + 1 {
            Ok((
                Some(store_next_sync_committee),
                Some(consensus_update.next_sync_committee()),
            ))
        } else {
            // no updates
            Ok((None, None))
        }
    } else if update_finalized_period == store_period {
        Ok((None, Some(consensus_update.next_sync_committee())))
    } else {
        Err(Error::CannotRotateNextSyncCommittee(
            store_period,
            update_finalized_period,
        ))
    }
}
