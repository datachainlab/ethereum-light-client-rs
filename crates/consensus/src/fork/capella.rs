pub use crate::fork::bellatrix::EXECUTION_PAYLOAD_TREE_DEPTH;
use crate::{
    beacon::{
        Attestation, AttesterSlashing, BeaconBlockHeader, Deposit, Eth1Data, ProposerSlashing,
        Root, SignedBlsToExecutionChange, SignedVoluntaryExit, Slot, ValidatorIndex, Withdrawal,
        BLOCK_BODY_EXECUTION_PAYLOAD_LEAF_INDEX,
    },
    bls::Signature,
    compute::hash_tree_root,
    errors::Error,
    execution::BlockNumber,
    internal_prelude::*,
    merkle::MerkleTree,
    sync_protocol::{
        SyncAggregate, SyncCommittee, CURRENT_SYNC_COMMITTEE_DEPTH, EXECUTION_PAYLOAD_DEPTH,
        FINALIZED_ROOT_DEPTH, NEXT_SYNC_COMMITTEE_DEPTH,
    },
    types::{Address, ByteList, ByteVector, Bytes32, H256, U256, U64},
};
use ssz_rs::{Deserialize, List, Merkleized, Sized};
use ssz_rs_derive::SimpleSerialize;

/// Beacon Block
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#beaconblock
#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct BeaconBlock<
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
    const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
    const MAX_BLS_TO_EXECUTION_CHANGES: usize,
    const SYNC_COMMITTEE_SIZE: usize,
> {
    pub slot: Slot,
    pub proposer_index: ValidatorIndex,
    pub parent_root: Root,
    pub state_root: Root,
    pub body: BeaconBlockBody<
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
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        SYNC_COMMITTEE_SIZE,
    >,
}

impl<
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
        const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
        const MAX_BLS_TO_EXECUTION_CHANGES: usize,
        const SYNC_COMMITTEE_SIZE: usize,
    >
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
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        SYNC_COMMITTEE_SIZE,
    >
{
    pub fn to_header(self) -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot: self.slot,
            proposer_index: self.proposer_index,
            parent_root: self.parent_root,
            state_root: self.state_root,
            body_root: hash_tree_root(self.body).unwrap(),
        }
    }
}

/// Beacon Block Body
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/bellatrix/beacon-chain.md#beaconblockbody
#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct BeaconBlockBody<
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
    const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
    const MAX_BLS_TO_EXECUTION_CHANGES: usize,
    const SYNC_COMMITTEE_SIZE: usize,
> {
    pub randao_reveal: Signature,
    pub eth1_data: Eth1Data,
    pub graffiti: Bytes32,
    pub proposer_slashings: List<ProposerSlashing, MAX_PROPOSER_SLASHINGS>,
    pub attester_slashings:
        List<AttesterSlashing<MAX_VALIDATORS_PER_COMMITTEE>, MAX_ATTESTER_SLASHINGS>,
    pub attestations: List<Attestation<MAX_VALIDATORS_PER_COMMITTEE>, MAX_ATTESTATIONS>,
    pub deposits: List<Deposit<DEPOSIT_CONTRACT_TREE_DEPTH>, MAX_DEPOSITS>,
    pub voluntary_exits: List<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>,
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    pub execution_payload: ExecutionPayload<
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        MAX_WITHDRAWALS_PER_PAYLOAD,
    >,
    pub bls_to_execution_changes: List<SignedBlsToExecutionChange, MAX_BLS_TO_EXECUTION_CHANGES>,
}

// Execution

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/bellatrix/beacon-chain.md#executionpayload
#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct ExecutionPayload<
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
    const MAX_BYTES_PER_TRANSACTION: usize,
    const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
    const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
> {
    /// Execution block header fields
    pub parent_hash: H256,
    pub fee_recipient: Address,
    pub state_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: ByteVector<BYTES_PER_LOGS_BLOOM>,
    /// 'difficulty' in the yellow paper
    pub prev_randao: H256,
    /// 'number' in the yellow paper
    pub block_number: BlockNumber,
    pub gas_limit: U64,
    pub gas_used: U64,
    pub timestamp: U64,
    pub extra_data: ByteList<MAX_EXTRA_DATA_BYTES>,
    pub base_fee_per_gas: U256,
    /// Extra payload fields
    /// Hash of execution block
    pub block_hash: H256,
    pub transactions: List<ByteList<MAX_BYTES_PER_TRANSACTION>, MAX_TRANSACTIONS_PER_PAYLOAD>,
    pub withdrawals: List<Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD>,
}

impl<
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
        const MAX_BYTES_PER_TRANSACTION: usize,
        const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
        const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
    >
    ExecutionPayload<
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        MAX_WITHDRAWALS_PER_PAYLOAD,
    >
{
    pub fn to_header(
        mut self,
    ) -> ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES> {
        ExecutionPayloadHeader {
            parent_hash: self.parent_hash,
            fee_recipient: self.fee_recipient,
            state_root: self.state_root,
            receipts_root: self.receipts_root,
            logs_bloom: self.logs_bloom,
            prev_randao: self.prev_randao,
            block_number: self.block_number,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: self.timestamp,
            extra_data: self.extra_data,
            base_fee_per_gas: self.base_fee_per_gas,
            block_hash: self.block_hash,
            transactions_root: Root::from_slice(
                self.transactions.hash_tree_root().unwrap().as_bytes(),
            ),
            withdrawals_root: Root::from_slice(
                self.withdrawals.hash_tree_root().unwrap().as_bytes(),
            ),
        }
    }
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/bellatrix/beacon-chain.md#executionpayloadheader
#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct ExecutionPayloadHeader<
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
> {
    /// Execution block header fields
    pub parent_hash: H256,
    pub fee_recipient: Address,
    pub state_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: ByteVector<BYTES_PER_LOGS_BLOOM>,
    /// 'difficulty' in the yellow paper
    pub prev_randao: H256,
    /// 'number' in the yellow paper
    pub block_number: U64,
    pub gas_limit: U64,
    pub gas_used: U64,
    pub timestamp: U64,
    pub extra_data: ByteList<MAX_EXTRA_DATA_BYTES>,
    pub base_fee_per_gas: U256,
    /// Extra payload fields
    /// Hash of execution block
    pub block_hash: H256,
    pub transactions_root: Root,
    pub withdrawals_root: Root,
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#lightclientbootstrap
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LightClientBootstrap<
    const SYNC_COMMITTEE_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
> {
    pub header: LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    /// Current sync committee corresponding to `beacon_header.state_root`
    pub current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub current_sync_committee_branch: [H256; CURRENT_SYNC_COMMITTEE_DEPTH],
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LightClientUpdate<
    const SYNC_COMMITTEE_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
> {
    /// Header attested to by the sync committee
    pub attested_header: LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    /// Next sync committee corresponding to `attested_header.state_root`
    pub next_sync_committee: Option<(
        SyncCommittee<SYNC_COMMITTEE_SIZE>,
        [H256; NEXT_SYNC_COMMITTEE_DEPTH],
    )>,
    /// Finalized header corresponding to `attested_header.state_root`
    pub finalized_header: LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    pub finality_branch: [H256; FINALIZED_ROOT_DEPTH],
    /// Sync committee aggregate signature
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    /// Slot at which the aggregate signature was created (untrusted)
    pub signature_slot: Slot,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LightClientHeader<const BYTES_PER_LOGS_BLOOM: usize, const MAX_EXTRA_DATA_BYTES: usize> {
    /// Header matching the requested beacon block root
    pub beacon: BeaconBlockHeader,
    pub execution: ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    pub execution_branch: [H256; EXECUTION_PAYLOAD_DEPTH],
}

// TODO each fork's prover implementation is redundant

pub fn gen_execution_payload_proof<
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
    const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
    const MAX_BLS_TO_EXECUTION_CHANGES: usize,
    const SYNC_COMMITTEE_SIZE: usize,
>(
    body: &BeaconBlockBody<
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
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        SYNC_COMMITTEE_SIZE,
    >,
) -> Result<(Root, [H256; EXECUTION_PAYLOAD_DEPTH]), Error> {
    let tree = MerkleTree::from_leaves(
        ([
            hash_tree_root(body.randao_reveal.clone()).unwrap().0,
            hash_tree_root(body.eth1_data.clone()).unwrap().0,
            body.graffiti.0,
            hash_tree_root(body.proposer_slashings.clone()).unwrap().0,
            hash_tree_root(body.attester_slashings.clone()).unwrap().0,
            hash_tree_root(body.attestations.clone()).unwrap().0,
            hash_tree_root(body.deposits.clone()).unwrap().0,
            hash_tree_root(body.voluntary_exits.clone()).unwrap().0,
            hash_tree_root(body.sync_aggregate.clone()).unwrap().0,
            hash_tree_root(body.execution_payload.clone()).unwrap().0,
            hash_tree_root(body.bls_to_execution_changes.clone())
                .unwrap()
                .0,
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
        ] as [_; 16])
            .as_ref(),
    );
    let mut branch = [Default::default(); EXECUTION_PAYLOAD_DEPTH];
    branch.copy_from_slice(
        tree.proof(&[BLOCK_BODY_EXECUTION_PAYLOAD_LEAF_INDEX])
            .proof_hashes()
            .iter()
            .map(|h| H256::from_slice(h))
            .collect::<Vec<H256>>()
            .as_slice(),
    );
    Ok((H256(tree.root().unwrap()), branch))
}

pub fn gen_execution_payload_field_proof<
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
>(
    payload: &ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    leaf_index: usize,
) -> Result<(Root, [H256; EXECUTION_PAYLOAD_TREE_DEPTH]), Error> {
    let tree = MerkleTree::from_leaves(
        ([
            payload.parent_hash.0,
            hash_tree_root(payload.fee_recipient.clone()).unwrap().0,
            payload.state_root.0,
            payload.receipts_root.0,
            hash_tree_root(payload.logs_bloom.clone()).unwrap().0,
            payload.prev_randao.0,
            hash_tree_root(payload.block_number).unwrap().0,
            hash_tree_root(payload.gas_limit).unwrap().0,
            hash_tree_root(payload.gas_used).unwrap().0,
            hash_tree_root(payload.timestamp).unwrap().0,
            hash_tree_root(payload.extra_data.clone()).unwrap().0,
            hash_tree_root(payload.base_fee_per_gas.clone()).unwrap().0,
            payload.block_hash.0,
            payload.transactions_root.0,
            payload.withdrawals_root.0,
            Default::default(),
        ] as [_; 16])
            .as_ref(),
    );
    let mut branch = [Default::default(); EXECUTION_PAYLOAD_TREE_DEPTH];
    branch.copy_from_slice(
        tree.proof(&[leaf_index])
            .proof_hashes()
            .iter()
            .map(|h| H256::from_slice(h))
            .collect::<Vec<H256>>()
            .as_slice(),
    );
    Ok((H256(tree.root().unwrap()), branch))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::beacon::BLOCK_BODY_EXECUTION_PAYLOAD_LEAF_INDEX;
    use crate::merkle::is_valid_merkle_branch;
    use crate::sync_protocol::EXECUTION_PAYLOAD_DEPTH;
    use crate::{compute::hash_tree_root, types::H256};
    use ssz_rs::Merkleized;
    use std::fs;

    #[test]
    fn beacon_header_serialization() {
        use crate::execution::{
            EXECUTION_PAYLOAD_BLOCK_NUMBER_LEAF_INDEX, EXECUTION_PAYLOAD_STATE_ROOT_LEAF_INDEX,
        };
        let mut header: BeaconBlockHeader = serde_json::from_str(
            &fs::read_to_string("./data/goerli_capella_header_5209248.json").unwrap(),
        )
        .unwrap();

        let mut block: crate::preset::mainnet::CapellaBeaconBlock = serde_json::from_str(
            &fs::read_to_string("./data/goerli_capella_block_5209248.json").unwrap(),
        )
        .unwrap();

        assert_eq!(header, block.clone().to_header());
        assert_eq!(
            header.hash_tree_root().unwrap(),
            block.hash_tree_root().unwrap()
        );

        let (block_root, payload_proof) = gen_execution_payload_proof(&block.body).unwrap();
        assert_eq!(
            block_root.as_bytes(),
            block.body.hash_tree_root().unwrap().as_bytes()
        );

        let payload_root = block.body.execution_payload.hash_tree_root().unwrap();
        let payload_header = block.body.execution_payload.clone().to_header();

        assert!(is_valid_merkle_branch(
            H256::from_slice(payload_root.as_bytes()),
            &payload_proof,
            EXECUTION_PAYLOAD_DEPTH as u32,
            BLOCK_BODY_EXECUTION_PAYLOAD_LEAF_INDEX as u64,
            block_root
        )
        .is_ok());

        {
            let (root, proof) = gen_execution_payload_field_proof(
                &payload_header,
                EXECUTION_PAYLOAD_STATE_ROOT_LEAF_INDEX,
            )
            .unwrap();
            assert_eq!(root.as_bytes(), payload_root.as_bytes());

            assert!(is_valid_merkle_branch(
                hash_tree_root(payload_header.state_root).unwrap().0.into(),
                &proof,
                EXECUTION_PAYLOAD_TREE_DEPTH as u32,
                EXECUTION_PAYLOAD_STATE_ROOT_LEAF_INDEX as u64,
                root,
            )
            .is_ok());
        }
        {
            let (root, proof) = gen_execution_payload_field_proof(
                &payload_header,
                EXECUTION_PAYLOAD_BLOCK_NUMBER_LEAF_INDEX,
            )
            .unwrap();
            assert_eq!(root.as_bytes(), payload_root.as_bytes());

            assert!(is_valid_merkle_branch(
                hash_tree_root(payload_header.block_number)
                    .unwrap()
                    .0
                    .into(),
                &proof,
                EXECUTION_PAYLOAD_TREE_DEPTH as u32,
                EXECUTION_PAYLOAD_BLOCK_NUMBER_LEAF_INDEX as u64,
                root,
            )
            .is_ok());
        }
    }
}
