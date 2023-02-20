use crate::compute::hash_tree_root;
use crate::errors::Error;
use crate::internal_prelude::*;
use crate::types::{ByteList, ByteVector, U256, U64};
use crate::{
    beacon::Root,
    types::{Address, H256},
};
use ssz_rs::{Deserialize, List, Merkleized, Sized};
use ssz_rs_derive::SimpleSerialize;

pub const EXECUTION_PAYLOAD_STATE_ROOT_INDEX: usize = 2;
pub const EXECUTION_PAYLOAD_BLOCK_NUMBER_INDEX: usize = 6;

pub type BlockNumber = U64;

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/bellatrix/beacon-chain.md#executionpayload
#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct ExecutionPayload<
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
    const MAX_BYTES_PER_TRANSACTION: usize,
    const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
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
}

impl<
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
        const MAX_BYTES_PER_TRANSACTION: usize,
        const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
    >
    ExecutionPayload<
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
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
}

pub fn gen_execution_payload_fields_proof<
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
>(
    payload: &ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    leaf_indices: &[usize],
) -> Result<(Root, Vec<H256>), Error> {
    let tree = rs_merkle::MerkleTree::<rs_merkle::algorithms::Sha256>::from_leaves(&[
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
        Default::default(),
        Default::default(),
    ]);
    Ok((
        H256(tree.root().unwrap()),
        tree.proof(leaf_indices)
            .proof_hashes()
            .into_iter()
            .map(|h| H256::from_slice(h))
            .collect(),
    ))
}
