use crate::{
    bls::{PublicKey, Signature},
    compute::hash_tree_root,
    errors::Error,
    execution::ExecutionPayload,
    internal_prelude::*,
    sync_protocol::SyncAggregate,
    types::{serde_hex, Bytes32, H256, U64},
};
use sha2::{Digest, Sha256};
use ssz_rs::{Bitlist, Deserialize, List, Sized, Vector};
use ssz_rs_derive::SimpleSerialize;

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#custom-types
pub type Slot = U64;
pub type Epoch = U64;
pub type CommitteeIndex = U64;
pub type ValidatorIndex = U64;
pub type Gwei = U64;
pub type Root = H256;
/// https://github.com/ethereum/consensus-specs/blob/dev/ssz/merkle-proofs.md#generalized-merkle-tree-index
pub type GeneralizedIndex = u64;

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/beacon-chain.md#domain-types
pub const DOMAIN_SYNC_COMMITTEE: DomainType = DomainType([7, 0, 0, 0]);

pub const PUBLIC_KEY_BYTES_LEN: usize = 48;
pub const SIGNATURE_BYTES_LEN: usize = 96;

pub const BLOCK_BODY_EXECUTION_PAYLOAD_INDEX: usize = 9;

#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct Version(#[serde(with = "serde_hex")] pub [u8; 4]);

#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct DomainType(#[serde(with = "serde_hex")] pub [u8; 4]);

#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct ForkDigest(#[serde(with = "serde_hex")] pub [u8; 4]);

#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct Domain(#[serde(with = "serde_hex")] pub [u8; 32]);

#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct ForkData {
    pub current_version: Version,
    pub genesis_validators_root: Root,
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#signingdata
#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct SigningData {
    pub object_root: Root,
    pub domain: Domain,
}

/// Beacon Block Header
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#beaconblockheader
#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct BeaconBlockHeader {
    pub slot: Slot,
    pub proposer_index: ValidatorIndex,
    pub parent_root: Root,
    pub state_root: Root,
    pub body_root: Root,
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
    >,
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#signedbeaconblockheader
#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct SignedBeaconBlockHeader {
    pub message: BeaconBlockHeader,
    pub signature: Signature,
}

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

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#eth1data
#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct Eth1Data {
    pub deposit_root: Root,
    pub deposit_count: U64,
    pub block_hash: H256,
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#proposerslashing
#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct ProposerSlashing {
    pub signed_header_1: SignedBeaconBlockHeader,
    pub signed_header_2: SignedBeaconBlockHeader,
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#attesterslashing
#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct AttesterSlashing<const MAX_VALIDATORS_PER_COMMITTEE: usize> {
    pub attestation_1: IndexedAttestation<MAX_VALIDATORS_PER_COMMITTEE>,
    pub attestation_2: IndexedAttestation<MAX_VALIDATORS_PER_COMMITTEE>,
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#indexedattestation
#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct IndexedAttestation<const MAX_VALIDATORS_PER_COMMITTEE: usize> {
    pub attesting_indices: List<ValidatorIndex, MAX_VALIDATORS_PER_COMMITTEE>,
    pub data: AttestationData,
    pub signature: Signature,
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#attestationdata
#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct AttestationData {
    pub slot: Slot,
    pub index: CommitteeIndex,
    /// LMD GHOST vote
    pub beacon_block_root: Root,
    /// FFG vote
    pub source: Checkpoint,
    pub target: Checkpoint,
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#checkpoint
#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct Checkpoint {
    pub epoch: Epoch,
    pub root: Root,
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#attestation
#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct Attestation<const MAX_VALIDATORS_PER_COMMITTEE: usize> {
    pub aggregation_bits: Bitlist<MAX_VALIDATORS_PER_COMMITTEE>,
    pub data: AttestationData,
    pub signature: Signature,
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#deposit
#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct Deposit<const DEPOSIT_CONTRACT_TREE_DEPTH: usize> {
    /// Merkle path to deposit root
    pub proof: Vector<Bytes32, DEPOSIT_CONTRACT_TREE_DEPTH>,
    pub data: DepositData,
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#depositdata
#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct DepositData {
    pub pubkey: PublicKey,
    pub withdrawal_credentials: Bytes32,
    pub amount: Gwei,
    /// Signing over DepositMessage
    pub signature: Signature,
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#signedvoluntaryexit
#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct SignedVoluntaryExit {
    pub message: VoluntaryExit,
    pub signature: Signature,
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#voluntaryexit
#[derive(
    Clone, Debug, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct VoluntaryExit {
    /// Earliest epoch when voluntary exit can be processed
    pub epoch: Epoch,
    pub validator_index: ValidatorIndex,
}

/// Check if ``leaf`` at ``index`` verifies against the Merkle ``root`` and ``branch``.
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#is_valid_merkle_branch
pub fn is_valid_merkle_branch(leaf: H256, branch: &[H256], index: u64, root: Root) -> bool {
    let mut value = leaf;
    for (i, b) in branch.iter().enumerate() {
        if let Some(v) = 2u64.checked_pow(i as u32) {
            if index / v % 2 == 1 {
                value = hash([b.as_bytes(), value.as_bytes()].concat());
            } else {
                value = hash([value.as_bytes(), b.as_bytes()].concat());
            }
        } else {
            return false;
        }
    }
    value == root
}

pub fn hash(bz: Vec<u8>) -> H256 {
    let mut output = H256::default();
    output.0.copy_from_slice(Sha256::digest(bz).as_slice());
    output
}

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
        SYNC_COMMITTEE_SIZE,
    >,
) -> Result<(Root, Vec<H256>), Error> {
    let tree = rs_merkle::MerkleTree::<rs_merkle::algorithms::Sha256>::from_leaves(&[
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
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
    ]);
    Ok((
        H256(tree.root().unwrap()),
        tree.proof(&[9])
            .proof_hashes()
            .into_iter()
            .map(|h| H256::from_slice(h))
            .collect(),
    ))
}

#[cfg(test)]
mod test {
    use super::BeaconBlockHeader;
    use rs_merkle::algorithms::Sha256;
    use rs_merkle::MerkleProof;
    use ssz_rs::Merkleized;
    use std::fs;

    use crate::errors::Error;
    use crate::{beacon::Root, compute::hash_tree_root, types::H256};

    #[test]
    fn beacon_block_serialization() {
        use crate::{
            beacon::{gen_execution_payload_proof, is_valid_merkle_branch},
            execution::{
                gen_execution_payload_fields_proof, EXECUTION_PAYLOAD_BLOCK_NUMBER_INDEX,
                EXECUTION_PAYLOAD_STATE_ROOT_INDEX,
            },
        };
        let mut header: BeaconBlockHeader =
            serde_json::from_str(&fs::read_to_string("./data/goerli_header_4825088.json").unwrap())
                .unwrap();

        let mut block: crate::preset::mainnet::BeaconBlock =
            serde_json::from_str(&fs::read_to_string("./data/goerli_block_4825088.json").unwrap())
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
            9,
            block_root
        ));

        let (root, proof) = gen_execution_payload_fields_proof(
            &payload_header,
            &[
                EXECUTION_PAYLOAD_STATE_ROOT_INDEX,
                EXECUTION_PAYLOAD_BLOCK_NUMBER_INDEX,
            ],
        )
        .unwrap();
        assert_eq!(root.as_bytes(), payload_root.as_bytes());

        assert!(is_valid_multiproofs_branch(
            root,
            &proof,
            &[
                EXECUTION_PAYLOAD_STATE_ROOT_INDEX,
                EXECUTION_PAYLOAD_BLOCK_NUMBER_INDEX
            ],
            &[
                hash_tree_root(payload_header.state_root).unwrap().0.into(),
                hash_tree_root(payload_header.block_number)
                    .unwrap()
                    .0
                    .into()
            ]
        )
        .unwrap());
    }

    fn is_valid_multiproofs_branch(
        root: Root,
        proof: &[H256],
        leaf_indices: &[usize],
        leaf_hashes: &[H256],
    ) -> Result<bool, Error> {
        let proof: Vec<[u8; 32]> = proof.iter().map(|h| h.0.clone()).collect();
        let proof = MerkleProof::<Sha256>::new(proof);
        let leaf_hashes: Vec<[u8; 32]> = leaf_hashes.iter().map(|h| h.0.clone()).collect();
        // TODO execution payload specific
        Ok(proof.verify(root.0, leaf_indices, &leaf_hashes, 16))
    }
}
