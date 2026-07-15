//! Per-target canonical encoding for [`L0FinalityProof`].
//!
//! Each target chain consumes proofs in a slightly different shape:
//!
//! * EVM contracts prefer ABI-encoded structs.
//! * Solana programs expect bincode-friendly little-endian byte streams.
//! * Tron / TVM looks like EVM but uses Base58 addresses.
//! * Stellar / Soroban expects XDR.
//! * Move chains (Aptos, Sui) speak BCS.
//! * Cosmos consumers usually expect protobuf.
//!
//! Rather than dragging every codec into the core crate, we standardize
//! on **serde JSON** as a stable, debuggable transport and let the
//! relayer side handle any final transformation specific to the target.
//!
//! The encoded payload is wrapped in [`EncodedProof`] which carries the
//! canonical hash of the proof to make integrity checks trivial.

use serde::{Deserialize, Serialize};

use crate::l0::error::{L0Error, L0Result};
use crate::l0::proof::L0FinalityProof;
use crate::l0::registry::{ChainAdapter, ChainFamily};
use crate::types::Hash;

/// On-the-wire format used by an encoded proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EncodingFormat {
    /// Compact JSON intended for EVM/EVM-like consumers.
    JsonEvm,
    /// Compact JSON intended for SVM (Solana) consumers.
    JsonSvm,
    /// Compact JSON intended for TVM (Tron) consumers.
    JsonTvm,
    /// Compact JSON wrapped for Stellar / Soroban.
    JsonStellar,
    /// Compact JSON wrapped for Move chains (Aptos, Sui).
    JsonMove,
    /// Compact JSON wrapped for Cosmos consumers.
    JsonCosmos,
    /// Compact JSON wrapped for Ripple (XRPL) consumers.
    JsonRipple,
    /// Catch-all: the proof is serialized as compact JSON without any
    /// chain-specific framing.
    JsonGeneric,
}

impl EncodingFormat {
    /// Selects the encoding flavor that matches the family of a chain.
    pub fn for_family(family: ChainFamily) -> Self {
        match family {
            ChainFamily::Evm => EncodingFormat::JsonEvm,
            ChainFamily::Svm => EncodingFormat::JsonSvm,
            ChainFamily::Tvm => EncodingFormat::JsonTvm,
            ChainFamily::Stellar => EncodingFormat::JsonStellar,
            ChainFamily::Move => EncodingFormat::JsonMove,
            ChainFamily::Cosmos => EncodingFormat::JsonCosmos,
            ChainFamily::Ripple => EncodingFormat::JsonRipple,
            ChainFamily::Icp => EncodingFormat::JsonGeneric,
            ChainFamily::Algorand => EncodingFormat::JsonGeneric,
            ChainFamily::Hedera => EncodingFormat::JsonGeneric,
            ChainFamily::Canton => EncodingFormat::JsonGeneric,
            ChainFamily::Near => EncodingFormat::JsonGeneric,
            ChainFamily::Ton => EncodingFormat::JsonGeneric,
            ChainFamily::Bitcoin => EncodingFormat::JsonGeneric,
            ChainFamily::Substrate => EncodingFormat::JsonGeneric,
            ChainFamily::Cardano => EncodingFormat::JsonGeneric,
            ChainFamily::Tezos => EncodingFormat::JsonGeneric,
            ChainFamily::Custom => EncodingFormat::JsonGeneric,
        }
    }
}

/// Pre-computed EVM calldata for on-chain submission.
/// Allows the relay receiver to call both verifier contracts
/// without re-parsing the full proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvmCalldata {
    /// Calldata for QuantosL0Verifier.verifyProof() or finalizeBlock().
    pub l0_verifier_calldata: String,
    /// Calldata for QuantosStarkVerifier.submitCommitment().
    /// None if the proof has no STARK commitment.
    pub stark_verifier_calldata: Option<String>,
    /// 32-byte STARK commitment (hex) for reference.
    pub stark_commitment: String,
}

/// Output of an encoding step, ready to ship to a target.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncodedProof {
    /// Hash of the proof bytes that were committed to.
    pub proof_hash: Hash,
    /// Encoded payload bytes.
    pub payload: Vec<u8>,
    /// Encoding format used for the payload.
    pub format: EncodingFormat,
    /// Pre-computed EVM calldata (EVM chains only).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub evm_calldata: Option<EvmCalldata>,
}

/// Stateless encoder that turns proofs into chain-flavored payloads.
#[derive(Clone, Debug, Default)]
pub struct CanonicalEncoder;

impl CanonicalEncoder {
    /// Creates a new encoder. No internal state, this is just a marker
    /// type for namespace clarity.
    pub fn new() -> Self {
        Self
    }

    /// Encodes a proof for the given adapter.
    pub fn encode(
        &self,
        proof: &L0FinalityProof,
        adapter: &ChainAdapter,
    ) -> L0Result<EncodedProof> {
        let format = EncodingFormat::for_family(adapter.family);
        let proof_hash = proof.proof_hash();
        let envelope = ProofEnvelope {
            family: family_tag(adapter.family).to_string(),
            chain_id: adapter.id.as_str().to_string(),
            chain_magic: adapter.chain_magic,
            proof_hash,
            proof: proof.clone(),
        };

        let payload = serde_json::to_vec(&envelope)
            .map_err(|e| L0Error::Encoding(format!("json: {e}")))?;

        // For EVM chains, pre-compute calldata for both verifier contracts so
        // the relay receiver can submit on-chain without re-parsing the proof.
        let evm_calldata = if adapter.family == crate::l0::registry::ChainFamily::Evm {
            Some(build_evm_calldata(proof, &proof_hash))
        } else {
            None
        };

        Ok(EncodedProof {
            proof_hash,
            payload,
            format,
            evm_calldata,
        })
    }

    /// Decodes a payload previously produced by [`CanonicalEncoder::encode`].
    /// Mainly useful for off-chain verifiers and tests.
    pub fn decode(&self, payload: &[u8]) -> L0Result<L0FinalityProof> {
        let envelope: ProofEnvelope = serde_json::from_slice(payload)
            .map_err(|e| L0Error::Encoding(format!("json: {e}")))?;
        Ok(envelope.proof)
    }
}

#[derive(Serialize, Deserialize)]
struct ProofEnvelope {
    family: String,
    chain_id: String,
    chain_magic: u64,
    #[serde(with = "hex_array")]
    proof_hash: Hash,
    proof: L0FinalityProof,
}

fn family_tag(family: ChainFamily) -> &'static str {
    match family {
        ChainFamily::Evm => "evm",
        ChainFamily::Svm => "svm",
        ChainFamily::Tvm => "tvm",
        ChainFamily::Stellar => "stellar",
        ChainFamily::Move => "move",
        ChainFamily::Cosmos => "cosmos",
        ChainFamily::Near => "near",
        ChainFamily::Ton => "ton",
        ChainFamily::Bitcoin => "bitcoin",
        ChainFamily::Substrate => "substrate",
        ChainFamily::Cardano => "cardano",
        ChainFamily::Tezos => "tezos",
        ChainFamily::Ripple => "ripple",
        ChainFamily::Icp => "icp",
        ChainFamily::Algorand => "algorand",
        ChainFamily::Hedera => "hedera",
        ChainFamily::Canton => "canton",
        ChainFamily::Custom => "custom",
    }
}

/// Pre-compute EVM calldata for QuantosL0Verifier.verifyProof() and
/// QuantosStarkVerifier.submitCommitment() from an L0FinalityProof.
///
/// Encoding: 4-byte Keccak selector (first 4 bytes of keccak256(signature))
/// followed by ABI-packed arguments.  The relay receiver submits two txs:
///   tx1 → l0_verifier_calldata  to QuantosL0Verifier
///   tx2 → stark_verifier_calldata to QuantosStarkVerifier (if STARK present)
fn build_evm_calldata(proof: &L0FinalityProof, proof_hash: &[u8; 32]) -> EvmCalldata {
    use sha3::{Digest, Keccak256};

    // ── verifyProof(bytes32,bytes32,uint128,uint64,uint64,bytes32,string,bytes32,uint128) ──
    // selector = keccak256("verifyProof(bytes32,bytes32,uint128,uint64,uint64,bytes32,string,bytes32,uint128)")[0..4]
    let l0_sig = b"verifyProof(bytes32,bytes32,uint128,uint64,uint64,bytes32,string,bytes32,uint128)";
    let selector_l0: [u8; 4] = Keccak256::digest(l0_sig)[..4].try_into().unwrap_or([0u8; 4]);

    // Pack args (ABI encoding — all fixed-size except string chainId):
    // proofHash(32) | validatorSetRoot(32) | signedStake(16, left-padded 32)
    // | epoch(8, left-padded 32) | slot(8, left-padded 32)
    // | stateRoot(32) | chainId_offset(32) | parentBlockHash(32)
    // | chainWork(16, left-padded 32) | chainId_len(32) | chainId_bytes(padded)
    let chain_id_bytes = proof.header.external_chain
        .as_ref()
        .map(|c| c.as_str().as_bytes().to_vec())
        .unwrap_or_else(|| b"quantos".to_vec());

    let signed_stake = proof.signed_stake();
    let mut l0_data = selector_l0.to_vec();
    l0_data.extend_from_slice(proof_hash);
    l0_data.extend_from_slice(&proof.header.validator_set_root);
    l0_data.extend_from_slice(&pad32_u128(signed_stake));
    l0_data.extend_from_slice(&pad32_u64(proof.header.epoch));
    l0_data.extend_from_slice(&pad32_u64(proof.header.slot));
    l0_data.extend_from_slice(&proof.header.state_root);
    // dynamic string offset (9 fixed params × 32 = 288 = 0x120)
    l0_data.extend_from_slice(&pad32_u64(9 * 32));
    l0_data.extend_from_slice(&proof.header.parent_block_hash);
    l0_data.extend_from_slice(&pad32_u128(proof.header.chain_work));
    // chain_id string: length then padded bytes
    l0_data.extend_from_slice(&pad32_u64(chain_id_bytes.len() as u64));
    let padded_len = ((chain_id_bytes.len() + 31) / 32) * 32;
    let mut padded_chain = chain_id_bytes.clone();
    padded_chain.resize(padded_len, 0);
    l0_data.extend_from_slice(&padded_chain);

    // ── submitCommitment(bytes32,bytes32,bytes32,uint128,uint128,uint32,bytes32) ──
    let stark_calldata = if proof.header.stark_commitment != [0u8; 32] {
        let sc_sig = b"submitCommitment(bytes32,bytes32,bytes32,uint128,uint128,uint32,bytes32)";
        let selector_sc: [u8; 4] = Keccak256::digest(sc_sig)[..4].try_into().unwrap_or([0u8; 4]);

        let signer_count = proof.signatures.len() as u32;
        let digest = proof.signing_digest();

        let mut sc_data = selector_sc.to_vec();
        sc_data.extend_from_slice(&proof.header.stark_commitment);
        sc_data.extend_from_slice(&proof.header.validator_set_root);
        sc_data.extend_from_slice(&digest);
        sc_data.extend_from_slice(&pad32_u128(signed_stake));
        sc_data.extend_from_slice(&pad32_u128(proof.header.stake_threshold));
        sc_data.extend_from_slice(&pad32_u64(signer_count as u64));
        sc_data.extend_from_slice(proof_hash);
        Some(hex::encode(sc_data))
    } else {
        None
    };

    EvmCalldata {
        l0_verifier_calldata: hex::encode(l0_data),
        stark_verifier_calldata: stark_calldata,
        stark_commitment: hex::encode(proof.header.stark_commitment),
    }
}

fn pad32_u64(v: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[24..].copy_from_slice(&v.to_be_bytes());
    b
}

fn pad32_u128(v: u128) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[16..].copy_from_slice(&v.to_be_bytes());
    b
}

mod hex_array {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}
