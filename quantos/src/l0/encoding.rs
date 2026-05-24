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
            ChainFamily::Near => EncodingFormat::JsonGeneric,
            ChainFamily::Ton => EncodingFormat::JsonGeneric,
            ChainFamily::Bitcoin => EncodingFormat::JsonGeneric,
            ChainFamily::Substrate => EncodingFormat::JsonGeneric,
            ChainFamily::Cardano => EncodingFormat::JsonGeneric,
            ChainFamily::Custom => EncodingFormat::JsonGeneric,
        }
    }
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
        let envelope = ProofEnvelope {
            family: family_tag(adapter.family).to_string(),
            chain_id: adapter.id.as_str().to_string(),
            chain_magic: adapter.chain_magic,
            proof_hash: proof.proof_hash(),
            proof: proof.clone(),
        };

        let payload = serde_json::to_vec(&envelope)
            .map_err(|e| L0Error::Encoding(format!("json: {e}")))?;

        Ok(EncodedProof {
            proof_hash: envelope.proof_hash,
            payload,
            format,
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
        ChainFamily::Custom => "custom",
    }
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
