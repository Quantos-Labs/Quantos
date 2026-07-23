// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! Domain separation tags for all signed messages in Quantos.
//!
//! Every distinct message type gets a unique, versioned ASCII tag. Each
//! `signing_data()` call prepends:
//!
//! ```text
//! [tag length as u16 LE] || [tag bytes] || [message bytes]
//! ```
//!
//! This encoding is prefix-free: no two distinct `(domain, message)` pairs
//! produce the same byte sequence, preventing cross-context signature reuse.

/// Prepends a domain tag to raw message bytes.
///
/// The 2-byte length prefix ensures unambiguous parsing regardless of tag length.
#[inline]
pub fn with_domain(domain: &[u8], message: &[u8]) -> Vec<u8> {
    debug_assert!(domain.len() <= u16::MAX as usize, "domain tag too long");
    let mut out = Vec::with_capacity(2 + domain.len() + message.len());
    out.extend_from_slice(&(domain.len() as u16).to_le_bytes());
    out.extend_from_slice(domain);
    out.extend_from_slice(message);
    out
}

// ── Signing domains ───────────────────────────────────────────────────────────

/// ML-DSA-65 signatures over user transactions.
pub const DOMAIN_TX: &[u8] = b"QUANTOS_TX_V1";

/// ML-DSA-65 signatures over DAG vertices.
pub const DOMAIN_VERTEX: &[u8] = b"QUANTOS_VERTEX_V1";

/// ML-DSA-65 signatures over committee votes.
pub const DOMAIN_COMMITTEE_VOTE: &[u8] = b"QUANTOS_COMMITTEE_VOTE_V1";

/// ML-DSA-65 signatures over finality checkpoints.
pub const DOMAIN_CHECKPOINT: &[u8] = b"QUANTOS_CHECKPOINT_V1";

/// ML-DSA-65 signatures over view-change messages.
pub const DOMAIN_VIEW_CHANGE: &[u8] = b"QUANTOS_VIEW_CHANGE_V1";

/// ML-DSA-65 signatures over pipelined proposal votes.
pub const DOMAIN_PIPELINE_VOTE: &[u8] = b"QUANTOS_PIPELINE_VOTE_V1";

// ── VRF internal domains (never used as transaction signing domains) ──────────

/// Derives the per-keypair PRF key from raw secret key bytes.
pub const DOMAIN_VRF_PRF: &[u8] = b"QUANTOS_VRF_PRF_V1";

/// Derives the deterministic VRF output beta from (prf_key, seed).
pub const DOMAIN_VRF_OUTPUT: &[u8] = b"QUANTOS_VRF_OUTPUT_V1";

/// Prefixes the message signed as the VRF proof: (seed ‖ beta).
pub const DOMAIN_VRF_PROVE: &[u8] = b"QUANTOS_VRF_PROVE_V1";

// ── Cross-shard atomic protocol domains ──────────────────────────────────────

/// ML-DSA-65 signatures over CSAP lock-vote messages.
pub const DOMAIN_CSAP_VOTE: &[u8] = b"QUANTOS_CSAP_VOTE_V1";

/// ML-DSA-65 signatures over CSAP lock-acknowledgment messages.
pub const DOMAIN_CSAP_ACK: &[u8] = b"QUANTOS_CSAP_ACK_V1";

// ── Slashing evidence domains ─────────────────────────────────────────────────

/// Message prefix for double-signing evidence signatures.
pub const DOMAIN_SLASH_DOUBLE_SIGN: &[u8] = b"QUANTOS_SLASH_DS_V1";

/// Message prefix for equivocation evidence signatures.
pub const DOMAIN_SLASH_EQUIVOC: &[u8] = b"QUANTOS_SLASH_EQ_V1";

/// Message prefix for invalid-block proposer signatures.
pub const DOMAIN_SLASH_INVALID_BLOCK: &[u8] = b"QUANTOS_SLASH_IBLOCK_V1";

/// Message prefix for proven front-running (accountable leader order violation).
pub const DOMAIN_SLASH_FRONT_RUN: &[u8] = b"QUANTOS_SLASH_FRUN_V1";

// ── Network / transport binding (not transaction signatures) ─────────────────

/// Binds a ML-DSA-65 public key to a Quantos network PeerId preimage (SHA-256 multihash).
pub const DOMAIN_PQ_PEER_ID: &[u8] = b"QUANTOS_PQ_PEER_ID_V1";

/// Prefix for ML-DSA-65 signatures over PQ-KEM handshake transcripts.
pub const DOMAIN_PQ_KEM_HANDSHAKE: &[u8] = b"QUANTOS_PQ_KEM_HS_V1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_with_domain_no_collision() {
        let msg = b"hello";
        let a = with_domain(DOMAIN_TX, msg);
        let b = with_domain(DOMAIN_VERTEX, msg);
        let c = with_domain(DOMAIN_CHECKPOINT, msg);
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn test_domain_uniqueness() {
        let all: &[&[u8]] = &[
            DOMAIN_TX,
            DOMAIN_VERTEX,
            DOMAIN_COMMITTEE_VOTE,
            DOMAIN_CHECKPOINT,
            DOMAIN_VIEW_CHANGE,
            DOMAIN_PIPELINE_VOTE,
            DOMAIN_VRF_PRF,
            DOMAIN_VRF_OUTPUT,
            DOMAIN_VRF_PROVE,
            DOMAIN_CSAP_VOTE,
            DOMAIN_CSAP_ACK,
            DOMAIN_SLASH_DOUBLE_SIGN,
            DOMAIN_SLASH_EQUIVOC,
            DOMAIN_SLASH_INVALID_BLOCK,
            DOMAIN_SLASH_FRONT_RUN,
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "domains[{}] == domains[{}]", i, j);
            }
        }
    }
}
