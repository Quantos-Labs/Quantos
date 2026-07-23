// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! PQCGuard — on-chain gate helper for EVM targets.
//!
//! This module bridges the Quantos STARK prover to the `PQCGuard.sol`
//! contract.  It does **not** verify ML-DSA-65 directly on the EVM;
//! instead it produces a 32-byte STARK commitment that `PQCGuard.sol`
//! checks with a cheap SLOAD (~20 k gas).
//!
//! ## Pipeline
//!
//! ```text
//!   ┌──────────────┐    ┌──────────────┐    ┌─────────────────────┐
//!   │  ML-DSA-65   │───▶│  STARK proof │───▶│  PQCGuard.sol       │
//!   │  verification│    │  (1 signer)  │    │  registerCommitment │
//!   │  (native)    │    │  commitment  │    │  verifyAction       │
//!   └──────────────┘    └──────────────┘    └─────────────────────┘
//! ```

use crate::crypto::{CryptoError, CryptoResult};
use crate::l0::stark_prover::{BatchPublicInputs, SignerInput, StarkBatchProof, prove_batch, verify_batch};
use sha3::{Digest, Sha3_256};
use tiny_keccak::{Hasher, Keccak};

/// Prove that a single PQC signature is valid and bind it to a STARK
/// commitment that `PQCGuard.sol` can verify on-chain.
///
/// # Arguments
/// * `pubkey`   — 32-byte validator public key (ML-DSA-65).
/// * `message`  — the canonical message that was signed.
/// * `signature` — the raw ML-DSA-65 detached signature bytes.
/// * `stake`    — stake weight of this validator.
///
/// # Returns
/// A [`StarkBatchProof`] whose `commitment` field is what the Solidity
/// contract stores and checks.
pub fn prove_single_action(
    pubkey: &[u8; 32],
    message: &[u8],
    signature: &[u8],
    stake: u128,
) -> CryptoResult<StarkBatchProof> {
    let sig_commitment = SignerInput::build_commitment(pubkey, message, signature);

    let signer = SignerInput {
        validator_index: 0,
        stake,
        sig_commitment,
        is_signer: true,
    };

    let pub_inputs = BatchPublicInputs {
        validator_set_root: *pubkey, // single-signer set = pubkey itself
        message_hash: {
            let mut h = [0u8; 32];
            let mut hasher = Sha3_256::new();
            hasher.update(message);
            h.copy_from_slice(&hasher.finalize());
            h
        },
        signed_stake: stake,
        stake_threshold: stake, // single signer meets its own threshold
        signer_count: 1,
    };

    prove_batch(&[signer], pub_inputs)
        .map_err(|e| CryptoError::HashError(format!("STARK single-prove: {e}")))
}

/// Verify a [`StarkBatchProof`] off-chain before posting it on-chain.
pub fn verify_single_action(stark_proof: &StarkBatchProof) -> CryptoResult<bool> {
    verify_batch(stark_proof)
        .map_err(|e| CryptoError::HashError(format!("STARK single-verify: {e}")))
}

// ── EVM calldata encoding ──────────────────────────────────────────────────

/// Selector for `registerCommitment(bytes32)` — first 4 bytes of
/// `keccak256("registerCommitment(bytes32)")`.
/// Computed off-line with `cast sig "registerCommitment(bytes32)"`.
pub const REGISTER_SELECTOR: [u8; 4] = [0xd9, 0xe3, 0x14, 0xd8];

/// Selector for `verifyAction(bytes32,bytes32)` — first 4 bytes of
/// `keccak256("verifyAction(bytes32,bytes32)")`.
/// Computed off-line with `cast sig "verifyAction(bytes32,bytes32)"`.
pub const VERIFY_SELECTOR: [u8; 4] = [0xa7, 0x71, 0xa9, 0xc1];

/// Encode a call to `PQCGuard.registerCommitment(commitment)`.
///
/// Calldata layout:
/// ```text
/// 0x00..0x03  selector (4 bytes)
/// 0x04..0x23  commitment (32 bytes, left-padded to 32-byte word)
/// ```
pub fn encode_evm_register_calldata(commitment: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(&REGISTER_SELECTOR);
    out.extend_from_slice(commitment);
    out
}

/// Encode a call to `PQCGuard.verifyAction(actionHash, commitment)`.
///
/// Calldata layout:
/// ```text
/// 0x00..0x03  selector (4 bytes)
/// 0x04..0x23  actionHash (32 bytes)
/// 0x24..0x43  commitment (32 bytes)
/// ```
pub fn encode_evm_verify_calldata(
    action_hash: &[u8; 32],
    commitment: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 + 32);
    out.extend_from_slice(&VERIFY_SELECTOR);
    out.extend_from_slice(action_hash);
    out.extend_from_slice(commitment);
    out
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ml_dsa::MlDsa65Keypair;

    #[test]
    #[ignore = "slow: STARK proving takes ~15s in debug builds"]
    fn test_prove_and_verify_single_action() {
        let kp = MlDsa65Keypair::generate().expect("keygen failed");
        let message = b"hello pqc guard";
        let sig = kp.sign(message).expect("sign failed");

        let proof = prove_single_action(
            &kp.public_key_bytes(),
            message,
            &sig,
            1_000_000,
        )
        .expect("prove failed");

        let valid = verify_single_action(&proof).expect("verify failed");
        assert!(valid, "STARK proof for single action must be valid");
        assert_ne!(proof.commitment, [0u8; 32], "commitment must be non-zero");
    }

    #[test]
    fn test_register_calldata_encoding() {
        let c = [0xABu8; 32];
        let calldata = encode_evm_register_calldata(&c);
        assert_eq!(calldata.len(), 36);
        assert_eq!(&calldata[0..4], &REGISTER_SELECTOR);
        assert_eq!(&calldata[4..36], &c);
    }

    #[test]
    fn test_verify_calldata_encoding() {
        let a = [0xCDu8; 32];
        let c = [0xEFu8; 32];
        let calldata = encode_evm_verify_calldata(&a, &c);
        assert_eq!(calldata.len(), 68);
        assert_eq!(&calldata[0..4], &VERIFY_SELECTOR);
        assert_eq!(&calldata[4..36], &a);
        assert_eq!(&calldata[36..68], &c);
    }

    #[test]
    fn test_selector_matches_solidity() {
        // Sanity: recompute selectors from strings with keccak256 at runtime
        // and compare with the hard-coded constants.
        let register_sig = b"registerCommitment(bytes32)";
        let verify_sig = b"verifyAction(bytes32,bytes32)";

        let mut reg_hash = [0u8; 32];
        let mut hasher = Keccak::v256();
        hasher.update(register_sig);
        hasher.finalize(&mut reg_hash);
        assert_eq!(&reg_hash[..4], &REGISTER_SELECTOR[..]);

        let mut ver_hash = [0u8; 32];
        let mut hasher = Keccak::v256();
        hasher.update(verify_sig);
        hasher.finalize(&mut ver_hash);
        assert_eq!(&ver_hash[..4], &VERIFY_SELECTOR[..]);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Attestor set — the QTS economic anchor for PQC-Guard
// ═══════════════════════════════════════════════════════════════════════════

/// PQC-Guard attestor set, finalized on Quantos and exported to target chains.
///
/// This is the Quantos-side source of truth that makes Quantos NON-OPTIONAL to
/// PQC-Guard: an attestor is a Quantos validator staking QTS. Their membership
/// and Winternitz (WOTS) commitment roots are committed into a keccak256 Merkle
/// tree whose root is delivered to EVM chains inside an L0 finality proof. The
/// EVM `StakeAttestationVerifier` checks membership against this exact root.
///
/// All hashing uses **keccak256** (not SHA3-256) to match the EVM contracts
/// bit-for-bit. The encodings mirror `src/lib/WOTS.sol`, `src/lib/AttestorSet.sol`
/// and `src/lib/MerkleOTS`.
///
/// POC / TESTNET ONLY. // AUDIT REQUIRED
pub mod attestor_set {
    use tiny_keccak::{Hasher, Keccak};

    /// Winternitz parameter (matches WOTS.sol).
    pub const W: usize = 16;
    /// Number of hash chains per WOTS key (64 message + 3 checksum).
    pub const WOTS_LEN: usize = 67;

    /// keccak256 of arbitrary bytes (EVM-compatible).
    pub fn keccak256(data: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut h = Keccak::v256();
        h.update(data);
        h.finalize(&mut out);
        out
    }

    /// keccak256 of the concatenation of two 32-byte words (Merkle node).
    fn keccak_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut h = Keccak::v256();
        h.update(a);
        h.update(b);
        h.finalize(&mut out);
        out
    }

    /// Expand a 32-byte digest into 64 message + 3 checksum base-16 digits.
    /// Mirrors `WOTS.digits` in Solidity exactly.
    pub fn wots_digits(digest: &[u8; 32]) -> [u8; WOTS_LEN] {
        let mut d = [0u8; WOTS_LEN];
        let mut csum: usize = 0;
        for i in 0..32 {
            let b = digest[i];
            let hi = b >> 4;
            let lo = b & 0x0f;
            d[2 * i] = hi;
            d[2 * i + 1] = lo;
            csum += (W - 1) - hi as usize;
            csum += (W - 1) - lo as usize;
        }
        d[64] = ((csum >> 8) & 0x0f) as u8;
        d[65] = ((csum >> 4) & 0x0f) as u8;
        d[66] = (csum & 0x0f) as u8;
        d
    }

    /// Recompute the compressed WOTS public key implied by `sig` over `digest`.
    /// Mirrors `WOTS.pubKeyFromSig`.
    pub fn wots_pub_from_sig(digest: &[u8; 32], sig: &[[u8; 32]]) -> [u8; 32] {
        assert_eq!(sig.len(), WOTS_LEN, "WOTS: bad signature length");
        let d = wots_digits(digest);
        let mut concat = Vec::with_capacity(WOTS_LEN * 32);
        for i in 0..WOTS_LEN {
            let mut x = sig[i];
            let mut j = d[i] as usize;
            while j < W - 1 {
                x = keccak256(&x);
                j += 1;
            }
            concat.extend_from_slice(&x);
        }
        keccak256(&concat)
    }

    /// Domain-separated WOTS Merkle leaf (mirrors `MerkleOTS.leaf`).
    pub fn wots_merkle_leaf(wots_pub: &[u8; 32]) -> [u8; 32] {
        let mut data = Vec::with_capacity(14 + 32);
        data.extend_from_slice(b"PQCG_WOTS_LEAF");
        data.extend_from_slice(wots_pub);
        keccak256(&data)
    }

    /// Recompute a Merkle root from a leaf, its index and path (mirrors
    /// `MerkleOTS.rootFromLeaf`: index-addressed, keccak(left,right)).
    pub fn merkle_root_from_leaf(leaf: &[u8; 32], index: u64, path: &[[u8; 32]]) -> [u8; 32] {
        let mut h = *leaf;
        let mut idx = index;
        for sibling in path {
            if idx & 1 == 0 {
                h = keccak_pair(&h, sibling);
            } else {
                h = keccak_pair(sibling, &h);
            }
            idx >>= 1;
        }
        h
    }

    /// Domain-separated attestor-set leaf (mirrors `AttestorSet.leaf`).
    pub fn attestor_leaf(attestor_id: &[u8; 32], wots_root: &[u8; 32]) -> [u8; 32] {
        let mut data = Vec::with_capacity(18 + 32 + 32);
        data.extend_from_slice(b"PQCG_ATTESTOR_LEAF");
        data.extend_from_slice(attestor_id);
        data.extend_from_slice(wots_root);
        keccak256(&data)
    }

    /// A single attestor = a Quantos validator opted into PQC-Guard duty.
    #[derive(Clone, Debug)]
    pub struct Attestor {
        /// 32-byte Quantos validator address (distinctness key on the EVM side).
        pub id: [u8; 32],
        /// Committed WOTS Merkle tree root for this attestor's one-time keys.
        pub wots_root: [u8; 32],
        /// QTS staked behind this attestor (the slashable security budget).
        pub stake_qts: u128,
        /// Whether the attestor is currently eligible.
        pub active: bool,
        /// Whether the attestor has been slashed (permanently excluded).
        pub slashed: bool,
    }

    /// Error raised by slashing.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum SlashError {
        /// The two digests were identical → not a reuse.
        SameDigest,
        /// A signature/path did not verify against the attestor's root.
        InvalidEvidence,
        /// No such attestor.
        UnknownAttestor,
        /// Attestor already slashed.
        AlreadySlashed,
    }

    /// The finalized attestor set. Produces the root exported via L0.
    #[derive(Clone, Debug, Default)]
    pub struct AttestorSet {
        attestors: Vec<Attestor>,
        /// M in the M-of-N quorum.
        pub threshold: usize,
    }

    impl AttestorSet {
        pub fn new(threshold: usize) -> Self {
            Self { attestors: Vec::new(), threshold }
        }

        /// Register/append an attestor (a staked Quantos validator).
        pub fn add(&mut self, id: [u8; 32], wots_root: [u8; 32], stake_qts: u128) {
            self.attestors.push(Attestor {
                id,
                wots_root,
                stake_qts,
                active: true,
                slashed: false,
            });
        }

        /// Active, non-slashed attestors in registration order.
        pub fn active(&self) -> Vec<&Attestor> {
            self.attestors.iter().filter(|a| a.active && !a.slashed).collect()
        }

        /// Total QTS staked behind the active attestor set (security budget).
        pub fn total_stake(&self) -> u128 {
            self.active().iter().fold(0u128, |acc, a| acc.saturating_add(a.stake_qts))
        }

        /// Tree height needed to hold the active leaves (power-of-two padded).
        fn height(n: usize) -> u32 {
            let mut h = 0u32;
            let mut cap = 1usize;
            while cap < n {
                cap <<= 1;
                h += 1;
            }
            h
        }

        /// Build the padded leaf vector (active attestor leaves + zero padding).
        fn leaves(&self) -> Vec<[u8; 32]> {
            let active = self.active();
            let n = active.len().max(1);
            let h = Self::height(n);
            let cap = 1usize << h;
            let mut leaves = Vec::with_capacity(cap);
            for a in &active {
                leaves.push(attestor_leaf(&a.id, &a.wots_root));
            }
            while leaves.len() < cap {
                leaves.push([0u8; 32]); // zero padding
            }
            leaves
        }

        /// Compute the attestor-set Merkle root exported to target chains.
        pub fn root(&self) -> [u8; 32] {
            let mut level = self.leaves();
            while level.len() > 1 {
                let mut next = Vec::with_capacity(level.len() / 2);
                let mut i = 0;
                while i < level.len() {
                    next.push(keccak_pair(&level[i], &level[i + 1]));
                    i += 2;
                }
                level = next;
            }
            level[0]
        }

        /// Merkle inclusion path for the active attestor at position `index`.
        pub fn inclusion_path(&self, index: usize) -> Vec<[u8; 32]> {
            let mut level = self.leaves();
            let mut path = Vec::new();
            let mut idx = index;
            while level.len() > 1 {
                let sibling = idx ^ 1;
                path.push(level[sibling]);
                let mut next = Vec::with_capacity(level.len() / 2);
                let mut i = 0;
                while i < level.len() {
                    next.push(keccak_pair(&level[i], &level[i + 1]));
                    i += 2;
                }
                level = next;
                idx >>= 1;
            }
            path
        }

        /// Slash an attestor on proof of WOTS one-time reuse (two valid
        /// signatures from the same leaf over different digests). Returns the
        /// QTS amount slashed. Mirrors `AttestorRegistry.slashOnReuse`.
        #[allow(clippy::too_many_arguments)]
        pub fn slash_on_reuse(
            &mut self,
            attestor_id: &[u8; 32],
            leaf_index: u64,
            digest_a: &[u8; 32],
            sig_a: &[[u8; 32]],
            path_a: &[[u8; 32]],
            digest_b: &[u8; 32],
            sig_b: &[[u8; 32]],
            path_b: &[[u8; 32]],
        ) -> Result<u128, SlashError> {
            if digest_a == digest_b {
                return Err(SlashError::SameDigest);
            }
            let pos = self
                .attestors
                .iter()
                .position(|a| &a.id == attestor_id)
                .ok_or(SlashError::UnknownAttestor)?;
            if self.attestors[pos].slashed {
                return Err(SlashError::AlreadySlashed);
            }
            let root = self.attestors[pos].wots_root;

            let root_a = merkle_root_from_leaf(
                &wots_merkle_leaf(&wots_pub_from_sig(digest_a, sig_a)),
                leaf_index,
                path_a,
            );
            let root_b = merkle_root_from_leaf(
                &wots_merkle_leaf(&wots_pub_from_sig(digest_b, sig_b)),
                leaf_index,
                path_b,
            );
            if root_a != root || root_b != root {
                return Err(SlashError::InvalidEvidence);
            }

            let slashed = self.attestors[pos].stake_qts;
            self.attestors[pos].stake_qts = 0;
            self.attestors[pos].slashed = true;
            self.attestors[pos].active = false;
            Ok(slashed)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Deterministic WOTS keygen for tests (mirrors WOTSSigner.sol).
        fn wots_sk(seed: &[u8; 32], leaf_index: u64, chain: usize) -> [u8; 32] {
            let mut data = Vec::new();
            data.extend_from_slice(b"PQCG_WOTS_SK");
            data.extend_from_slice(seed);
            // Solidity packs leafIndex and chain as uint256 (32 bytes each).
            let mut li = [0u8; 32];
            li[24..].copy_from_slice(&leaf_index.to_be_bytes());
            data.extend_from_slice(&li);
            let mut ci = [0u8; 32];
            ci[24..].copy_from_slice(&(chain as u64).to_be_bytes());
            data.extend_from_slice(&ci);
            keccak256(&data)
        }

        fn wots_sign(seed: &[u8; 32], leaf_index: u64, digest: &[u8; 32]) -> Vec<[u8; 32]> {
            let d = wots_digits(digest);
            let mut sig = Vec::with_capacity(WOTS_LEN);
            for i in 0..WOTS_LEN {
                let mut x = wots_sk(seed, leaf_index, i);
                for _ in 0..d[i] {
                    x = keccak256(&x);
                }
                sig.push(x);
            }
            sig
        }

        fn wots_root_single(seed: &[u8; 32], leaf_index: u64) -> [u8; 32] {
            // Single-leaf "tree": root == the WOTS merkle leaf itself (height 0).
            let mut ends: Vec<u8> = Vec::with_capacity(WOTS_LEN * 32);
            for i in 0..WOTS_LEN {
                let mut x = wots_sk(seed, leaf_index, i);
                for _ in 0..(W - 1) {
                    x = keccak256(&x);
                }
                ends.extend_from_slice(&x);
            }
            let wots_pub = keccak256(&ends);
            wots_merkle_leaf(&wots_pub)
        }

        #[test]
        fn test_wots_roundtrip() {
            let seed = [7u8; 32];
            let digest = keccak256(b"hello pqc");
            let sig = wots_sign(&seed, 0, &digest);
            let pubk = wots_pub_from_sig(&digest, &sig);
            // Recompute expected pub directly.
            let mut ends: Vec<u8> = Vec::new();
            for i in 0..WOTS_LEN {
                let mut x = wots_sk(&seed, 0, i);
                for _ in 0..(W - 1) {
                    x = keccak256(&x);
                }
                ends.extend_from_slice(&x);
            }
            assert_eq!(pubk, keccak256(&ends), "WOTS pubkey mismatch");
        }

        #[test]
        fn test_attestor_set_root_deterministic() {
            let mut set = AttestorSet::new(2);
            set.add([1u8; 32], [0xaa; 32], 1000);
            set.add([2u8; 32], [0xbb; 32], 2000);
            let r1 = set.root();
            let r2 = set.root();
            assert_eq!(r1, r2, "root must be deterministic");
            assert_eq!(set.total_stake(), 3000);
        }

        #[test]
        fn test_inclusion_path_verifies() {
            let mut set = AttestorSet::new(2);
            set.add([1u8; 32], [0xaa; 32], 1000);
            set.add([2u8; 32], [0xbb; 32], 2000);
            set.add([3u8; 32], [0xcc; 32], 3000);

            let root = set.root();
            let active = set.active();
            for (i, a) in active.iter().enumerate() {
                let leaf = attestor_leaf(&a.id, &a.wots_root);
                let path = set.inclusion_path(i);
                let recomputed = merkle_root_from_leaf(&leaf, i as u64, &path);
                assert_eq!(recomputed, root, "inclusion proof must verify for {i}");
            }
        }

        #[test]
        fn test_slash_on_reuse_detects_fraud() {
            // Build an attestor whose wots_root is a height-0 tree (single leaf).
            let seed = [9u8; 32];
            let leaf_index = 0u64;
            let wots_root = wots_root_single(&seed, leaf_index);

            let mut set = AttestorSet::new(1);
            let id = [42u8; 32];
            set.add(id, wots_root, 5000);

            let digest_a = keccak256(b"message A");
            let digest_b = keccak256(b"message B");
            let sig_a = wots_sign(&seed, leaf_index, &digest_a);
            let sig_b = wots_sign(&seed, leaf_index, &digest_b);
            let empty: Vec<[u8; 32]> = Vec::new();

            let slashed = set
                .slash_on_reuse(&id, leaf_index, &digest_a, &sig_a, &empty, &digest_b, &sig_b, &empty)
                .expect("reuse must be slashable");
            assert_eq!(slashed, 5000);
            assert!(set.active().is_empty(), "slashed attestor excluded");
        }

        #[test]
        fn test_slash_same_digest_rejected() {
            let seed = [9u8; 32];
            let wots_root = wots_root_single(&seed, 0);
            let mut set = AttestorSet::new(1);
            let id = [42u8; 32];
            set.add(id, wots_root, 5000);
            let digest = keccak256(b"same");
            let sig = wots_sign(&seed, 0, &digest);
            let empty: Vec<[u8; 32]> = Vec::new();
            let err = set
                .slash_on_reuse(&id, 0, &digest, &sig, &empty, &digest, &sig, &empty)
                .unwrap_err();
            assert_eq!(err, SlashError::SameDigest);
        }
    }
}
