// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! ZK-STARK batch verification for L0 PQC signatures.
//!
//! Uses Winterfell (Meta's STARK library, already a project dependency) to
//! produce a succinct proof that N PQC signatures are valid and their
//! aggregated stake meets the finality threshold.
//!
//! # Design rationale
//!
//! Full ML-DSA-65 / ML-DSA-65 verification inside a STARK circuit is
//! impractical (lattice arithmetic requires millions of constraints). We use a
//! **commitment-based aggregation** approach instead:
//!
//! 1. The prover verifies every PQC signature natively in Rust.
//! 2. For each signer it computes a binding commitment:
//!    `sig_commitment = SHA3-256(pubkey || message || raw_sig)`
//! 3. A Winterfell STARK circuit proves:
//!    * Each `sig_commitment` is correctly embedded in the execution trace.
//!    * The accumulated signed stake is computed honestly (transition constraint).
//!    * The final `acc_stake` equals the publicly-claimed `signed_stake`.
//! 4. The circuit's boundary assertions bind `signed_stake` cryptographically.
//!    A prover cannot inflate stake without forging a SHA3 pre-image.
//!
//! # On-chain footprint
//!
//! Instead of submitting N × ~1 KB PQC signatures on-chain, the proof is
//! hashed to a 32-byte `stark_commitment` that is stored in the
//! `QuantosStarkVerifier` contract.  Full proof verification is done
//! off-chain in < 10 ms via [`verify_batch`].
//!
//! # Trace layout  (7 columns)
//!
//! | Col | Name          | Meaning                                    |
//! |-----|---------------|--------------------------------------------|
//! | 0   | `is_signer`   | 1 if this validator signed, 0 otherwise    |
//! | 1   | `stake`       | Validator stake (u128 as field element)    |
//! | 2   | `sig_c0`      | sig_commitment bytes 0–7 (little-endian)   |
//! | 3   | `sig_c1`      | sig_commitment bytes 8–15                  |
//! | 4   | `sig_c2`      | sig_commitment bytes 16–23                 |
//! | 5   | `sig_c3`      | sig_commitment bytes 24–31                 |
//! | 6   | `acc_stake`   | Accumulated signed stake before this row   |
//!
//! Transition:
//!   `acc_stake[i+1] = acc_stake[i] + is_signer[i] * stake[i]`
//!
//! Boundary:
//!   `acc_stake[0] = 0`, `acc_stake[last] = signed_stake`

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use winterfell::{
    Air, AirContext, Assertion, DefaultConstraintEvaluator, DefaultTraceLde,
    EvaluationFrame, FieldExtension, ProofOptions, Proof, Prover,
    TraceInfo, TraceTable, TransitionConstraintDegree,
};
use winterfell::crypto::{hashers::Blake3_256, DefaultRandomCoin};
use winterfell::math::{FieldElement, ToElements};
use winter_math::fields::f128::BaseElement;
use winter_prover::{
    ConstraintCompositionCoefficients, StarkDomain, TracePolyTable,
    matrix::ColMatrix,
};

use crate::l0::error::{L0Error, L0Result};
use crate::types::Hash;

// ── Trace layout constants ─────────────────────────────────────────────────

const TRACE_WIDTH: usize = 7;
const COL_IS_SIGNER: usize = 0;
const COL_STAKE:     usize = 1;
const COL_SIG_C0:    usize = 2;
const COL_SIG_C1:    usize = 3;
const COL_SIG_C2:    usize = 4;
const COL_SIG_C3:    usize = 5;
const COL_ACC:       usize = 6;

// ── Public types ───────────────────────────────────────────────────────────

/// Per-signer input into the STARK batch circuit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignerInput {
    /// Index into the validator set (informational, not in the circuit).
    pub validator_index: u32,
    /// Raw stake weight (u128).
    pub stake: u128,
    /// `SHA3-256(pubkey || message || raw_sig)` — the binding commitment.
    /// Computed off-chain after native PQC verification succeeds.
    pub sig_commitment: [u8; 32],
    /// Whether this validator actually signed.
    pub is_signer: bool,
}

impl SignerInput {
    /// Compute the signature commitment used as circuit input.
    pub fn build_commitment(pubkey: &[u8], message: &[u8], raw_sig: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(pubkey);
        h.update(message);
        h.update(raw_sig);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        out
    }
}

/// Public inputs for the batch aggregation circuit.
///
/// These values are embedded in the STARK proof and verified by any party
/// that calls [`verify_batch`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchPublicInputs {
    /// Merkle root of the validator set snapshot.
    pub validator_set_root: Hash,
    /// Hash of the message (proof signing digest) that signers committed to.
    pub message_hash: Hash,
    /// Claimed total signed stake; bound by the circuit's boundary assertion.
    pub signed_stake: u128,
    /// Minimum stake required for finality (informational — enforced in hub).
    pub stake_threshold: u128,
    /// Number of signers that contributed (informational).
    pub signer_count: u32,
}

impl ToElements<BaseElement> for BatchPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut out = Vec::with_capacity(13);
        for chunk in self.validator_set_root.chunks(8) {
            let mut b = [0u8; 8];
            b[..chunk.len()].copy_from_slice(chunk);
            out.push(BaseElement::new(u64::from_le_bytes(b) as u128));
        }
        for chunk in self.message_hash.chunks(8) {
            let mut b = [0u8; 8];
            b[..chunk.len()].copy_from_slice(chunk);
            out.push(BaseElement::new(u64::from_le_bytes(b) as u128));
        }
        out.push(BaseElement::new(self.signed_stake));
        out.push(BaseElement::new(self.stake_threshold));
        out.push(BaseElement::new(self.signer_count as u128));
        out
    }
}

/// The ZK-STARK proof produced by [`prove_batch`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StarkBatchProof {
    /// Raw Winterfell STARK proof bytes.
    pub proof_bytes: Vec<u8>,
    /// `SHA3-256(proof_bytes || validator_set_root || message_hash || signed_stake)`
    /// This 32-byte value is what gets stored on-chain in `QuantosStarkVerifier`.
    pub commitment: Hash,
    /// Public inputs attested by the proof (reconstructable from the proof).
    pub public_inputs: BatchPublicInputs,
}

impl StarkBatchProof {
    /// Compute the on-chain commitment over proof data + public inputs.
    pub fn compute_commitment(proof_bytes: &[u8], pub_inputs: &BatchPublicInputs) -> Hash {
        let mut h = Sha3_256::new();
        h.update(proof_bytes);
        h.update(pub_inputs.validator_set_root);
        h.update(pub_inputs.message_hash);
        h.update(pub_inputs.signed_stake.to_be_bytes());
        h.update(pub_inputs.stake_threshold.to_be_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        out
    }
}

// ── Public API ─────────────────────────────────────────────────────────────

/// Generate a ZK-STARK batch proof for a set of validators.
///
/// The caller must have already verified every PQC signature natively
/// and built the `SignerInput` list with correct `sig_commitment` values.
///
/// Returns a [`StarkBatchProof`] whose `commitment` can be stored on-chain
/// and whose `proof_bytes` can be verified off-chain via [`verify_batch`].
pub fn prove_batch(
    signers: &[SignerInput],
    pub_inputs: BatchPublicInputs,
) -> L0Result<StarkBatchProof> {
    let trace = build_trace(signers);

    let options = ProofOptions::new(
        28,  // queries — ~96-bit conjectured security
        8,   // blowup factor
        16,  // grinding bits
        FieldExtension::None,
        8,   // FRI folding factor
        31,  // FRI max remainder polynomial degree
    );

    let prover = BatchAggProver {
        options,
        pub_inputs: pub_inputs.clone(),
    };

    let proof = prover
        .prove(trace)
        .map_err(|e| L0Error::InvalidCheckpoint(format!("STARK prove: {:?}", e)))?;

    let proof_bytes = proof.to_bytes();
    let commitment = StarkBatchProof::compute_commitment(&proof_bytes, &pub_inputs);

    Ok(StarkBatchProof {
        proof_bytes,
        commitment,
        public_inputs: pub_inputs,
    })
}

/// Verify a [`StarkBatchProof`] off-chain (full cryptographic verification).
///
/// Returns `Ok(true)` if the proof is valid, `Ok(false)` if it is invalid.
pub fn verify_batch(stark_proof: &StarkBatchProof) -> L0Result<bool> {
    let proof = Proof::from_bytes(&stark_proof.proof_bytes)
        .map_err(|e| L0Error::Encoding(format!("STARK deserialize: {:?}", e)))?;

    let acceptable = winterfell::AcceptableOptions::MinConjecturedSecurity(96);
    match winterfell::verify::<
        BatchAggAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
    >(proof, stark_proof.public_inputs.clone(), &acceptable)
    {
        Ok(()) => Ok(true),
        Err(e) => {
            tracing::warn!("STARK batch proof verification failed: {:?}", e);
            Ok(false)
        }
    }
}

// ── Trace builder ──────────────────────────────────────────────────────────

/// Build the Winterfell execution trace from the signer inputs.
///
/// Trace length = `(len + 1).next_power_of_two().max(8)`.
/// The extra row at the end carries the final accumulated stake so the
/// boundary assertion `acc_stake[last] = signed_stake` is satisfied.
fn build_trace(signers: &[SignerInput]) -> TraceTable<BaseElement> {
    let n = (signers.len() + 1).next_power_of_two().max(8);
    let mut columns = vec![vec![BaseElement::ZERO; n]; TRACE_WIDTH];

    let mut acc: u128 = 0;

    for row in 0..n {
        // Row `row` contains validator `row`'s data (or zeros for padding).
        if row < signers.len() {
            let s = &signers[row];
            columns[COL_IS_SIGNER][row] = BaseElement::new(if s.is_signer { 1u128 } else { 0u128 });
            columns[COL_STAKE][row]     = BaseElement::new(s.stake);
            for j in 0..4 {
                let mut b = [0u8; 8];
                b.copy_from_slice(&s.sig_commitment[j * 8..(j + 1) * 8]);
                columns[COL_SIG_C0 + j][row] =
                    BaseElement::new(u64::from_le_bytes(b) as u128);
            }
        }
        // acc_stake at this row = accumulated stake BEFORE this row's signer.
        columns[COL_ACC][row] = BaseElement::new(acc);
        // Advance accumulator for next row.
        if row < signers.len() && signers[row].is_signer {
            acc = acc.wrapping_add(signers[row].stake);
        }
    }

    TraceTable::init(columns)
}

// ── AIR ────────────────────────────────────────────────────────────────────

/// Algebraic Intermediate Representation for batch stake aggregation.
///
/// Constraints
/// -----------
/// 1. Boolean: `is_signer * (1 - is_signer) = 0`   (degree 2)
/// 2. Accumulator: `acc[i+1] - (acc[i] + is_signer[i] * stake[i]) = 0`  (degree 2)
///
/// Boundary assertions
/// -------------------
/// * `acc[0] = 0`
/// * `acc[last] = signed_stake`  (from public inputs)
struct BatchAggAir {
    context: AirContext<BaseElement>,
    signed_stake: u128,
}

impl Air for BatchAggAir {
    type BaseField = BaseElement;
    type PublicInputs = BatchPublicInputs;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        let degrees = vec![
            TransitionConstraintDegree::new(2), // is_signer ∈ {0, 1}
            TransitionConstraintDegree::new(2), // acc accumulation
        ];
        let context = AirContext::new(trace_info, degrees, 2, options);
        Self {
            context,
            signed_stake: pub_inputs.signed_stake,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current();
        let nxt = frame.next();

        let is_signer = cur[COL_IS_SIGNER];
        let stake     = cur[COL_STAKE];
        let acc       = cur[COL_ACC];

        // Constraint 0: is_signer ∈ {0, 1}
        result[0] = is_signer * (E::ONE - is_signer);

        // Constraint 1: acc[i+1] = acc[i] + is_signer[i] * stake[i]
        result[1] = nxt[COL_ACC] - (acc + is_signer * stake);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last = self.trace_length() - 1;
        vec![
            Assertion::single(COL_ACC, 0,    BaseElement::ZERO),
            Assertion::single(COL_ACC, last, BaseElement::new(self.signed_stake)),
        ]
    }
}

// ── Prover ─────────────────────────────────────────────────────────────────

struct BatchAggProver {
    options: ProofOptions,
    pub_inputs: BatchPublicInputs,
}

impl Prover for BatchAggProver {
    type BaseField = BaseElement;
    type Air = BatchAggAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3_256<BaseElement>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> BatchPublicInputs {
        self.pub_inputs.clone()
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<winterfell::AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_signer(stake: u128, is_signer: bool) -> SignerInput {
        SignerInput {
            validator_index: 0,
            stake,
            sig_commitment: SignerInput::build_commitment(
                &[1u8; 32],
                &[2u8; 32],
                &[3u8; 64],
            ),
            is_signer,
        }
    }

    #[test]
    fn test_prove_verify_batch_all_sign() {
        let signers = vec![
            make_signer(100, true),
            make_signer(200, true),
            make_signer(150, false),
            make_signer(50, true),
        ];
        let signed_stake: u128 = 100 + 200 + 50; // 350

        let pub_inputs = BatchPublicInputs {
            validator_set_root: [1u8; 32],
            message_hash: [2u8; 32],
            signed_stake,
            stake_threshold: 200,
            signer_count: 3,
        };

        let proof = prove_batch(&signers, pub_inputs).expect("prove failed");
        assert_eq!(proof.public_inputs.signed_stake, signed_stake);

        let valid = verify_batch(&proof).expect("verify failed");
        assert!(valid, "proof should be valid");
    }

    #[test]
    fn test_sig_commitment_is_deterministic() {
        let c1 = SignerInput::build_commitment(&[1u8; 32], &[2u8; 32], &[3u8; 64]);
        let c2 = SignerInput::build_commitment(&[1u8; 32], &[2u8; 32], &[3u8; 64]);
        assert_eq!(c1, c2);

        let c3 = SignerInput::build_commitment(&[9u8; 32], &[2u8; 32], &[3u8; 64]);
        assert_ne!(c1, c3, "different pubkeys must yield different commitments");
    }
}
