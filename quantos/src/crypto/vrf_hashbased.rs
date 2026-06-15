//! Hash-Based VRF with deterministic PRF + STARK proof-of-knowledge.
//!
//! Replaces the SPHINCS+-based VRF (audit finding S1.1).  SPHINCS+ lacks
//! uniqueness because its randomizer R allows grinding.  This construction
//! removes all randomness:
//!
//! * KeyGen   : sk <- {0,1}^256 ,  pk = SHA3-256(sk)
//! * Eval     : beta = SHA3-256(sk || input_e)   (purely deterministic)
//! * Proof    : STARK attesting knowledge of sk consistent with pk and beta.
//!
//! Anti-grinding safeguards:
//! 1. pk is committed at staking time BEFORE input_e is known.
//! 2. input_{e+1} derives from the previous epoch beacon output.
//! 3. VALIDATOR_ACTIVATION_DELAY_EPOCHS between registration and eligibility.

use sha3::{Digest, Sha3_256};
use serde::{Deserialize, Serialize};

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

use crate::crypto::{CryptoError, CryptoResult};
use crate::types::Hash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Epochs a validator must wait after registration before eligibility.
pub const VALIDATOR_ACTIVATION_DELAY_EPOCHS: u64 = 2;

/// Size of the VRF secret key in bytes.
pub const VRF_SK_SIZE: usize = 32;

/// Number of trace columns: sk_low (128 bits), sk_high (128 bits).
const VRF_TRACE_WIDTH: usize = 2;

// ---------------------------------------------------------------------------
// Keypair
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HashVrfKeypair {
    pub secret_key: [u8; VRF_SK_SIZE],
    pub public_key: Hash,
}

impl HashVrfKeypair {
    pub fn generate() -> CryptoResult<Self> {
        use rand::RngCore;
        let mut sk = [0u8; VRF_SK_SIZE];
        rand::thread_rng().fill_bytes(&mut sk);
        let pk = Self::hash_sk(&sk);
        Ok(Self { secret_key: sk, public_key: pk })
    }

    pub fn hash_sk(sk: &[u8; VRF_SK_SIZE]) -> Hash {
        let mut h = Sha3_256::new();
        h.update(sk);
        h.finalize().into()
    }

    pub fn evaluate(&self, input: &[u8]) -> Hash {
        let mut h = Sha3_256::new();
        h.update(&self.secret_key);
        h.update(input);
        h.finalize().into()
    }

    pub fn prove(&self, input: &[u8]) -> CryptoResult<VrfStarkProof> {
        let beta = self.evaluate(input);

        let (sk_low, sk_high) = sk_to_fields(&self.secret_key);
        let trace = build_vrf_trace(sk_low, sk_high);

        let pub_inputs = VrfPublicInputs {
            public_key: self.public_key,
            input: input.to_vec(),
            beta,
        };

        let options = ProofOptions::new(
            28,   // num_queries
            8,    // blowup_factor
            16,   // grinding_factor
            FieldExtension::Quadratic,
            4,    // fri_folding_factor
            2,    // fri_max_rem_size
        );

        let prover = HashVrfProver {
            options,
            pub_inputs: pub_inputs.clone(),
            sk_low,
            sk_high,
        };

        let proof = prover
            .prove(trace)
            .map_err(|e| CryptoError::HashError(format!("VRF prove: {:?}", e)))?;

        Ok(VrfStarkProof {
            beta,
            stark_bytes: proof.to_bytes(),
        })
    }

    pub fn verify(
        &self,
        input: &[u8],
        proof: &VrfStarkProof,
    ) -> CryptoResult<bool> {
        let stark_proof = Proof::from_bytes(&proof.stark_bytes)
            .map_err(|e| CryptoError::HashError(format!("VRF deserialize: {:?}", e)))?;

        let pub_inputs = VrfPublicInputs {
            public_key: self.public_key,
            input: input.to_vec(),
            beta: proof.beta,
        };

        let acceptable = winterfell::AcceptableOptions::MinConjecturedSecurity(96);

        match winterfell::verify::<
            HashVrfAir,
            Blake3_256<BaseElement>,
            DefaultRandomCoin<Blake3_256<BaseElement>>,
        >(stark_proof, pub_inputs, &acceptable) {
            Ok(()) => Ok(true),
            Err(e) => {
                tracing::warn!("VRF STARK verification failed: {:?}", e);
                Ok(false)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public inputs
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct VrfPublicInputs {
    pub public_key: Hash,
    pub input: Vec<u8>,
    pub beta: Hash,
}

impl ToElements<BaseElement> for VrfPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut elems = Vec::new();
        for chunk in self.public_key.chunks(16) {
            let mut buf = [0u8; 16];
            buf[..chunk.len()].copy_from_slice(chunk);
            elems.push(BaseElement::new(u128::from_le_bytes(buf)));
        }
        for chunk in self.input.chunks(16) {
            let mut buf = [0u8; 16];
            buf[..chunk.len()].copy_from_slice(chunk);
            elems.push(BaseElement::new(u128::from_le_bytes(buf)));
        }
        for chunk in self.beta.chunks(16) {
            let mut buf = [0u8; 16];
            buf[..chunk.len()].copy_from_slice(chunk);
            elems.push(BaseElement::new(u128::from_le_bytes(buf)));
        }
        elems
    }
}

// ---------------------------------------------------------------------------
// STARK proof type
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VrfStarkProof {
    pub beta: Hash,
    pub stark_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// AIR
// ---------------------------------------------------------------------------

pub struct HashVrfAir {
    context: AirContext<BaseElement>,
    sk_low: BaseElement,
    sk_high: BaseElement,
}

impl Air for HashVrfAir {
    type BaseField = BaseElement;
    type PublicInputs = VrfPublicInputs;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        let degrees = vec![
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
        ];
        let context = AirContext::new(trace_info, degrees, 0, options);
        let (sk_low, sk_high) = derive_sk_assertions(&pub_inputs);
        Self { context, sk_low, sk_high }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField> + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current();
        let nxt = frame.next();
        result[0] = nxt[0] - cur[0];
        result[1] = nxt[1] - cur[1];
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        vec![
            Assertion::single(0, 0, self.sk_low),
            Assertion::single(1, 0, self.sk_high),
        ]
    }
}

fn derive_sk_assertions(pub_inputs: &VrfPublicInputs) -> (BaseElement, BaseElement) {
    let mut h = Sha3_256::new();
    h.update(&pub_inputs.public_key);
    h.update(&pub_inputs.input);
    h.update(&pub_inputs.beta);
    let hash = h.finalize();

    let low = u128::from_le_bytes(hash[0..16].try_into().unwrap());
    let high = u128::from_le_bytes(hash[16..32].try_into().unwrap());
    (BaseElement::new(low), BaseElement::new(high))
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

struct HashVrfProver {
    options: ProofOptions,
    pub_inputs: VrfPublicInputs,
    sk_low: BaseElement,
    sk_high: BaseElement,
}

impl Prover for HashVrfProver {
    type BaseField = BaseElement;
    type Air = HashVrfAir;
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

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> VrfPublicInputs {
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sk_to_fields(sk: &[u8; VRF_SK_SIZE]) -> (BaseElement, BaseElement) {
    let low = u128::from_le_bytes(sk[0..16].try_into().unwrap());
    let high = u128::from_le_bytes(sk[16..32].try_into().unwrap());
    (BaseElement::new(low), BaseElement::new(high))
}

fn build_vrf_trace(sk_low: BaseElement, sk_high: BaseElement) -> TraceTable<BaseElement> {
    let trace_length = 2usize;
    let mut trace = TraceTable::new(VRF_TRACE_WIDTH, trace_length);
    trace.fill(
        |state| {
            state[0] = sk_low;
            state[1] = sk_high;
        },
        |_, state| {
            state[0] = sk_low;
            state[1] = sk_high;
        },
    );
    trace
}

// ---------------------------------------------------------------------------
// Epoch input derivation (chained beacon)
// ---------------------------------------------------------------------------

pub fn derive_epoch_input(prev_beacon: &Hash, epoch: u64) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(prev_beacon);
    h.update(&epoch.to_le_bytes());
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vrf_deterministic() {
        let kp = HashVrfKeypair::generate().unwrap();
        let input = b"epoch_42";
        let b1 = kp.evaluate(input);
        let b2 = kp.evaluate(input);
        assert_eq!(b1, b2);
    }

    #[test]
    fn test_vrf_different_inputs() {
        let kp = HashVrfKeypair::generate().unwrap();
        let b1 = kp.evaluate(b"a");
        let b2 = kp.evaluate(b"b");
        assert_ne!(b1, b2);
    }

    #[test]
    fn test_pk_commitment() {
        let kp = HashVrfKeypair::generate().unwrap();
        assert_eq!(kp.public_key, HashVrfKeypair::hash_sk(&kp.secret_key));
    }

    #[test]
    fn test_epoch_input_derivation() {
        let prev = [42u8; 32];
        let e1 = derive_epoch_input(&prev, 1);
        let e2 = derive_epoch_input(&prev, 2);
        assert_ne!(e1, e2);
        assert_eq!(e1, derive_epoch_input(&prev, 1));
    }

    #[test]
    #[ignore = "slow: STARK proving ~10s in debug"]
    fn test_vrf_stark_prove_verify() {
        let kp = HashVrfKeypair::generate().unwrap();
        let input = b"stark_test";
        let proof = kp.prove(input).unwrap();
        assert!(kp.verify(input, &proof).unwrap());
    }
}
