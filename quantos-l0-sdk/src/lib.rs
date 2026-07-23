// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

pub mod types;
pub mod error;
pub mod verifier;
pub mod fetcher;
pub mod registry;

pub use types::{
    Hash, L0FinalityProof, L0ProofHeader, L0_PROOF_VERSION, PqcSignatureAlgo, ProofSignature,
    ValidatorRecord,
};
pub use error::{L0Error, L0Result, ValidatorSetSnapshot, VerificationReport};
pub use verifier::{verify_ml_dsa_65, verify_proof};
pub use fetcher::{fetch_latest_proof, fetch_proof};
pub use registry::register_validator_set;
