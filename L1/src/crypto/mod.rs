//! # Quantos Post-Quantum Cryptography
//!
//! This module provides post-quantum cryptographic primitives for the Quantos blockchain.
//! All algorithms are NIST-standardized and provide 128-bit post-quantum security.
//!
//! ## Algorithms
//!
//! | Algorithm | Usage | Key Size | Signature Size |
//! |-----------|-------|----------|----------------|
//! | **ML-DSA-65** | Transaction & checkpoint signatures (FIPS 204) | 1952 bytes | 3309 bytes |
//!
//! ## Security Considerations
//!
//! - All keys are generated using cryptographically secure random number generators
//! - Private keys should never be logged or exposed
//! - Signature verification is constant-time to prevent timing attacks
//!
//! ## Example
//!
//! ```rust,ignore
//! use quantos::crypto::{MlDsa65Keypair, sign_ml_dsa_65, verify_ml_dsa_65};
//!
//! // Generate a keypair
//! let keypair = MlDsa65Keypair::generate()?;
//!
//! // Sign a message
//! let message = b"Hello, Quantos!";
//! let signature = keypair.sign(message)?;
//!
//! // Verify the signature
//! let valid = keypair.verify(message, &signature)?;
//! assert!(valid);
//! ```

mod kyber_kem;
mod sphincs;
mod ml_dsa;
mod vrf;
mod rescue_constants;
pub mod vrf_hashbased;
pub mod domains;
mod hash;
mod keypair;
mod merkle_pq;
mod batch;
mod aggregation;
mod simd;
mod memory_pool;
mod zero_copy;
mod precomputed;
mod verify_worker;
pub mod batch_verify;
pub mod signature_aggregation;
pub mod adaptive_pqc;

pub use domains::{with_domain, DOMAIN_TX, DOMAIN_VERTEX, DOMAIN_COMMITTEE_VOTE,
    DOMAIN_CHECKPOINT, DOMAIN_VIEW_CHANGE, DOMAIN_PIPELINE_VOTE,
    DOMAIN_VRF_PRF, DOMAIN_VRF_OUTPUT, DOMAIN_VRF_PROVE,
    DOMAIN_CSAP_VOTE, DOMAIN_CSAP_ACK,
    DOMAIN_SLASH_DOUBLE_SIGN, DOMAIN_SLASH_EQUIVOC, DOMAIN_SLASH_INVALID_BLOCK,
    DOMAIN_SLASH_FRONT_RUN,
    DOMAIN_PQ_PEER_ID, DOMAIN_PQ_KEM_HANDSHAKE};
pub use kyber_kem::*;
pub use sphincs::*;
pub use ml_dsa::*;
pub use vrf::*;
pub use vrf_hashbased::*;
pub use hash::*;
pub use keypair::*;
pub use merkle_pq::*;
pub use batch_verify::*;
pub use signature_aggregation::*;
pub use adaptive_pqc::*;
pub use batch::*;
pub use aggregation::*;
pub use simd::*;
pub use memory_pool::*;
pub use zero_copy::*;
pub use precomputed::*;
pub use verify_worker::*;

use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Error, Debug)]
pub enum CryptoError {
    /// The signature format is invalid or corrupted
    #[error("Invalid signature")]
    InvalidSignature,
    
    /// The public key format is invalid or corrupted
    #[error("Invalid public key")]
    InvalidPublicKey,
    
    /// The private key format is invalid or corrupted
    #[error("Invalid private key")]
    InvalidPrivateKey,
    
    /// Signature verification failed (signature does not match message)
    #[error("Signature verification failed")]
    VerificationFailed,
    
    /// Key generation failed due to RNG or other issues
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
    
    /// VRF proof is invalid
    #[error("VRF proof invalid")]
    InvalidVRFProof,
    
    /// Hash computation error
    #[error("Hash error: {0}")]
    HashError(String),

    /// KEM ciphertext malformed or failed decapsulation
    #[error("Invalid KEM ciphertext")]
    InvalidKemCiphertext,
}

/// Result type for cryptographic operations.
pub type CryptoResult<T> = Result<T, CryptoError>;
