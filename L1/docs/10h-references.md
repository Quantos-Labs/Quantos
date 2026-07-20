---
sidebar_position: 33
slug: /references
---

# 32. References

The design of Quantos draws on the following standards and peer-reviewed literature. This list documents the external foundations cited throughout the whitepaper.

## 32.1 Post-Quantum Cryptography Standards

1. **NIST FIPS 204** — *Module-Lattice-Based Digital Signature Standard (ML-DSA)*. National Institute of Standards and Technology, finalized August 2024. (Basis for Quantos signatures.)
2. **NIST FIPS 203** — *Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)*. NIST, finalized August 2024. (Basis for Quantos key encapsulation.)
3. **NIST FIPS 202** — *SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions*. NIST, 2015. (SHA3-256 / SHAKE256.)
4. **NIST FIPS 205** — *Stateless Hash-Based Digital Signature Standard (SLH-DSA / SPHINCS+)*. NIST, 2024. (Referenced for historical/interoperability context.)
5. P. W. Shor. *Polynomial-Time Algorithms for Prime Factorization and Discrete Logarithms on a Quantum Computer.* SIAM J. Computing, 1997. (The threat motivating PQC.)
6. L. K. Grover. *A Fast Quantum Mechanical Algorithm for Database Search.* STOC, 1996. (Motivates 256-bit hashing.)

## 32.2 Consensus

7. A. Spiegelman, N. Giridharan, A. Sonnino, L. Kokoris-Kogias. *Narwhal and Tusk: A DAG-based Mempool and Efficient BFT Consensus.* EuroSys, 2022.
8. A. Spiegelman et al. *Bullshark: DAG BFT Protocols Made Practical.* CCS, 2022.
9. M. Yin, D. Malkhi, M. K. Reiter, G. Golan-Gueta, I. Abraham. *HotStuff: BFT Consensus with Linearity and Responsiveness.* PODC, 2019.
10. C. Dwork, N. Lynch, L. Stockmeyer. *Consensus in the Presence of Partial Synchrony.* J. ACM, 1988. (The synchrony model Quantos assumes.)
11. M. Castro, B. Liskov. *Practical Byzantine Fault Tolerance.* OSDI, 1999.

## 32.3 Proofs and Randomness

12. E. Ben-Sasson, I. Bentov, Y. Horesh, M. Riabzev. *Scalable, Transparent, and Post-Quantum Secure Computational Integrity (STARKs).* IACR ePrint, 2018. (Basis for VRF proof-of-knowledge and L0 aggregation.)
13. S. Micali, M. Rabin, S. Vadhan. *Verifiable Random Functions.* FOCS, 1999.
14. A. Fiat, A. Shamir. *How to Prove Yourself: Practical Solutions to Identification and Signature Problems.* CRYPTO, 1986. (Non-interactive proof transform.)

## 32.4 Hash-Based Signatures and Accumulators

16. J. Buchmann, E. Dahmen, A. Hülsing. *XMSS — A Practical Forward Secure Signature Scheme Based on Minimal Security Assumptions.* PQCrypto, 2011. (Winternitz/WOTS lineage used by PQC-Guard.)
17. R. C. Merkle. *A Digital Signature Based on a Conventional Encryption Function.* CRYPTO, 1987. (Merkle trees / Merkle Mountain Ranges.)

## 32.5 Systems and Tooling

18. *RocksDB: A Persistent Key-Value Store for Fast Storage Environments.* (Quantos storage backend.)
19. *Wasmer: The Universal WebAssembly Runtime* and *Cranelift Code Generator.* (QuantosVM execution engine.)
20. *Solang: A Solidity Compiler for Solana and Substrate (WASM).* (Solidity-to-WASM path on QuantosVM.)
21. *Winterfell: A STARK Prover and Verifier (Rust).* (L0 stake-aggregation circuit.)
22. *libp2p: A Modular Network Stack.* (Quantos P2P layer.)

## 32.6 Source Code

23. **Quantos source, tests, and benchmarks** — `github.com/Quantos-Labs/Quantos`. The implementation is the normative reference for this whitepaper; where prose and code differ, the code governs.

---

*Note: standard titles and years are provided for orientation. Readers implementing against Quantos should consult the canonical NIST publications and the source repository for exact parameters.*
