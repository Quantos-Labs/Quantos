# 9. Network Layer

## 9.1 P2P Communication

Validator P2P uses ML-KEM-768 for key encapsulation during handshake, followed by ChaCha20-Poly1305 for the session. This provides post-quantum confidentiality for all consensus traffic.

## 9.2 Data Availability

Each shard maintains a data availability layer using erasure-coded blobs. Cross-shard transactions include a Merkle proof of availability that the target shard can verify without downloading the full blob.
