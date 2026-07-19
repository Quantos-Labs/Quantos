---
sidebar_position: 15
slug: /mempool
---

# 14. Mempool, MEV & Transaction Lifecycle

## 14.1 Sharded Mempool

Pending transactions live in a **sharded mempool** (`quantos/src/mempool/`): each shard maintains its own pool, so admission and ordering scale with shard count rather than contending on a single global pool. The mempool is quota-aware (it integrates with STACC), rejecting transactions a sender cannot afford in CU before they consume validator resources.

## 14.2 Transaction Lifecycle

A transaction traverses a well-defined pipeline:

```
sign (ML-DSA-65)
   → gossip propagation
   → mempool admission (quota + anti-spam + validity checks)
   → DAG vertex inclusion (2–8 parents)
   → optimistic parallel execution
   → committee vote (>2/3 stake)
   → pre-confirmation (~50 ms)
   → checkpoint finality (~1 s)
```

The first confirmation a user perceives (~50 ms) is the committee pre-confirmation; deterministic, irreversible finality follows at the next checkpoint (~1 s).

## 14.3 Encrypted Mempool (Anti-Front-Running)

The encrypted mempool (`mempool/encrypted_mempool.rs`) hides transaction *content* until ordering is fixed, defeating front-running and sandwich attacks. Transactions are encrypted under ML-KEM-768 (FIPS 203). The **mainnet default** uses the accountable-leader front-running protection (`mempool/accountable_leader.rs`): canonical order is determined by `H(ordering_beacon ‖ tx_hash)`, and any deviation is slashable as proven front-running.

## 14.4 Fair Ordering

Complementing encryption, the fair-ordering module (`mempool/fair_ordering.rs`) sequences transactions by a rule that does not depend on their content — for example, by hash of the encrypted blob — so the proposer has no discretion over ordering. Encryption removes the *information* needed to extract MEV; fair ordering removes the *discretion*.

**Grinding caveat:** if the ordering key is derived from the hash of the encrypted blob, a sender who submits multiple re-encrypted versions of the same transaction (varying the encryption nonce) can grind the hash to target a favorable position. The primary barrier is the STACC per-sender CU quota, which makes repeated re-submissions economically costly. This makes position grinding *expensive*, not *impossible*; the ordering guarantee is therefore best characterised as *manipulation-resistant under quota constraints* rather than unconditionally manipulation-proof.

## 14.5 Proposer-Builder Separation (PBS)

For the residual MEV that cannot be eliminated, Quantos democratizes its extraction via Proposer-Builder Separation (`mempool/pbs.rs`). Block *building* is separated from block *proposing*:

- A competitive **builder market** assembles candidate blocks and bids for inclusion via **sealed-bid auctions** (preventing bid manipulation).
- **Builder reputation** (a 0–1000 score) tracks builder reliability.
- **Proposer protection** guarantees the proposer a minimum payment, so proposers need not run sophisticated MEV strategies themselves.
- A **relay** layer mediates between builders and proposers for privacy.

PBS prevents the centralising pressure where only the most sophisticated proposers capture MEV, distributing it through an open market instead.

## 14.6 Blob Transactions and Adaptive Routing

The mempool also supports **blob transactions** (`mempool/blob_transactions.rs`) for large data payloads carried via the data-availability layer rather than inline, and **adaptive routing** (`mempool/adaptive_routing.rs`) that steers transactions toward the shard best able to process them, smoothing load before it reaches the sharding rebalancer. A hardened `secure.rs` path applies additional validation for sensitive admission flows.
