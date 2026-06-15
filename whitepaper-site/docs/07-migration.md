# 7. PQC Key Migration

## 7.1 The Problem

No on-chain mechanism can distinguish an attacker holding a stolen ECDSA key from the legitimate owner. Earlier commit-reveal designs suffered from symmetric griefing: both the attacker and the legitimate owner could cancel each other's commitments, resulting in a denial-of-service race.

## 7.2 Three-Mechanism Migration Model

Quantos replaces the commit-reveal design with a three-mechanism model:

| Mechanism | Purpose | Trigger |
|-----------|---------|---------|
| 1. Direct registration + PoP | Normal case (99% of users) | User proactively registers PQC key |
| 2. 48h PENDING delay + alert | Anti-theft safeguard | Automatic on every registration |
| 3. Social recovery M-of-N | Account already compromised | Guardians intervene during 48h window |

**Mechanism 1 — Direct registration**: The user submits their PQC public key (ML-DSA-65) with an ECDSA binding signature and a PQC proof-of-possession (PoP). The guardian root is bound at first registration and becomes immutable.

**Mechanism 2 — PENDING delay**: After registration, the key enters a `Pending` state for 48 hours (`PENDING_DELAY_SECONDS = 172,800`). During this window, an alert is emitted. The user can activate the key after the delay expires; the activation is permissionless (any node can call it).

**Mechanism 3 — Guardian freeze**: If the registration was unauthorized, the user's guardians (configured in advance, 2-of-3 or 3-of-5) can freeze the account during the 48-hour window. Guardians are independent of the ECDSA key; the attacker cannot revoke them without passing the same 48-hour delay.

**Guardian set changes**: Also subject to the 48-hour delay, preventing an attacker from immediately swapping guardians after stealing the ECDSA key.
