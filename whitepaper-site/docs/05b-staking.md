---
sidebar_position: 18
slug: /staking
---

# 17. Staking, Delegation & Slashing

## 17.1 Becoming a Validator

An account becomes a validator by staking QTS and submitting a `ValidatorRegister` transaction (State Model section). Registration binds the validator's post-quantum signing key *and* its VRF public key, the latter fixed at staking time so that committee selection cannot be ground (Committee section). A registered validator becomes eligible only after `VALIDATOR_ACTIVATION_DELAY_EPOCHS = 2`, closing the window for last-moment manipulation. The validator set is capped (`MAX_VALIDATORS = 1000` per set in the reference configuration) and ordered by stake.

## 17.2 Delegation and Commission

Validators may accept delegated stake and charge a commission, expressed in basis points up to `MAX_COMMISSION_RATE = 10000` (100%). Delegation lets QTS holders who do not run infrastructure contribute to security and share in rewards, while validators compete on reliability and commission. Stake — whether self-bonded or delegated — is what weights a validator's votes and its CU quota.

## 17.3 Reward Distribution

Validator rewards are assembled from the three revenue sources (Tokenomics section) — declining inflation, state rent (80% of collected rent), and slash redistribution — and distributed in proportion to active stake, net of each validator's commission to its delegators (`stacc/validator_rewards.rs`). Because rewards track *active participation*, a validator that is jailed or idle forgoes its share.

## 17.4 Slashing Offenses and Penalties

Misbehaviour is penalised by the slashing subsystem (`consensus/slashing.rs`) according to severity:

| Offense | Penalty | Evidence |
|---------|---------|----------|
| Invalid block | 10% of stake | Block failing validation |
| Double signing | 5% of stake | Two conflicting signed messages |
| Surround vote | 5% of stake | A vote that surrounds another |
| Equivocation | 5% of stake | Conflicting committee votes at one slot |
| Downtime | 0.1% per epoch | Missed blocks/votes |

Penalties are graduated: liveness faults (downtime) are minor and recoverable, while safety faults (equivocation, invalid blocks, double-signing) are severe because they directly threaten consensus integrity.

## 17.5 Slashing Pipeline

Slashing is evidence-driven and runs as a verifiable pipeline:

```
1. Evidence submission        → SlashingPool
2. Evidence verification       → validate cryptographic proofs
3. Penalty calculation         → compute stake to deduct
4. Execution                   → deduct stake, jail validator
5. Distribution                → reward the reporter, burn the remainder
```

Because evidence (e.g. two conflicting signed messages) is self-verifying, anyone can submit it; the reporter is rewarded from the slashed amount, creating an incentive to police misbehaviour. The remainder is burned, making safety violations directly costly to the offender and mildly deflationary for the network. Equivocation evidence is produced automatically by the runtime equivocation detector in the consensus safety model.

## 17.6 Jailing and Exit

A slashed validator is **jailed** — removed from active committees — and must satisfy a recovery process before rejoining, preventing an immediately-recidivist validator from continuing to threaten consensus. A validator may also leave voluntarily via `ValidatorExit`, after which its stake is subject to an unbonding delay before withdrawal, ensuring it remains slashable for offenses committed while it was active.
