# 5. STACC: Zero-Gas Execution

## 5.1 Bandwidth Quotas

STACC (Stake-Timed Access and Compute Credit) replaces per-transaction gas fees with a quota system proportional to staked QTS:

- Each account receives a compute-unit (CU) quota per slot proportional to its stake.
- Transactions consume CU based on computational cost (state reads, writes, cross-shard hops).
- Quota unused in a slot does not roll over.

## 5.2 Known Limitations and Mitigations

The zero-gas model has documented failure modes, inherited from prior implementations (e.g., EOS):

1. **Spam at marginal cost**: Within quota, spam is free. Mitigation: (a) bandwidth quotas are finite and stake-proportional, (b) STACC includes an anti-spam module that rate-limits high-frequency senders, (c) state rent (see §5.3) prices persistent storage independently of bandwidth.

2. **New-user onboarding**: A user with zero stake has zero quota and cannot transact. Mitigation: The protocol supports a `sponsor` field in transactions; any staked account can sponsor CU for another account. The super app infrastructure can provide default sponsorship for new users.

3. **Storage not priced by bandwidth**: Bandwidth limits throughput but not state growth. Mitigation: State rent (§5.3) charges per byte of occupied storage per slot.

4. **MEV survives zero gas**: The block producer still controls transaction ordering. Mitigation: (a) encrypted mempool (§2.3) hides transaction content until ordering is finalized, (b) a fair-ordering module sequences transactions by hash-of-encrypted-blob to remove ordering predictability.

## 5.3 State Rent

State rent is the pricing mechanism for persistent storage:

- `RENT_RATE_PER_SLOT_PER_BYTE = 1` CU per byte per slot.
- Accounts with `storage_bytes ≤ 128` are exempt (dust prevention).
- Accounts with zero quota for `N_EXPIRE_SLOTS` (~48 hours at 200 ms/slot) are archived to cold storage.
- Archived state can be restored by paying `RESTORE_COST_PER_BYTE` in quota plus providing a Merkle proof.
- 20% of collected rent is burned; 80% is redistributed to validators.

## 5.4 Tokenomics: Three-Source Revenue

Validator rewards come from three sources, avoiding the 100% inflation trap of pure zero-fee models:

1. **Targeted inflation**: 3–5% annually, declining as staking rate approaches 67%. Formula: `inflation(t) = max(1%, 5% × (1 - staking_rate / 0.67))`.
2. **State rent**: Grows with adoption, progressively replacing inflation as the dominant revenue source.
3. **Slash redistribution**: Slashed stake is split 80% to honest validators, 20% burned.

**Sustainability metrics**: The tokenomics engine reports `rent_coverage` (fraction of validator revenue from rent, not inflation) and `years_to_rent_parity` (estimated time until rent covers 50% of rewards). At genesis, rent coverage is near zero; the model projects parity within 3–5 years at conservative adoption curves.
