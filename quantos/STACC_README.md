# STACC (Stake‑Timed Access & Compute Credit)

Quantos implements a **gas‑free** execution model. Users do not pay fees; instead, **bandwidth and compute** are bounded and prioritized by **stake‑timed access** and **compute credits** (CU).

## End‑to‑end transaction flow

```text
UserTx
  │
  ├─ (mempool) signature + nonce checks
  ├─ (stacc/activation) sender must be activated (deposit + cooldown in full protocol)
  ├─ (stacc/quota) token‑bucket CU quota check: try_consume(sender, max_compute_units)
  ├─ (stacc/wfq_scheduler) WFQ ordering: per‑address flows + min‑heap (O(log N))
  │
  └─ (block production)
        ├─ system_lane (5% CU): protocol/system tx (bypass STACC)
        └─ stacc_lane (95% CU): WFQ‑selected txs until block_cu_limit
              │
              └─ (state/vm)
                    ├─ apply_transaction (no fee deduction)
                    └─ VM enforces CU ceiling via max_compute_units
```

## Modules

- `src/stacc/activation.rs`
  - Activation ledger + cooldown and `anciennete_factor()`.
- `src/stacc/quota.rs`
  - Token‑bucket quota: `quota_base + quota_stake` with a `2×` capacity cap.
- `src/stacc/priority_boost.rs`
  - Computes a boost factor from a temporary lock (no burn).
- `src/stacc/wfq_scheduler.rs`
  - **Core** scheduler: flows keyed by address, each tx has a `virtual_finish`.
  - Global min‑heap orders flows by head tx `finish`. Insert/pop are \(O(\log N)\).
- `src/stacc/mempool.rs`
  - Admission control: activation check + quota consume + mempool caps by addr and global CU.
- `src/stacc/block_builder.rs`
  - Defines `system_lane`/`stacc_lane` CU splits.
- `src/stacc/validator_rewards.rs`
  - Inflation‑only rewards with a performance score hook (no fees).

## Notes

This repository currently centralizes STACC scheduling and quota enforcement at the mempool / block building boundary. State execution remains **fee‑free** and VM CU metering is enforced by `max_compute_units`.

