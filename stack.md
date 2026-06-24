
## 2. ~~🔴 Threshold ML-KEM présenté comme brique de production~~ → ✅ Résolu

**Ce que disait le whitepaper (§3.4, §3.5, §14.3) :** mempool chiffré via threshold ML-KEM-768 + NIZK lattice maison, présenté comme code de production.

**Actions prises :**

1. **Audit crypto** — threshold ML-KEM, Shamir Z_q et lattice NIZK sont en **priorité 1** dans `AUDIT_SCOPE.md` (avant consensus).
2. **Plan de repli livré** — mainnet utilise désormais **Accountable Leader** par défaut :
   - `mempool/accountable_leader.rs` : leader tournant + ordre canonique `H(beacon || tx_hash)`
   - `mempool/mempool_policy.rs` : `MempoolFrontRunningMode::AccountableLeader` = default
   - `consensus/slashing.rs` : `OffenseType::FrontRunning` (2 % stake) avec preuve d'écart d'ordre
3. **Hors chemin critique mainnet** — modules `threshold_mlkem.rs`, `shamir_zq.rs`, `lattice_nizk.rs` compilent uniquement avec la feature Cargo `experimental-threshold-mlkem` (désactivée par défaut).
4. **Whitepaper §2.3** mis à jour : mainnet = accountable leader ; threshold ML-KEM = expérimental en attente d'audit.

**Propriété mainnet reformulée :** *front-running protection with accountable leader* (briques standard, livrables immédiatement).
