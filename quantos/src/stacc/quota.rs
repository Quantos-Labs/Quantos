use std::collections::HashMap;
use crate::types::Address;
use crate::stacc::StaccTier;

// CU refill rates per tier (CU per second)
pub const R_CHARGE_BASIC: u64 = 10; // Basic: 10 CU/s
pub const R_CHARGE_BUILDER: u64 = 100; // Builder: 100 CU/s
pub const R_CHARGE_ENTERPRISE: u64 = 1000; // Enterprise: 1000 CU/s

// Burst and bucket sizing
pub const BURST_FACTOR: u64 = 10; // allow short burst = R_charge * BURST_FACTOR
pub const BUCKET_SECONDS: u64 = 3600; // bucket baseline in seconds (1 hour)

pub const BASE_RATE: u64 = 50_000;
pub const STAKE_BW_POOL: u64 = 50_000_000;
pub const BUCKET_CAP_MULTIPLIER: u64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaError {
    InsufficientQuota,
}

#[derive(Debug, Clone, Copy)]
pub struct Bucket {
    pub capacity: u64,
    pub tokens: u64,
    pub last_refill_block: u64,
}

impl Bucket {
    pub fn new(capacity: u64, now_block: u64) -> Self {
        Self { capacity, tokens: capacity, last_refill_block: now_block }
    }

    pub fn refill_to(&mut self, capacity: u64, refill_amount: u64, now_block: u64) {
        if now_block <= self.last_refill_block {
            // Still allow capacity changes.
            self.capacity = capacity;
            self.tokens = self.tokens.min(self.capacity);
            return;
        }
        // One refill per block: add refill_amount and clamp.
        self.capacity = capacity;
        self.tokens = self.tokens.saturating_add(refill_amount).min(self.capacity);
        self.last_refill_block = now_block;
    }

    pub fn try_consume(&mut self, amount: u64) -> Result<(), QuotaError> {
        if self.tokens < amount {
            return Err(QuotaError::InsufficientQuota);
        }
        self.tokens -= amount;
        Ok(())
    }
}

pub trait StakeProvider: Send + Sync {
    fn stake_of(&self, addr: &Address) -> u128;
    fn total_stake(&self) -> u128;
}

pub trait AncienneteProvider: Send + Sync {
    /// Returns ancienneté factor in [1.0, 3.0].
    fn anciennete_factor(&self, addr: &Address, now_block: u64) -> f64;
}

#[derive(Clone)]
pub struct QuotaManager<S: StakeProvider, A: AncienneteProvider> {
    stake: S,
    anciennete: A,
    buckets: HashMap<Address, Bucket>,
    /// Track consecutive heavy-burn cycles per address: (count, last_burn_block)
    burns: HashMap<Address, (u32, u64)>,
}

impl<S: StakeProvider, A: AncienneteProvider> QuotaManager<S, A> {
    pub fn new(stake: S, anciennete: A) -> Self {
        Self { stake, anciennete, buckets: HashMap::new(), burns: HashMap::new() }
    }

    pub fn quota_base(&self, addr: &Address, now_block: u64) -> u64 {
        let tier = match StaccTier::from_stake(self.stake.stake_of(addr)) {
            Some(t) => t,
            None => return 0,
        };
        let f = self.anciennete.anciennete_factor(addr, now_block);
        (tier.quota_base() as f64 * f).round().clamp(0.0, u64::MAX as f64) as u64
    }

    pub fn quota_stake(&self, addr: &Address) -> u64 {
        let total = self.stake.total_stake();
        if total == 0 {
            return 0;
        }
        let s = self.stake.stake_of(addr);
        // floor((s/total)*POOL)
        // Apply diminishing returns: use log-like curve to reduce marginal gains
        let stake_u128 = s;
        if stake_u128 == 0 {
            return 0;
        }
        // ln(1 + stake) / ln(1 + total) * POOL
        let stake_f = (stake_u128 as f64).ln_1p();
        let total_f = ((total as f64).ln_1p()).max(1.0);
        let ratio = (stake_f / total_f).max(0.0);
        ((ratio * (STAKE_BW_POOL as f64)).round() as u64).min(STAKE_BW_POOL)
    }

    pub fn quota_total(&self, addr: &Address, now_block: u64) -> u64 {
        self.quota_base(addr, now_block).saturating_add(self.quota_stake(addr))
    }

    /// Returns tier-specific per-transaction hard cap (CU)
    pub fn cu_tx_max(&self, addr: &Address) -> u64 {
        match StaccTier::from_stake(self.stake.stake_of(addr)) {
            Some(StaccTier::Basic) => 10_000,
            Some(StaccTier::Builder) => 100_000,
            Some(StaccTier::Enterprise) => 1_000_000,
            None => 10_000, // default conservative cap
        }
    }

    pub fn priority_weight_boost(&self, addr: &Address) -> f64 {
        StaccTier::from_stake(self.stake.stake_of(addr))
            .map_or(0.0, |tier| tier.priority_weight_boost())
    }

    pub fn bucket_capacity(&self, addr: &Address, now_block: u64) -> u64 {
        // Use refill rate based bucket sizing as primary source for burst capacity
        let tier = StaccTier::from_stake(self.stake.stake_of(addr));
        let r = match tier {
            Some(t) => match t {
                StaccTier::Basic => R_CHARGE_BASIC,
                StaccTier::Builder => R_CHARGE_BUILDER,
                StaccTier::Enterprise => R_CHARGE_ENTERPRISE,
            },
            None => R_CHARGE_BASIC,
        };
        let cap = 2_u128.saturating_mul(r as u128).saturating_mul(BUCKET_SECONDS as u128);
        cap.min(u128::from(u64::MAX)) as u64
    }

    pub fn refill_block(&mut self, now_block: u64) {
        // Refill all known buckets once per block.
        // This is O(N) and intended to run once per block in block-builder context.
        let addrs: Vec<Address> = self.buckets.keys().copied().collect();
        for addr in addrs {
            let refill = self.quota_total(&addr, now_block);
            let cap = self.bucket_capacity(&addr, now_block);
            // Apply PAC speed multiplier based on recent consecutive burns
            let (burns, last_burn_block) = self.burns.get(&addr).copied().unwrap_or((0u32, 0u64));
            let m_speed = 1.0 / (1.0 + (burns as f64).powi(2));
            let refill_effective = ((refill as f64) * m_speed).round() as u64;
            if let Some(b) = self.buckets.get_mut(&addr) {
                b.refill_to(cap, refill_effective, now_block);
            }
            // Decay consecutive_burns slowly if there has been no recent burn
            if burns > 0 {
                if now_block.saturating_sub(last_burn_block) > BUCKET_SECONDS {
                    let entry = self.burns.get_mut(&addr).unwrap();
                    entry.0 = entry.0.saturating_sub(1);
                    entry.1 = now_block;
                }
            }
        }
    }

    pub fn ensure_bucket(&mut self, addr: Address, now_block: u64) {
        if self.buckets.contains_key(&addr) {
            return;
        }
        let cap = self.bucket_capacity(&addr, now_block);
        self.buckets.insert(addr, Bucket::new(cap, now_block));
        // initialize burn tracking
        self.burns.entry(addr).or_insert((0u32, 0u64));
    }

    pub fn try_consume(&mut self, addr: Address, cu: u64, now_block: u64) -> Result<(), QuotaError> {
        self.ensure_bucket(addr, now_block);
        let refill = self.quota_total(&addr, now_block);
        let cap = self.bucket_capacity(&addr, now_block);
        // Reject transactions that exceed per-transaction hard cap
        if cu > self.cu_tx_max(&addr) {
            return Err(QuotaError::InsufficientQuota);
        }
        if let Some(b) = self.buckets.get_mut(&addr) {
            b.refill_to(cap, refill, now_block);
            // detect heavy burn before consumption
            let threshold = (cap.saturating_mul(9)) / 10; // 90% of cap
            if cu >= threshold {
                // increment consecutive burns
                let entry = self.burns.entry(addr).or_insert((0u32, now_block));
                entry.0 = entry.0.saturating_add(1);
                entry.1 = now_block;
            }
            b.try_consume(cu)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct TestStake {
        stakes: HashMap<Address, u128>,
        total: u128,
    }
    impl StakeProvider for TestStake {
        fn stake_of(&self, addr: &Address) -> u128 { *self.stakes.get(addr).unwrap_or(&0) }
        fn total_stake(&self) -> u128 { self.total }
    }

    #[derive(Clone)]
    struct TestAge;
    impl AncienneteProvider for TestAge {
        fn anciennete_factor(&self, _addr: &Address, _now_block: u64) -> f64 { 1.0 }
    }

    #[test]
    fn bucket_refill_and_cap() {
        let a = [1u8; 32];
        let mut stakes = HashMap::new();
        stakes.insert(a, 0);
        let stake = TestStake { stakes, total: 0 };
        let age = TestAge;
        let mut qm = QuotaManager::new(stake, age);

        // At block 1, cap = 2*BASE_RATE, tokens = cap.
        qm.ensure_bucket(a, 1);
        let cap = qm.bucket_capacity(&a, 1);
        // expected cap = 2 * R_CHARGE_BASIC * BUCKET_SECONDS
        assert_eq!(cap, 2 * R_CHARGE_BASIC * BUCKET_SECONDS);

        // Consume some; since account has zero stake, quota_total==0, refill won't add tokens.
        qm.try_consume(a, 1_000, 1).unwrap();
        qm.refill_block(2);
        let b = qm.buckets.get(&a).unwrap();
        assert_eq!(b.tokens, cap - 1_000); // no refill expected for zero-stake quota
    }

    #[test]
    fn insufficient_quota_rejected() {
        let a = [2u8; 32];
        let stake = TestStake { stakes: HashMap::new(), total: 0 };
        let age = TestAge;
        let mut qm = QuotaManager::new(stake, age);
        let res = qm.try_consume(a, 10 * BASE_RATE, 1);
        assert_eq!(res, Err(QuotaError::InsufficientQuota));
    }
}

