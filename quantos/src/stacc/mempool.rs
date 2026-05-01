use std::collections::HashMap;

use crate::mempool::{MempoolError, MempoolResult};
use crate::stacc::{ActivationLedger, QuotaManager, StakeProvider, AncienneteProvider, WfqScheduler};
use crate::stacc::cu_metering::{BLOCK_CU_LIMIT, clamp_tx_cu};
use crate::types::{Address, SignedTransaction};

pub const MAX_PENDING_CU: u64 = 10 * BLOCK_CU_LIMIT;
pub const FLOOR_PENDING: u64 = 10_000;

pub struct StaccAdmission<S: StakeProvider, A: AncienneteProvider> {
    pub activation: ActivationLedger,
    pub quota: QuotaManager<S, A>,
    pub scheduler: WfqScheduler<S, A>,
    pending_cu_by_addr: HashMap<Address, u64>,
    pending_cu_total: u64,
}

impl<S: StakeProvider + Clone, A: AncienneteProvider + Clone> StaccAdmission<S, A> {
    pub fn new(activation: ActivationLedger, quota: QuotaManager<S, A>) -> Self {
        let scheduler = WfqScheduler::new(quota.clone());
        Self {
            activation,
            quota,
            scheduler,
            pending_cu_by_addr: HashMap::new(),
            pending_cu_total: 0,
        }
    }

    fn max_pending_for_addr(&self, addr: &Address, now_block: u64) -> u64 {
        let q = self.quota.quota_total(addr, now_block);
        (2 * q).max(FLOOR_PENDING)
    }

    pub fn admit(&mut self, tx: SignedTransaction, now_block: u64) -> MempoolResult<()> {
        let sender = tx.transaction.from;
        if !self.activation.is_active(&sender) {
            return Err(MempoolError::InvalidTransaction("STACC: address not activated".into()));
        }

        let cu = clamp_tx_cu(tx.transaction.max_compute_units);
        // Quota check (token bucket).
        self.quota.try_consume(sender, cu, now_block)
            .map_err(|_| MempoolError::InvalidTransaction("STACC: insufficient CU quota".into()))?;

        // Mempool caps.
        let per_addr = self.pending_cu_by_addr.get(&sender).copied().unwrap_or(0);
        let per_addr_max = self.max_pending_for_addr(&sender, now_block);
        if per_addr.saturating_add(cu) > per_addr_max {
            return Err(MempoolError::MempoolFull);
        }
        if self.pending_cu_total.saturating_add(cu) > MAX_PENDING_CU {
            return Err(MempoolError::MempoolFull);
        }

        self.pending_cu_by_addr.insert(sender, per_addr.saturating_add(cu));
        self.pending_cu_total = self.pending_cu_total.saturating_add(cu);
        self.scheduler.insert(tx, now_block);
        Ok(())
    }

    pub fn pop_next(&mut self) -> Option<SignedTransaction> {
        let tx = self.scheduler.pop_next()?;
        let sender = tx.transaction.from;
        let cu = clamp_tx_cu(tx.transaction.max_compute_units);
        if let Some(v) = self.pending_cu_by_addr.get_mut(&sender) {
            *v = v.saturating_sub(cu);
        }
        self.pending_cu_total = self.pending_cu_total.saturating_sub(cu);
        Some(tx)
    }

    pub fn pending_len(&self) -> usize {
        self.scheduler.len()
    }
}

