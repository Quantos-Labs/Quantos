use crate::types::transaction::PriorityBoost;

pub const BOOST_BASE: u64 = 1_000;

pub fn boost_factor(boost: &Option<PriorityBoost>) -> f64 {
    let Some(b) = boost else { return 0.0; };
    if b.locked_tokens < BOOST_BASE || b.lock_duration_blocks == 0 {
        return 0.0;
    }
    let ratio = (b.locked_tokens as f64) / (BOOST_BASE as f64);
    let log2 = ratio.log2().max(0.0);
    log2 * (1.0 / (b.lock_duration_blocks as f64))
}

