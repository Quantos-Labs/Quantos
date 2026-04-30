use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, VecDeque};

use crate::types::{Address, Hash, SignedTransaction};
use crate::stacc::{QuotaManager, StakeProvider, AncienneteProvider};
use crate::stacc::priority_boost::boost_factor;

#[derive(Clone, Debug)]
pub struct ScheduledTx {
    pub tx: SignedTransaction,
    pub arrival_seq: u64,
    pub start: f64,
    pub finish: f64,
}

#[derive(Clone, Debug)]
struct Flow {
    queue: VecDeque<ScheduledTx>,
    last_finish: f64,
}

#[derive(Clone, Debug)]
struct HeapEntry {
    finish: f64,
    addr: Address,
    arrival_seq: u64,
}

impl PartialEq for HeapEntry {
    fn eq(&self, other: &Self) -> bool {
        self.finish.to_bits() == other.finish.to_bits()
            && self.addr == other.addr
            && self.arrival_seq == other.arrival_seq
    }
}
impl Eq for HeapEntry {}
impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse for min-heap behavior.
        match other.finish.partial_cmp(&self.finish).unwrap_or(Ordering::Equal) {
            Ordering::Equal => other.arrival_seq.cmp(&self.arrival_seq).then_with(|| other.addr.cmp(&self.addr)),
            o => o,
        }
    }
}

#[derive(Clone)]
pub struct WfqScheduler<S: StakeProvider, A: AncienneteProvider> {
    quota: QuotaManager<S, A>,
    virtual_clock: f64,
    flows: HashMap<Address, Flow>,
    heap: BinaryHeap<HeapEntry>,
    next_seq: u64,
}

impl<S: StakeProvider, A: AncienneteProvider> WfqScheduler<S, A> {
    pub fn new(quota: QuotaManager<S, A>) -> Self {
        Self {
            quota,
            virtual_clock: 0.0,
            flows: HashMap::new(),
            heap: BinaryHeap::new(),
            next_seq: 1,
        }
    }

    fn weight(&self, addr: &Address, now_block: u64, tx: &SignedTransaction) -> f64 {
        let base = self.quota.quota_base(addr, now_block) as f64;
        let stake = self.quota.quota_stake(addr) as f64;
        let boost = boost_factor(&tx.transaction.boost);
        // Weight must be >0 for fairness. Ensure minimal positive weight.
        (base + stake + boost).max(1.0)
    }

    pub fn insert(&mut self, tx: SignedTransaction, now_block: u64) {
        let addr = tx.transaction.from;
        let arrival_seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);

        let w = self.weight(&addr, now_block, &tx);
        let cu = tx.transaction.max_compute_units as f64;

        let flow = self.flows.entry(addr).or_insert(Flow {
            queue: VecDeque::new(),
            last_finish: self.virtual_clock,
        });

        let start = flow.last_finish.max(self.virtual_clock);
        let finish = start + (cu / w);
        flow.last_finish = finish;
        flow.queue.push_back(ScheduledTx { tx, arrival_seq, start, finish });

        // Only push/update heap for the head element (min finish per flow).
        if let Some(head) = flow.queue.front() {
            self.heap.push(HeapEntry { finish: head.finish, addr, arrival_seq: head.arrival_seq });
        }
    }

    pub fn pop_next(&mut self) -> Option<SignedTransaction> {
        loop {
            let entry = self.heap.pop()?;
            let flow = match self.flows.get_mut(&entry.addr) {
                Some(f) => f,
                None => continue,
            };
            let head = match flow.queue.front() {
                Some(h) => h,
                None => {
                    self.flows.remove(&entry.addr);
                    continue;
                }
            };

            // Stale heap entry guard (head changed).
            if head.arrival_seq != entry.arrival_seq {
                continue;
            }

            let scheduled = flow.queue.pop_front().unwrap();
            self.virtual_clock = self.virtual_clock.max(scheduled.start);

            if let Some(new_head) = flow.queue.front() {
                self.heap.push(HeapEntry {
                    finish: new_head.finish,
                    addr: entry.addr,
                    arrival_seq: new_head.arrival_seq,
                });
            } else {
                self.flows.remove(&entry.addr);
            }

            return Some(scheduled.tx);
        }
    }

    pub fn len(&self) -> usize {
        self.flows.values().map(|f| f.queue.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Amount, Transaction, TransactionType};

    #[derive(Clone)]
    struct TestStake;
    impl StakeProvider for TestStake {
        fn stake_of(&self, _addr: &Address) -> u128 { 0 }
        fn total_stake(&self) -> u128 { 0 }
    }
    #[derive(Clone)]
    struct TestAge;
    impl AncienneteProvider for TestAge {
        fn anciennete_factor(&self, _addr: &Address, _now_block: u64) -> f64 { 1.0 }
    }

    fn mk_tx(from: Address, nonce: u64, max_cu: u64) -> SignedTransaction {
        let tx = Transaction::new(
            TransactionType::Transfer,
            from,
            [9u8; 32],
            Amount(1),
            nonce,
            max_cu,
            None,
            Vec::new(),
            0,
        );
        SignedTransaction::new(tx)
    }

    #[test]
    fn wfq_basic_fifo_per_flow() {
        let quota = QuotaManager::new(TestStake, TestAge);
        let mut s = WfqScheduler::new(quota);
        let a = [1u8; 32];
        s.insert(mk_tx(a, 0, 10), 1);
        s.insert(mk_tx(a, 1, 10), 1);
        assert_eq!(s.pop_next().unwrap().transaction.nonce, 0);
        assert_eq!(s.pop_next().unwrap().transaction.nonce, 1);
    }
}

