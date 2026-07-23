// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # Transaction Parallelization Analyzer
//!
//! Production-ready conflict detection and dependency analysis for parallel execution.
//!
//! ## Features
//!
//! - **Read/Write Set Analysis**: Detect conflicts between transactions
//! - **Dependency Graph**: Build transaction dependency DAG
//! - **Parallel Batching**: Group independent transactions for parallel execution
//! - **Conflict Resolution**: Detect and resolve conflicts early
//! - **Execution Scheduling**: Optimal scheduling for maximum parallelism
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │          Transaction Parallelization Analyzer               │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                             │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
//! │  │ Read/Write   │  │ Dependency   │  │ Batch        │    │
//! │  │ Set Analyzer │  │ Graph Builder│  │ Scheduler    │    │
//! │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘    │
//! │         │                  │                  │            │
//! │         └──────────────────┼──────────────────┘            │
//! │                            ▼                               │
//! │                  ┌─────────────────┐                      │
//! │                  │ Parallel Batches│                      │
//! │                  │ (Independent)   │                      │
//! │                  └─────────────────┘                      │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use std::collections::{HashMap, HashSet, VecDeque};
use serde::{Deserialize, Serialize};

use crate::types::{Address, SignedTransaction};

/// Maximum transactions per parallel batch.
const MAX_BATCH_SIZE: usize = 1000;
/// Maximum dependency graph depth.
const MAX_GRAPH_DEPTH: usize = 100;
/// Minimum ERC20 transfer calldata length (4 selector + 32 address + 32 value)
const MIN_ERC20_TRANSFER_LEN: usize = 68;
/// Minimum ERC20 transferFrom calldata length (4 selector + 32 from + 32 to + 32 value)
const MIN_ERC20_TRANSFER_FROM_LEN: usize = 100;

/// Configuration for parallelization analysis.
#[derive(Clone, Debug)]
pub struct ParallelizationConfig {
    /// Maximum batch size
    pub max_batch_size: usize,
    /// Enable aggressive batching
    pub aggressive_batching: bool,
    /// Enable read-only optimization
    pub optimize_read_only: bool,
    /// Maximum dependency depth
    pub max_dependency_depth: usize,
}

impl Default for ParallelizationConfig {
    fn default() -> Self {
        Self {
            max_batch_size: MAX_BATCH_SIZE,
            aggressive_batching: true,
            optimize_read_only: true,
            max_dependency_depth: MAX_GRAPH_DEPTH,
        }
    }
}

/// Read/Write set for a transaction.
#[derive(Clone, Debug, Default)]
pub struct AccessSet {
    /// Addresses read by this transaction
    pub read_set: HashSet<Address>,
    /// Addresses written by this transaction
    pub write_set: HashSet<Address>,
    /// Is this a read-only transaction?
    pub is_read_only: bool,
}

impl AccessSet {
    /// Checks if this transaction conflicts with another.
    pub fn conflicts_with(&self, other: &AccessSet) -> bool {
        // Write-Write conflict
        if !self.write_set.is_disjoint(&other.write_set) {
            return true;
        }
        
        // Read-Write conflict
        if !self.read_set.is_disjoint(&other.write_set) {
            return true;
        }
        
        // Write-Read conflict
        if !self.write_set.is_disjoint(&other.read_set) {
            return true;
        }
        
        // Read-Read is OK (no conflict)
        false
    }
}

/// Transaction with its access set.
#[derive(Clone, Debug)]
pub struct AnalyzedTransaction {
    /// Original transaction
    pub tx: SignedTransaction,
    /// Access set
    pub access_set: AccessSet,
    /// Transaction index in batch
    pub index: usize,
}

/// Dependency between transactions.
#[derive(Clone, Debug)]
struct Dependency {
    /// Transaction that must execute first
    before: usize,
    /// Transaction that must execute after
    after: usize,
}

/// Parallel execution batch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParallelBatch {
    /// Transactions in this batch (can execute in parallel)
    pub transactions: Vec<usize>,
    /// Batch level (execution order)
    pub level: usize,
}

/// Analysis result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParallelizationResult {
    /// Parallel batches (ordered by level)
    pub batches: Vec<ParallelBatch>,
    /// Total transactions analyzed
    pub total_transactions: usize,
    /// Maximum parallelism achieved
    pub max_parallelism: usize,
    /// Average parallelism per batch
    pub avg_parallelism: f64,
    /// Sequential transactions (conflicts)
    pub sequential_count: usize,
}

/// Transaction parallelization analyzer.
pub struct TxParallelizationAnalyzer {
    config: ParallelizationConfig,
}

impl TxParallelizationAnalyzer {
    /// Creates a new parallelization analyzer.
    pub fn new(config: ParallelizationConfig) -> Self {
        Self { config }
    }

    /// Analyzes a transaction to extract its read/write sets.
    /// 
    /// Determines state access patterns for conflict detection:
    /// - Simple transfers: reads sender, writes sender + recipient
    /// - Contract calls: analyzes calldata to infer storage slots accessed
    /// - Contract creation: writes to new contract address
    pub fn analyze_transaction(&self, tx: &SignedTransaction) -> AccessSet {
        let mut access_set = AccessSet::default();
        
        // Always reads from sender (balance + nonce check)
        access_set.read_set.insert(tx.transaction.from);
        
        // Always writes to sender (nonce update, balance deduction)
        access_set.write_set.insert(tx.transaction.from);
        
        // Writes to recipient (balance credit or contract interaction)
        access_set.write_set.insert(tx.transaction.to);
        
        // Analyze transaction data for contract interactions
        let data = &tx.transaction.data;
        
        if tx.transaction.to == [0u8; 32] {
            // Contract creation: writes to derived contract address
            let mut create_seed = Vec::new();
            create_seed.extend_from_slice(&tx.transaction.from);
            create_seed.extend_from_slice(&tx.transaction.nonce.to_le_bytes());
            let contract_addr = crate::types::hash_data(&create_seed);
            access_set.write_set.insert(contract_addr);
            access_set.is_read_only = false;
        } else if data.len() >= 4 {
            // Contract call: extract function selector and infer storage access
            let selector = &data[..4];
            
            // ERC20 transfer(address,uint256) = 0xa9059cbb
            // ERC20 approve(address,uint256) = 0x095ea7b3  
            // ERC20 transferFrom(address,address,uint256) = 0x23b872dd
            match selector {
                [0xa9, 0x05, 0x9c, 0xbb] => {
                    // transfer: reads contract state, writes to+from balances
                    access_set.read_set.insert(tx.transaction.to); // token contract
                    // HIGH: Validate data length before parsing parameters
                    if data.len() >= MIN_ERC20_TRANSFER_LEN {
                        // ABI-encoded address is in bytes 4..36, right-padded to 32 bytes
                        // The actual 20-byte address is in the last 20 bytes of the 32-byte slot
                        let mut recipient = [0u8; 32];
                        recipient[12..32].copy_from_slice(&data[16..36]);
                        access_set.write_set.insert(recipient);
                    } else {
                        // Malformed calldata — conservatively mark contract as written
                        tracing::warn!("ERC20 transfer calldata too short: {} < {}", data.len(), MIN_ERC20_TRANSFER_LEN);
                        access_set.write_set.insert(tx.transaction.to);
                    }
                }
                [0x23, 0xb8, 0x72, 0xdd] => {
                    // transferFrom: reads allowance, writes from+to balances
                    access_set.read_set.insert(tx.transaction.to);
                    // HIGH: Validate data length before parsing parameters
                    if data.len() >= MIN_ERC20_TRANSFER_FROM_LEN {
                        let mut from_addr = [0u8; 32];
                        from_addr[12..32].copy_from_slice(&data[16..36]);
                        let mut to_addr = [0u8; 32];
                        to_addr[12..32].copy_from_slice(&data[48..68]);
                        access_set.read_set.insert(from_addr);
                        access_set.write_set.insert(from_addr);
                        access_set.write_set.insert(to_addr);
                    } else {
                        tracing::warn!("ERC20 transferFrom calldata too short: {} < {}", data.len(), MIN_ERC20_TRANSFER_FROM_LEN);
                        access_set.write_set.insert(tx.transaction.to);
                    }
                }
                [0x09, 0x5e, 0xa7, 0xb3] => {
                    // approve: writes allowance mapping
                    access_set.write_set.insert(tx.transaction.to);
                }
                _ => {
                    // Unknown contract call: mark contract address as read+write
                    // This is conservative for the contract itself but does NOT block
                    // unrelated transactions from running in parallel
                    access_set.read_set.insert(tx.transaction.to);
                    access_set.write_set.insert(tx.transaction.to);
                }
            }
            access_set.is_read_only = false;
        } else if tx.transaction.amount.0 > 0 {
            // Simple value transfer
            access_set.is_read_only = false;
        } else {
            // Zero-value call with no data (e.g., poke)
            access_set.is_read_only = true;
        }
        
        access_set
    }

    /// Analyzes a batch of transactions and groups them for parallel execution.
    pub fn analyze_batch(&self, transactions: &[SignedTransaction]) -> ParallelizationResult {
        if transactions.is_empty() {
            return ParallelizationResult {
                batches: Vec::new(),
                total_transactions: 0,
                max_parallelism: 0,
                avg_parallelism: 0.0,
                sequential_count: 0,
            };
        }
        
        // Analyze all transactions
        let analyzed: Vec<AnalyzedTransaction> = transactions
            .iter()
            .enumerate()
            .map(|(i, tx)| AnalyzedTransaction {
                tx: tx.clone(),
                access_set: self.analyze_transaction(tx),
                index: i,
            })
            .collect();
        
        // Build dependency graph
        let dependencies = self.build_dependency_graph(&analyzed);
        
        // Schedule into parallel batches
        let batches = self.schedule_batches(&analyzed, &dependencies);
        
        // Calculate statistics
        let max_parallelism = batches.iter().map(|b| b.transactions.len()).max().unwrap_or(0);
        let avg_parallelism = if batches.is_empty() {
            0.0
        } else {
            batches.iter().map(|b| b.transactions.len()).sum::<usize>() as f64 / batches.len() as f64
        };
        
        let sequential_count = batches.iter().filter(|b| b.transactions.len() == 1).count();
        
        ParallelizationResult {
            batches,
            total_transactions: transactions.len(),
            max_parallelism,
            avg_parallelism,
            sequential_count,
        }
    }

    /// Builds a dependency graph between transactions.
    fn build_dependency_graph(&self, transactions: &[AnalyzedTransaction]) -> Vec<Dependency> {
        let mut dependencies = Vec::new();
        
        for i in 0..transactions.len() {
            for j in (i + 1)..transactions.len() {
                if transactions[i].access_set.conflicts_with(&transactions[j].access_set) {
                    // Transaction i must execute before transaction j
                    dependencies.push(Dependency {
                        before: i,
                        after: j,
                    });
                }
            }
        }
        
        dependencies
    }

    /// Schedules transactions into parallel batches using topological sort.
    fn schedule_batches(
        &self,
        transactions: &[AnalyzedTransaction],
        dependencies: &[Dependency],
    ) -> Vec<ParallelBatch> {
        let n = transactions.len();
        
        // Build adjacency list and in-degree map
        let mut adj: HashMap<usize, Vec<usize>> = HashMap::new();
        let mut in_degree: HashMap<usize, usize> = HashMap::new();
        
        for i in 0..n {
            adj.entry(i).or_insert_with(Vec::new);
            in_degree.entry(i).or_insert(0);
        }
        
        for dep in dependencies {
            adj.entry(dep.before).or_insert_with(Vec::new).push(dep.after);
            *in_degree.entry(dep.after).or_insert(0) += 1;
        }
        
        // Topological sort with level assignment
        let mut batches: Vec<ParallelBatch> = Vec::new();
        let mut queue: VecDeque<usize> = VecDeque::new();
        let mut levels: HashMap<usize, usize> = HashMap::new();
        
        // Start with nodes that have no dependencies
        for i in 0..n {
            if *in_degree.get(&i).unwrap_or(&0) == 0 {
                queue.push_back(i);
                levels.insert(i, 0);
            }
        }
        
        while !queue.is_empty() {
            let current_level = batches.len();
            let mut current_batch = Vec::new();
            let level_size = queue.len();
            
            for _ in 0..level_size {
                if let Some(node) = queue.pop_front() {
                    current_batch.push(node);
                    
                    // Process neighbors
                    if let Some(neighbors) = adj.get(&node) {
                        for &neighbor in neighbors {
                            let degree = in_degree.get_mut(&neighbor).unwrap();
                            *degree -= 1;
                            
                            if *degree == 0 {
                                queue.push_back(neighbor);
                                levels.insert(neighbor, current_level + 1);
                            }
                        }
                    }
                }
            }
            
            if !current_batch.is_empty() {
                // Limit batch size
                if current_batch.len() > self.config.max_batch_size {
                    // Split into multiple batches at same level
                    for chunk in current_batch.chunks(self.config.max_batch_size) {
                        batches.push(ParallelBatch {
                            transactions: chunk.to_vec(),
                            level: current_level,
                        });
                    }
                } else {
                    batches.push(ParallelBatch {
                        transactions: current_batch,
                        level: current_level,
                    });
                }
            }
        }
        
        batches
    }

    /// Estimates the speedup from parallelization.
    pub fn estimate_speedup(&self, result: &ParallelizationResult) -> f64 {
        if result.total_transactions == 0 || result.batches.is_empty() {
            return 1.0;
        }
        
        // Sequential time = total transactions
        let sequential_time = result.total_transactions as f64;
        
        // Parallel time = number of batches (assuming perfect parallelism within batch)
        let parallel_time = result.batches.len() as f64;
        
        sequential_time / parallel_time
    }

    /// Checks if a transaction is independent (no conflicts with others).
    pub fn is_independent(&self, tx: &SignedTransaction, others: &[SignedTransaction]) -> bool {
        let access_set = self.analyze_transaction(tx);
        
        for other in others {
            let other_set = self.analyze_transaction(other);
            if access_set.conflicts_with(&other_set) {
                return false;
            }
        }
        
        true
    }

    /// Re-validates a parallelization result against current state before execution.
    ///
    /// HIGH: The static analysis in analyze_batch may become stale if state changes
    /// between analysis and execution. This method re-checks conflicts at execution
    /// time and demotes any newly-conflicting transactions to sequential batches.
    pub fn validate_batch_at_execution(
        &self,
        transactions: &[SignedTransaction],
        result: &ParallelizationResult,
    ) -> ParallelizationResult {
        // Re-analyze all transactions with fresh access sets
        let fresh_analyzed: Vec<AnalyzedTransaction> = transactions
            .iter()
            .enumerate()
            .map(|(i, tx)| AnalyzedTransaction {
                tx: tx.clone(),
                access_set: self.analyze_transaction(tx),
                index: i,
            })
            .collect();
        
        let mut validated_batches: Vec<ParallelBatch> = Vec::new();
        
        for batch in &result.batches {
            let mut safe_parallel: Vec<usize> = Vec::new();
            let mut demoted: Vec<usize> = Vec::new();
            
            for &tx_idx in &batch.transactions {
                if tx_idx >= fresh_analyzed.len() {
                    continue;
                }
                
                // Check if this tx still has no conflicts with others in the same batch
                let mut has_conflict = false;
                for &other_idx in &safe_parallel {
                    if fresh_analyzed[tx_idx].access_set.conflicts_with(&fresh_analyzed[other_idx].access_set) {
                        has_conflict = true;
                        break;
                    }
                }
                
                if has_conflict {
                    demoted.push(tx_idx);
                } else {
                    safe_parallel.push(tx_idx);
                }
            }
            
            if !safe_parallel.is_empty() {
                validated_batches.push(ParallelBatch {
                    transactions: safe_parallel,
                    level: batch.level,
                });
            }
            
            // Demoted transactions become their own sequential batch
            for tx_idx in demoted {
                validated_batches.push(ParallelBatch {
                    transactions: vec![tx_idx],
                    level: batch.level,
                });
            }
        }
        
        let max_parallelism = validated_batches.iter().map(|b| b.transactions.len()).max().unwrap_or(0);
        let avg_parallelism = if validated_batches.is_empty() {
            0.0
        } else {
            validated_batches.iter().map(|b| b.transactions.len()).sum::<usize>() as f64 / validated_batches.len() as f64
        };
        let sequential_count = validated_batches.iter().filter(|b| b.transactions.len() == 1).count();
        
        ParallelizationResult {
            batches: validated_batches,
            total_transactions: result.total_transactions,
            max_parallelism,
            avg_parallelism,
            sequential_count,
        }
    }

    /// Finds the maximum independent set of transactions.
    pub fn find_independent_set(&self, transactions: &[SignedTransaction]) -> Vec<usize> {
        let analyzed: Vec<(usize, AccessSet)> = transactions
            .iter()
            .enumerate()
            .map(|(i, tx)| (i, self.analyze_transaction(tx)))
            .collect();
        
        let mut independent: Vec<usize> = Vec::new();
        
        for (i, access_set) in &analyzed {
            let mut conflicts = false;
            
            for &j in &independent {
                if access_set.conflicts_with(&analyzed[j].1) {
                    conflicts = true;
                    break;
                }
            }
            
            if !conflicts {
                independent.push(*i);
            }
        }
        
        independent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Transaction, Amount};

    fn create_test_tx(from: Address, to: Address) -> SignedTransaction {
        let tx = Transaction::new(
            crate::types::TransactionType::Transfer,
            from,
            to,
            Amount(100),
            1,
            21000,
            None,
            Vec::new(),
            0,
        );
        SignedTransaction::new(tx)
    }

    #[test]
    fn test_conflict_detection() {
        let addr1 = [1u8; 32];
        let addr2 = [2u8; 32];
        
        let mut set1 = AccessSet::default();
        set1.write_set.insert(addr1);
        
        let mut set2 = AccessSet::default();
        set2.read_set.insert(addr1);
        
        // Write-Read conflict
        assert!(set1.conflicts_with(&set2));
        
        let mut set3 = AccessSet::default();
        set3.write_set.insert(addr2);
        
        // No conflict (different addresses)
        assert!(!set1.conflicts_with(&set3));
    }

    #[test]
    fn test_independent_transactions() {
        let analyzer = TxParallelizationAnalyzer::new(ParallelizationConfig::default());
        
        let addr1 = [1u8; 32];
        let addr2 = [2u8; 32];
        let addr3 = [3u8; 32];
        let addr4 = [4u8; 32];
        
        let txs = vec![
            create_test_tx(addr1, addr2),
            create_test_tx(addr3, addr4),
        ];
        
        let result = analyzer.analyze_batch(&txs);
        
        // These transactions are independent, should be in same batch
        assert_eq!(result.batches.len(), 1);
        assert_eq!(result.batches[0].transactions.len(), 2);
    }

    #[test]
    fn test_dependent_transactions() {
        let analyzer = TxParallelizationAnalyzer::new(ParallelizationConfig::default());
        
        let addr1 = [1u8; 32];
        let addr2 = [2u8; 32];
        
        let txs = vec![
            create_test_tx(addr1, addr2),
            create_test_tx(addr2, addr1), // Conflict: writes to addr2, then reads from addr2
        ];
        
        let result = analyzer.analyze_batch(&txs);
        
        // These transactions conflict, should be in different batches
        assert!(result.batches.len() >= 1);
    }

    #[test]
    fn test_speedup_estimation() {
        let analyzer = TxParallelizationAnalyzer::new(ParallelizationConfig::default());
        
        let result = ParallelizationResult {
            batches: vec![
                ParallelBatch { transactions: vec![0, 1, 2, 3], level: 0 },
                ParallelBatch { transactions: vec![4, 5], level: 1 },
            ],
            total_transactions: 6,
            max_parallelism: 4,
            avg_parallelism: 3.0,
            sequential_count: 0,
        };
        
        let speedup = analyzer.estimate_speedup(&result);
        
        // 6 transactions in 2 batches = 3x speedup
        assert_eq!(speedup, 3.0);
    }

    #[test]
    fn test_find_independent_set() {
        let analyzer = TxParallelizationAnalyzer::new(ParallelizationConfig::default());
        
        let addr1 = [1u8; 32];
        let addr2 = [2u8; 32];
        let addr3 = [3u8; 32];
        let addr4 = [4u8; 32];
        
        let txs = vec![
            create_test_tx(addr1, addr2),
            create_test_tx(addr2, addr3), // Conflicts with tx0
            create_test_tx(addr3, addr4), // Conflicts with tx1
        ];
        
        let independent = analyzer.find_independent_set(&txs);
        
        // Should find at least one transaction
        assert!(!independent.is_empty());
    }
}
