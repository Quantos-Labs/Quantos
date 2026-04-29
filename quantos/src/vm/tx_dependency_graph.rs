//! # Transaction Dependency Graph
//!
//! Optimal transaction scheduling based on dependency analysis.
//! Maximizes parallelism while respecting data dependencies.
//!
//! ## Features
//!
//! - **Dependency Detection**: Static and dynamic dependency analysis
//! - **Parallel Scheduling**: Execute independent transactions concurrently
//! - **Topological Ordering**: Respect dependency order
//! - **Conflict Graph**: Track read-write and write-write conflicts
//! - **Batch Optimization**: Group compatible transactions

use std::collections::{HashMap, HashSet, VecDeque, BinaryHeap};
use std::cmp::Ordering;
use parking_lot::{Mutex, RwLock};

use crate::types::{Hash, Address, SignedTransaction};
use crate::state::{StateError, StateResult};

/// Transaction ID for dependency tracking
pub type TxId = u64;

/// Dependency type between transactions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DependencyType {
    /// Read-After-Write (RAW) - true dependency
    ReadAfterWrite,
    /// Write-After-Read (WAR) - anti dependency
    WriteAfterRead,
    /// Write-After-Write (WAW) - output dependency
    WriteAfterWrite,
}

/// A dependency edge in the graph
#[derive(Debug, Clone)]
pub struct DependencyEdge {
    /// Source transaction
    pub from: TxId,
    /// Target transaction
    pub to: TxId,
    /// Type of dependency
    pub dep_type: DependencyType,
    /// Address causing dependency
    pub address: Address,
    /// Optional storage key
    pub storage_key: Option<Hash>,
}

/// Transaction node in dependency graph
#[derive(Clone)]
pub struct TxNode {
    /// Transaction ID
    pub id: TxId,
    /// Transaction hash
    pub hash: Hash,
    /// Read set (addresses read)
    pub read_set: HashSet<Address>,
    /// Write set (addresses written)
    pub write_set: HashSet<Address>,
    /// Storage read set
    pub storage_reads: HashSet<(Address, Hash)>,
    /// Storage write set
    pub storage_writes: HashSet<(Address, Hash)>,
    /// Incoming dependencies (transactions this depends on)
    pub dependencies: HashSet<TxId>,
    /// Outgoing dependencies (transactions depending on this)
    pub dependents: HashSet<TxId>,
    /// Priority (for scheduling)
    pub priority: i64,
    /// Gas estimate
    pub gas_estimate: u64,
    /// Original transaction
    pub transaction: SignedTransaction,
}

impl TxNode {
    pub fn new(id: TxId, transaction: SignedTransaction) -> Self {
        Self {
            id,
            hash: transaction.hash,
            read_set: HashSet::new(),
            write_set: HashSet::new(),
            storage_reads: HashSet::new(),
            storage_writes: HashSet::new(),
            dependencies: HashSet::new(),
            dependents: HashSet::new(),
            priority: 0,
            gas_estimate: transaction.transaction.gas_limit,
            transaction,
        }
    }
    
    /// Analyzes transaction to populate read/write sets
    pub fn analyze(&mut self) {
        let tx = &self.transaction.transaction;
        
        // Sender is always read and written (balance, nonce)
        self.read_set.insert(tx.from);
        self.write_set.insert(tx.from);
        
        // Receiver is read and written
        if tx.from != tx.to {
            self.read_set.insert(tx.to);
            self.write_set.insert(tx.to);
        }
        
        // Contract calls may have additional dependencies
        // This would be determined by static analysis of contract code
    }
    
    /// Checks if this transaction conflicts with another
    pub fn conflicts_with(&self, other: &TxNode) -> Option<DependencyType> {
        // Write-Write conflict
        if !self.write_set.is_disjoint(&other.write_set) {
            return Some(DependencyType::WriteAfterWrite);
        }
        
        // Read-Write conflict (RAW if we read what they write)
        if !self.read_set.is_disjoint(&other.write_set) {
            return Some(DependencyType::ReadAfterWrite);
        }
        
        // Write-Read conflict (WAR if we write what they read)
        if !self.write_set.is_disjoint(&other.read_set) {
            return Some(DependencyType::WriteAfterRead);
        }
        
        // Storage conflicts
        if !self.storage_writes.is_disjoint(&other.storage_writes) {
            return Some(DependencyType::WriteAfterWrite);
        }
        
        if !self.storage_reads.is_disjoint(&other.storage_writes) {
            return Some(DependencyType::ReadAfterWrite);
        }
        
        None
    }
    
    /// Returns number of unresolved dependencies
    pub fn dependency_count(&self) -> usize {
        self.dependencies.len()
    }
    
    /// Checks if ready to execute (no dependencies)
    pub fn is_ready(&self) -> bool {
        self.dependencies.is_empty()
    }
}

/// Scheduled transaction with priority
#[derive(Clone)]
struct ScheduledTx {
    id: TxId,
    priority: i64,
    gas: u64,
}

impl PartialEq for ScheduledTx {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for ScheduledTx {}

impl PartialOrd for ScheduledTx {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScheduledTx {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first, then lower gas (faster execution)
        self.priority.cmp(&other.priority)
            .then_with(|| other.gas.cmp(&self.gas))
    }
}

/// Execution batch of independent transactions
#[derive(Clone, Default)]
pub struct ExecutionBatch {
    /// Transactions in this batch (can be executed in parallel)
    pub transactions: Vec<TxId>,
    /// Total gas in batch
    pub total_gas: u64,
    /// Batch priority
    pub priority: i64,
}

impl ExecutionBatch {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn add(&mut self, tx: &TxNode) {
        self.transactions.push(tx.id);
        self.total_gas += tx.gas_estimate;
        self.priority = self.priority.max(tx.priority);
    }
    
    pub fn len(&self) -> usize {
        self.transactions.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

/// Dependency graph configuration
#[derive(Clone, Debug)]
pub struct DependencyGraphConfig {
    /// Maximum transactions in graph
    pub max_transactions: usize,
    /// Maximum batch size
    pub max_batch_size: usize,
    /// Maximum gas per batch
    pub max_batch_gas: u64,
    /// Enable storage dependency tracking
    pub track_storage: bool,
    /// Priority boost for high-value transactions
    pub value_priority_factor: f64,
}

impl Default for DependencyGraphConfig {
    fn default() -> Self {
        Self {
            max_transactions: 100_000,
            max_batch_size: 1000,
            max_batch_gas: 30_000_000,
            track_storage: true,
            value_priority_factor: 0.001,
        }
    }
}

/// Transaction Dependency Graph
pub struct TxDependencyGraph {
    config: DependencyGraphConfig,
    /// All transaction nodes
    nodes: RwLock<HashMap<TxId, TxNode>>,
    /// Transaction ID counter
    id_counter: Mutex<TxId>,
    /// Hash to ID mapping
    hash_to_id: RwLock<HashMap<Hash, TxId>>,
    /// Address to transactions mapping (for fast conflict detection)
    address_index: RwLock<HashMap<Address, HashSet<TxId>>>,
    /// Storage key to transactions mapping
    storage_index: RwLock<HashMap<(Address, Hash), HashSet<TxId>>>,
    /// Statistics
    stats: Mutex<GraphStats>,
}

/// Graph statistics
#[derive(Default, Clone, Debug)]
pub struct GraphStats {
    pub transactions_added: u64,
    pub dependencies_detected: u64,
    pub batches_created: u64,
    pub parallel_txs: u64,
    pub sequential_txs: u64,
}

impl TxDependencyGraph {
    pub fn new(config: DependencyGraphConfig) -> Self {
        Self {
            config,
            nodes: RwLock::new(HashMap::new()),
            id_counter: Mutex::new(0),
            hash_to_id: RwLock::new(HashMap::new()),
            address_index: RwLock::new(HashMap::new()),
            storage_index: RwLock::new(HashMap::new()),
            stats: Mutex::new(GraphStats::default()),
        }
    }
    
    /// Adds a transaction to the graph
    pub fn add_transaction(&self, transaction: SignedTransaction) -> StateResult<TxId> {
        let nodes_count = self.nodes.read().len();
        if nodes_count >= self.config.max_transactions {
            return Err(StateError::ExecutionError("Graph full".to_string()));
        }
        
        // Generate ID
        let id = {
            let mut counter = self.id_counter.lock();
            *counter += 1;
            *counter
        };
        
        // Create and analyze node
        let mut node = TxNode::new(id, transaction.clone());
        node.analyze();
        
        // Calculate priority
        node.priority = self.calculate_priority(&node);
        
        // Detect dependencies with existing transactions
        self.detect_dependencies(&mut node)?;
        
        // Update indices
        self.update_indices(&node);
        
        // Store node
        self.hash_to_id.write().insert(transaction.hash, id);
        self.nodes.write().insert(id, node);
        
        self.stats.lock().transactions_added += 1;
        
        Ok(id)
    }
    
    /// Adds multiple transactions in batch
    pub fn add_transactions(&self, transactions: Vec<SignedTransaction>) -> Vec<StateResult<TxId>> {
        transactions.into_iter()
            .map(|tx| self.add_transaction(tx))
            .collect()
    }
    
    /// Calculates priority for a transaction
    fn calculate_priority(&self, node: &TxNode) -> i64 {
        let tx = &node.transaction.transaction;
        
        // Base priority from gas price
        let gas_priority = tx.gas_price as i64;
        
        // Boost for high-value transactions
        let value_boost = (tx.amount.0 as f64 * self.config.value_priority_factor) as i64;
        
        // Penalty for many dependencies (harder to schedule)
        let dep_penalty = (node.dependencies.len() as i64) * 10;
        
        gas_priority + value_boost - dep_penalty
    }
    
    /// Detects dependencies between a new node and existing nodes
    fn detect_dependencies(&self, node: &mut TxNode) -> StateResult<()> {
        let mut nodes = self.nodes.write();
        let address_index = self.address_index.read();
        
        // Find potentially conflicting transactions via address index
        let mut candidates: HashSet<TxId> = HashSet::new();
        
        for addr in node.read_set.iter().chain(node.write_set.iter()) {
            if let Some(txs) = address_index.get(addr) {
                candidates.extend(txs);
            }
        }
        
        // Check each candidate for actual conflict
        for &other_id in &candidates {
            if let Some(other) = nodes.get_mut(&other_id) {
                if let Some(dep_type) = node.conflicts_with(other) {
                    // Determine dependency direction based on type
                    match dep_type {
                        DependencyType::ReadAfterWrite => {
                            // We depend on them (they write, we read)
                            node.dependencies.insert(other_id);
                            other.dependents.insert(node.id);
                        }
                        DependencyType::WriteAfterRead | DependencyType::WriteAfterWrite => {
                            // They depend on us (we should complete first)
                            // But since they're already in graph, we depend on them
                            node.dependencies.insert(other_id);
                            other.dependents.insert(node.id);
                        }
                    }
                    
                    self.stats.lock().dependencies_detected += 1;
                }
            }
        }
        
        Ok(())
    }
    
    /// Updates address and storage indices
    fn update_indices(&self, node: &TxNode) {
        let mut address_index = self.address_index.write();
        
        for addr in node.read_set.iter().chain(node.write_set.iter()) {
            address_index.entry(*addr)
                .or_insert_with(HashSet::new)
                .insert(node.id);
        }
        
        if self.config.track_storage {
            let mut storage_index = self.storage_index.write();
            
            for key in node.storage_reads.iter().chain(node.storage_writes.iter()) {
                storage_index.entry(*key)
                    .or_insert_with(HashSet::new)
                    .insert(node.id);
            }
        }
    }
    
    /// Generates optimal execution schedule
    pub fn schedule(&self) -> Vec<ExecutionBatch> {
        let mut batches = Vec::new();
        let mut completed: HashSet<TxId> = HashSet::new();
        let nodes = self.nodes.read();
        
        // Clone dependency info for modification
        let remaining_deps: HashMap<TxId, HashSet<TxId>> = nodes.iter()
            .map(|(id, node)| (*id, node.dependencies.clone()))
            .collect();
        
        while completed.len() < nodes.len() {
            // Find ready transactions (no unmet dependencies)
            let mut ready: BinaryHeap<ScheduledTx> = BinaryHeap::new();
            
            for (id, deps) in &remaining_deps {
                if !completed.contains(id) && deps.is_subset(&completed) {
                    if let Some(node) = nodes.get(id) {
                        ready.push(ScheduledTx {
                            id: *id,
                            priority: node.priority,
                            gas: node.gas_estimate,
                        });
                    }
                }
            }
            
            if ready.is_empty() {
                // Cycle detected — break lowest-priority edge to make progress (v9)
                let remaining: Vec<TxId> = remaining_deps.keys()
                    .filter(|id| !completed.contains(id))
                    .copied()
                    .collect();
                if remaining.is_empty() {
                    break;
                }
                // Find the node with fewest unmet deps and force it ready
                let forced = remaining.iter()
                    .filter_map(|id| {
                        let unmet = remaining_deps.get(id)?
                            .iter()
                            .filter(|d| !completed.contains(d))
                            .count();
                        Some((*id, unmet))
                    })
                    .min_by_key(|(_, unmet)| *unmet)
                    .map(|(id, _)| id);
                if let Some(forced_id) = forced {
                    tracing::warn!("Breaking dependency cycle: forcing tx {} into batch (v9)", forced_id);
                    let mut forced_batch = ExecutionBatch::new();
                    if let Some(node) = nodes.get(&forced_id) {
                        forced_batch.add(node);
                    }
                    completed.insert(forced_id);
                    self.stats.lock().sequential_txs += 1;
                    batches.push(forced_batch);
                    continue;
                }
                break;
            }
            
            // Create batch from ready transactions
            let batch = self.create_batch(&ready, &nodes);
            
            // Mark batch transactions as completed
            for &tx_id in &batch.transactions {
                completed.insert(tx_id);
            }
            
            if batch.len() > 1 {
                self.stats.lock().parallel_txs += batch.len() as u64;
            } else {
                self.stats.lock().sequential_txs += batch.len() as u64;
            }
            
            batches.push(batch);
        }
        
        self.stats.lock().batches_created += batches.len() as u64;
        
        batches
    }
    
    /// Creates a batch from ready transactions
    fn create_batch(
        &self,
        ready: &BinaryHeap<ScheduledTx>,
        nodes: &HashMap<TxId, TxNode>,
    ) -> ExecutionBatch {
        let mut batch = ExecutionBatch::new();
        let mut batch_write_set: HashSet<Address> = HashSet::new();
        let mut batch_read_set: HashSet<Address> = HashSet::new();
        
        // Greedily add transactions that don't conflict within the batch
        for scheduled in ready.iter() {
            if batch.len() >= self.config.max_batch_size {
                break;
            }
            
            if let Some(node) = nodes.get(&scheduled.id) {
                if batch.total_gas + node.gas_estimate > self.config.max_batch_gas {
                    continue;
                }
                
                // Check if this transaction conflicts with batch
                let conflicts = !node.write_set.is_disjoint(&batch_write_set)
                    || !node.write_set.is_disjoint(&batch_read_set)
                    || !node.read_set.is_disjoint(&batch_write_set);
                
                if !conflicts {
                    batch.add(node);
                    batch_write_set.extend(&node.write_set);
                    batch_read_set.extend(&node.read_set);
                }
            }
        }
        
        // Ensure at least one transaction per batch
        if batch.is_empty() {
            if let Some(scheduled) = ready.peek() {
                if let Some(node) = nodes.get(&scheduled.id) {
                    batch.add(node);
                }
            }
        }
        
        batch
    }
    
    /// Gets topological ordering of transactions.
    /// Returns error if the graph contains cycles (v9).
    pub fn topological_order(&self) -> StateResult<Vec<TxId>> {
        let nodes = self.nodes.read();
        let mut in_degree: HashMap<TxId, usize> = HashMap::new();
        let mut result = Vec::new();
        let mut queue: VecDeque<TxId> = VecDeque::new();
        
        // Calculate in-degrees
        for (id, node) in nodes.iter() {
            in_degree.insert(*id, node.dependencies.len());
            if node.dependencies.is_empty() {
                queue.push_back(*id);
            }
        }
        
        // Kahn's algorithm
        while let Some(id) = queue.pop_front() {
            result.push(id);
            
            if let Some(node) = nodes.get(&id) {
                for &dependent in &node.dependents {
                    if let Some(degree) = in_degree.get_mut(&dependent) {
                        *degree -= 1;
                        if *degree == 0 {
                            queue.push_back(dependent);
                        }
                    }
                }
            }
        }
        
        // Detect cycles: if not all nodes were visited, a cycle exists (v9)
        if result.len() < nodes.len() {
            let cycled: Vec<TxId> = nodes.keys()
                .filter(|id| !result.contains(id))
                .copied()
                .collect();
            tracing::warn!("Cycle detected in dependency graph involving {} transactions", cycled.len());
            return Err(StateError::ExecutionError(
                format!("Dependency cycle detected involving {} transactions", cycled.len())
            ));
        }
        
        Ok(result)
    }
    
    /// Removes a transaction from the graph
    pub fn remove_transaction(&self, tx_id: TxId) -> StateResult<()> {
        let mut nodes = self.nodes.write();
        
        if let Some(node) = nodes.remove(&tx_id) {
            // Remove from hash index
            self.hash_to_id.write().remove(&node.hash);
            
            // Update address index
            {
                let mut address_index = self.address_index.write();
                for addr in node.read_set.iter().chain(node.write_set.iter()) {
                    if let Some(txs) = address_index.get_mut(addr) {
                        txs.remove(&tx_id);
                    }
                }
            }
            
            // Update dependencies of other nodes
            for (&_other_id, other_node) in nodes.iter_mut() {
                other_node.dependencies.remove(&tx_id);
                other_node.dependents.remove(&tx_id);
            }
        }
        
        Ok(())
    }
    
    /// Clears the graph
    pub fn clear(&self) {
        self.nodes.write().clear();
        self.hash_to_id.write().clear();
        self.address_index.write().clear();
        self.storage_index.write().clear();
        *self.id_counter.lock() = 0;
    }
    
    /// Gets transaction by ID
    pub fn get_transaction(&self, tx_id: TxId) -> Option<SignedTransaction> {
        self.nodes.read().get(&tx_id).map(|n| n.transaction.clone())
    }
    
    /// Gets transaction ID by hash
    pub fn get_id_by_hash(&self, hash: &Hash) -> Option<TxId> {
        self.hash_to_id.read().get(hash).copied()
    }
    
    /// Returns number of transactions
    pub fn len(&self) -> usize {
        self.nodes.read().len()
    }
    
    /// Checks if empty
    pub fn is_empty(&self) -> bool {
        self.nodes.read().is_empty()
    }
    
    /// Returns parallelism ratio
    pub fn parallelism_ratio(&self) -> f64 {
        let stats = self.stats.lock();
        let total = stats.parallel_txs + stats.sequential_txs;
        if total == 0 {
            0.0
        } else {
            stats.parallel_txs as f64 / total as f64
        }
    }
    
    /// Returns statistics
    pub fn stats(&self) -> GraphStats {
        self.stats.lock().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Transaction, TransactionType, Amount};
    
    fn make_tx(from: Address, to: Address, nonce: u64) -> SignedTransaction {
        let tx = Transaction::new(
            TransactionType::Transfer,
            from,
            to,
            Amount(100),
            nonce,
            21000,
            1,
            Vec::new(),
            0,
        );
        SignedTransaction::new(tx)
    }
    
    #[test]
    fn test_independent_transactions() {
        let graph = TxDependencyGraph::new(DependencyGraphConfig::default());
        
        // Add independent transactions (different addresses)
        let tx1 = make_tx([1u8; 32], [2u8; 32], 0);
        let tx2 = make_tx([3u8; 32], [4u8; 32], 0);
        let tx3 = make_tx([5u8; 32], [6u8; 32], 0);
        
        graph.add_transaction(tx1).unwrap();
        graph.add_transaction(tx2).unwrap();
        graph.add_transaction(tx3).unwrap();
        
        let batches = graph.schedule();
        
        // All should be in same batch (parallel)
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 3);
    }
    
    #[test]
    fn test_dependent_transactions() {
        let graph = TxDependencyGraph::new(DependencyGraphConfig::default());
        
        // Add transactions with same sender (dependent)
        let tx1 = make_tx([1u8; 32], [2u8; 32], 0);
        let tx2 = make_tx([1u8; 32], [3u8; 32], 1);
        let tx3 = make_tx([1u8; 32], [4u8; 32], 2);
        
        graph.add_transaction(tx1).unwrap();
        graph.add_transaction(tx2).unwrap();
        graph.add_transaction(tx3).unwrap();
        
        let batches = graph.schedule();
        
        // Should be sequential (3 batches)
        assert_eq!(batches.len(), 3);
    }
    
    #[test]
    fn test_topological_order() {
        let graph = TxDependencyGraph::new(DependencyGraphConfig::default());
        
        let tx1 = make_tx([1u8; 32], [2u8; 32], 0);
        let tx2 = make_tx([1u8; 32], [3u8; 32], 1);
        
        let id1 = graph.add_transaction(tx1).unwrap();
        let id2 = graph.add_transaction(tx2).unwrap();
        
        let order = graph.topological_order().unwrap();
        
        // tx1 should come before tx2
        let pos1 = order.iter().position(|&id| id == id1).unwrap();
        let pos2 = order.iter().position(|&id| id == id2).unwrap();
        
        assert!(pos1 < pos2);
    }
}
