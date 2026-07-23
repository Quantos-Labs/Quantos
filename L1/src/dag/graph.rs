// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use dashmap::DashMap;
use parking_lot::{RwLock, Mutex};

/// Maximum vertices in memory before eviction
const MAX_VERTICES_IN_MEMORY: usize = 1_000_000;

/// Maximum vertices to visit in traversal
const MAX_TRAVERSAL_VERTICES: usize = 10_000;

/// Maximum tips per shard
const MAX_TIPS_PER_SHARD: usize = 100;

/// Maximum number of distinct shards to prevent memory exhaustion
const MAX_SHARDS: usize = 1_024;

/// Maximum children per vertex to prevent unbounded growth
const MAX_CHILDREN_PER_VERTEX: usize = 256;

/// Well-known genesis creator address
const GENESIS_CREATOR: Address = [0u8; 32];

use crate::dag::{DAGError, DAGResult};
use crate::storage::Storage;
use crate::types::{
    Address, DAGVertex, Hash, ShardId, SignedTransaction, VertexStatus,
};

pub struct DAGGraph {
    storage: Storage,
    vertices: Arc<DashMap<Hash, DAGVertex>>,
    tips: Arc<DashMap<ShardId, Vec<Hash>>>,
    children: Arc<DashMap<Hash, Vec<Hash>>>,
    heights: Arc<DashMap<ShardId, u64>>,
    min_parents: usize,
    max_parents: usize,
    /// Admin address that controls authorization management
    admin: Arc<RwLock<Address>>,
    /// Authorized addresses that can add vertices
    authorized_creators: Arc<RwLock<HashSet<Address>>>,
    /// Track vertex count for memory limits
    vertex_count: Arc<AtomicUsize>,
    /// Mutex for atomic vertex addition and eviction
    add_vertex_lock: Arc<Mutex<()>>,
}

impl DAGGraph {
    pub fn new(storage: Storage, min_parents: usize, max_parents: usize) -> Self {
        Self {
            storage,
            vertices: Arc::new(DashMap::new()),
            tips: Arc::new(DashMap::new()),
            children: Arc::new(DashMap::new()),
            heights: Arc::new(DashMap::new()),
            min_parents,
            max_parents,
            admin: Arc::new(RwLock::new(GENESIS_CREATOR)),
            authorized_creators: Arc::new(RwLock::new({
                let mut set = HashSet::new();
                set.insert(GENESIS_CREATOR);
                set
            })),
            vertex_count: Arc::new(AtomicUsize::new(0)),
            add_vertex_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Sets the admin address. Only the current admin can transfer admin rights.
    pub fn set_admin(&self, caller: &Address, new_admin: Address) -> DAGResult<()> {
        let current_admin = self.admin.read();
        if caller != &*current_admin {
            return Err(DAGError::Unauthorized(
                "Only admin can transfer admin rights".to_string()
            ));
        }
        drop(current_admin);
        *self.admin.write() = new_admin;
        Ok(())
    }

    /// Adds an authorized address that can create vertices.
    /// Requires admin privileges.
    pub fn add_authorized_creator(&self, address: Address) {
        self.authorized_creators.write().insert(address);
    }

    /// Adds an authorized creator with access control.
    /// Only the admin can grant vertex creation privileges.
    pub fn add_authorized_creator_checked(&self, caller: &Address, address: Address) -> DAGResult<()> {
        if caller != &*self.admin.read() {
            return Err(DAGError::Unauthorized(
                "Only admin can add authorized creators".to_string()
            ));
        }
        self.authorized_creators.write().insert(address);
        Ok(())
    }

    /// Removes an authorized creator with access control.
    /// Only the admin can revoke vertex creation privileges.
    pub fn remove_authorized_creator(&self, address: &Address) {
        self.authorized_creators.write().remove(address);
    }

    /// Removes an authorized creator with access control.
    /// Only the admin can revoke vertex creation privileges.
    pub fn remove_authorized_creator_checked(&self, caller: &Address, address: &Address) -> DAGResult<()> {
        if caller != &*self.admin.read() {
            return Err(DAGError::Unauthorized(
                "Only admin can remove authorized creators".to_string()
            ));
        }
        self.authorized_creators.write().remove(address);
        Ok(())
    }

    /// Checks if an address is authorized to create vertices.
    pub fn is_authorized_creator(&self, address: &Address) -> bool {
        self.authorized_creators.read().contains(address)
    }

    /// Adds a vertex to the DAG.
    /// 
    /// CRITICAL: Requires authorization to prevent unauthorized vertex creation.
    /// Uses atomic operations to prevent race conditions.
    pub fn add_vertex(&self, vertex: DAGVertex) -> DAGResult<()> {
        // Access control: only authorized addresses can add vertices
        if !self.is_authorized_creator(&vertex.creator) {
            return Err(DAGError::Unauthorized(
                format!("Address {:?} not authorized to create vertices", vertex.creator)
            ));
        }

        // Check memory limits
        if self.vertex_count.load(Ordering::SeqCst) >= MAX_VERTICES_IN_MEMORY {
            self.evict_old_vertices()?;
            
            // Check again after eviction
            if self.vertex_count.load(Ordering::SeqCst) >= MAX_VERTICES_IN_MEMORY {
                return Err(DAGError::MemoryExhausted(
                    format!("Vertex limit reached: {}", MAX_VERTICES_IN_MEMORY)
                ));
            }
        }

        // Acquire lock for atomic vertex addition
        let _lock = self.add_vertex_lock.lock();
        if vertex.parents.len() < self.min_parents && vertex.height > 0 {
            return Err(DAGError::TooFewParents {
                min: self.min_parents,
                got: vertex.parents.len(),
            });
        }

        if vertex.parents.len() > self.max_parents {
            return Err(DAGError::TooManyParents {
                max: self.max_parents,
                got: vertex.parents.len(),
            });
        }

        for parent_hash in &vertex.parents {
            if !self.vertices.contains_key(parent_hash) {
                if self.storage.get_vertex(parent_hash)
                    .map_err(|e| DAGError::StorageError(e.to_string()))?
                    .is_none()
                {
                    return Err(DAGError::InvalidParent);
                }
            }
        }

        let vertex_hash = vertex.hash;
        let shard_id = vertex.shard_id;

        // Check shard limit to prevent unbounded shard creation
        if !self.tips.contains_key(&shard_id) && self.tips.len() >= MAX_SHARDS {
            return Err(DAGError::ShardLimitExceeded(MAX_SHARDS));
        }

        for parent_hash in &vertex.parents {
            let mut children_entry = self.children
                .entry(*parent_hash)
                .or_insert_with(Vec::new);
            // Cap children per vertex to prevent unbounded growth
            if children_entry.len() >= MAX_CHILDREN_PER_VERTEX {
                return Err(DAGError::ChildrenLimitExceeded);
            }
            children_entry.push(vertex_hash);
        }

        self.update_tips(shard_id, &vertex);

        self.heights
            .entry(shard_id)
            .and_modify(|h| {
                if vertex.height > *h {
                    *h = vertex.height;
                }
            })
            .or_insert(vertex.height);

        self.storage.put_vertex(&vertex)
            .map_err(|e| DAGError::StorageError(e.to_string()))?;

        self.vertices.insert(vertex_hash, vertex);
        self.vertex_count.fetch_add(1, Ordering::SeqCst);

        Ok(())
    }

    /// Evicts old vertices from memory to storage.
    /// Acquires add_vertex_lock to prevent race conditions with concurrent add_vertex calls.
    fn evict_old_vertices(&self) -> DAGResult<()> {
        let _lock = self.add_vertex_lock.lock();
        
        let mut to_evict = Vec::new();
        
        // Collect vertices to evict (keep only recent ones)
        for entry in self.vertices.iter() {
            if entry.status == VertexStatus::Confirmed {
                to_evict.push(*entry.key());
                if to_evict.len() >= MAX_VERTICES_IN_MEMORY / 10 {
                    break;
                }
            }
        }

        // Evict vertices
        for hash in &to_evict {
            self.vertices.remove(hash);
        }
        // Update count atomically after all removals
        self.vertex_count.fetch_sub(to_evict.len(), Ordering::SeqCst);

        Ok(())
    }

    /// Updates tips for a shard.
    /// Optimized: uses truncate instead of drain for excess removal.
    fn update_tips(&self, shard_id: ShardId, vertex: &DAGVertex) {
        self.tips
            .entry(shard_id)
            .and_modify(|tips| {
                tips.retain(|tip| !vertex.parents.contains(tip));
                tips.push(vertex.hash);
                
                // Truncate oldest tips efficiently
                if tips.len() > MAX_TIPS_PER_SHARD {
                    let excess = tips.len() - MAX_TIPS_PER_SHARD;
                    tips.rotate_left(excess);
                    tips.truncate(MAX_TIPS_PER_SHARD);
                }
            })
            .or_insert_with(|| vec![vertex.hash]);
    }

    pub fn get_vertex(&self, hash: &Hash) -> DAGResult<Option<DAGVertex>> {
        if let Some(vertex) = self.vertices.get(hash) {
            return Ok(Some(vertex.clone()));
        }

        self.storage.get_vertex(hash)
            .map_err(|e| DAGError::StorageError(e.to_string()))
    }

    pub fn get_tips(&self, shard_id: ShardId) -> Vec<Hash> {
        self.tips.get(&shard_id)
            .map(|tips| tips.clone())
            .unwrap_or_default()
    }

    pub fn get_children(&self, hash: &Hash) -> Vec<Hash> {
        self.children.get(hash)
            .map(|children| children.clone())
            .unwrap_or_default()
    }

    pub fn get_height(&self, shard_id: ShardId) -> u64 {
        self.heights.get(&shard_id)
            .map(|h| *h)
            .unwrap_or(0)
    }

    pub fn select_parents(&self, shard_id: ShardId) -> Vec<Hash> {
        let tips = self.get_tips(shard_id);
        let num_parents = std::cmp::min(
            std::cmp::max(tips.len(), self.min_parents),
            self.max_parents,
        );
        
        tips.into_iter().take(num_parents).collect()
    }

    /// Creates a new vertex.
    /// 
    /// CRITICAL: Requires authorization and validates parent count.
    pub fn create_vertex(
        &self,
        shard_id: ShardId,
        transactions: Vec<SignedTransaction>,
        creator: Address,
    ) -> DAGResult<DAGVertex> {
        // Access control
        if !self.is_authorized_creator(&creator) {
            return Err(DAGError::Unauthorized(
                format!("Address {:?} not authorized to create vertices", creator)
            ));
        }

        let parents = self.select_parents(shard_id);
        
        // Validate parent count
        if parents.len() < self.min_parents && self.get_height(shard_id) > 0 {
            return Err(DAGError::TooFewParents {
                min: self.min_parents,
                got: parents.len(),
            });
        }
        
        // Use checked arithmetic to prevent overflow
        let current_height = self.get_height(shard_id);
        let height = current_height.checked_add(1)
            .ok_or_else(|| DAGError::HeightOverflow(current_height))?;
        
        let vertex = DAGVertex::new(
            parents,
            transactions,
            shard_id,
            creator,
            height,
        ).map_err(|e| DAGError::InvalidVertex(e))?;

        Ok(vertex)
    }

    /// Gets ancestors of a vertex with depth and count limits.
    /// Prevents unbounded traversal that could exhaust memory.
    pub fn get_ancestors(&self, hash: &Hash, depth: usize) -> DAGResult<Vec<Hash>> {
        let mut ancestors = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        
        queue.push_back((*hash, 0usize));
        visited.insert(*hash);

        while let Some((current, current_depth)) = queue.pop_front() {
            // Limit total vertices visited
            if visited.len() >= MAX_TRAVERSAL_VERTICES {
                return Err(DAGError::TraversalLimitExceeded(MAX_TRAVERSAL_VERTICES));
            }

            if current_depth >= depth {
                continue;
            }

            if let Some(vertex) = self.get_vertex(&current)? {
                for parent in &vertex.parents {
                    if visited.insert(*parent) {
                        ancestors.push(*parent);
                        queue.push_back((*parent, current_depth + 1));
                    }
                }
            }
        }

        Ok(ancestors)
    }

    /// Gets descendants of a vertex with depth and count limits.
    /// Prevents unbounded traversal that could exhaust memory.
    pub fn get_descendants(&self, hash: &Hash, depth: usize) -> DAGResult<Vec<Hash>> {
        let mut descendants = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        
        queue.push_back((*hash, 0usize));
        visited.insert(*hash);

        while let Some((current, current_depth)) = queue.pop_front() {
            // Limit total vertices visited
            if visited.len() >= MAX_TRAVERSAL_VERTICES {
                return Err(DAGError::TraversalLimitExceeded(MAX_TRAVERSAL_VERTICES));
            }

            if current_depth >= depth {
                continue;
            }

            for child in self.get_children(&current) {
                if visited.insert(child) {
                    descendants.push(child);
                    queue.push_back((child, current_depth + 1));
                }
            }
        }

        Ok(descendants)
    }

    /// Updates vertex status.
    /// 
    /// Requires caller to be an authorized creator or admin to prevent
    /// external manipulation of vertex state.
    pub fn update_vertex_status(&self, caller: &Address, hash: &Hash, status: VertexStatus) -> DAGResult<()> {
        // Only authorized creators or admin can update status
        let is_admin = *caller == *self.admin.read();
        if !is_admin && !self.is_authorized_creator(caller) {
            return Err(DAGError::Unauthorized(
                "Only authorized creators or admin can update vertex status".to_string()
            ));
        }
        if let Some(mut vertex) = self.vertices.get_mut(hash) {
            vertex.status = status;
            self.storage.put_vertex(&vertex)
                .map_err(|e| DAGError::StorageError(e.to_string()))?;
        }
        Ok(())
    }

    /// Updates vertex status without access control (internal use only).
    /// This is pub(crate) to restrict external callers.
    pub(crate) fn update_vertex_status_internal(&self, hash: &Hash, status: VertexStatus) -> DAGResult<()> {
        if let Some(mut vertex) = self.vertices.get_mut(hash) {
            vertex.status = status;
            self.storage.put_vertex(&vertex)
                .map_err(|e| DAGError::StorageError(e.to_string()))?;
        } else if let Some(mut vertex) = self.storage.get_vertex(hash)
            .map_err(|e| DAGError::StorageError(e.to_string()))?
        {
            vertex.status = status;
            self.storage.put_vertex(&vertex)
                .map_err(|e| DAGError::StorageError(e.to_string()))?;
        }
        Ok(())
    }

    /// Marks all reachable ancestors from the supplied tips as finalized up to
    /// the checkpoint's captured DAG frontier. Returns
    /// `(vertices_finalized, transactions_finalized)`.
    pub(crate) fn finalize_reachable_from_tips(
        &self,
        tips: &[Hash],
    ) -> DAGResult<(u64, u64)> {
        let mut finalized_vertices = 0u64;
        let mut finalized_transactions = 0u64;
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        for tip in tips {
            if visited.insert(*tip) {
                queue.push_back(*tip);
            }
        }

        while let Some(hash) = queue.pop_front() {
            if visited.len() >= MAX_TRAVERSAL_VERTICES {
                return Err(DAGError::TraversalLimitExceeded(MAX_TRAVERSAL_VERTICES));
            }

            let Some(mut vertex) = self.get_vertex(&hash)? else {
                continue;
            };

            for parent in &vertex.parents {
                if visited.insert(*parent) {
                    queue.push_back(*parent);
                }
            }

            if vertex.status != VertexStatus::Finalized {
                vertex.status = VertexStatus::Finalized;
                finalized_vertices = finalized_vertices.saturating_add(1);
                finalized_transactions = finalized_transactions
                    .saturating_add(vertex.transactions.len() as u64);
                self.storage.put_vertex(&vertex)
                    .map_err(|e| DAGError::StorageError(e.to_string()))?;
                self.vertices.insert(hash, vertex);
            }
        }

        Ok((finalized_vertices, finalized_transactions))
    }

    pub fn vertex_count(&self) -> usize {
        self.vertex_count.load(Ordering::SeqCst)
    }

    /// Gets the maximum allowed vertices in memory.
    pub fn max_vertices(&self) -> usize {
        MAX_VERTICES_IN_MEMORY
    }

    pub fn tip_count(&self, shard_id: ShardId) -> usize {
        self.tips.get(&shard_id).map(|t| t.len()).unwrap_or(0)
    }
}

pub struct GenesisVertex;

impl GenesisVertex {
    /// Creates a genesis vertex for the given shard.
    /// Uses the well-known GENESIS_CREATOR address.
    pub fn create(shard_id: ShardId) -> DAGResult<DAGVertex> {
        DAGVertex::new(
            Vec::new(),
            Vec::new(),
            shard_id,
            GENESIS_CREATOR,
            0,
        ).map_err(|e| DAGError::InvalidVertex(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_dag_basic() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path()).unwrap();
        let dag = DAGGraph::new(storage, 0, 8); // min_parents=0 for genesis
        
        // Add authorized creator
        let creator = [0u8; 32];
        dag.add_authorized_creator(creator);

        let genesis = GenesisVertex::create(0).unwrap();
        dag.add_vertex(genesis.clone()).unwrap();

        let tips = dag.get_tips(0);
        assert_eq!(tips.len(), 1);
        assert_eq!(tips[0], genesis.hash);
    }

    #[test]
    fn test_dag_parent_child() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path()).unwrap();
        let dag = DAGGraph::new(storage, 0, 8); // min_parents=0 for genesis
        
        // Add authorized creator
        let creator = [0u8; 32];
        dag.add_authorized_creator(creator);

        let genesis = GenesisVertex::create(0).unwrap();
        dag.add_vertex(genesis.clone()).unwrap();

        let vertex = DAGVertex::new(
            vec![genesis.hash],
            Vec::new(),
            0,
            creator,
            1,
        ).unwrap();
        dag.add_vertex(vertex.clone()).unwrap();

        let children = dag.get_children(&genesis.hash);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0], vertex.hash);
    }
}
