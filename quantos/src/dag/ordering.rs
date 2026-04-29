use std::collections::{HashMap, HashSet, BinaryHeap, VecDeque};
use std::cmp::Ordering;

use crate::dag::{DAGGraph, DAGResult};
use crate::types::{DAGVertex, Hash};

#[derive(Clone, Eq, PartialEq)]
struct WeightedVertex {
    hash: Hash,
    weight: u64,
    height: u64,
    timestamp: u64,
}

impl Ord for WeightedVertex {
    fn cmp(&self, other: &Self) -> Ordering {
        other.weight.cmp(&self.weight)
            .then_with(|| other.height.cmp(&self.height))
            .then_with(|| self.timestamp.cmp(&other.timestamp))
    }
}

impl PartialOrd for WeightedVertex {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub struct TopologicalOrderer {
    dag: DAGGraph,
}

impl TopologicalOrderer {
    pub fn new(dag: DAGGraph) -> Self {
        Self { dag }
    }

    pub fn topological_sort(&self, vertices: &[Hash]) -> DAGResult<Vec<Hash>> {
        let mut in_degree: HashMap<Hash, usize> = HashMap::new();
        let mut graph: HashMap<Hash, Vec<Hash>> = HashMap::new();
        
        for hash in vertices {
            in_degree.entry(*hash).or_insert(0);
            graph.entry(*hash).or_insert_with(Vec::new);
            
            if let Some(vertex) = self.dag.get_vertex(hash)? {
                for parent in &vertex.parents {
                    if vertices.contains(parent) {
                        graph.entry(*parent).or_insert_with(Vec::new).push(*hash);
                        let deg = in_degree.entry(*hash).or_insert(0);
                        *deg = deg.saturating_add(1);
                    }
                }
            }
        }

        let mut queue: VecDeque<Hash> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(hash, _)| *hash)
            .collect();

        let mut sorted = Vec::new();

        while let Some(hash) = queue.pop_front() {
            sorted.push(hash);
            
            if let Some(children) = graph.get(&hash) {
                for child in children {
                    if let Some(deg) = in_degree.get_mut(child) {
                        *deg = deg.saturating_sub(1);
                        if *deg == 0 {
                            queue.push_back(*child);
                        }
                    }
                }
            }
        }

        Ok(sorted)
    }

    pub fn weighted_topological_sort(&self, vertices: &[Hash]) -> DAGResult<Vec<Hash>> {
        let mut in_degree: HashMap<Hash, usize> = HashMap::new();
        let mut graph: HashMap<Hash, Vec<Hash>> = HashMap::new();
        let mut weights: HashMap<Hash, u64> = HashMap::new();
        
        for hash in vertices {
            in_degree.entry(*hash).or_insert(0);
            graph.entry(*hash).or_insert_with(Vec::new);
            
            if let Some(vertex) = self.dag.get_vertex(hash)? {
                weights.insert(*hash, vertex.weight);
                
                for parent in &vertex.parents {
                    if vertices.contains(parent) {
                        graph.entry(*parent).or_insert_with(Vec::new).push(*hash);
                        let deg = in_degree.entry(*hash).or_insert(0);
                        *deg = deg.saturating_add(1);
                    }
                }
            }
        }

        let mut heap: BinaryHeap<WeightedVertex> = BinaryHeap::new();
        
        for (hash, deg) in &in_degree {
            if *deg == 0 {
                if let Some(vertex) = self.dag.get_vertex(hash)? {
                    heap.push(WeightedVertex {
                        hash: *hash,
                        weight: vertex.weight,
                        height: vertex.height,
                        timestamp: vertex.timestamp,
                    });
                }
            }
        }

        let mut sorted = Vec::new();

        while let Some(wv) = heap.pop() {
            sorted.push(wv.hash);
            
            if let Some(children) = graph.get(&wv.hash) {
                for child in children {
                    if let Some(deg) = in_degree.get_mut(child) {
                        *deg = deg.saturating_sub(1);
                        if *deg == 0 {
                            if let Some(vertex) = self.dag.get_vertex(child)? {
                                heap.push(WeightedVertex {
                                    hash: *child,
                                    weight: vertex.weight,
                                    height: vertex.height,
                                    timestamp: vertex.timestamp,
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(sorted)
    }

    pub fn find_common_ancestor(&self, a: &Hash, b: &Hash) -> DAGResult<Option<Hash>> {
        let mut visited_a: HashSet<Hash> = HashSet::new();
        let mut visited_b: HashSet<Hash> = HashSet::new();
        let mut queue_a: VecDeque<Hash> = VecDeque::new();
        let mut queue_b: VecDeque<Hash> = VecDeque::new();
        
        queue_a.push_back(*a);
        queue_b.push_back(*b);
        visited_a.insert(*a);
        visited_b.insert(*b);

        loop {
            if queue_a.is_empty() && queue_b.is_empty() {
                return Ok(None);
            }

            if let Some(current) = queue_a.pop_front() {
                if visited_b.contains(&current) {
                    return Ok(Some(current));
                }
                
                if let Some(vertex) = self.dag.get_vertex(&current)? {
                    for parent in &vertex.parents {
                        if visited_a.insert(*parent) {
                            queue_a.push_back(*parent);
                        }
                    }
                }
            }

            if let Some(current) = queue_b.pop_front() {
                if visited_a.contains(&current) {
                    return Ok(Some(current));
                }
                
                if let Some(vertex) = self.dag.get_vertex(&current)? {
                    for parent in &vertex.parents {
                        if visited_b.insert(*parent) {
                            queue_b.push_back(*parent);
                        }
                    }
                }
            }
        }
    }
}

pub struct ConflictResolver {
    dag: DAGGraph,
}

impl ConflictResolver {
    pub fn new(dag: DAGGraph) -> Self {
        Self { dag }
    }

    pub fn resolve_double_spend(&self, _tx_hash: Hash, vertices: &[Hash]) -> DAGResult<Hash> {
        // Prevent panic on empty array
        if vertices.is_empty() {
            return Err(crate::dag::DAGError::InvalidInput(
                "Cannot resolve double spend with empty vertices array".to_string()
            ));
        }

        let mut max_weight = 0u64;
        let mut winner = vertices[0];

        for vertex_hash in vertices {
            if let Some(vertex) = self.dag.get_vertex(vertex_hash)? {
                if vertex.weight > max_weight {
                    max_weight = vertex.weight;
                    winner = *vertex_hash;
                } else if vertex.weight == max_weight {
                    // Deterministic tiebreaker: use lexicographic hash comparison
                    // instead of timestamps which can be manipulated by vertex creators.
                    if vertex_hash < &winner {
                        winner = *vertex_hash;
                    }
                }
            }
        }

        Ok(winner)
    }

    pub fn detect_conflicting_transactions(
        &self,
        vertex: &DAGVertex,
        recent_vertices: &[DAGVertex],
    ) -> Vec<(Hash, Hash)> {
        let mut conflicts = Vec::new();
        let mut seen_spends: HashMap<([u8; 32], u64), Hash> = HashMap::new();

        for tx in &vertex.transactions {
            let key = (tx.transaction.from, tx.transaction.nonce);
            if let Some(existing_tx) = seen_spends.get(&key) {
                conflicts.push((*existing_tx, tx.hash));
            }
            seen_spends.insert(key, tx.hash);
        }

        for other in recent_vertices {
            if other.hash == vertex.hash {
                continue;
            }
            
            for tx in &other.transactions {
                let key = (tx.transaction.from, tx.transaction.nonce);
                if seen_spends.contains_key(&key) {
                    conflicts.push((seen_spends[&key], tx.hash));
                }
            }
        }

        conflicts
    }
}
