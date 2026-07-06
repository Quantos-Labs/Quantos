---
sidebar_position: 6
slug: /dag
---

# 5. DAG Structure & Ordering

## 5.1 Why a DAG Instead of a Chain

A linear blockchain serialises all transactions into a single sequence of blocks, which fundamentally caps throughput at one block producer at a time. Quantos replaces the chain with a **Directed Acyclic Graph (DAG)** of vertices (`quantos/src/dag/`). Many validators add vertices concurrently, each vertex referencing multiple parents, so transaction inclusion is parallel rather than serial. There is no single "latest block" bottleneck.

## 5.2 Vertices and Parent References

Each DAG vertex (`types/vertex.rs`) bundles a set of transactions and references between **2 and 8 parent vertices** (`min_dag_parents = 2`, `max_dag_parents = 8`). Multiple parents serve two purposes: they weave concurrent vertices into a single connected structure, and they act as votes of availability — referencing a parent asserts that the referencer has seen and validated it.

The DAG enforces strict structural invariants (`dag/graph.rs`), each mapped to an explicit error:

- **Parent-count bounds**: fewer than `min` parents (`TooFewParents`) or more than `max` (`TooManyParents`) is rejected.
- **Acyclicity**: a reference that would create a cycle (`CycleDetected`) is rejected — the graph must remain acyclic for ordering to terminate.
- **Parent existence**: references to unknown vertices (`InvalidParent`, `VertexNotFound`) are rejected.
- **Resource bounds**: per-vertex children limits, per-shard limits, traversal limits, and height-overflow checks (`ChildrenLimitExceeded`, `ShardLimitExceeded`, `TraversalLimitExceeded`, `HeightOverflow`) bound memory and CPU so that a malicious vertex cannot trigger unbounded work.

## 5.3 Ingress and Validation

New vertices enter through the ingress path (`dag/ingress.rs`), which validates structure, signatures, and parent availability before admitting a vertex to the graph. Invalid vertices are rejected at ingress and never pollute the graph, so the ordering layer always operates over a well-formed DAG.

## 5.4 Deterministic Topological Ordering

Although vertices are produced concurrently, every honest node must agree on a single **total order** of transactions to compute the same state. The ordering engine (`dag/ordering.rs`) performs a deterministic topological sort of the DAG: parents are always ordered before children, and ties between concurrent vertices are broken by a deterministic rule (hash-based) so that all nodes derive an identical sequence from the same graph. This is the bridge between parallel inclusion and a single, replayable state transition, and it is what safety invariant **INV-S3 (Total Order)** in the consensus section certifies at runtime.

## 5.5 Conflict Resolution

Two concurrent vertices may contain conflicting transactions (e.g. two spends of the same balance). Because both can be admitted to the DAG before the conflict is visible, resolution happens at ordering time: the deterministic total order decides which conflicting transaction is applied first; the later one fails validation against the now-updated state and is dropped. Combined with optimistic execution (handled in the execution layer), this keeps the common, conflict-free path fast while guaranteeing that conflicts are resolved identically on every node.
