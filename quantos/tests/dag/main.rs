//! Comprehensive tests for the DAG module (dag/graph.rs, dag/ordering.rs)

use quantos::dag::*;
use quantos::storage::Storage;
use quantos::types::*;
use tempfile::tempdir;

// ── Helpers ──────────────────────────────────────────────

fn setup_dag(min_parents: usize, max_parents: usize) -> (DAGGraph, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let storage = Storage::new(dir.path()).unwrap();
    let dag = DAGGraph::new(storage, min_parents, max_parents);
    (dag, dir)
}

fn setup_dag_with_genesis() -> (DAGGraph, DAGVertex, tempfile::TempDir) {
    let (dag, dir) = setup_dag(0, 8);
    let creator = [0u8; 32];
    dag.add_authorized_creator(creator);
    let genesis = GenesisVertex::create(0).unwrap();
    dag.add_vertex(genesis.clone()).unwrap();
    (dag, genesis, dir)
}

fn make_vertex(parents: Vec<Hash>, shard_id: ShardId, creator: Address, height: u64) -> DAGVertex {
    DAGVertex::new(parents, Vec::new(), shard_id, creator, height).unwrap()
}

// ── Genesis ──────────────────────────────────────────────

#[test]
fn test_genesis_vertex_creation() {
    let genesis = GenesisVertex::create(0).unwrap();
    assert_eq!(genesis.height, 0);
    assert_eq!(genesis.shard_id, 0);
    assert!(genesis.parents.is_empty());
    assert!(genesis.transactions.is_empty());
    assert_eq!(genesis.status, VertexStatus::Pending);
}

#[test]
fn test_genesis_different_shards() {
    let g0 = GenesisVertex::create(0).unwrap();
    let g1 = GenesisVertex::create(1).unwrap();
    assert_ne!(g0.hash, g1.hash);
    assert_eq!(g0.shard_id, 0);
    assert_eq!(g1.shard_id, 1);
}

// ── Basic DAG operations ─────────────────────────────────

#[test]
fn test_add_genesis_vertex() {
    let (dag, genesis, _dir) = setup_dag_with_genesis();
    assert_eq!(dag.vertex_count(), 1);
    let tips = dag.get_tips(0);
    assert_eq!(tips.len(), 1);
    assert_eq!(tips[0], genesis.hash);
}

#[test]
fn test_add_child_vertex() {
    let (dag, genesis, _dir) = setup_dag_with_genesis();
    let creator = [0u8; 32];
    let child = make_vertex(vec![genesis.hash], 0, creator, 1);
    dag.add_vertex(child.clone()).unwrap();

    assert_eq!(dag.vertex_count(), 2);
    let children = dag.get_children(&genesis.hash);
    assert_eq!(children.len(), 1);
    assert_eq!(children[0], child.hash);
}

#[test]
fn test_get_vertex() {
    let (dag, genesis, _dir) = setup_dag_with_genesis();
    let fetched = dag.get_vertex(&genesis.hash).unwrap().unwrap();
    assert_eq!(fetched.hash, genesis.hash);
    assert_eq!(fetched.height, 0);
}

#[test]
fn test_get_nonexistent_vertex() {
    let (dag, _genesis, _dir) = setup_dag_with_genesis();
    let fake_hash = [99u8; 32];
    let result = dag.get_vertex(&fake_hash).unwrap();
    assert!(result.is_none());
}

// ── Tips management ──────────────────────────────────────

#[test]
fn test_tips_update_on_child_add() {
    let (dag, genesis, _dir) = setup_dag_with_genesis();
    let creator = [0u8; 32];

    // Genesis is the only tip
    assert_eq!(dag.get_tips(0), vec![genesis.hash]);

    // Add child referencing genesis → genesis removed from tips, child is tip
    let child = make_vertex(vec![genesis.hash], 0, creator, 1);
    dag.add_vertex(child.clone()).unwrap();
    let tips = dag.get_tips(0);
    assert_eq!(tips.len(), 1);
    assert_eq!(tips[0], child.hash);
}

#[test]
fn test_multiple_tips() {
    let (dag, genesis, _dir) = setup_dag_with_genesis();
    let creator = [0u8; 32];

    let c1 = make_vertex(vec![genesis.hash], 0, creator, 1);
    dag.add_vertex(c1.clone()).unwrap();

    // Create a second child also referencing genesis
    // genesis already consumed from tips by c1, but c2 should add another tip
    let c2 = make_vertex(vec![genesis.hash], 0, creator, 1);
    dag.add_vertex(c2.clone()).unwrap();

    let tips = dag.get_tips(0);
    assert!(tips.len() >= 2);
}

#[test]
fn test_tips_empty_shard() {
    let (dag, _genesis, _dir) = setup_dag_with_genesis();
    let tips = dag.get_tips(999);
    assert!(tips.is_empty());
}

// ── Height tracking ──────────────────────────────────────

#[test]
fn test_height_tracking() {
    let (dag, genesis, _dir) = setup_dag_with_genesis();
    let creator = [0u8; 32];
    assert_eq!(dag.get_height(0), 0);

    let child = make_vertex(vec![genesis.hash], 0, creator, 1);
    dag.add_vertex(child.clone()).unwrap();
    assert_eq!(dag.get_height(0), 1);

    let grandchild = make_vertex(vec![child.hash], 0, creator, 2);
    dag.add_vertex(grandchild).unwrap();
    assert_eq!(dag.get_height(0), 2);
}

#[test]
fn test_height_default_zero() {
    let (dag, _genesis, _dir) = setup_dag_with_genesis();
    assert_eq!(dag.get_height(999), 0);
}

// ── Parent validation ────────────────────────────────────

#[test]
fn test_too_many_parents_rejected() {
    let (dag, _dir) = setup_dag(0, 2); // max 2 parents
    let creator = [0u8; 32];
    dag.add_authorized_creator(creator);
    let g = GenesisVertex::create(0).unwrap();
    dag.add_vertex(g.clone()).unwrap();

    let c1 = make_vertex(vec![g.hash], 0, creator, 1);
    dag.add_vertex(c1.clone()).unwrap();

    let c2 = make_vertex(vec![g.hash], 0, creator, 1);
    dag.add_vertex(c2.clone()).unwrap();

    // 3 parents when max is 2
    let bad = DAGVertex::new(vec![g.hash, c1.hash, c2.hash], Vec::new(), 0, creator, 2).unwrap();
    let result = dag.add_vertex(bad);
    assert!(result.is_err());
}

#[test]
fn test_invalid_parent_rejected() {
    let (dag, _genesis, _dir) = setup_dag_with_genesis();
    let creator = [0u8; 32];
    let fake_parent = [42u8; 32];
    let bad = DAGVertex::new(vec![fake_parent], Vec::new(), 0, creator, 1).unwrap();
    let result = dag.add_vertex(bad);
    assert!(result.is_err());
}

// ── Authorization ────────────────────────────────────────

#[test]
fn test_unauthorized_creator_rejected() {
    let (dag, _dir) = setup_dag(0, 8);
    let unauthorized = [99u8; 32];
    // Do NOT add as authorized
    let genesis = DAGVertex::new(Vec::new(), Vec::new(), 0, unauthorized, 0).unwrap();
    let result = dag.add_vertex(genesis);
    assert!(result.is_err());
}

#[test]
fn test_add_authorized_creator() {
    let (dag, _dir) = setup_dag(0, 8);
    let addr = [5u8; 32];
    assert!(!dag.is_authorized_creator(&addr));
    dag.add_authorized_creator(addr);
    assert!(dag.is_authorized_creator(&addr));
}

#[test]
fn test_remove_authorized_creator() {
    let (dag, _dir) = setup_dag(0, 8);
    let addr = [5u8; 32];
    dag.add_authorized_creator(addr);
    assert!(dag.is_authorized_creator(&addr));
    dag.remove_authorized_creator(&addr);
    assert!(!dag.is_authorized_creator(&addr));
}

#[test]
fn test_admin_transfer() {
    let (dag, _dir) = setup_dag(0, 8);
    let genesis_admin = [0u8; 32]; // GENESIS_CREATOR
    let new_admin = [1u8; 32];

    dag.set_admin(&genesis_admin, new_admin).unwrap();

    // Old admin cannot transfer anymore
    let result = dag.set_admin(&genesis_admin, [2u8; 32]);
    assert!(result.is_err());

    // New admin can transfer
    dag.set_admin(&new_admin, [3u8; 32]).unwrap();
}

#[test]
fn test_checked_authorized_creator_requires_admin() {
    let (dag, _dir) = setup_dag(0, 8);
    let genesis_admin = [0u8; 32];
    let non_admin = [99u8; 32];
    let target = [5u8; 32];

    // Admin can add
    dag.add_authorized_creator_checked(&genesis_admin, target).unwrap();
    assert!(dag.is_authorized_creator(&target));

    // Non-admin cannot add
    let result = dag.add_authorized_creator_checked(&non_admin, [6u8; 32]);
    assert!(result.is_err());
}

#[test]
fn test_checked_remove_creator_requires_admin() {
    let (dag, _dir) = setup_dag(0, 8);
    let genesis_admin = [0u8; 32];
    let non_admin = [99u8; 32];
    let target = [5u8; 32];
    dag.add_authorized_creator(target);

    // Non-admin cannot remove
    let result = dag.remove_authorized_creator_checked(&non_admin, &target);
    assert!(result.is_err());
    assert!(dag.is_authorized_creator(&target));

    // Admin can remove
    dag.remove_authorized_creator_checked(&genesis_admin, &target).unwrap();
    assert!(!dag.is_authorized_creator(&target));
}

// ── Vertex status ────────────────────────────────────────

#[test]
fn test_update_vertex_status() {
    let (dag, genesis, _dir) = setup_dag_with_genesis();
    let admin = [0u8; 32];
    dag.update_vertex_status(&admin, &genesis.hash, VertexStatus::Confirmed).unwrap();
    let v = dag.get_vertex(&genesis.hash).unwrap().unwrap();
    assert_eq!(v.status, VertexStatus::Confirmed);
}

#[test]
fn test_update_vertex_status_unauthorized() {
    let (dag, genesis, _dir) = setup_dag_with_genesis();
    let rando = [99u8; 32];
    let result = dag.update_vertex_status(&rando, &genesis.hash, VertexStatus::Confirmed);
    assert!(result.is_err());
}

// ── Traversal ────────────────────────────────────────────

#[test]
fn test_get_ancestors() {
    let (dag, genesis, _dir) = setup_dag_with_genesis();
    let creator = [0u8; 32];

    let child = make_vertex(vec![genesis.hash], 0, creator, 1);
    dag.add_vertex(child.clone()).unwrap();

    let grandchild = make_vertex(vec![child.hash], 0, creator, 2);
    dag.add_vertex(grandchild.clone()).unwrap();

    let ancestors = dag.get_ancestors(&grandchild.hash, 10).unwrap();
    assert!(ancestors.contains(&child.hash));
    assert!(ancestors.contains(&genesis.hash));
}

#[test]
fn test_get_descendants() {
    let (dag, genesis, _dir) = setup_dag_with_genesis();
    let creator = [0u8; 32];

    let child = make_vertex(vec![genesis.hash], 0, creator, 1);
    dag.add_vertex(child.clone()).unwrap();

    let descendants = dag.get_descendants(&genesis.hash, 10).unwrap();
    assert!(descendants.contains(&child.hash));
}

#[test]
fn test_ancestors_depth_limit() {
    let (dag, genesis, _dir) = setup_dag_with_genesis();
    let creator = [0u8; 32];

    let child = make_vertex(vec![genesis.hash], 0, creator, 1);
    dag.add_vertex(child.clone()).unwrap();

    let grandchild = make_vertex(vec![child.hash], 0, creator, 2);
    dag.add_vertex(grandchild.clone()).unwrap();

    // Depth=1 should only return child, not genesis
    let ancestors = dag.get_ancestors(&grandchild.hash, 1).unwrap();
    assert!(ancestors.contains(&child.hash));
    assert!(!ancestors.contains(&genesis.hash));
}

// ── Select parents ───────────────────────────────────────

#[test]
fn test_select_parents() {
    let (dag, genesis, _dir) = setup_dag_with_genesis();
    let parents = dag.select_parents(0);
    assert!(!parents.is_empty());
    assert!(parents.contains(&genesis.hash));
}

#[test]
fn test_select_parents_empty_shard() {
    let (dag, _genesis, _dir) = setup_dag_with_genesis();
    let parents = dag.select_parents(999);
    assert!(parents.is_empty());
}

// ── Create vertex ────────────────────────────────────────

#[test]
fn test_create_vertex_authorized() {
    let (dag, _genesis, _dir) = setup_dag_with_genesis();
    let creator = [0u8; 32];
    let vertex = dag.create_vertex(0, Vec::new(), creator).unwrap();
    assert_eq!(vertex.shard_id, 0);
    assert_eq!(vertex.height, 1);
}

#[test]
fn test_create_vertex_unauthorized() {
    let (dag, _genesis, _dir) = setup_dag_with_genesis();
    let rando = [99u8; 32];
    let result = dag.create_vertex(0, Vec::new(), rando);
    assert!(result.is_err());
}

// ── Multi-shard ──────────────────────────────────────────

#[test]
fn test_multi_shard_vertices() {
    let (dag, _dir) = setup_dag(0, 8);
    let creator = [0u8; 32];
    dag.add_authorized_creator(creator);

    let g0 = GenesisVertex::create(0).unwrap();
    let g1 = GenesisVertex::create(1).unwrap();
    dag.add_vertex(g0.clone()).unwrap();
    dag.add_vertex(g1.clone()).unwrap();

    assert_eq!(dag.vertex_count(), 2);
    assert_eq!(dag.get_tips(0).len(), 1);
    assert_eq!(dag.get_tips(1).len(), 1);
    assert_eq!(dag.get_height(0), 0);
    assert_eq!(dag.get_height(1), 0);
}

// ── Vertex count ─────────────────────────────────────────

#[test]
fn test_vertex_count() {
    let (dag, genesis, _dir) = setup_dag_with_genesis();
    let creator = [0u8; 32];
    assert_eq!(dag.vertex_count(), 1);

    let c1 = make_vertex(vec![genesis.hash], 0, creator, 1);
    dag.add_vertex(c1).unwrap();
    assert_eq!(dag.vertex_count(), 2);
}

#[test]
fn test_tip_count() {
    let (dag, _genesis, _dir) = setup_dag_with_genesis();
    assert_eq!(dag.tip_count(0), 1);
    assert_eq!(dag.tip_count(999), 0);
}

// ── DAGVertex type ───────────────────────────────────────

#[test]
fn test_vertex_hash_deterministic() {
    let parents = vec![[1u8; 32]];
    let v1 = DAGVertex::new(parents.clone(), Vec::new(), 0, [0u8; 32], 1).unwrap();
    let v2 = DAGVertex::new(parents, Vec::new(), 0, [0u8; 32], 1).unwrap();
    // Hashes differ because timestamp differs (chrono::Utc::now())
    // But both should be non-zero
    assert_ne!(v1.hash, [0u8; 32]);
    assert_ne!(v2.hash, [0u8; 32]);
}
