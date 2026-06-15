// PQC-Guard — cross-VM crypto primitives for Sui (Move).
//
// Implements the INVARIANT keccak256 encodings from MULTIVM_SPEC.md §2:
// Winternitz OTS verification + one-time Merkle trees + attestor-set leaves.
// These MUST match `quantos/src/l0/pqc_guard.rs` and the EVM libs byte-for-byte.
//
// TESTNET ONLY. // AUDIT REQUIRED.
module quantos::pqc_guard_crypto {
    use std::vector;
    use sui::hash;

    /// Winternitz parameter.
    const W: u64 = 16;
    /// Number of hash chains (64 message + 3 checksum).
    const LEN: u64 = 67;

    const E_BAD_DIGEST_LEN: u64 = 100;
    const E_BAD_SIG_LEN: u64 = 101;

    // ── low-level helpers ──────────────────────────────────────────────────

    /// keccak256 of a byte buffer.
    public fun k(data: &vector<u8>): vector<u8> {
        hash::keccak256(data)
    }

    /// keccak256(a ++ b) for two 32-byte words (Merkle node).
    public fun node(left: &vector<u8>, right: &vector<u8>): vector<u8> {
        let mut buf = vector::empty<u8>();
        vector::append(&mut buf, *left);
        vector::append(&mut buf, *right);
        hash::keccak256(&buf)
    }

    /// 32-byte big-endian encoding of a u64 (the `u256_be(n)` of the spec).
    public fun u256_be_from_u64(n: u64): vector<u8> {
        let mut out = vector::empty<u8>();
        let mut i = 0;
        while (i < 24) { vector::push_back(&mut out, 0u8); i = i + 1; };
        let mut j: u64 = 8;
        while (j > 0) {
            j = j - 1;
            let shift = (j as u8) * 8;
            let byte = ((n >> shift) & 0xff) as u8;
            vector::push_back(&mut out, byte);
        };
        out
    }

    // ── Winternitz ─────────────────────────────────────────────────────────

    /// Expand a 32-byte digest into 64 message + 3 checksum base-16 digits.
    public fun digits(digest: &vector<u8>): vector<u8> {
        assert!(vector::length(digest) == 32, E_BAD_DIGEST_LEN);
        let mut d = vector::empty<u8>();
        let mut csum: u64 = 0;
        let mut i = 0;
        while (i < 32) {
            let b = *vector::borrow(digest, i);
            let hi = b >> 4;
            let lo = b & 0x0f;
            vector::push_back(&mut d, hi);
            vector::push_back(&mut d, lo);
            csum = csum + (W - 1 - (hi as u64));
            csum = csum + (W - 1 - (lo as u64));
            i = i + 1;
        };
        vector::push_back(&mut d, (((csum >> 8) & 0x0f) as u8));
        vector::push_back(&mut d, (((csum >> 4) & 0x0f) as u8));
        vector::push_back(&mut d, ((csum & 0x0f) as u8));
        d
    }

    /// Recompute the compressed WOTS public key from a signature over `digest`.
    /// `sig` is a vector of 67 32-byte elements.
    public fun pub_key_from_sig(digest: &vector<u8>, sig: &vector<vector<u8>>): vector<u8> {
        assert!(vector::length(sig) == (LEN as u64), E_BAD_SIG_LEN);
        let d = digits(digest);
        let mut concat = vector::empty<u8>();
        let mut i = 0;
        while (i < (LEN as u64)) {
            let mut x = *vector::borrow(sig, i);
            let target = W - 1;
            let mut j = (*vector::borrow(&d, i) as u64);
            while (j < target) {
                x = hash::keccak256(&x);
                j = j + 1;
            };
            vector::append(&mut concat, x);
            i = i + 1;
        };
        hash::keccak256(&concat)
    }

    // ── Merkle ───────────────────────────────────────────────────────────--

    /// Domain-separated WOTS Merkle leaf.
    public fun wots_leaf(wots_pub: &vector<u8>): vector<u8> {
        let mut buf = b"PQCG_WOTS_LEAF";
        vector::append(&mut buf, *wots_pub);
        hash::keccak256(&buf)
    }

    /// Recompute a Merkle root from a leaf, its index and an authentication path.
    public fun root_from_leaf(leaf: vector<u8>, index: u64, path: &vector<vector<u8>>): vector<u8> {
        let mut h = leaf;
        let mut idx = index;
        let n = vector::length(path);
        let mut i = 0;
        while (i < n) {
            let sib = vector::borrow(path, i);
            if (idx & 1 == 0) {
                h = node(&h, sib);
            } else {
                h = node(sib, &h);
            };
            idx = idx >> 1;
            i = i + 1;
        };
        h
    }

    /// Domain-separated attestor-set leaf (binds Quantos validator id + WOTS root).
    public fun attestor_leaf(attestor_id: &vector<u8>, wots_root: &vector<u8>): vector<u8> {
        let mut buf = b"PQCG_ATTESTOR_LEAF";
        vector::append(&mut buf, *attestor_id);
        vector::append(&mut buf, *wots_root);
        hash::keccak256(&buf)
    }

    // ── tests ────────────────────────────────────────────────────────────--

    #[test_only]
    /// Deterministic secret element (mirrors the spec sk()).
    fun sk(seed: &vector<u8>, leaf_index: u64, chain: u64): vector<u8> {
        let mut buf = b"PQCG_WOTS_SK";
        vector::append(&mut buf, *seed);
        vector::append(&mut buf, u256_be_from_u64(leaf_index));
        vector::append(&mut buf, u256_be_from_u64(chain));
        hash::keccak256(&buf)
    }

    #[test_only]
    fun sign(seed: &vector<u8>, leaf_index: u64, digest: &vector<u8>): vector<vector<u8>> {
        let d = digits(digest);
        let mut sig = vector::empty<vector<u8>>();
        let mut i = 0;
        while (i < (LEN as u64)) {
            let mut x = sk(seed, leaf_index, i);
            let reps = (*vector::borrow(&d, i) as u64);
            let mut r = 0;
            while (r < reps) { x = hash::keccak256(&x); r = r + 1; };
            vector::push_back(&mut sig, x);
            i = i + 1;
        };
        sig
    }

    #[test_only]
    fun pub_direct(seed: &vector<u8>, leaf_index: u64): vector<u8> {
        let mut concat = vector::empty<u8>();
        let mut i = 0;
        while (i < (LEN as u64)) {
            let mut x = sk(seed, leaf_index, i);
            let mut r = 0;
            while (r < W - 1) { x = hash::keccak256(&x); r = r + 1; };
            vector::append(&mut concat, x);
            i = i + 1;
        };
        hash::keccak256(&concat)
    }

    #[test]
    fun test_wots_roundtrip() {
        let seed = b"00000000000000000000000000000007";
        let digest = hash::keccak256(&b"hello pqc");
        let sig = sign(&seed, 0, &digest);
        let recomputed = pub_key_from_sig(&digest, &sig);
        assert!(recomputed == pub_direct(&seed, 0), 0);
    }

    #[test]
    fun test_u256_be() {
        let v = u256_be_from_u64(1);
        assert!(vector::length(&v) == 32, 1);
        assert!(*vector::borrow(&v, 31) == 1u8, 2);
        assert!(*vector::borrow(&v, 0) == 0u8, 3);
    }
}
