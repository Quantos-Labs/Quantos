// PQC-Guard — cross-VM crypto primitives for Aptos (Move).
//
// Implements the INVARIANT keccak256 encodings from MULTIVM_SPEC.md §2:
// Winternitz OTS verification + one-time Merkle trees + attestor-set leaves.
// MUST match `quantos/src/l0/pqc_guard.rs`, the EVM libs, and the Sui port
// byte-for-byte.
//
// Aptos Move notes: locals are mutable by default (no `let mut`), and
// `aptos_hash::keccak256` consumes its argument (takes `vector<u8>` by value).
//
// TESTNET ONLY. // AUDIT REQUIRED.
module quantos::pqc_guard_crypto {
    use std::vector;
    use aptos_std::aptos_hash;

    const W: u64 = 16;
    const LEN: u64 = 67;

    const E_BAD_DIGEST_LEN: u64 = 100;
    const E_BAD_SIG_LEN: u64 = 101;

    /// keccak256(a ++ b) for two 32-byte words (Merkle node).
    public fun node(left: vector<u8>, right: vector<u8>): vector<u8> {
        let buf = vector::empty<u8>();
        vector::append(&mut buf, left);
        vector::append(&mut buf, right);
        aptos_hash::keccak256(buf)
    }

    /// 32-byte big-endian encoding of a u64 (the `u256_be(n)` of the spec).
    public fun u256_be_from_u64(n: u64): vector<u8> {
        let out = vector::empty<u8>();
        let i = 0;
        while (i < 24) { vector::push_back(&mut out, 0u8); i = i + 1; };
        let j = 8;
        while (j > 0) {
            j = j - 1;
            let shift = (j as u8) * 8;
            let byte = (((n >> shift) & 0xff) as u8);
            vector::push_back(&mut out, byte);
        };
        out
    }

    /// Expand a 32-byte digest into 64 message + 3 checksum base-16 digits.
    public fun digits(digest: &vector<u8>): vector<u8> {
        assert!(vector::length(digest) == 32, E_BAD_DIGEST_LEN);
        let d = vector::empty<u8>();
        let csum: u64 = 0;
        let i = 0;
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
    public fun pub_key_from_sig(digest: &vector<u8>, sig: &vector<vector<u8>>): vector<u8> {
        assert!(vector::length(sig) == LEN, E_BAD_SIG_LEN);
        let d = digits(digest);
        let concat = vector::empty<u8>();
        let i = 0;
        while (i < LEN) {
            let x = *vector::borrow(sig, i);
            let target = W - 1;
            let j = (*vector::borrow(&d, i) as u64);
            while (j < target) { x = aptos_hash::keccak256(x); j = j + 1; };
            vector::append(&mut concat, x);
            i = i + 1;
        };
        aptos_hash::keccak256(concat)
    }

    /// Domain-separated WOTS Merkle leaf.
    public fun wots_leaf(wots_pub: &vector<u8>): vector<u8> {
        let buf = b"PQCG_WOTS_LEAF";
        vector::append(&mut buf, *wots_pub);
        aptos_hash::keccak256(buf)
    }

    /// Recompute a Merkle root from a leaf, its index and an authentication path.
    public fun root_from_leaf(leaf: vector<u8>, index: u64, path: &vector<vector<u8>>): vector<u8> {
        let h = leaf;
        let idx = index;
        let n = vector::length(path);
        let i = 0;
        while (i < n) {
            let sib = *vector::borrow(path, i);
            if (idx & 1 == 0) { h = node(h, sib); } else { h = node(sib, h); };
            idx = idx >> 1;
            i = i + 1;
        };
        h
    }

    /// Domain-separated attestor-set leaf (binds Quantos validator id + WOTS root).
    public fun attestor_leaf(attestor_id: &vector<u8>, wots_root: &vector<u8>): vector<u8> {
        let buf = b"PQCG_ATTESTOR_LEAF";
        vector::append(&mut buf, *attestor_id);
        vector::append(&mut buf, *wots_root);
        aptos_hash::keccak256(buf)
    }
}
