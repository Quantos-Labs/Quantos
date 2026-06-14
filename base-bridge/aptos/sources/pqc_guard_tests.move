// PQC-Guard Aptos — verification tests (no resources needed).
//
// Builds the canonical attestation blob (spec §4) for height-0 attestor trees
// and checks the §5 verification algorithm: quorum reached / not reached /
// non-member rejected.
//
// TESTNET ONLY. // AUDIT REQUIRED.
#[test_only]
module quantos::pqc_guard_tests {
    use std::vector;
    use aptos_std::aptos_hash;
    use quantos::pqc_guard_crypto as crypto;
    use quantos::pqc_guard;

    const W: u64 = 16;
    const LEN: u64 = 67;

    // ── WOTS test signer (mirrors the spec sk/sign) ─────────────────────────

    fun sk(seed: &vector<u8>, leaf: u64, chain: u64): vector<u8> {
        let buf = b"PQCG_WOTS_SK";
        vector::append(&mut buf, *seed);
        vector::append(&mut buf, crypto::u256_be_from_u64(leaf));
        vector::append(&mut buf, crypto::u256_be_from_u64(chain));
        aptos_hash::keccak256(buf)
    }

    fun sign(seed: &vector<u8>, leaf: u64, digest: &vector<u8>): vector<vector<u8>> {
        let d = crypto::digits(digest);
        let sig = vector::empty<vector<u8>>();
        let i = 0;
        while (i < LEN) {
            let x = sk(seed, leaf, i);
            let reps = (*vector::borrow(&d, i) as u64);
            let r = 0;
            while (r < reps) { x = aptos_hash::keccak256(x); r = r + 1; };
            vector::push_back(&mut sig, x);
            i = i + 1;
        };
        sig
    }

    /// Height-0 WOTS root = wots_leaf(pub) for the given seed/leaf.
    fun wots_root0(seed: &vector<u8>, leaf: u64, digest: &vector<u8>): vector<u8> {
        let sig = sign(seed, leaf, digest);
        let pubk = crypto::pub_key_from_sig(digest, &sig);
        crypto::wots_leaf(&pubk)
    }

    // ── blob encoders (canonical big-endian, spec §4) ───────────────────────

    fun push_u32(buf: &mut vector<u8>, n: u64) {
        let i = 4;
        while (i > 0) {
            i = i - 1;
            vector::push_back(buf, (((n >> ((i as u8) * 8)) & 0xff) as u8));
        };
    }

    fun push_u64(buf: &mut vector<u8>, n: u64) {
        let i = 8;
        while (i > 0) {
            i = i - 1;
            vector::push_back(buf, (((n >> ((i as u8) * 8)) & 0xff) as u8));
        };
    }

    fun push_words(buf: &mut vector<u8>, ws: &vector<vector<u8>>) {
        push_u32(buf, vector::length(ws));
        let n = vector::length(ws);
        let i = 0;
        while (i < n) {
            vector::append(buf, *vector::borrow(ws, i));
            i = i + 1;
        };
    }

    fun encode_proof(
        buf: &mut vector<u8>,
        id: &vector<u8>,
        wots_root: &vector<u8>,
        leaf_index: u64,
        sig: &vector<vector<u8>>,
        path: &vector<vector<u8>>,
        set_index: u64,
        set_proof: &vector<vector<u8>>,
    ) {
        vector::append(buf, *id);
        vector::append(buf, *wots_root);
        push_u64(buf, leaf_index);
        push_words(buf, sig);
        push_words(buf, path);
        push_u64(buf, set_index);
        push_words(buf, set_proof);
    }

    fun word(byte: u8): vector<u8> {
        let v = vector::empty<u8>();
        let i = 0;
        while (i < 32) { vector::push_back(&mut v, byte); i = i + 1; };
        v
    }

    // ── tests ────────────────────────────────────────────────────────────--

    #[test]
    fun test_quorum_reached() {
        let digest = aptos_hash::keccak256(b"authorize this");
        let seed0 = word(1);
        let seed1 = word(2);
        let id0 = word(0x11);
        let id1 = word(0x22);

        let root0 = wots_root0(&seed0, 0, &digest);
        let root1 = wots_root0(&seed1, 0, &digest);

        let leaf0 = crypto::attestor_leaf(&id0, &root0);
        let leaf1 = crypto::attestor_leaf(&id1, &root1);
        let set_root = crypto::node(leaf0, leaf1);

        let sig0 = sign(&seed0, 0, &digest);
        let sig1 = sign(&seed1, 0, &digest);
        let empty = vector::empty<vector<u8>>();
        let sp0 = vector::empty<vector<u8>>();
        vector::push_back(&mut sp0, leaf1);
        let sp1 = vector::empty<vector<u8>>();
        vector::push_back(&mut sp1, leaf0);

        let blob = vector::empty<u8>();
        push_u32(&mut blob, 2);
        encode_proof(&mut blob, &id0, &root0, 0, &sig0, &empty, 0, &sp0);
        encode_proof(&mut blob, &id1, &root1, 0, &sig1, &empty, 1, &sp1);

        assert!(pqc_guard::verify_authorization(&blob, &digest, &set_root, 2), 0);
    }

    #[test]
    fun test_quorum_not_reached() {
        let digest = aptos_hash::keccak256(b"authorize this");
        let seed0 = word(1);
        let seed1 = word(2);
        let id0 = word(0x11);
        let id1 = word(0x22);

        let root0 = wots_root0(&seed0, 0, &digest);
        let root1 = wots_root0(&seed1, 0, &digest);
        let leaf0 = crypto::attestor_leaf(&id0, &root0);
        let leaf1 = crypto::attestor_leaf(&id1, &root1);
        let set_root = crypto::node(leaf0, leaf1);

        let sig0 = sign(&seed0, 0, &digest);
        let empty = vector::empty<vector<u8>>();
        let sp0 = vector::empty<vector<u8>>();
        vector::push_back(&mut sp0, leaf1);

        let blob = vector::empty<u8>();
        push_u32(&mut blob, 1);
        encode_proof(&mut blob, &id0, &root0, 0, &sig0, &empty, 0, &sp0);

        assert!(!pqc_guard::verify_authorization(&blob, &digest, &set_root, 2), 1);
    }

    #[test]
    fun test_not_in_set_rejected() {
        let digest = aptos_hash::keccak256(b"authorize this");
        let seed0 = word(1);
        let seed1 = word(2);
        let id0 = word(0x11);
        let id1 = word(0x22);

        let root0 = wots_root0(&seed0, 0, &digest);
        let root1 = wots_root0(&seed1, 0, &digest);
        let leaf0 = crypto::attestor_leaf(&id0, &root0);
        let leaf1 = crypto::attestor_leaf(&id1, &root1);
        let set_root = crypto::node(leaf0, leaf1);

        let fake_id = word(0xDE);
        let sig0 = sign(&seed0, 0, &digest);
        let sig1 = sign(&seed1, 0, &digest);
        let empty = vector::empty<vector<u8>>();
        let sp0 = vector::empty<vector<u8>>();
        vector::push_back(&mut sp0, leaf1);
        let sp1 = vector::empty<vector<u8>>();
        vector::push_back(&mut sp1, leaf0);

        let blob = vector::empty<u8>();
        push_u32(&mut blob, 2);
        encode_proof(&mut blob, &id0, &root0, 0, &sig0, &empty, 0, &sp0);
        encode_proof(&mut blob, &fake_id, &root1, 0, &sig1, &empty, 1, &sp1);

        assert!(!pqc_guard::verify_authorization(&blob, &digest, &set_root, 2), 2);
    }
}
