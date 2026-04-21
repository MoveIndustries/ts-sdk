/// Merkle tree for the shielded pool: keccak256 domain-separated pairing, batch root, and
/// incremental append-only updates (fixed depth, Zcash-style note-commitment-tree *shape*) for O(depth) shield gas.
module shielded_assets::merkle {
    use aptos_std::aptos_hash;
    use std::vector;

    fun concat2(a: vector<u8>, b: vector<u8>): vector<u8> {
        vector::append(&mut a, b);
        a
    }

    /// Precomputed empty leaf (32 bytes).
    public fun zero_leaf(): vector<u8> {
        aptos_hash::keccak256(b"SA_ZERO_LEAF_v1")
    }

    /// Hash two 32-byte children.
    public fun hash_children(left: vector<u8>, right: vector<u8>): vector<u8> {
        let d = concat2(b"SA_MERKLE_PAIR_v1", left);
        aptos_hash::keccak256(concat2(d, right))
    }

    /// Empty-subtree hashes: `z[0] = zero_leaf()`, `z[i+1] = H(z[i], z[i])`.
    public fun precompute_zero_levels(depth: u64): vector<vector<u8>> {
        let z = vector::empty();
        vector::push_back(&mut z, zero_leaf());
        let i = 1u64;
        while (i < depth) {
            let prev = *vector::borrow(&z, i - 1);
            vector::push_back(&mut z, hash_children(copy prev, prev));
            i += 1;
        };
        z
    }

    /// Smallest power of two >= n (n > 0).
    public fun next_power_of_two(n: u64): u64 {
        if (n <= 1) {
            return 1
        };
        let p = 1u64;
        while (p < n) {
            p = p << 1;
        };
        p
    }

    fun pad_leaves(leaves: &vector<vector<u8>>): vector<vector<u8>> {
        let n = vector::length(leaves);
        let pad = next_power_of_two(if (n == 0) { 1 } else { n });
        let out = vector::empty();
        let i = 0u64;
        while (i < n) {
            vector::push_back(&mut out, *vector::borrow(leaves, i));
            i += 1;
        };
        let z = zero_leaf();
        while (vector::length(&out) < pad) {
            vector::push_back(&mut out, z);
        };
        out
    }

    /// Full Merkle root (padded). Tests / off-chain parity.
    public fun compute_root(leaves: &vector<vector<u8>>): vector<u8> {
        compute_root_inner(pad_leaves(leaves))
    }

    fun compute_root_inner(level: vector<vector<u8>>): vector<u8> {
        if (vector::length(&level) == 1) {
            return *vector::borrow(&level, 0)
        };
        let next = vector::empty();
        let i = 0u64;
        let len = vector::length(&level);
        while (i < len) {
            let left = *vector::borrow(&level, i);
            let right = *vector::borrow(&level, i + 1);
            vector::push_back(&mut next, hash_children(left, right));
            i += 2;
        };
        compute_root_inner(next)
    }

    fun incremental_append_rec(
        current: vector<u8>,
        level: u64,
        depth: u64,
        filled_subtrees: &mut vector<vector<u8>>,
        zero_levels: &vector<vector<u8>>,
        index: u64,
    ): vector<u8> {
        if (level == depth) {
            return current
        };
        let z = vector::borrow(zero_levels, level);
        if (index % 2 == 0) {
            *vector::borrow_mut(filled_subtrees, level) = copy current;
            let next = hash_children(current, *z);
            incremental_append_rec(next, level + 1, depth, filled_subtrees, zero_levels, index >> 1)
        } else {
            let left = *vector::borrow(filled_subtrees, level);
            let next = hash_children(left, current);
            incremental_append_rec(next, level + 1, depth, filled_subtrees, zero_levels, index >> 1)
        }
    }

    /// Append one leaf with incremental bookkeeping (`filled_subtrees`, zero-subtree hashes per level).
    /// Same high-level pattern as Zcash’s note commitment tree; hash function and depth differ from Sapling/Orchard.
    public fun incremental_append(
        leaf: vector<u8>,
        depth: u64,
        filled_subtrees: &mut vector<vector<u8>>,
        zero_levels: &vector<vector<u8>>,
        next_index: u64,
    ): vector<u8> {
        assert!(vector::length(filled_subtrees) == depth, 1);
        assert!(vector::length(zero_levels) == depth, 2);
        assert!(next_index < max_leaves_for_depth(depth), 3);
        incremental_append_rec(leaf, 0, depth, filled_subtrees, zero_levels, next_index)
    }

    public fun max_leaves_for_depth(d: u64): u64 {
        let r = 1u64;
        let i = 0u64;
        while (i < d) {
            r = r << 1;
            i += 1;
        };
        r
    }

    fun fold_merkle_path(
        cur: vector<u8>,
        leaf_index: u64,
        s: u64,
        depth: u64,
        siblings: &vector<vector<u8>>,
    ): vector<u8> {
        if (s == depth) {
            return cur
        };
        let idx_at_level = leaf_index >> (s as u8);
        let sib = vector::borrow(siblings, s);
        let next = if (idx_at_level % 2 == 0) {
            hash_children(cur, *sib)
        } else {
            hash_children(*sib, cur)
        };
        fold_merkle_path(next, leaf_index, s + 1, depth, siblings)
    }

    /// Verify Merkle path against a **fixed-depth** tree (same depth as incremental append).
    /// `siblings.len()` must equal `tree_depth` (each 32 bytes; use zero-level hashes for empty siblings).
    public fun verify_proof(
        leaf: vector<u8>,
        leaf_index: u64,
        num_leaves: u64,
        tree_depth: u64,
        siblings: &vector<vector<u8>>,
        expected_root: vector<u8>,
    ): bool {
        if (num_leaves == 0) {
            return false
        };
        if (leaf_index >= num_leaves) {
            return false
        };
        if (vector::length(siblings) != tree_depth) {
            return false
        };
        let s = 0u64;
        while (s < tree_depth) {
            if (vector::length(vector::borrow(siblings, s)) != 32) {
                return false
            };
            s += 1;
        };
        fold_merkle_path(leaf, leaf_index, 0, tree_depth, siblings) == expected_root
    }

    #[test]
    fun test_incremental_three_leaves_smoke() {
        let depth = 4u64;
        let zeros = precompute_zero_levels(depth);
        let filled = vector::empty();
        let z0 = *vector::borrow(&zeros, 0);
        let j = 0u64;
        while (j < depth) {
            vector::push_back(&mut filled, copy z0);
            j += 1;
        };
        let l1 = aptos_hash::keccak256(b"l1");
        let l2 = aptos_hash::keccak256(b"l2");
        let l3 = aptos_hash::keccak256(b"l3");
        let mut_filled = filled;
        let _r1 = incremental_append(l1, depth, &mut mut_filled, &zeros, 0);
        let _r2 = incremental_append(l2, depth, &mut mut_filled, &zeros, 1);
        let r3 = incremental_append(l3, depth, &mut mut_filled, &zeros, 2);
        assert!(vector::length(&r3) == 32, 1);
        assert!(r3 != aptos_hash::keccak256(b""), 2);
    }
}
