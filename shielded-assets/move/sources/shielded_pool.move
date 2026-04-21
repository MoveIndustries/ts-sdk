/// FA-backed shielded pool: incremental Merkle tree, nullifier set, historical roots, FA via
/// [`aptos_framework::fungible_asset`].
///
/// **Viewer keys (Zcash-style auditability):** shield/unshield carry optional ciphertext blobs for
/// incoming / outgoing viewing keys. The chain does not decrypt them; wallets and auditors recover
/// plaintext off-chain using the same key material conventions as the TypeScript SDK.
///
/// **Privacy:** Shield / unshield / `shielded_transfer` use a **witness** in tx args (`amount`,
/// blindings, Merkle siblings) in this witness-based protocol; ciphertext fields are for **wallet
/// sync / audit**, not on-chain zero-knowledge. A future ZK spend can hide these.
module shielded_assets::shielded_pool {
    use std::bcs;
    use std::error;
    use std::signer;
    use std::vector;
    use aptos_std::aptos_hash;
    use aptos_std::table::{Self, Table};
    use aptos_framework::event;
    use aptos_framework::fungible_asset::{Self, Metadata};
    use aptos_framework::object::{Self, Object};
    use aptos_framework::primary_fungible_store;
    use shielded_assets::merkle;

    //
    // Constants
    //

    const TREE_DEPTH: u64 = 20;
    const ROOT_HISTORY_LEN: u64 = 128;
    const MAX_INCOMING_VIEW_CIPHERTEXT: u64 = 512;
    const MAX_OUTGOING_VIEW_CIPHERTEXT: u64 = 256;
    const BLINDING_LEN: u64 = 32;

    //
    // Errors
    //

    const E_INVALID_BLINDING_LEN: u64 = 1;
    const E_ZERO_AMOUNT: u64 = 2;
    const E_BAD_LEAF_INDEX: u64 = 3;
    const E_BAD_MERKLE_PROOF: u64 = 5;
    const E_NULLIFIER_REPLAY: u64 = 6;
    const E_UNKNOWN_ROOT: u64 = 7;
    const E_TREE_FULL: u64 = 8;
    const E_INCOMING_CT_TOO_LONG: u64 = 9;
    const E_OUTGOING_CT_TOO_LONG: u64 = 10;
    const E_NO_POOL: u64 = 11;
    const E_SAME_BLINDING: u64 = 12;

    //
    // Events (indexers + wallets decrypt `*_view_ciphertext` off-chain with IVK/OVK)
    //

    #[event]
    struct ShieldedInsertEvent has store, drop {
        metadata: address,
        leaf_index: u64,
        commitment: vector<u8>,
        merkle_root: vector<u8>,
        incoming_view_ciphertext: vector<u8>,
    }

    #[event]
    struct UnshieldEvent has store, drop {
        metadata: address,
        amount: u64,
        recipient: address,
        nullifier: vector<u8>,
        outgoing_view_ciphertext: vector<u8>,
    }

    #[event]
    struct ShieldedTransferEvent has store, drop {
        metadata: address,
        leaf_index_in: u64,
        leaf_index_out: u64,
        commitment_in: vector<u8>,
        commitment_out: vector<u8>,
        nullifier: vector<u8>,
        merkle_root: vector<u8>,
        outgoing_view_ciphertext: vector<u8>,
    }

    //
    // State
    //

    struct ShieldedPoolRegistry has key {
        extend_ref: object::ExtendRef,
        pools: Table<address, TokenPool>,
    }

    struct TokenPool has store {
        filled_subtrees: vector<vector<u8>>,
        next_leaf_index: u64,
        current_root: vector<u8>,
        roots_ring: vector<vector<u8>>,
        roots_write_seq: u64,
        nullifiers: Table<vector<u8>, bool>,
    }

    //
    // Commitments (must match TS SDK)
    //

    fun note_commitment(amount: u64, blinding: &vector<u8>): vector<u8> {
        assert!(vector::length(blinding) == BLINDING_LEN, error::invalid_argument(E_INVALID_BLINDING_LEN));
        let data = b"SA_NOTE_v1";
        vector::append(&mut data, bcs::to_bytes(&amount));
        vector::append(&mut data, *blinding);
        aptos_hash::keccak256(data)
    }

    fun derive_nullifier(blinding: &vector<u8>): vector<u8> {
        assert!(vector::length(blinding) == BLINDING_LEN, error::invalid_argument(E_INVALID_BLINDING_LEN));
        let data = b"SA_NULL_v1";
        vector::append(&mut data, *blinding);
        aptos_hash::keccak256(data)
    }

    fun blindings_differ(a: &vector<u8>, b: &vector<u8>): bool {
        if (vector::length(a) != vector::length(b)) {
            return false
        };
        let i = 0u64;
        let n = vector::length(a);
        while (i < n) {
            if (*vector::borrow(a, i) != *vector::borrow(b, i)) {
                return true
            };
            i += 1;
        };
        false
    }

    fun pool_address(): address acquires ShieldedPoolRegistry {
        let reg = borrow_global<ShieldedPoolRegistry>(@shielded_assets);
        object::address_from_extend_ref(&reg.extend_ref)
    }

    fun init_filled_subtrees(): vector<vector<u8>> {
        let zero_levels = merkle::precompute_zero_levels(TREE_DEPTH);
        let z0 = *vector::borrow(&zero_levels, 0);
        let filled = vector::empty();
        let k = 0u64;
        while (k < TREE_DEPTH) {
            vector::push_back(&mut filled, copy z0);
            k += 1;
        };
        filled
    }

    fun push_root(pool: &mut TokenPool, root: vector<u8>) {
        let len = vector::length(&pool.roots_ring);
        if (len < ROOT_HISTORY_LEN) {
            vector::push_back(&mut pool.roots_ring, root);
        } else {
            let pos = pool.roots_write_seq % ROOT_HISTORY_LEN;
            *vector::borrow_mut(&mut pool.roots_ring, pos) = root;
        };
        pool.roots_write_seq += 1;
    }

    fun roots_contain(pool: &TokenPool, root: &vector<u8>): bool {
        let n = vector::length(&pool.roots_ring);
        let i = 0u64;
        while (i < n) {
            if (*vector::borrow(&pool.roots_ring, i) == *root) {
                return true
            };
            i += 1;
        };
        false
    }

    fun ensure_pool(reg: &mut ShieldedPoolRegistry, metadata_addr: address): &mut TokenPool {
        if (!table::contains(&reg.pools, metadata_addr)) {
            table::add(
                &mut reg.pools,
                metadata_addr,
                TokenPool {
                    filled_subtrees: init_filled_subtrees(),
                    next_leaf_index: 0,
                    current_root: merkle::zero_leaf(),
                    roots_ring: vector::empty(),
                    roots_write_seq: 0,
                    nullifiers: table::new(),
                },
            );
        };
        table::borrow_mut(&mut reg.pools, metadata_addr)
    }

    fun borrow_pool_mut(reg: &mut ShieldedPoolRegistry, metadata_addr: address): &mut TokenPool {
        assert!(table::contains(&reg.pools, metadata_addr), error::not_found(E_NO_POOL));
        table::borrow_mut(&mut reg.pools, metadata_addr)
    }

    /// Called once when the package is published.
    fun init_module(deployer: &signer) {
        let deployer_addr = signer::address_of(deployer);
        let ctor = &object::create_object(deployer_addr);
        move_to(
            deployer,
            ShieldedPoolRegistry {
                extend_ref: object::generate_extend_ref(ctor),
                pools: table::new(),
            },
        );
    }

    /// Deposit FA and append a note commitment. `incoming_view_ciphertext` encrypts note plaintext
    /// for the holder's **incoming viewing key** (see SDK); may be empty.
    public entry fun shield(
        user: &signer,
        metadata: Object<Metadata>,
        amount: u64,
        blinding: vector<u8>,
        incoming_view_ciphertext: vector<u8>,
    ) acquires ShieldedPoolRegistry {
        assert!(amount > 0, error::invalid_argument(E_ZERO_AMOUNT));
        assert!(vector::length(&blinding) == BLINDING_LEN, error::invalid_argument(E_INVALID_BLINDING_LEN));
        assert!(
            vector::length(&incoming_view_ciphertext) <= MAX_INCOMING_VIEW_CIPHERTEXT,
            error::invalid_argument(E_INCOMING_CT_TOO_LONG),
        );

        let reg = borrow_global_mut<ShieldedPoolRegistry>(@shielded_assets);
        let meta_addr = object::object_address(&metadata);
        let pool = ensure_pool(reg, meta_addr);
        assert!(
            pool.next_leaf_index < merkle::max_leaves_for_depth(TREE_DEPTH),
            error::invalid_state(E_TREE_FULL),
        );

        let cm = note_commitment(amount, &blinding);
        let zl = merkle::precompute_zero_levels(TREE_DEPTH);
        let new_root = merkle::incremental_append(
            cm,
            TREE_DEPTH,
            &mut pool.filled_subtrees,
            &zl,
            pool.next_leaf_index,
        );
        let leaf_index = pool.next_leaf_index;
        pool.next_leaf_index += 1;
        pool.current_root = copy new_root;
        push_root(pool, copy new_root);

        let user_addr = signer::address_of(user);
        let ps = object::generate_signer_for_extending(&reg.extend_ref);
        let paddr = signer::address_of(&ps);
        let from_store = primary_fungible_store::ensure_primary_store_exists(user_addr, metadata);
        let pool_store = primary_fungible_store::ensure_primary_store_exists(paddr, metadata);
        let fa = fungible_asset::withdraw(user, from_store, amount);
        fungible_asset::deposit(pool_store, fa);

        event::emit(ShieldedInsertEvent {
            metadata: meta_addr,
            leaf_index,
            commitment: cm,
            merkle_root: new_root,
            incoming_view_ciphertext,
        });
    }

    /// **Shielded → shielded:** spend one note (Merkle proof + nullifier) and append a **new** note
    /// with the same `amount` and `blinding_out`. Pool FA balance is unchanged (no unshield).
    ///
    /// The recipient learns `blinding_out` out-of-band; this format does not embed a payee address
    /// on-chain.
    public entry fun shielded_transfer(
        _witness: &signer,
        metadata: Object<Metadata>,
        amount: u64,
        blinding_in: vector<u8>,
        leaf_index: u64,
        merkle_siblings: vector<vector<u8>>,
        historic_root: vector<u8>,
        blinding_out: vector<u8>,
        outgoing_view_ciphertext: vector<u8>,
    ) acquires ShieldedPoolRegistry {
        assert!(amount > 0, error::invalid_argument(E_ZERO_AMOUNT));
        assert!(vector::length(&blinding_in) == BLINDING_LEN, error::invalid_argument(E_INVALID_BLINDING_LEN));
        assert!(vector::length(&blinding_out) == BLINDING_LEN, error::invalid_argument(E_INVALID_BLINDING_LEN));
        assert!(
            blindings_differ(&blinding_in, &blinding_out),
            error::invalid_argument(E_SAME_BLINDING),
        );
        assert!(
            vector::length(&outgoing_view_ciphertext) <= MAX_OUTGOING_VIEW_CIPHERTEXT,
            error::invalid_argument(E_OUTGOING_CT_TOO_LONG),
        );

        let reg = borrow_global_mut<ShieldedPoolRegistry>(@shielded_assets);
        let meta_addr = object::object_address(&metadata);
        let pool = borrow_pool_mut(reg, meta_addr);
        let num_leaves = pool.next_leaf_index;
        assert!(leaf_index < num_leaves, error::out_of_range(E_BAD_LEAF_INDEX));
        assert!(
            pool.next_leaf_index < merkle::max_leaves_for_depth(TREE_DEPTH),
            error::invalid_state(E_TREE_FULL),
        );

        let cm_in = note_commitment(amount, &blinding_in);
        assert!(roots_contain(pool, &historic_root), error::invalid_argument(E_UNKNOWN_ROOT));
        assert!(
            merkle::verify_proof(cm_in, leaf_index, num_leaves, TREE_DEPTH, &merkle_siblings, historic_root),
            error::invalid_argument(E_BAD_MERKLE_PROOF),
        );

        let nf = derive_nullifier(&blinding_in);
        assert!(!table::contains(&pool.nullifiers, copy nf), error::invalid_argument(E_NULLIFIER_REPLAY));
        let nf_evt = copy nf;
        table::add(&mut pool.nullifiers, nf, true);

        let cm_out = note_commitment(amount, &blinding_out);
        let zl = merkle::precompute_zero_levels(TREE_DEPTH);
        let new_root = merkle::incremental_append(
            cm_out,
            TREE_DEPTH,
            &mut pool.filled_subtrees,
            &zl,
            pool.next_leaf_index,
        );
        let leaf_index_out = pool.next_leaf_index;
        pool.next_leaf_index += 1;
        pool.current_root = copy new_root;
        push_root(pool, copy new_root);

        event::emit(ShieldedTransferEvent {
            metadata: meta_addr,
            leaf_index_in: leaf_index,
            leaf_index_out,
            commitment_in: cm_in,
            commitment_out: cm_out,
            nullifier: nf_evt,
            merkle_root: new_root,
            outgoing_view_ciphertext,
        });
    }

    /// Spend a note to a transparent FA balance using a **historical** Merkle root from [`roots_ring`].
    /// `outgoing_view_ciphertext` encrypts spend metadata for **outgoing viewing** (see SDK).
    public entry fun unshield(
        _witness: &signer,
        metadata: Object<Metadata>,
        amount: u64,
        blinding: vector<u8>,
        leaf_index: u64,
        merkle_siblings: vector<vector<u8>>,
        historic_root: vector<u8>,
        recipient: address,
        outgoing_view_ciphertext: vector<u8>,
    ) acquires ShieldedPoolRegistry {
        assert!(amount > 0, error::invalid_argument(E_ZERO_AMOUNT));
        assert!(vector::length(&blinding) == BLINDING_LEN, error::invalid_argument(E_INVALID_BLINDING_LEN));
        assert!(
            vector::length(&outgoing_view_ciphertext) <= MAX_OUTGOING_VIEW_CIPHERTEXT,
            error::invalid_argument(E_OUTGOING_CT_TOO_LONG),
        );

        let reg = borrow_global_mut<ShieldedPoolRegistry>(@shielded_assets);
        let meta_addr = object::object_address(&metadata);
        let pool = borrow_pool_mut(reg, meta_addr);
        let num_leaves = pool.next_leaf_index;
        assert!(leaf_index < num_leaves, error::out_of_range(E_BAD_LEAF_INDEX));

        let cm = note_commitment(amount, &blinding);
        assert!(roots_contain(pool, &historic_root), error::invalid_argument(E_UNKNOWN_ROOT));

        assert!(
            merkle::verify_proof(cm, leaf_index, num_leaves, TREE_DEPTH, &merkle_siblings, historic_root),
            error::invalid_argument(E_BAD_MERKLE_PROOF),
        );

        let nf = derive_nullifier(&blinding);
        assert!(!table::contains(&pool.nullifiers, copy nf), error::invalid_argument(E_NULLIFIER_REPLAY));
        let nf_evt = copy nf;
        table::add(&mut pool.nullifiers, nf, true);

        let ps = object::generate_signer_for_extending(&reg.extend_ref);
        let paddr = signer::address_of(&ps);
        let pool_store = primary_fungible_store::ensure_primary_store_exists(paddr, metadata);
        let to_store = primary_fungible_store::ensure_primary_store_exists(recipient, metadata);
        let fa = fungible_asset::withdraw(&ps, pool_store, amount);
        fungible_asset::deposit(to_store, fa);

        event::emit(UnshieldEvent {
            metadata: meta_addr,
            amount,
            recipient,
            nullifier: nf_evt,
            outgoing_view_ciphertext,
        });
    }

    //
    // Views
    //

    #[view]
    public fun tree_depth(): u64 {
        TREE_DEPTH
    }

    #[view]
    public fun leaf_count(metadata: Object<Metadata>): u64 acquires ShieldedPoolRegistry {
        let a = object::object_address(&metadata);
        let reg = borrow_global<ShieldedPoolRegistry>(@shielded_assets);
        if (!table::contains(&reg.pools, a)) {
            return 0
        };
        table::borrow(&reg.pools, a).next_leaf_index
    }

    #[view]
    /// Current Merkle root (after last shield).
    public fun current_merkle_root(metadata: Object<Metadata>): vector<u8> acquires ShieldedPoolRegistry {
        let a = object::object_address(&metadata);
        let reg = borrow_global<ShieldedPoolRegistry>(@shielded_assets);
        if (!table::contains(&reg.pools, a)) {
            return merkle::zero_leaf()
        };
        table::borrow(&reg.pools, a).current_root
    }

    #[view]
    public fun pool_balance(metadata: Object<Metadata>): u64 acquires ShieldedPoolRegistry {
        let p = pool_address();
        if (!primary_fungible_store::primary_store_exists(p, metadata)) {
            return 0
        };
        primary_fungible_store::balance(p, metadata)
    }

    #[view]
    public fun is_known_root(metadata: Object<Metadata>, root: vector<u8>): bool acquires ShieldedPoolRegistry {
        let a = object::object_address(&metadata);
        let reg = borrow_global<ShieldedPoolRegistry>(@shielded_assets);
        if (!table::contains(&reg.pools, a)) {
            return false
        };
        roots_contain(table::borrow(&reg.pools, a), &root)
    }

    #[view]
    public fun root_history_len(metadata: Object<Metadata>): u64 acquires ShieldedPoolRegistry {
        let a = object::object_address(&metadata);
        let reg = borrow_global<ShieldedPoolRegistry>(@shielded_assets);
        if (!table::contains(&reg.pools, a)) {
            return 0
        };
        vector::length(&table::borrow(&reg.pools, a).roots_ring)
    }
}
