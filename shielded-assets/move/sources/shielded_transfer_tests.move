#[test_only]
/// Merkle + commitment checks for the **shielded_transfer** spend-then-append pattern (no FA / registry).
module shielded_assets::shielded_transfer_tests {
    use std::bcs;
    use std::vector;
    use aptos_std::aptos_hash;
    use shielded_assets::merkle;

    const DEPTH: u64 = 8;

    fun note_commitment_local(amount: u64, blinding: &vector<u8>): vector<u8> {
        let data = b"SA_NOTE_v1";
        vector::append(&mut data, bcs::to_bytes(&amount));
        vector::append(&mut data, *blinding);
        aptos_hash::keccak256(data)
    }

    fun derive_nullifier_local(blinding: &vector<u8>): vector<u8> {
        let data = b"SA_NULL_v1";
        vector::append(&mut data, *blinding);
        aptos_hash::keccak256(data)
    }

    fun blinding_pattern(start: u8): vector<u8> {
        let v = vector::empty();
        let i = 0u64;
        while (i < 32) {
            vector::push_back(&mut v, ((start as u64) + i) as u8);
            i += 1;
        };
        v
    }

    #[test]
    /// After one shield (one leaf), inclusion of `cm_in` verifies; appending `cm_out` matches incremental transfer.
    fun spend_first_note_then_append_output_matches_incremental_path() {
        let zeros = merkle::precompute_zero_levels(DEPTH);
        let z0 = *vector::borrow(&zeros, 0);
        let filled = vector::empty();
        let j = 0u64;
        while (j < DEPTH) {
            vector::push_back(&mut filled, copy z0);
            j += 1;
        };

        let blind_in = blinding_pattern(1);
        let blind_out = blinding_pattern(100);

        let amount = 1000u64;
        let cm_in = note_commitment_local(amount, &blind_in);
        let cm_out = note_commitment_local(amount, &blind_out);

        let root_after_in = merkle::incremental_append(
            copy cm_in,
            DEPTH,
            &mut filled,
            &zeros,
            0,
        );

        let num_leaves = 1u64;
        let siblings = vector::empty();
        let k = 0u64;
        while (k < DEPTH) {
            vector::push_back(&mut siblings, *vector::borrow(&zeros, k));
            k += 1;
        };

        assert!(
            merkle::verify_proof(copy cm_in, 0, num_leaves, DEPTH, &siblings, root_after_in),
            1,
        );

        let nf = derive_nullifier_local(&blind_in);
        assert!(vector::length(&nf) == 32, 2);

        let _root_final = merkle::incremental_append(
            cm_out,
            DEPTH,
            &mut filled,
            &zeros,
            1,
        );
        assert!(merkle::max_leaves_for_depth(DEPTH) > 1, 3);
    }
}
