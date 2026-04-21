import { keccak_256 } from "@noble/hashes/sha3";
import { concatBytes } from "@noble/hashes/utils";

const ZERO_LEAF_LABEL = new TextEncoder().encode("SA_ZERO_LEAF_v1");
const MERKLE_PAIR_LABEL = new TextEncoder().encode("SA_MERKLE_PAIR_v1");

/** 32-byte zero leaf — matches Move `merkle::zero_leaf`. */
export function zeroLeaf(): Uint8Array {
  return keccak_256(ZERO_LEAF_LABEL);
}

/** Matches Move `merkle::hash_children`. */
export function hashChildren(left: Uint8Array, right: Uint8Array): Uint8Array {
  return keccak_256(concatBytes(MERKLE_PAIR_LABEL, left, right));
}

/** Matches Move `merkle::precompute_zero_levels`. */
export function precomputeZeroLevels(depth: number): Uint8Array[] {
  const z: Uint8Array[] = [zeroLeaf()];
  for (let i = 1; i < depth; i++) {
    const prev = z[i - 1]!;
    z.push(hashChildren(prev, prev));
  }
  return z;
}

export function maxLeavesForDepth(depth: number): bigint {
  return 1n << BigInt(depth);
}
