import { hashChildren, precomputeZeroLevels, zeroLeaf } from "./hash";
import { TREE_DEPTH } from "./consts";

/**
 * Mirrors on-chain `merkle::incremental_append` so clients can build Merkle paths for spends (Zcash-style fixed-depth tree).
 * Replay the same ordered commitments as on-chain shields.
 */
export class MerkleTreeSimulator {
  readonly depth: number;

  readonly zeroLevels: Uint8Array[];

  filledSubtrees: Uint8Array[];

  nextIndex = 0;

  private readonly paths: Uint8Array[][] = [];

  private lastRoot: Uint8Array;

  constructor(depth: number = TREE_DEPTH) {
    this.depth = depth;
    this.zeroLevels = precomputeZeroLevels(depth);
    const z0 = this.zeroLevels[0]!;
    this.filledSubtrees = Array.from({ length: depth }, () => Uint8Array.from(z0));
    this.lastRoot = zeroLeaf();
  }

  /** Append a leaf commitment (32 bytes). Returns leaf index and new Merkle root. */
  append(leaf: Uint8Array): { leafIndex: number; newRoot: Uint8Array } {
    if (leaf.length !== 32) {
      throw new Error("leaf must be 32 bytes");
    }
    if (this.nextIndex >= Number(1n << BigInt(this.depth))) {
      throw new Error("tree full");
    }
    const leafIndex = this.nextIndex;
    const pathAtLevel: Uint8Array[] = [];
    let index = BigInt(leafIndex);
    let current = Uint8Array.from(leaf);
    for (let level = 0; level < this.depth; level++) {
      const z = this.zeroLevels[level]!;
      if (index % 2n === 0n) {
        pathAtLevel.push(Uint8Array.from(z));
        this.filledSubtrees[level] = Uint8Array.from(current);
        current = Uint8Array.from(hashChildren(current, z));
      } else {
        const left = this.filledSubtrees[level]!;
        pathAtLevel.push(Uint8Array.from(left));
        current = Uint8Array.from(hashChildren(left, current));
      }
      index >>= 1n;
    }
    this.paths.push(pathAtLevel);
    this.nextIndex += 1;
    this.lastRoot = current;
    return { leafIndex, newRoot: current };
  }

  /** Current Merkle root after all appends. */
  getRoot(): Uint8Array {
    return Uint8Array.from(this.lastRoot);
  }

  /** Sibling hashes bottom-up (length === depth), matching Move `verify_proof`. */
  getPath(leafIndex: number): Uint8Array[] {
    const p = this.paths[leafIndex];
    if (!p) {
      throw new Error("unknown leaf index; replay shields in order first");
    }
    return p.map((x) => Uint8Array.from(x));
  }
}

/** Rebuild simulator from an ordered list of leaf commitments (e.g. from indexer events). */
export function replayMerkleFromLeaves(leaves: Uint8Array[], depth: number = TREE_DEPTH): MerkleTreeSimulator {
  const sim = new MerkleTreeSimulator(depth);
  for (const l of leaves) {
    sim.append(l);
  }
  return sim;
}
