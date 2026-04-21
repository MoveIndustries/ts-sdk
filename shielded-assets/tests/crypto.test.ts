import { noteCommitment } from "../src/commitment";
import { MerkleTreeSimulator, replayMerkleFromLeaves } from "../src/merkleSimulator";
import {
  decodeIncomingPlaintext,
  decryptIncomingViewPayload,
  encryptIncomingViewPayload,
  encodeIncomingPlaintext,
  randomViewingKey32,
} from "../src/viewKey";
import { TREE_DEPTH } from "../src/consts";

describe("viewing keys", () => {
  it("roundtrips incoming ciphertext", () => {
    const ivk = randomViewingKey32();
    const blinding = randomViewingKey32();
    const meta = randomViewingKey32();
    const amount = 12345n;
    const plain = encodeIncomingPlaintext(amount, blinding, meta);
    const blob = encryptIncomingViewPayload(ivk, plain);
    const out = decryptIncomingViewPayload(ivk, blob);
    expect(out).not.toBeNull();
    const dec = decodeIncomingPlaintext(out!);
    expect(dec.amount).toBe(amount);
    expect(dec.blinding.every((b, i) => b === blinding[i])).toBe(true);
    expect(dec.metadataAddress.every((b, i) => b === meta[i])).toBe(true);
  });

  it("fails decrypt with wrong IVK", () => {
    const ivk = randomViewingKey32();
    const wrong = randomViewingKey32();
    const plain = encodeIncomingPlaintext(1n, randomViewingKey32(), randomViewingKey32());
    const blob = encryptIncomingViewPayload(ivk, plain);
    expect(decryptIncomingViewPayload(wrong, blob)).toBeNull();
  });
});

describe("merkle simulator", () => {
  it("produces paths of depth TREE_DEPTH", () => {
    const sim = new MerkleTreeSimulator(4);
    const a = new Uint8Array(32).fill(1);
    const b = new Uint8Array(32).fill(2);
    sim.append(a);
    sim.append(b);
    expect(sim.getPath(0).length).toBe(4);
    expect(sim.getPath(1).length).toBe(4);
  });

  it("replay matches append order", () => {
    const leaves = [new Uint8Array(32).fill(3), new Uint8Array(32).fill(4)];
    const sim = replayMerkleFromLeaves(leaves, TREE_DEPTH);
    expect(sim.nextIndex).toBe(2);
    expect(sim.getPath(0).length).toBe(TREE_DEPTH);
  });
});

describe("commitments", () => {
  it("note commitment length", () => {
    const c = noteCommitment(99n, new Uint8Array(32).fill(7));
    expect(c.length).toBe(32);
  });
});
