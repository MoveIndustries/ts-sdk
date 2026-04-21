import { noteCommitment, deriveNullifier } from "../src/commitment";
import { MerkleTreeSimulator } from "../src/merkleSimulator";
import { ShieldedPoolClient } from "../src/shieldedPool";
import { TREE_DEPTH } from "../src/consts";

describe("shielded transfer (shielded → shielded)", () => {
  it("simulates spend + append: nullifier, new commitment, root updates", () => {
    const amount = 500n;
    const blindingIn = new Uint8Array(32).map((_, i) => i + 1);
    const blindingOut = new Uint8Array(32).map((_, i) => i + 50);

    const cmIn = noteCommitment(amount, blindingIn);
    const cmOut = noteCommitment(amount, blindingOut);
    expect(cmIn.some((b, i) => b !== cmOut[i])).toBe(true);

    const sim = new MerkleTreeSimulator(TREE_DEPTH);
    const { leafIndex, newRoot: rootAfterShield } = sim.append(cmIn);
    expect(leafIndex).toBe(0);

    const siblings = sim.getPath(0);
    expect(siblings.length).toBe(TREE_DEPTH);

    const nf = deriveNullifier(blindingIn);
    expect(nf.length).toBe(32);

    const { newRoot: rootAfterTransfer } = sim.append(cmOut);
    expect(rootAfterTransfer.length).toBe(32);
    expect(sim.nextIndex).toBe(2);
    expect(rootAfterTransfer.some((b, i) => b !== rootAfterShield[i])).toBe(true);
  });

  it("rejects wrong merkle depth before any network call", async () => {
    const client = new ShieldedPoolClient(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      {} as any,
      "0x1",
    );
    await expect(
      client.buildShieldedTransfer({
        sender: "0x1",
        metadata: "0x2",
        amount: 1n,
        blindingIn: new Uint8Array(32),
        leafIndex: 0n,
        merkleSiblings: [],
        historicRoot: new Uint8Array(32),
        blindingOut: new Uint8Array(32),
      }),
    ).rejects.toThrow(/merkleSiblings must have length/);
  });
});
