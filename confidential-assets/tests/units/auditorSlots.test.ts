import { TwistedEd25519PrivateKey, TwistedEd25519PublicKey } from "../../src/crypto";
import { assembleAuditorEks } from "../../src/internal/confidentialAssetTxnBuilder";

/**
 * Unit coverage for the `auditor_eks` slot contract from movementlabsxyz/aptos-core#328:
 *
 *   [0]   chain auditor             (mandatory; ECHAIN_AUDITOR_NOT_SET otherwise)
 *   [1]   per-asset auditor         (mandatory iff configured)
 *   [2..] voluntary per-transfer    (sender-supplied; ordered as given)
 *
 * Slot identity is bound into the transfer's Fiat–Shamir transcript via the order of these
 * keys, so any reorder breaks proof verification on chain. These tests pin the layout so a
 * future refactor can't silently shuffle the slots.
 */
describe("assembleAuditorEks (slot contract)", () => {
  const chain = TwistedEd25519PrivateKey.generate().publicKey();
  const asset = TwistedEd25519PrivateKey.generate().publicKey();
  const v0 = TwistedEd25519PrivateKey.generate().publicKey();
  const v1 = TwistedEd25519PrivateKey.generate().publicKey();
  const v2 = TwistedEd25519PrivateKey.generate().publicKey();

  function asHex(keys: TwistedEd25519PublicKey[]): string[] {
    return keys.map((k) => k.toString());
  }

  it("places the chain auditor at slot [0] when no asset auditor and no voluntary auditors", () => {
    const out = assembleAuditorEks({ chain });
    expect(out.length).toBe(1);
    expect(asHex(out)).toEqual([chain.toString()]);
  });

  it("places the asset auditor at slot [1] when configured", () => {
    const out = assembleAuditorEks({ chain, asset });
    expect(out.length).toBe(2);
    expect(asHex(out)).toEqual([chain.toString(), asset.toString()]);
  });

  it("preserves voluntary-auditor order at slots [2..]", () => {
    const out = assembleAuditorEks({ chain, asset, voluntary: [v0, v1, v2] });
    expect(out.length).toBe(5);
    expect(asHex(out)).toEqual([chain.toString(), asset.toString(), v0.toString(), v1.toString(), v2.toString()]);
  });

  it("skips slot [1] when no asset auditor is configured but voluntary auditors are present", () => {
    // Important: voluntary auditors must NOT shift up to fill slot [1] — that slot is reserved
    // for the per-asset auditor by position. validate_auditors checks slot [0] against the chain
    // auditor; downstream slots are bound by Fiat–Shamir order, not by name.
    const out = assembleAuditorEks({ chain, voluntary: [v0, v1] });
    expect(out.length).toBe(3);
    expect(asHex(out)).toEqual([chain.toString(), v0.toString(), v1.toString()]);
  });

  it("returns just [chain] for an empty voluntary list", () => {
    const out = assembleAuditorEks({ chain, voluntary: [] });
    expect(asHex(out)).toEqual([chain.toString()]);
  });

  it("does not deduplicate when chain == asset (caller-supplied; protocol-side concern)", () => {
    // The protocol can reject this, but the helper is purely positional. Documenting the
    // behavior so callers don't rely on the SDK to filter.
    const out = assembleAuditorEks({ chain, asset: chain });
    expect(asHex(out)).toEqual([chain.toString(), chain.toString()]);
  });
});
