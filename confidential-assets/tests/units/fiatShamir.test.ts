import { describe, it, expect } from "vitest";
import { taggedHash, fiatShamirChallenge } from "../../src/crypto/fiatShamir";

describe("SHA3-512 Tagged Fiat-Shamir", () => {
  it("taggedHash produces 64-byte output", () => {
    const result = taggedHash("test-tag", new Uint8Array([1, 2, 3]));
    expect(result.length).toBe(64);
  });

  it("taggedHash is deterministic", () => {
    const data = new Uint8Array([1, 2, 3, 4]);
    const a = taggedHash("tag", data);
    const b = taggedHash("tag", data);
    expect(a).toEqual(b);
  });

  it("different tags produce different hashes", () => {
    const data = new Uint8Array([1, 2, 3]);
    const a = taggedHash("tag-a", data);
    const b = taggedHash("tag-b", data);
    expect(a).not.toEqual(b);
  });

  it("different data produces different hashes", () => {
    const a = taggedHash("tag", new Uint8Array([1]));
    const b = taggedHash("tag", new Uint8Array([2]));
    expect(a).not.toEqual(b);
  });

  it("fiatShamirChallenge returns a bigint", () => {
    const sender = new Uint8Array(32);
    const token = new Uint8Array(32);
    const challenge = fiatShamirChallenge("Test", 1, sender, token);
    expect(typeof challenge).toBe("bigint");
    expect(challenge).toBeGreaterThan(0n);
  });

  it("fiatShamirChallenge is deterministic", () => {
    const sender = new Uint8Array(32).fill(0xaa);
    const token = new Uint8Array(32).fill(0xbb);
    const data = new Uint8Array([1, 2, 3]);
    const a = fiatShamirChallenge("Withdrawal", 1, sender, token, data);
    const b = fiatShamirChallenge("Withdrawal", 1, sender, token, data);
    expect(a).toBe(b);
  });

  it("different chain IDs produce different challenges", () => {
    const sender = new Uint8Array(32);
    const token = new Uint8Array(32);
    const data = new Uint8Array([1, 2, 3]);
    const a = fiatShamirChallenge("Withdrawal", 1, sender, token, data);
    const b = fiatShamirChallenge("Withdrawal", 2, sender, token, data);
    expect(a).not.toBe(b);
  });

  it("different protocol IDs produce different challenges", () => {
    const sender = new Uint8Array(32);
    const token = new Uint8Array(32);
    const a = fiatShamirChallenge("Withdrawal", 1, sender, token);
    const b = fiatShamirChallenge("Transfer", 1, sender, token);
    expect(a).not.toBe(b);
  });

  it("different sender addresses produce different challenges", () => {
    const token = new Uint8Array(32);
    const sender1 = new Uint8Array(32).fill(0x01);
    const sender2 = new Uint8Array(32).fill(0x02);
    const a = fiatShamirChallenge("Withdrawal", 1, sender1, token);
    const b = fiatShamirChallenge("Withdrawal", 1, sender2, token);
    expect(a).not.toBe(b);
  });
});
