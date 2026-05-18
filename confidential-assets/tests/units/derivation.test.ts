// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { hkdf } from "@noble/hashes/hkdf";
import { AccountAddress } from "@moveindustries/ts-sdk";
import {
  TwistedEd25519PrivateKey,
  hardwareDecryptionKeyDerivationMessage,
  keylessDecryptionKey,
  softwareDecryptionKeyDerivationPath,
  tokenIndexFromMetadataAddress,
} from "../../src";

const TOKEN_A = "0x000000000000000000000000000000000000000000000000000000000000000a";
const TOKEN_B = "0x00000000000000000000000000000000000000000000000000000000000000ff";
const ACCOUNT_X = "0x1111111111111111111111111111111111111111111111111111111111111111";
const ACCOUNT_Y = "0x2222222222222222222222222222222222222222222222222222222222222222";

describe("tokenIndexFromMetadataAddress", () => {
  it("computes u32_le(SHA-256(metaAddr)[0..4]) & 0x7FFFFFFF", () => {
    const addr = AccountAddress.from(TOKEN_A).toUint8Array();
    const digest = sha256(addr);
    const expected = ((digest[0]! | (digest[1]! << 8) | (digest[2]! << 16) | (digest[3]! << 24)) >>> 0) & 0x7fffffff;
    expect(tokenIndexFromMetadataAddress(TOKEN_A)).toBe(expected);
  });

  it("returns a non-negative integer in the hardened-index range", () => {
    const idx = tokenIndexFromMetadataAddress(TOKEN_A);
    expect(Number.isInteger(idx)).toBe(true);
    expect(idx).toBeGreaterThanOrEqual(0);
    expect(idx).toBeLessThan(0x80000000);
  });

  it("clears the top bit deterministically (regardless of input)", () => {
    // Try a few addresses and confirm the result is always < 2^31
    for (const addr of [TOKEN_A, TOKEN_B, ACCOUNT_X, ACCOUNT_Y]) {
      expect(tokenIndexFromMetadataAddress(addr)).toBeLessThan(0x80000000);
    }
  });

  it("is deterministic for the same input", () => {
    expect(tokenIndexFromMetadataAddress(TOKEN_A)).toBe(tokenIndexFromMetadataAddress(TOKEN_A));
  });

  it("differs across distinct metadata addresses (collision-resistant under SHA-256)", () => {
    expect(tokenIndexFromMetadataAddress(TOKEN_A)).not.toBe(tokenIndexFromMetadataAddress(TOKEN_B));
  });
});

describe("softwareDecryptionKeyDerivationPath", () => {
  it("produces the canonical path layout m/44'/637'/{accountIndex}'/1'/{tokenIndex}'", () => {
    const idx = tokenIndexFromMetadataAddress(TOKEN_A);
    expect(softwareDecryptionKeyDerivationPath(0, TOKEN_A)).toBe(`m/44'/637'/0'/1'/${idx}'`);
    expect(softwareDecryptionKeyDerivationPath(7, TOKEN_A)).toBe(`m/44'/637'/7'/1'/${idx}'`);
  });

  it("uses the CA branch (1') — never the signing-key branch (0')", () => {
    const path = softwareDecryptionKeyDerivationPath(0, TOKEN_A);
    expect(path).toMatch(/\/1'\/\d+'$/);
  });

  it("rejects negative or non-integer accountIndex", () => {
    expect(() => softwareDecryptionKeyDerivationPath(-1, TOKEN_A)).toThrow();
    expect(() => softwareDecryptionKeyDerivationPath(0.5, TOKEN_A)).toThrow();
  });
});

describe("hardwareDecryptionKeyDerivationMessage", () => {
  it('matches `decryptionKeyDerivationMessage ‖ ":" ‖ lowerHex(metaAddr)`', () => {
    const expected = new TextEncoder().encode(
      `${TwistedEd25519PrivateKey.decryptionKeyDerivationMessage}:${AccountAddress.from(TOKEN_A)
        .toStringLongWithoutPrefix()
        .toLowerCase()}`,
    );
    expect(hardwareDecryptionKeyDerivationMessage(TOKEN_A)).toEqual(expected);
  });

  it("uses lowercase hex with no 0x prefix", () => {
    const decoded = new TextDecoder().decode(hardwareDecryptionKeyDerivationMessage(TOKEN_A));
    const [, hexAddr] = decoded.split(":");
    expect(hexAddr).toMatch(/^[0-9a-f]{64}$/);
    expect(hexAddr!.startsWith("0x")).toBe(false);
  });

  it("yields different bytes for different tokens (so fromSignature gives different dks)", () => {
    expect(hardwareDecryptionKeyDerivationMessage(TOKEN_A)).not.toEqual(
      hardwareDecryptionKeyDerivationMessage(TOKEN_B),
    );
  });
});

describe("keylessDecryptionKey (HKDF layout for keyless backings)", () => {
  const PEPPER = new Uint8Array(31).map((_, i) => (i * 7 + 1) & 0xff); // 31 deterministic bytes

  it("matches the canonical HKDF expansion for keyless backings", () => {
    const acct = AccountAddress.from(ACCOUNT_X).toUint8Array();
    const tok = AccountAddress.from(TOKEN_A).toUint8Array();
    const info = new Uint8Array(3 + 32 + 32);
    info.set(new TextEncoder().encode("dk:"), 0);
    info.set(acct, 3);
    info.set(tok, 35);
    const okm = hkdf(sha512, PEPPER, new TextEncoder().encode("movement-ca/v1"), info, 64);
    const expected = TwistedEd25519PrivateKey.fromUniformBytes(okm);

    const got = keylessDecryptionKey(PEPPER, ACCOUNT_X, TOKEN_A);
    expect(got.toUint8Array()).toEqual(expected.toUint8Array());
  });

  it("is deterministic for the same (pepper, account, token)", () => {
    const a = keylessDecryptionKey(PEPPER, ACCOUNT_X, TOKEN_A);
    const b = keylessDecryptionKey(PEPPER, ACCOUNT_X, TOKEN_A);
    expect(a.toUint8Array()).toEqual(b.toUint8Array());
  });

  it("binds accountAddress into info — different accounts under one pepper yield different dks", () => {
    // This is the property that lets a single keyless identity safely back its own account
    // plus any number of multisigs the owner is the designated proposer for.
    const ownerDk = keylessDecryptionKey(PEPPER, ACCOUNT_X, TOKEN_A);
    const multisigDk = keylessDecryptionKey(PEPPER, ACCOUNT_Y, TOKEN_A);
    expect(ownerDk.toUint8Array()).not.toEqual(multisigDk.toUint8Array());
  });

  it("binds tokenMetadataAddress into info — different tokens for one account yield different dks", () => {
    const dkA = keylessDecryptionKey(PEPPER, ACCOUNT_X, TOKEN_A);
    const dkB = keylessDecryptionKey(PEPPER, ACCOUNT_X, TOKEN_B);
    expect(dkA.toUint8Array()).not.toEqual(dkB.toUint8Array());
  });

  it("treats different peppers as different identities", () => {
    const otherPepper = new Uint8Array(31).map((_, i) => (i * 11 + 3) & 0xff);
    const dkA = keylessDecryptionKey(PEPPER, ACCOUNT_X, TOKEN_A);
    const dkB = keylessDecryptionKey(otherPepper, ACCOUNT_X, TOKEN_A);
    expect(dkA.toUint8Array()).not.toEqual(dkB.toUint8Array());
  });

  it("accepts peppers of any length (HKDF is length-agnostic)", () => {
    const pepper16 = new Uint8Array(16).fill(0x42);
    const pepper64 = new Uint8Array(64).fill(0x42);
    expect(() => keylessDecryptionKey(pepper16, ACCOUNT_X, TOKEN_A)).not.toThrow();
    expect(() => keylessDecryptionKey(pepper64, ACCOUNT_X, TOKEN_A)).not.toThrow();
  });

  it("rejects an empty pepper", () => {
    expect(() => keylessDecryptionKey(new Uint8Array(0), ACCOUNT_X, TOKEN_A)).toThrow();
  });

  it("returns a key whose publicKey matches normal usage (not corrupt)", () => {
    const dk = keylessDecryptionKey(PEPPER, ACCOUNT_X, TOKEN_A);
    expect(dk.publicKey().toUint8Array().length).toBe(32);
  });
});

describe("TwistedEd25519PrivateKey.fromUniformBytes", () => {
  it("rejects fewer than 32 bytes", () => {
    expect(() => TwistedEd25519PrivateKey.fromUniformBytes(new Uint8Array(31))).toThrow();
  });

  it("accepts ≥ 32 bytes and reduces mod ℓ", () => {
    const k = TwistedEd25519PrivateKey.fromUniformBytes(new Uint8Array(64).fill(0xab));
    expect(k.toUint8Array().length).toBe(32);
  });

  it("is deterministic", () => {
    const bytes = new Uint8Array(64).map((_, i) => (i * 31 + 7) & 0xff);
    const a = TwistedEd25519PrivateKey.fromUniformBytes(bytes);
    const b = TwistedEd25519PrivateKey.fromUniformBytes(bytes);
    expect(a.toUint8Array()).toEqual(b.toUint8Array());
  });
});
