// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import { ed25519, edwardsToMontgomeryPub, edwardsToMontgomeryPriv, x25519 } from "@noble/curves/ed25519";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import {
  vaultDecryptionKey,
  keylessDecryptionKey,
  sealVaultDk,
  openVaultDk,
  encodeVaultDkRaw,
  decodeVaultDkRaw,
  VAULT_DK_EXPORT_V1_PREFIX,
  VAULT_ENVELOPE_VERSION_TAG,
} from "../../src";

const MULTISIG = "0x00000000000000000000000000000000000000000000000000000000000000aa";
const MULTISIG_B = "0x00000000000000000000000000000000000000000000000000000000000000ab";
const DEALER = "0x00000000000000000000000000000000000000000000000000000000000000d0";
const TOKEN_A = "0x000000000000000000000000000000000000000000000000000000000000000a";
const TOKEN_B = "0x00000000000000000000000000000000000000000000000000000000000000ff";
const RECIP_ADDR = "0x00000000000000000000000000000000000000000000000000000000000000c1";

// dkVault = 0x00 01 02 ... 1f
const DK_VAULT = new Uint8Array(32);
for (let i = 0; i < 32; i += 1) DK_VAULT[i] = i;

// Fixed recipient: ed25519 seed = 0xaa repeated.
const RECIP_SEED = new Uint8Array(32).fill(0xaa);
const RECIP_PUB = ed25519.getPublicKey(RECIP_SEED);

function freshOwner(seedByte: number): { seed: Uint8Array; pub: Uint8Array } {
  const seed = new Uint8Array(32).fill(seedByte);
  return { seed, pub: ed25519.getPublicKey(seed) };
}

describe("vaultDecryptionKey (HKDF-SHA512, salt movement-ca-vault/v1)", () => {
  // Pinned vector — a change here means a derivation drift that would orphan
  // every on-chain ek[Vault, token] registration.
  it("matches the fixed test vector", () => {
    expect(vaultDecryptionKey(DK_VAULT, MULTISIG, TOKEN_A).toStringWithoutPrefix()).toBe(
      "8d05cf26539032dc095e641ec294de1f800bb70f8a49029766cef43fd812490f",
    );
  });

  it("is deterministic", () => {
    expect(vaultDecryptionKey(DK_VAULT, MULTISIG, TOKEN_A).toStringWithoutPrefix()).toBe(
      vaultDecryptionKey(DK_VAULT, MULTISIG, TOKEN_A).toStringWithoutPrefix(),
    );
  });

  it("is domain-separated by multisig address and token", () => {
    const base = vaultDecryptionKey(DK_VAULT, MULTISIG, TOKEN_A).toStringWithoutPrefix();
    expect(vaultDecryptionKey(DK_VAULT, MULTISIG_B, TOKEN_A).toStringWithoutPrefix()).not.toBe(base);
    expect(vaultDecryptionKey(DK_VAULT, MULTISIG, TOKEN_B).toStringWithoutPrefix()).not.toBe(base);
  });

  it("differs from keyless derivation for the same bytes (salt separation)", () => {
    const vault = vaultDecryptionKey(DK_VAULT, MULTISIG, TOKEN_A).toStringWithoutPrefix();
    const keyless = keylessDecryptionKey(DK_VAULT, MULTISIG, TOKEN_A).toStringWithoutPrefix();
    expect(vault).not.toBe(keyless);
  });

  it("rejects a non-32-byte root", () => {
    expect(() => vaultDecryptionKey(new Uint8Array(31), MULTISIG, TOKEN_A)).toThrow(/32 bytes/);
    expect(() => vaultDecryptionKey(new Uint8Array(33), MULTISIG, TOKEN_A)).toThrow(/32 bytes/);
    // @ts-expect-error wrong type on purpose
    expect(() => vaultDecryptionKey("nope", MULTISIG, TOKEN_A)).toThrow(/Uint8Array/);
  });
});

describe("Ed25519 -> X25519 birational map agreement", () => {
  it("pub-map equals the pub derived from the priv-map (fixed vector)", () => {
    const pubMap = edwardsToMontgomeryPub(RECIP_PUB);
    const pubFromPriv = x25519.getPublicKey(edwardsToMontgomeryPriv(RECIP_SEED));
    expect(bytesToHex(pubMap)).toBe("552291f02c9317519633021302d0f7ba39b1cf32310e23ee7aa6a4312ae4a027");
    expect(bytesToHex(pubFromPriv)).toBe(bytesToHex(pubMap));
  });

  it("dealer and recipient compute the same shared secret", () => {
    const eph = x25519.utils.randomPrivateKey();
    const ephPub = x25519.getPublicKey(eph);
    const dealerSide = x25519.getSharedSecret(eph, edwardsToMontgomeryPub(RECIP_PUB));
    const recipSide = x25519.getSharedSecret(edwardsToMontgomeryPriv(RECIP_SEED), ephPub);
    expect(bytesToHex(dealerSide)).toBe(bytesToHex(recipSide));
  });
});

describe("encodeVaultDkRaw / decodeVaultDkRaw (mv-dk-vault-raw-v1:)", () => {
  it("encodes the fixed vector", () => {
    expect(encodeVaultDkRaw(DK_VAULT)).toBe(
      `${VAULT_DK_EXPORT_V1_PREFIX}000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`,
    );
  });

  it("round-trips", () => {
    expect(bytesToHex(decodeVaultDkRaw(encodeVaultDkRaw(DK_VAULT)))).toBe(bytesToHex(DK_VAULT));
  });

  it("decodes bare hex and 0x-prefixed hex", () => {
    const bare = bytesToHex(DK_VAULT);
    expect(bytesToHex(decodeVaultDkRaw(bare))).toBe(bare);
    expect(bytesToHex(decodeVaultDkRaw(`0x${bare}`))).toBe(bare);
    expect(bytesToHex(decodeVaultDkRaw(`  ${VAULT_DK_EXPORT_V1_PREFIX}${bare}  `))).toBe(bare);
  });

  it("rejects a future version prefix", () => {
    expect(() => decodeVaultDkRaw(`mv-dk-vault-raw-v2:${bytesToHex(DK_VAULT)}`)).toThrow(
      /Unsupported vault dk export version/,
    );
  });

  it("rejects wrong-length material", () => {
    expect(() => decodeVaultDkRaw(`${VAULT_DK_EXPORT_V1_PREFIX}00`)).toThrow(/expected 32 bytes/);
    expect(() => encodeVaultDkRaw(new Uint8Array(31))).toThrow(/32-byte/);
  });
});

describe("sealVaultDk / openVaultDk round-trip", () => {
  const seal = (recipients: { ownerAddress: string; ed25519PublicKey: Uint8Array }[]) =>
    sealVaultDk({ dkVault: DK_VAULT, multisigAddress: MULTISIG, dealerOwnerAddress: DEALER, recipients });

  it("a single recipient recovers dk[Vault]", () => {
    const envelope = seal([{ ownerAddress: RECIP_ADDR, ed25519PublicKey: RECIP_PUB }]);
    const recovered = openVaultDk({
      envelope,
      multisigAddress: MULTISIG,
      recipientOwnerAddress: RECIP_ADDR,
      recipientEd25519PrivateKey: RECIP_SEED,
    });
    expect(bytesToHex(recovered)).toBe(bytesToHex(DK_VAULT));
  });

  it("every recipient in a multi-recipient envelope opens only its own slot", () => {
    const owners = [
      { addr: "0x00000000000000000000000000000000000000000000000000000000000000c1", kp: freshOwner(0x01) },
      { addr: "0x00000000000000000000000000000000000000000000000000000000000000c2", kp: freshOwner(0x02) },
      { addr: "0x00000000000000000000000000000000000000000000000000000000000000c3", kp: freshOwner(0x03) },
    ];
    const envelope = seal(owners.map((o) => ({ ownerAddress: o.addr, ed25519PublicKey: o.kp.pub })));

    for (const o of owners) {
      const recovered = openVaultDk({
        envelope,
        multisigAddress: MULTISIG,
        recipientOwnerAddress: o.addr,
        recipientEd25519PrivateKey: o.kp.seed,
      });
      expect(bytesToHex(recovered)).toBe(bytesToHex(DK_VAULT));
    }

    // An owner with the right key but trying another owner's slot/address fails.
    expect(() =>
      openVaultDk({
        envelope,
        multisigAddress: MULTISIG,
        recipientOwnerAddress: owners[0].addr,
        recipientEd25519PrivateKey: owners[1].kp.seed,
      }),
    ).toThrow();
  });

  it("throws when the recipient is not addressed in the envelope", () => {
    const envelope = seal([{ ownerAddress: RECIP_ADDR, ed25519PublicKey: RECIP_PUB }]);
    expect(() =>
      openVaultDk({
        envelope,
        multisigAddress: MULTISIG,
        recipientOwnerAddress: "0x00000000000000000000000000000000000000000000000000000000000000ee",
        recipientEd25519PrivateKey: freshOwner(0x09).seed,
      }),
    ).toThrow(/no envelope slot/);
  });

  it("throws on a wrong key for the addressed slot", () => {
    const envelope = seal([{ ownerAddress: RECIP_ADDR, ed25519PublicKey: RECIP_PUB }]);
    expect(() =>
      openVaultDk({
        envelope,
        multisigAddress: MULTISIG,
        recipientOwnerAddress: RECIP_ADDR,
        recipientEd25519PrivateKey: new Uint8Array(32).fill(0xbb),
      }),
    ).toThrow();
  });

  it("throws when the supplied multisigAddress disagrees with the envelope", () => {
    const envelope = seal([{ ownerAddress: RECIP_ADDR, ed25519PublicKey: RECIP_PUB }]);
    expect(() =>
      openVaultDk({
        envelope,
        multisigAddress: MULTISIG_B,
        recipientOwnerAddress: RECIP_ADDR,
        recipientEd25519PrivateKey: RECIP_SEED,
      }),
    ).toThrow(/multisigAddress does not match/);
  });

  it("throws on a tampered ciphertext (GCM tag) and tampered dealer (AAD)", () => {
    const envelope = seal([{ ownerAddress: RECIP_ADDR, ed25519PublicKey: RECIP_PUB }]);

    const tamperedCt = envelope.slice();
    tamperedCt[tamperedCt.length - 1] ^= 0xff;
    expect(() =>
      openVaultDk({
        envelope: tamperedCt,
        multisigAddress: MULTISIG,
        recipientOwnerAddress: RECIP_ADDR,
        recipientEd25519PrivateKey: RECIP_SEED,
      }),
    ).toThrow();

    // Flip a byte inside the dealer address (header offset 14+32 = 46) -> AAD mismatch.
    const tamperedDealer = envelope.slice();
    tamperedDealer[46] ^= 0xff;
    expect(() =>
      openVaultDk({
        envelope: tamperedDealer,
        multisigAddress: MULTISIG,
        recipientOwnerAddress: RECIP_ADDR,
        recipientEd25519PrivateKey: RECIP_SEED,
      }),
    ).toThrow();
  });

  it("throws on a truncated envelope and a bad version tag", () => {
    const envelope = seal([{ ownerAddress: RECIP_ADDR, ed25519PublicKey: RECIP_PUB }]);
    expect(() =>
      openVaultDk({
        envelope: envelope.subarray(0, 50),
        multisigAddress: MULTISIG,
        recipientOwnerAddress: RECIP_ADDR,
        recipientEd25519PrivateKey: RECIP_SEED,
      }),
    ).toThrow();

    const badTag = envelope.slice();
    badTag[0] ^= 0xff;
    expect(() =>
      openVaultDk({
        envelope: badTag,
        multisigAddress: MULTISIG,
        recipientOwnerAddress: RECIP_ADDR,
        recipientEd25519PrivateKey: RECIP_SEED,
      }),
    ).toThrow(/version tag/);
  });

  it("validates seal inputs", () => {
    expect(() =>
      sealVaultDk({
        dkVault: new Uint8Array(31),
        multisigAddress: MULTISIG,
        dealerOwnerAddress: DEALER,
        recipients: [{ ownerAddress: RECIP_ADDR, ed25519PublicKey: RECIP_PUB }],
      }),
    ).toThrow(/32-byte/);
    expect(() =>
      sealVaultDk({ dkVault: DK_VAULT, multisigAddress: MULTISIG, dealerOwnerAddress: DEALER, recipients: [] }),
    ).toThrow(/at least one recipient/);
    expect(() =>
      sealVaultDk({
        dkVault: DK_VAULT,
        multisigAddress: MULTISIG,
        dealerOwnerAddress: DEALER,
        recipients: [{ ownerAddress: RECIP_ADDR, ed25519PublicKey: new Uint8Array(31) }],
      }),
    ).toThrow(/ed25519PublicKey/);
  });
});

describe("envelope wire format (byte-exact)", () => {
  const EXPECTED_ENVELOPE =
    "6d762d646b2d7661756c742d763100000000000000000000000000000000000000000000000000000000000000aa00000000000000000000000000000000000000000000000000000000000000d07b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13010000000000000000000000000000000000000000000000000000000000000000c1222222222222222222222222503072cf496caa05f59e90a8b92b6e4328dd945ca201834052c606671dd0a32117d5dede27789968cc23d3c4748fe5e7";

  it("seal with fixed randomness produces the pinned envelope", () => {
    const envelope = sealVaultDk({
      dkVault: DK_VAULT,
      multisigAddress: MULTISIG,
      dealerOwnerAddress: DEALER,
      recipients: [{ ownerAddress: RECIP_ADDR, ed25519PublicKey: RECIP_PUB }],
      randomness: { ephemeralPrivateKey: new Uint8Array(32).fill(0x11), nonces: [new Uint8Array(12).fill(0x22)] },
    });
    expect(bytesToHex(envelope)).toBe(EXPECTED_ENVELOPE);
    // Header starts with the colon-less 14-byte version tag.
    expect(new TextDecoder().decode(envelope.subarray(0, 14))).toBe(VAULT_ENVELOPE_VERSION_TAG);
  });

  it("opens the pinned envelope (decrypt-only vector)", () => {
    const recovered = openVaultDk({
      envelope: hexToBytes(EXPECTED_ENVELOPE),
      multisigAddress: MULTISIG,
      recipientOwnerAddress: RECIP_ADDR,
      recipientEd25519PrivateKey: RECIP_SEED,
    });
    expect(bytesToHex(recovered)).toBe(bytesToHex(DK_VAULT));
  });
});
