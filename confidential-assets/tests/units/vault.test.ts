// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import { ed25519 } from "@noble/curves/ed25519";
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
  vaultEnvelopeKeyFromSeed,
  vaultEnvelopeKeyFromSignature,
  vaultEnvelopeKeyFromPepper,
  vaultEnvelopeKeyDerivationPath,
  vaultEnvelopeKeyOwnershipMessage,
  signVaultEnvelopeKeyOwnership,
  verifyVaultEnvelopeKeyOwnership,
  VAULT_ENVELOPE_KEY_DERIVATION_MESSAGE,
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

// Fixed recipient vault-envelope key from a deterministic seed.
const RECIP_VEK = vaultEnvelopeKeyFromSeed(new Uint8Array(32).fill(0xaa));

function freshVek(seedByte: number) {
  return vaultEnvelopeKeyFromSeed(new Uint8Array(32).fill(seedByte));
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

describe("vault-envelope key (vek) derivation", () => {
  it("fromSeed is deterministic and pins a fixed vector (seed 0xaa)", () => {
    // Independent X25519 keypair from the 32-byte seed (NOT the Ed25519 birational map).
    expect(bytesToHex(RECIP_VEK.publicKey)).toBe(
      "14ca9e4d387bccf35746e0407daaacc6b28a4f8445ef5a5158894db983e24070",
    );
    expect(bytesToHex(vaultEnvelopeKeyFromSeed(new Uint8Array(32).fill(0xaa)).publicKey)).toBe(
      bytesToHex(RECIP_VEK.publicKey),
    );
  });

  it("fromSignature = fromSeed(SHA-512(sig)[0..32]) and is deterministic", () => {
    const sig = new Uint8Array(64).fill(0x5a);
    const a = vaultEnvelopeKeyFromSignature(sig);
    const b = vaultEnvelopeKeyFromSignature(sig);
    expect(bytesToHex(a.publicKey)).toBe(bytesToHex(b.publicKey));
    expect(a.publicKey.length).toBe(32);
    // rejects a non-64-byte signature
    expect(() => vaultEnvelopeKeyFromSignature(new Uint8Array(63))).toThrow(/64 bytes/);
  });

  it("fromPepper binds accountAddress and is deterministic", () => {
    const pepper = new Uint8Array(31).fill(0x07);
    const a = vaultEnvelopeKeyFromPepper(pepper, MULTISIG);
    expect(bytesToHex(vaultEnvelopeKeyFromPepper(pepper, MULTISIG).publicKey)).toBe(bytesToHex(a.publicKey));
    // different account -> different key
    expect(bytesToHex(vaultEnvelopeKeyFromPepper(pepper, MULTISIG_B).publicKey)).not.toBe(bytesToHex(a.publicKey));
    expect(() => vaultEnvelopeKeyFromPepper(new Uint8Array(0), MULTISIG)).toThrow(/non-empty/);
  });

  it("derivation path is m/44'/637'/{accountIndex}'/2'/0'", () => {
    expect(vaultEnvelopeKeyDerivationPath(0)).toBe("m/44'/637'/0'/2'/0'");
    expect(vaultEnvelopeKeyDerivationPath(5)).toBe("m/44'/637'/5'/2'/0'");
    expect(() => vaultEnvelopeKeyDerivationPath(-1)).toThrow();
  });

  it("hardware derivation message is the SDK-fixed constant", () => {
    expect(VAULT_ENVELOPE_KEY_DERIVATION_MESSAGE).toBe(
      "Sign this message to derive your confidential-asset vault-envelope key",
    );
  });
});

describe("vault-envelope key ownership signature", () => {
  const OWNER_SEED = new Uint8Array(32).fill(0x11);
  const OWNER_PUB = ed25519.getPublicKey(OWNER_SEED);

  it("message is DST ‖ vekPub", () => {
    const msg = vaultEnvelopeKeyOwnershipMessage(RECIP_VEK.publicKey);
    const dst = new TextEncoder().encode("MovementConfidentialAsset/VaultEnvelopeKey/v1");
    expect(bytesToHex(msg.subarray(0, dst.length))).toBe(bytesToHex(dst));
    expect(bytesToHex(msg.subarray(dst.length))).toBe(bytesToHex(RECIP_VEK.publicKey));
  });

  it("sign then verify round-trips against the owner's Ed25519 pubkey", () => {
    const sig = signVaultEnvelopeKeyOwnership(RECIP_VEK.publicKey, OWNER_SEED);
    expect(verifyVaultEnvelopeKeyOwnership({ vekPub: RECIP_VEK.publicKey, ownerEd25519PublicKey: OWNER_PUB, signature: sig })).toBe(
      true,
    );
  });

  it("rejects a signature over a different vekPub (key substitution)", () => {
    const sig = signVaultEnvelopeKeyOwnership(RECIP_VEK.publicKey, OWNER_SEED);
    const otherVek = freshVek(0xbb).publicKey;
    expect(verifyVaultEnvelopeKeyOwnership({ vekPub: otherVek, ownerEd25519PublicKey: OWNER_PUB, signature: sig })).toBe(
      false,
    );
  });

  it("rejects a signature from a different owner key", () => {
    const sig = signVaultEnvelopeKeyOwnership(RECIP_VEK.publicKey, OWNER_SEED);
    const otherOwnerPub = ed25519.getPublicKey(new Uint8Array(32).fill(0x22));
    expect(
      verifyVaultEnvelopeKeyOwnership({ vekPub: RECIP_VEK.publicKey, ownerEd25519PublicKey: otherOwnerPub, signature: sig }),
    ).toBe(false);
  });

  it("returns false (not throw) on malformed inputs", () => {
    expect(
      verifyVaultEnvelopeKeyOwnership({ vekPub: RECIP_VEK.publicKey, ownerEd25519PublicKey: new Uint8Array(31), signature: new Uint8Array(64) }),
    ).toBe(false);
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
  const seal = (recipients: { ownerAddress: string; vaultEnvelopePublicKey: Uint8Array }[]) =>
    sealVaultDk({ dkVault: DK_VAULT, multisigAddress: MULTISIG, dealerOwnerAddress: DEALER, recipients });

  it("a single recipient recovers dk[Vault]", () => {
    const envelope = seal([{ ownerAddress: RECIP_ADDR, vaultEnvelopePublicKey: RECIP_VEK.publicKey }]);
    const recovered = openVaultDk({
      envelope,
      multisigAddress: MULTISIG,
      recipientOwnerAddress: RECIP_ADDR,
      recipientVaultEnvelopePrivateKey: RECIP_VEK.privateKey,
    });
    expect(bytesToHex(recovered)).toBe(bytesToHex(DK_VAULT));
  });

  it("every recipient in a multi-recipient envelope opens only its own slot", () => {
    const owners = [
      { addr: "0x00000000000000000000000000000000000000000000000000000000000000c1", vek: freshVek(0x01) },
      { addr: "0x00000000000000000000000000000000000000000000000000000000000000c2", vek: freshVek(0x02) },
      { addr: "0x00000000000000000000000000000000000000000000000000000000000000c3", vek: freshVek(0x03) },
    ];
    const envelope = seal(owners.map((o) => ({ ownerAddress: o.addr, vaultEnvelopePublicKey: o.vek.publicKey })));

    for (const o of owners) {
      const recovered = openVaultDk({
        envelope,
        multisigAddress: MULTISIG,
        recipientOwnerAddress: o.addr,
        recipientVaultEnvelopePrivateKey: o.vek.privateKey,
      });
      expect(bytesToHex(recovered)).toBe(bytesToHex(DK_VAULT));
    }

    // An owner with the right key but trying another owner's slot/address fails.
    expect(() =>
      openVaultDk({
        envelope,
        multisigAddress: MULTISIG,
        recipientOwnerAddress: owners[0].addr,
        recipientVaultEnvelopePrivateKey: owners[1].vek.privateKey,
      }),
    ).toThrow();
  });

  it("throws when the recipient is not addressed in the envelope", () => {
    const envelope = seal([{ ownerAddress: RECIP_ADDR, vaultEnvelopePublicKey: RECIP_VEK.publicKey }]);
    expect(() =>
      openVaultDk({
        envelope,
        multisigAddress: MULTISIG,
        recipientOwnerAddress: "0x00000000000000000000000000000000000000000000000000000000000000ee",
        recipientVaultEnvelopePrivateKey: freshVek(0x09).privateKey,
      }),
    ).toThrow(/no envelope slot/);
  });

  it("throws on a wrong key for the addressed slot", () => {
    const envelope = seal([{ ownerAddress: RECIP_ADDR, vaultEnvelopePublicKey: RECIP_VEK.publicKey }]);
    expect(() =>
      openVaultDk({
        envelope,
        multisigAddress: MULTISIG,
        recipientOwnerAddress: RECIP_ADDR,
        recipientVaultEnvelopePrivateKey: new Uint8Array(32).fill(0xbb),
      }),
    ).toThrow();
  });

  it("throws when the supplied multisigAddress disagrees with the envelope", () => {
    const envelope = seal([{ ownerAddress: RECIP_ADDR, vaultEnvelopePublicKey: RECIP_VEK.publicKey }]);
    expect(() =>
      openVaultDk({
        envelope,
        multisigAddress: MULTISIG_B,
        recipientOwnerAddress: RECIP_ADDR,
        recipientVaultEnvelopePrivateKey: RECIP_VEK.privateKey,
      }),
    ).toThrow(/multisigAddress does not match/);
  });

  it("throws on a tampered ciphertext (GCM tag) and tampered dealer (AAD)", () => {
    const envelope = seal([{ ownerAddress: RECIP_ADDR, vaultEnvelopePublicKey: RECIP_VEK.publicKey }]);

    const tamperedCt = envelope.slice();
    tamperedCt[tamperedCt.length - 1] ^= 0xff;
    expect(() =>
      openVaultDk({
        envelope: tamperedCt,
        multisigAddress: MULTISIG,
        recipientOwnerAddress: RECIP_ADDR,
        recipientVaultEnvelopePrivateKey: RECIP_VEK.privateKey,
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
        recipientVaultEnvelopePrivateKey: RECIP_VEK.privateKey,
      }),
    ).toThrow();
  });

  it("throws on a truncated envelope and a bad version tag", () => {
    const envelope = seal([{ ownerAddress: RECIP_ADDR, vaultEnvelopePublicKey: RECIP_VEK.publicKey }]);
    expect(() =>
      openVaultDk({
        envelope: envelope.subarray(0, 50),
        multisigAddress: MULTISIG,
        recipientOwnerAddress: RECIP_ADDR,
        recipientVaultEnvelopePrivateKey: RECIP_VEK.privateKey,
      }),
    ).toThrow();

    const badTag = envelope.slice();
    badTag[0] ^= 0xff;
    expect(() =>
      openVaultDk({
        envelope: badTag,
        multisigAddress: MULTISIG,
        recipientOwnerAddress: RECIP_ADDR,
        recipientVaultEnvelopePrivateKey: RECIP_VEK.privateKey,
      }),
    ).toThrow(/version tag/);
  });

  it("validates seal inputs", () => {
    expect(() =>
      sealVaultDk({
        dkVault: new Uint8Array(31),
        multisigAddress: MULTISIG,
        dealerOwnerAddress: DEALER,
        recipients: [{ ownerAddress: RECIP_ADDR, vaultEnvelopePublicKey: RECIP_VEK.publicKey }],
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
        recipients: [{ ownerAddress: RECIP_ADDR, vaultEnvelopePublicKey: new Uint8Array(31) }],
      }),
    ).toThrow(/vaultEnvelopePublicKey/);
  });
});

describe("envelope wire format (byte-exact)", () => {
  // Pinned with fixed randomness + the fixed recipient vek (seed 0xaa).
  const EXPECTED_ENVELOPE =
    "6d762d646b2d7661756c742d763100000000000000000000000000000000000000000000000000000000000000aa00000000000000000000000000000000000000000000000000000000000000d07b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13010000000000000000000000000000000000000000000000000000000000000000c1222222222222222222222222e5584e35254ebff8a85a0d4b9b98cc84581804c157b7c21be4c605f91cc47fd295796f2dbeb1a2c6b96a44ac9f588ff5";

  it("seal with fixed randomness produces the pinned envelope", () => {
    const envelope = sealVaultDk({
      dkVault: DK_VAULT,
      multisigAddress: MULTISIG,
      dealerOwnerAddress: DEALER,
      recipients: [{ ownerAddress: RECIP_ADDR, vaultEnvelopePublicKey: RECIP_VEK.publicKey }],
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
      recipientVaultEnvelopePrivateKey: RECIP_VEK.privateKey,
    });
    expect(bytesToHex(recovered)).toBe(bytesToHex(DK_VAULT));
  });
});
