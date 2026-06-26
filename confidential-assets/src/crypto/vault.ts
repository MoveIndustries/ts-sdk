// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import { x25519, edwardsToMontgomeryPub, edwardsToMontgomeryPriv } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes, randomBytes } from "@noble/hashes/utils";
import { gcm } from "@noble/ciphers/aes";
import { AccountAddress, AccountAddressInput } from "@moveindustries/ts-sdk";

// ───────────────────────────────────────────────────────────────────────────
// Multisig vault `dk[Vault]` envelope layer (MIP-001 §"Multisig accounts").
//
// A multisig vault shares one uniformly-random 32-byte root `dk[Vault]` across
// all co-owners. The dealer seals `dk[Vault]` to each co-owner under a
// per-recipient AES-GCM key derived from an X25519 ECDH between a single
// per-envelope ephemeral key and the recipient's X25519 key — itself the
// RFC 7748 birational map of the recipient's on-chain Ed25519 owner pubkey. The
// recipient opens its own slot with the X25519 key mapped from its Ed25519
// signing seed. Every holder of `dk[Vault]` then derives per-token
// `dk[Vault, token]` locally via `vaultDecryptionKey` (see `./derivation`).
//
// The off-chain store that transports envelopes sees only ciphertext;
// confidentiality does not depend on it.
//
// MIP RECONCILIATION — `dealerOwnerAddress` in the header. The MIP's AAD
// (lines 343-347) binds `dealerOwnerAddress`, and `openVaultDk` must rebuild
// that exact AAD to decrypt — but the MIP's envelope byte diagram (lines
// 333-341) omits `dealerOwnerAddress` and `openVaultDk`'s signature carries no
// dealer parameter. The only self-consistent reading is that the dealer address
// travels in the envelope. It is placed here directly after `multisigAddress`,
// mirroring the AAD field order (tag ‖ multisig ‖ dealer ‖ recipient ‖ ephPub).
// ───────────────────────────────────────────────────────────────────────────

/**
 * 14-byte ASCII envelope version tag. Embedded at the head of the envelope and
 * reused as the HKDF salt and as the leading bytes of the AAD / HKDF info.
 * Note: no trailing colon — the colon-suffixed `mv-dk-vault-v1:` form is the
 * wallet-UI import-string wrapper, not these protocol bytes.
 */
export const VAULT_ENVELOPE_VERSION_TAG = "mv-dk-vault-v1";

/** Magic prefix for a raw `dk[Vault]` export string (manual recovery path). */
export const VAULT_DK_EXPORT_V1_PREFIX = "mv-dk-vault-raw-v1:";

const VERSION_TAG_BYTES = new TextEncoder().encode(VAULT_ENVELOPE_VERSION_TAG);

const ADDRESS_LENGTH = 32;
const ED25519_PUBKEY_LENGTH = 32;
const ED25519_SEED_LENGTH = 32;
const X25519_KEY_LENGTH = 32;
const NONCE_LENGTH = 12;
const GCM_TAG_LENGTH = 16;
const VAULT_DK_LENGTH = 32;
const AES_KEY_LENGTH = 32;

/** 32-byte `dk[Vault]` + 16-byte GCM tag. */
const CIPHERTEXT_WITH_TAG_LENGTH = VAULT_DK_LENGTH + GCM_TAG_LENGTH; // 48

/** Per-recipient record: ownerAddress ‖ nonce ‖ ciphertextWithTag. */
const RECIPIENT_RECORD_LENGTH = ADDRESS_LENGTH + NONCE_LENGTH + CIPHERTEXT_WITH_TAG_LENGTH; // 92

/** tag(14) ‖ multisig(32) ‖ dealer(32) ‖ ephemeralPub(32) ‖ recipientCount(u16 LE). */
const ENVELOPE_HEADER_LENGTH = VERSION_TAG_BYTES.length + ADDRESS_LENGTH * 2 + X25519_KEY_LENGTH + 2; // 112

const MAX_RECIPIENTS = 0xffff;

/** A co-owner the dealer seals `dk[Vault]` to. */
export interface VaultRecipient {
  /** The co-owner's multisig owner address (bound into AAD; identifies the slot). */
  ownerAddress: AccountAddressInput;
  /** The co-owner's 32-byte on-chain Ed25519 owner public key. */
  ed25519PublicKey: Uint8Array;
}

export interface SealVaultDkParams {
  /** The 32-byte vault root to seal. */
  dkVault: Uint8Array;
  /** The multisig (vault) account address. */
  multisigAddress: AccountAddressInput;
  /** The dealer's own owner address (bound into every recipient's AAD). */
  dealerOwnerAddress: AccountAddressInput;
  /** One slot per co-owner (including, optionally, the dealer). */
  recipients: VaultRecipient[];
  /**
   * @internal Test-only deterministic randomness. OMIT in production — a CSPRNG
   * is used. Supplying values that are reused across envelopes breaks AES-GCM
   * security (nonce reuse). Exists solely to pin byte-exact test vectors.
   */
  randomness?: { ephemeralPrivateKey: Uint8Array; nonces: Uint8Array[] };
}

export interface OpenVaultDkParams {
  /** The serialized envelope produced by {@link sealVaultDk}. */
  envelope: Uint8Array;
  /** The multisig (vault) account address; validated against the envelope. */
  multisigAddress: AccountAddressInput;
  /** This recipient's owner address; selects the slot and is bound into AAD. */
  recipientOwnerAddress: AccountAddressInput;
  /** This recipient's 32-byte Ed25519 signing seed. */
  recipientEd25519PrivateKey: Uint8Array;
}

/**
 * Build the AAD, which is byte-identical to the HKDF `info`:
 * `tag ‖ multisigAddress ‖ dealerOwnerAddress ‖ recipientOwnerAddress ‖ ephemeralX25519Pub`.
 */
function buildAad(
  multisig: Uint8Array,
  dealer: Uint8Array,
  recipient: Uint8Array,
  ephemeralPub: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(VERSION_TAG_BYTES.length + ADDRESS_LENGTH * 3 + X25519_KEY_LENGTH);
  let o = 0;
  out.set(VERSION_TAG_BYTES, o);
  o += VERSION_TAG_BYTES.length;
  out.set(multisig, o);
  o += ADDRESS_LENGTH;
  out.set(dealer, o);
  o += ADDRESS_LENGTH;
  out.set(recipient, o);
  o += ADDRESS_LENGTH;
  out.set(ephemeralPub, o);
  return out;
}

/** HKDF-SHA256 of the X25519 shared secret into a 32-byte AES key. */
function deriveAesKey(sharedSecret: Uint8Array, aadInfo: Uint8Array): Uint8Array {
  return hkdf(sha256, sharedSecret, VERSION_TAG_BYTES, aadInfo, AES_KEY_LENGTH);
}

function readU16LE(buf: Uint8Array, offset: number): number {
  return buf[offset]! | (buf[offset + 1]! << 8);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Seal a 32-byte vault root `dk[Vault]` to every co-owner, returning the
 * serialized `mv-dk-vault-v1` envelope bytes. One ephemeral X25519 key is used
 * for the whole envelope; each recipient gets a fresh AES-GCM nonce.
 *
 * Envelope layout:
 *
 * ```
 * "mv-dk-vault-v1"        (14 bytes)
 *  ‖ multisigAddress      (32)
 *  ‖ dealerOwnerAddress   (32)   // see MIP reconciliation note above
 *  ‖ ephemeralX25519Pub   (32)
 *  ‖ recipientCount       (u16 little-endian)
 *  ‖ for each recipient:
 *        recipientOwnerAddress (32)
 *      ‖ nonce                 (12)
 *      ‖ ciphertextWithTag     (48 = 32-byte dk + 16-byte GCM tag)
 * ```
 *
 * @throws if `dkVault` is not exactly 32 bytes, there are zero recipients or
 *   more than 65535, or any recipient Ed25519 public key is not 32 bytes.
 */
export function sealVaultDk(params: SealVaultDkParams): Uint8Array {
  const { dkVault, multisigAddress, dealerOwnerAddress, recipients, randomness } = params;

  if (!(dkVault instanceof Uint8Array) || dkVault.length !== VAULT_DK_LENGTH) {
    throw new Error(`sealVaultDk: dkVault must be a ${VAULT_DK_LENGTH}-byte Uint8Array`);
  }
  if (recipients.length === 0) {
    throw new Error("sealVaultDk: at least one recipient is required");
  }
  if (recipients.length > MAX_RECIPIENTS) {
    throw new Error(`sealVaultDk: too many recipients (max ${MAX_RECIPIENTS})`);
  }

  const ephemeralPriv = randomness?.ephemeralPrivateKey ?? x25519.utils.randomPrivateKey();
  if (ephemeralPriv.length !== X25519_KEY_LENGTH) {
    throw new Error(`sealVaultDk: ephemeral private key must be ${X25519_KEY_LENGTH} bytes`);
  }
  const ephemeralPub = x25519.getPublicKey(ephemeralPriv);
  const multisigBytes = AccountAddress.from(multisigAddress).toUint8Array();
  const dealerBytes = AccountAddress.from(dealerOwnerAddress).toUint8Array();

  const envelope = new Uint8Array(ENVELOPE_HEADER_LENGTH + recipients.length * RECIPIENT_RECORD_LENGTH);
  let o = 0;
  envelope.set(VERSION_TAG_BYTES, o);
  o += VERSION_TAG_BYTES.length;
  envelope.set(multisigBytes, o);
  o += ADDRESS_LENGTH;
  envelope.set(dealerBytes, o);
  o += ADDRESS_LENGTH;
  envelope.set(ephemeralPub, o);
  o += X25519_KEY_LENGTH;
  envelope[o] = recipients.length & 0xff;
  envelope[o + 1] = (recipients.length >> 8) & 0xff;
  o += 2;

  recipients.forEach((recipient, i) => {
    if (
      !(recipient.ed25519PublicKey instanceof Uint8Array) ||
      recipient.ed25519PublicKey.length !== ED25519_PUBKEY_LENGTH
    ) {
      throw new Error(
        `sealVaultDk: recipient[${i}] ed25519PublicKey must be a ${ED25519_PUBKEY_LENGTH}-byte Uint8Array`,
      );
    }
    const recipientBytes = AccountAddress.from(recipient.ownerAddress).toUint8Array();
    const recipientX25519Pub = edwardsToMontgomeryPub(recipient.ed25519PublicKey);
    const sharedSecret = x25519.getSharedSecret(ephemeralPriv, recipientX25519Pub);
    const aad = buildAad(multisigBytes, dealerBytes, recipientBytes, ephemeralPub);
    const aesKey = deriveAesKey(sharedSecret, aad);

    const nonce = randomness?.nonces?.[i] ?? randomBytes(NONCE_LENGTH);
    if (nonce.length !== NONCE_LENGTH) {
      throw new Error(`sealVaultDk: nonce[${i}] must be ${NONCE_LENGTH} bytes`);
    }
    const ciphertextWithTag = gcm(aesKey, nonce, aad).encrypt(dkVault);

    envelope.set(recipientBytes, o);
    o += ADDRESS_LENGTH;
    envelope.set(nonce, o);
    o += NONCE_LENGTH;
    envelope.set(ciphertextWithTag, o);
    o += CIPHERTEXT_WITH_TAG_LENGTH;

    sharedSecret.fill(0);
    aesKey.fill(0);
  });

  // Zero the ephemeral scalar only when we generated it (don't clobber a
  // caller-supplied test array).
  if (!randomness) {
    ephemeralPriv.fill(0);
  }

  return envelope;
}

/**
 * Open the recipient's slot in an envelope and recover the 32-byte `dk[Vault]`.
 * Reconstructs the AAD from the envelope header plus the recipient's own
 * address; any mismatch (wrong multisig, dealer, recipient, or ephemeral key,
 * or a tampered ciphertext) fails the GCM tag check and throws.
 *
 * @throws if the envelope is malformed, the version tag or multisig address
 *   does not match, the recipient is not addressed in the envelope, or
 *   decryption fails.
 */
export function openVaultDk(params: OpenVaultDkParams): Uint8Array {
  const { envelope, multisigAddress, recipientOwnerAddress, recipientEd25519PrivateKey } = params;

  if (!(envelope instanceof Uint8Array) || envelope.length < ENVELOPE_HEADER_LENGTH) {
    throw new Error("openVaultDk: envelope is too short to contain a header");
  }
  if (
    !(recipientEd25519PrivateKey instanceof Uint8Array) ||
    recipientEd25519PrivateKey.length !== ED25519_SEED_LENGTH
  ) {
    throw new Error(`openVaultDk: recipientEd25519PrivateKey must be a ${ED25519_SEED_LENGTH}-byte seed`);
  }

  let o = 0;
  const tag = envelope.subarray(o, o + VERSION_TAG_BYTES.length);
  if (!bytesEqual(tag, VERSION_TAG_BYTES)) {
    throw new Error(`openVaultDk: unsupported envelope version tag (expected "${VAULT_ENVELOPE_VERSION_TAG}")`);
  }
  o += VERSION_TAG_BYTES.length;

  const multisigBytes = envelope.subarray(o, o + ADDRESS_LENGTH);
  o += ADDRESS_LENGTH;
  const expectedMultisig = AccountAddress.from(multisigAddress).toUint8Array();
  if (!bytesEqual(multisigBytes, expectedMultisig)) {
    throw new Error("openVaultDk: envelope multisigAddress does not match the supplied multisigAddress");
  }

  const dealerBytes = envelope.subarray(o, o + ADDRESS_LENGTH);
  o += ADDRESS_LENGTH;
  const ephemeralPub = envelope.subarray(o, o + X25519_KEY_LENGTH);
  o += X25519_KEY_LENGTH;
  const recipientCount = readU16LE(envelope, o);
  o += 2;

  const expected = ENVELOPE_HEADER_LENGTH + recipientCount * RECIPIENT_RECORD_LENGTH;
  if (envelope.length !== expected) {
    throw new Error(
      `openVaultDk: envelope length ${envelope.length} does not match header count ${recipientCount} (expected ${expected})`,
    );
  }

  const recipientBytes = AccountAddress.from(recipientOwnerAddress).toUint8Array();

  for (let i = 0; i < recipientCount; i += 1) {
    const base = o + i * RECIPIENT_RECORD_LENGTH;
    const slotOwner = envelope.subarray(base, base + ADDRESS_LENGTH);
    if (!bytesEqual(slotOwner, recipientBytes)) {
      continue;
    }
    const nonce = envelope.subarray(base + ADDRESS_LENGTH, base + ADDRESS_LENGTH + NONCE_LENGTH);
    const ciphertextWithTag = envelope.subarray(base + ADDRESS_LENGTH + NONCE_LENGTH, base + RECIPIENT_RECORD_LENGTH);

    const recipientX25519Priv = edwardsToMontgomeryPriv(recipientEd25519PrivateKey);
    const sharedSecret = x25519.getSharedSecret(recipientX25519Priv, ephemeralPub);
    const aad = buildAad(multisigBytes, dealerBytes, recipientBytes, ephemeralPub);
    const aesKey = deriveAesKey(sharedSecret, aad);
    try {
      const dkVault = gcm(aesKey, nonce, aad).decrypt(ciphertextWithTag);
      return dkVault;
    } finally {
      recipientX25519Priv.fill(0);
      sharedSecret.fill(0);
      aesKey.fill(0);
    }
  }

  throw new Error("openVaultDk: no envelope slot addressed to recipientOwnerAddress");
}

/**
 * Encode a raw 32-byte `dk[Vault]` as the manual-recovery export string:
 *
 * ```
 * mv-dk-vault-raw-v1:<64 lowercase hex chars>
 * ```
 *
 * This carries the *vault root* — distinct from `mv-dk-v1:` (see
 * `encodeDecryptionKeyVersioned` in `./derivation`), which carries a per-token
 * leaf `dk`. The two codecs coexist by design (MIP, "Storage and export").
 */
export function encodeVaultDkRaw(dkVault: Uint8Array): string {
  if (!(dkVault instanceof Uint8Array) || dkVault.length !== VAULT_DK_LENGTH) {
    throw new Error(`encodeVaultDkRaw: dkVault must be a ${VAULT_DK_LENGTH}-byte Uint8Array`);
  }
  return `${VAULT_DK_EXPORT_V1_PREFIX}${bytesToHex(dkVault)}`;
}

/**
 * Inverse of {@link encodeVaultDkRaw}. Accepts the version-tagged form
 * (`mv-dk-vault-raw-v1:<hex>`) or a bare 64-character hex string (with or
 * without `0x`). Rejects future-version prefixes (`mv-dk-vault-raw-v2:` etc.)
 * so an older SDK cannot silently mis-import newer material.
 *
 * @returns the 32-byte vault root
 */
export function decodeVaultDkRaw(encoded: string): Uint8Array {
  const trimmed = encoded.trim();
  let hex: string;
  if (trimmed.startsWith(VAULT_DK_EXPORT_V1_PREFIX)) {
    hex = trimmed.slice(VAULT_DK_EXPORT_V1_PREFIX.length);
  } else if (/^mv-dk-vault-raw-v\d+:/.test(trimmed)) {
    const tag = trimmed.slice(0, trimmed.indexOf(":") + 1);
    throw new Error(
      `Unsupported vault dk export version "${tag}". This SDK only understands "${VAULT_DK_EXPORT_V1_PREFIX}".`,
    );
  } else {
    hex = trimmed;
  }
  if (hex.startsWith("0x") || hex.startsWith("0X")) {
    hex = hex.slice(2);
  }
  const bytes = hexToBytes(hex.toLowerCase());
  if (bytes.length !== VAULT_DK_LENGTH) {
    throw new Error(`decodeVaultDkRaw: expected ${VAULT_DK_LENGTH} bytes, got ${bytes.length}`);
  }
  return bytes;
}
