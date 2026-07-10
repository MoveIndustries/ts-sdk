// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import { x25519, ed25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { bytesToHex, hexToBytes, randomBytes } from "@noble/hashes/utils";
import { gcm } from "@noble/ciphers/aes";
import { AccountAddress, AccountAddressInput } from "@moveindustries/ts-sdk";

// ───────────────────────────────────────────────────────────────────────────
// Multisig vault `dk[Vault]` envelope layer (MIP-001 §"Multisig accounts").
//
// A multisig vault shares one uniformly-random 32-byte root `dk[Vault]` across
// all co-owners. The dealer seals `dk[Vault]` to each co-owner under a
// per-recipient AES-GCM key derived from an X25519 ECDH between a single
// per-envelope ephemeral key and the recipient's **vault-envelope key** (`vek`)
// — a per-owner X25519 keypair whose private half every backing can reconstruct
// locally (on hardware, from a device signature) and whose public half the owner
// publishes. The recipient opens its own slot with `vek_priv`. Every holder of
// `dk[Vault]` then derives per-token `dk[Vault, token]` locally via
// `vaultDecryptionKey` (see `./derivation`).
//
// The recipient key is NOT the birational map of the Ed25519 owner key: that map
// opens only with the Ed25519 private scalar, which hardware backings never
// expose. The `vek` derivations and the ownership-signature publish/verify that
// authenticates a published `vek_pub` live at the bottom of this file.
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
const ED25519_SIGNATURE_LENGTH = 64;
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
  /**
   * The co-owner's 32-byte published **vault-envelope key** (`vek_pub`, X25519).
   * The dealer must have verified its ownership signature (see
   * {@link verifyVaultEnvelopeKeyOwnership}) against the owner's on-chain Ed25519
   * key before sealing to it.
   */
  vaultEnvelopePublicKey: Uint8Array;
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
  /**
   * This recipient's 32-byte **vault-envelope private key** (`vek_priv`, X25519),
   * reconstructed locally per backing (see {@link vaultEnvelopeKeyFromSignature} /
   * {@link vaultEnvelopeKeyFromPepper} / {@link vaultEnvelopeKeyFromSeed}).
   */
  recipientVaultEnvelopePrivateKey: Uint8Array;
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

function writeU16LE(buf: Uint8Array, offset: number, value: number): void {
  buf[offset] = value & 0xff;
  buf[offset + 1] = (value >> 8) & 0xff;
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
 *   more than 65535, or any recipient vault-envelope public key is not 32 bytes.
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
  writeU16LE(envelope, o, recipients.length);
  o += 2;

  recipients.forEach((recipient, i) => {
    if (
      !(recipient.vaultEnvelopePublicKey instanceof Uint8Array) ||
      recipient.vaultEnvelopePublicKey.length !== X25519_KEY_LENGTH
    ) {
      throw new Error(
        `sealVaultDk: recipient[${i}] vaultEnvelopePublicKey must be a ${X25519_KEY_LENGTH}-byte Uint8Array`,
      );
    }
    const recipientBytes = AccountAddress.from(recipient.ownerAddress).toUint8Array();
    const sharedSecret = x25519.getSharedSecret(ephemeralPriv, recipient.vaultEnvelopePublicKey);
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
  const { envelope, multisigAddress, recipientOwnerAddress, recipientVaultEnvelopePrivateKey } = params;

  if (!(envelope instanceof Uint8Array) || envelope.length < ENVELOPE_HEADER_LENGTH) {
    throw new Error("openVaultDk: envelope is too short to contain a header");
  }
  if (
    !(recipientVaultEnvelopePrivateKey instanceof Uint8Array) ||
    recipientVaultEnvelopePrivateKey.length !== X25519_KEY_LENGTH
  ) {
    throw new Error(`openVaultDk: recipientVaultEnvelopePrivateKey must be a ${X25519_KEY_LENGTH}-byte X25519 key`);
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

    const sharedSecret = x25519.getSharedSecret(recipientVaultEnvelopePrivateKey, ephemeralPub);
    const aad = buildAad(multisigBytes, dealerBytes, recipientBytes, ephemeralPub);
    const aesKey = deriveAesKey(sharedSecret, aad);
    try {
      const dkVault = gcm(aesKey, nonce, aad).decrypt(ciphertextWithTag);
      return dkVault;
    } finally {
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

// ───────────────────────────────────────────────────────────────────────────
// Vault-envelope key (`vek`) — MIP-001 §"Vault-envelope key".
//
// The recipient encryption key for the envelope. A per-owner X25519 keypair
// whose private half every backing can reconstruct locally and whose public
// half the owner publishes (ownership-authenticated) for dealers to seal to.
// `vek` is per owner identity, not per vault — the per-share binding lives in
// the envelope AAD/info, so one `vek` safely covers every vault the owner is in.
// ───────────────────────────────────────────────────────────────────────────

/** Salt + info prefix for the keyless `vek` HKDF; matches MIP §"Vault-envelope key". */
const VEK_HKDF_SALT = new TextEncoder().encode("movement-ca-vek/v1");
const VEK_INFO_PREFIX = new TextEncoder().encode("vek:");

/**
 * The fixed message a hardware device signs to derive its vault-envelope key.
 * Distinct from `TwistedEd25519PrivateKey.decryptionKeyDerivationMessage` so the
 * `vek` and the per-token `dk` come from independent device signatures.
 */
export const VAULT_ENVELOPE_KEY_DERIVATION_MESSAGE =
  "Sign this message to derive your confidential-asset vault-envelope key";

/** Ed25519 ownership-signature domain separator over `DST ‖ vekPub`. */
export const VAULT_ENVELOPE_KEY_OWNERSHIP_DST = "MovementConfidentialAsset/VaultEnvelopeKey/v1";
const VAULT_ENVELOPE_KEY_OWNERSHIP_DST_BYTES = new TextEncoder().encode(VAULT_ENVELOPE_KEY_OWNERSHIP_DST);

/** BIP-44 branch for the vault-envelope key (0'=signing, 1'=per-asset dk, 2'=vek). */
const VEK_BRANCH = 2;
const APTOS_COIN_TYPE = 637;

export interface VaultEnvelopeKeyPair {
  /** 32-byte X25519 private key (`vek_priv`); clamped by X25519 on use. Never persist at rest for hardware. */
  privateKey: Uint8Array;
  /** 32-byte X25519 public key (`vek_pub`) — the value the owner publishes. */
  publicKey: Uint8Array;
}

/**
 * Core: reduce 32 bytes of uniform seed material to an X25519 vault-envelope
 * keypair. `privateKey` is the raw 32-byte seed (X25519 clamps it on use);
 * `publicKey = X25519_basepoint(privateKey)`.
 *
 * Software backings pass the 32-byte Ed25519 private key derived at
 * {@link vaultEnvelopeKeyDerivationPath}; hardware and keyless use the dedicated
 * helpers below.
 */
export function vaultEnvelopeKeyFromSeed(seed: Uint8Array): VaultEnvelopeKeyPair {
  if (!(seed instanceof Uint8Array) || seed.length < X25519_KEY_LENGTH) {
    throw new Error(`vaultEnvelopeKeyFromSeed: seed must be at least ${X25519_KEY_LENGTH} bytes`);
  }
  const privateKey = seed.slice(0, X25519_KEY_LENGTH);
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/**
 * Hardware backing: derive the vault-envelope keypair from the device's Ed25519
 * signature over {@link VAULT_ENVELOPE_KEY_DERIVATION_MESSAGE}. `seed =
 * SHA-512(signature)[0..32]`. Recomputed from a fresh device signature each
 * session; the wallet must not persist `privateKey` at rest.
 *
 * @param signature the raw 64-byte Ed25519 device signature over the message
 */
export function vaultEnvelopeKeyFromSignature(signature: Uint8Array): VaultEnvelopeKeyPair {
  if (!(signature instanceof Uint8Array) || signature.length !== ED25519_SIGNATURE_LENGTH) {
    throw new Error(`vaultEnvelopeKeyFromSignature: signature must be ${ED25519_SIGNATURE_LENGTH} bytes`);
  }
  return vaultEnvelopeKeyFromSeed(sha512(signature));
}

/**
 * Keyless backing: derive the vault-envelope keypair from the keyless pepper via
 * `HKDF-SHA512(pepper, salt="movement-ca-vek/v1", info="vek:" ‖ accountAddress, L=32)`.
 */
export function vaultEnvelopeKeyFromPepper(
  pepper: Uint8Array,
  accountAddress: AccountAddressInput,
): VaultEnvelopeKeyPair {
  if (!(pepper instanceof Uint8Array) || pepper.length === 0) {
    throw new Error("vaultEnvelopeKeyFromPepper: pepper must be a non-empty Uint8Array");
  }
  const acct = AccountAddress.from(accountAddress).toUint8Array();
  const info = new Uint8Array(VEK_INFO_PREFIX.length + acct.length);
  info.set(VEK_INFO_PREFIX, 0);
  info.set(acct, VEK_INFO_PREFIX.length);
  const seed = hkdf(sha512, pepper, VEK_HKDF_SALT, info, X25519_KEY_LENGTH);
  return vaultEnvelopeKeyFromSeed(seed);
}

/**
 * Software backing: the canonical BIP-32 path for the vault-envelope key,
 * `m/44'/637'/{accountIndex}'/2'/0'`. The wallet derives the Ed25519 key at this
 * path and passes its 32-byte private key to {@link vaultEnvelopeKeyFromSeed}.
 */
export function vaultEnvelopeKeyDerivationPath(accountIndex: number): string {
  if (!Number.isInteger(accountIndex) || accountIndex < 0) {
    throw new Error(`vaultEnvelopeKeyDerivationPath: accountIndex must be a non-negative integer, got ${accountIndex}`);
  }
  return `m/44'/${APTOS_COIN_TYPE}'/${accountIndex}'/${VEK_BRANCH}'/0'`;
}

/**
 * The exact bytes an owner signs with their Ed25519 owner key to authenticate a
 * published `vek_pub`: `utf8("MovementConfidentialAsset/VaultEnvelopeKey/v1") ‖ vekPub`.
 * On hardware this is a device blind-sign; the wallet then publishes the signature.
 */
export function vaultEnvelopeKeyOwnershipMessage(vekPub: Uint8Array): Uint8Array {
  if (!(vekPub instanceof Uint8Array) || vekPub.length !== X25519_KEY_LENGTH) {
    throw new Error(`vaultEnvelopeKeyOwnershipMessage: vekPub must be ${X25519_KEY_LENGTH} bytes`);
  }
  const out = new Uint8Array(VAULT_ENVELOPE_KEY_OWNERSHIP_DST_BYTES.length + vekPub.length);
  out.set(VAULT_ENVELOPE_KEY_OWNERSHIP_DST_BYTES, 0);
  out.set(vekPub, VAULT_ENVELOPE_KEY_OWNERSHIP_DST_BYTES.length);
  return out;
}

/**
 * Software/test convenience: sign {@link vaultEnvelopeKeyOwnershipMessage} with the
 * owner's 32-byte Ed25519 private-key seed. Hardware backings instead device-sign
 * the message bytes and pass the resulting signature to the registry directly.
 */
export function signVaultEnvelopeKeyOwnership(vekPub: Uint8Array, ownerEd25519PrivateKey: Uint8Array): Uint8Array {
  if (!(ownerEd25519PrivateKey instanceof Uint8Array) || ownerEd25519PrivateKey.length !== ED25519_SEED_LENGTH) {
    throw new Error(`signVaultEnvelopeKeyOwnership: ownerEd25519PrivateKey must be a ${ED25519_SEED_LENGTH}-byte seed`);
  }
  return ed25519.sign(vaultEnvelopeKeyOwnershipMessage(vekPub), ownerEd25519PrivateKey);
}

/**
 * Verify a published `vek_pub`'s ownership signature against the owner's on-chain
 * Ed25519 public key. A dealer MUST call this before sealing to a published key;
 * a false result means the key is unauthenticated and must not be used.
 */
export function verifyVaultEnvelopeKeyOwnership(args: {
  vekPub: Uint8Array;
  ownerEd25519PublicKey: Uint8Array;
  signature: Uint8Array;
}): boolean {
  const { vekPub, ownerEd25519PublicKey, signature } = args;
  if (
    !(ownerEd25519PublicKey instanceof Uint8Array) ||
    ownerEd25519PublicKey.length !== ED25519_PUBKEY_LENGTH ||
    !(signature instanceof Uint8Array) ||
    signature.length !== ED25519_SIGNATURE_LENGTH
  ) {
    return false;
  }
  try {
    return ed25519.verify(signature, vaultEnvelopeKeyOwnershipMessage(vekPub), ownerEd25519PublicKey);
  } catch {
    return false;
  }
}
