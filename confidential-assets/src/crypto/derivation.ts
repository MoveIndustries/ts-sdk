// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { hkdf } from "@noble/hashes/hkdf";
import { AccountAddress, AccountAddressInput } from "@moveindustries/ts-sdk";
import { TwistedEd25519PrivateKey } from "./twistedEd25519";

/**
 * BIP-44 sub-path constants for the wallet ↔ chain compatibility contract.
 * The `coinType = 637` slot is the Aptos / Movement coin type; `branch = 1`
 * is the confidential-asset decryption-key branch (`0` is reserved for the
 * Ed25519 signing key).
 */
const APTOS_COIN_TYPE = 637;
const CA_BRANCH = 1;

/**
 * HKDF-SHA512 parameters shared by {@link keylessDecryptionKey} and
 * {@link vaultDecryptionKey}. Locked here because changing them yields a
 * different `dk` / `ek` and orphans every existing on-chain registration. Each
 * derivation supplies its own `salt` (the `v1` suffix reserves room for a `v2`
 * layout in a future release without breaking `v1` registrations); the `info`
 * shape (`"dk:" ‖ addr ‖ token`) and the 64-byte output length are common.
 */
const KEYLESS_HKDF_SALT = new TextEncoder().encode("movement-ca/v1");
const VAULT_HKDF_SALT = new TextEncoder().encode("movement-ca-vault/v1");
const HKDF_INFO_PREFIX = new TextEncoder().encode("dk:");
const HKDF_OUTPUT_LENGTH = 64;

/**
 * Shared HKDF-SHA512 core for the address-bound decryption-key derivations
 * ({@link keylessDecryptionKey}, {@link vaultDecryptionKey}). Builds
 * `info = "dk:" ‖ addr ‖ token` from the raw 32-byte addresses (not hex),
 * expands 64 bytes of OKM, and reduces it into the Ed25519 scalar field via
 * {@link TwistedEd25519PrivateKey.fromUniformBytes}.
 */
function deriveDkFromIkm(
  ikm: Uint8Array,
  salt: Uint8Array,
  addr: AccountAddressInput,
  tokenMetaAddr: AccountAddressInput,
): TwistedEd25519PrivateKey {
  const acctBytes = AccountAddress.from(addr).toUint8Array();
  const tokBytes = AccountAddress.from(tokenMetaAddr).toUint8Array();
  const info = new Uint8Array(HKDF_INFO_PREFIX.length + acctBytes.length + tokBytes.length);
  info.set(HKDF_INFO_PREFIX, 0);
  info.set(acctBytes, HKDF_INFO_PREFIX.length);
  info.set(tokBytes, HKDF_INFO_PREFIX.length + acctBytes.length);
  const okm = hkdf(sha512, ikm, salt, info, HKDF_OUTPUT_LENGTH);
  return TwistedEd25519PrivateKey.fromUniformBytes(okm);
}

/**
 * Derive the per-token BIP-32 hardened-index suffix from a fungible-asset
 * metadata address. Used in the `{tokenIndex}` slot of the confidential-asset
 * software-backing derivation path:
 *
 * ```
 * m/44'/637'/{accountIndex}'/1'/{tokenIndex}'
 * ```
 *
 * The formula is `u32_le(SHA-256(tokenMetadataAddress)[0..4]) & 0x7FFFFFFF` —
 * SHA-256 of the 32-byte metadata address, take the first 4 output bytes as a
 * little-endian unsigned 32-bit integer, and clear the top bit so the result
 * fits a hardened BIP-32 index (which must be < 2^31).
 *
 * @param tokenMetaAddr the FA metadata address
 * @returns a 31-bit non-negative integer suitable for use as a hardened index
 */
export function tokenIndexFromMetadataAddress(tokenMetaAddr: AccountAddressInput): number {
  const addr = AccountAddress.from(tokenMetaAddr).toUint8Array();
  const digest = sha256(addr);
  const u32 = (digest[0]! | (digest[1]! << 8) | (digest[2]! << 16) | (digest[3]! << 24)) >>> 0;
  return u32 & 0x7fffffff;
}

/**
 * Build the canonical BIP-32 derivation path for a software-backed
 * confidential-asset decryption key. Wallet implementations should call this
 * helper rather than re-assembling the path string themselves; a divergence
 * in the path produces a different `dk` and orphans the registration.
 *
 * @param accountIndex the BIP-44 account index (the `0'` in
 *   `m/44'/637'/0'/0'/0'` for the corresponding signing key)
 * @param tokenMetaAddr the FA metadata address whose `dk` is being derived
 * @returns the full hardened path `m/44'/637'/{accountIndex}'/1'/{tokenIndex}'`
 *   ready to feed into `TwistedEd25519PrivateKey.fromDerivationPath`
 */
export function softwareDecryptionKeyDerivationPath(accountIndex: number, tokenMetaAddr: AccountAddressInput): string {
  if (!Number.isInteger(accountIndex) || accountIndex < 0) {
    throw new Error(`accountIndex must be a non-negative integer, got ${accountIndex}`);
  }
  const tokenIndex = tokenIndexFromMetadataAddress(tokenMetaAddr);
  return `m/44'/${APTOS_COIN_TYPE}'/${accountIndex}'/${CA_BRANCH}'/${tokenIndex}'`;
}

/**
 * The fixed message prefix that hardware-backed wallets ask the device to
 * sign in order to derive a `dk`. The full message is this prefix, a single
 * ASCII colon, and the lowercase hex of the token metadata address (no
 * `0x` prefix).
 */
export const HARDWARE_DECRYPTION_KEY_DERIVATION_MESSAGE_PREFIX =
  TwistedEd25519PrivateKey.decryptionKeyDerivationMessage;

/**
 * Build the byte string a hardware device must sign to derive the
 * confidential-asset decryption key for a given token.
 *
 * The layout is:
 *
 * ```
 * decryptionKeyDerivationMessage ‖ ":" ‖ lowerHex(tokenMetadataAddress)
 * ```
 *
 * The 32-byte address is rendered as a 64-character lowercase hex string with
 * no `0x` prefix; the separator is a single ASCII colon (`0x3a`).
 *
 * The wallet feeds the device's resulting Ed25519 signature into
 * {@link TwistedEd25519PrivateKey.fromSignature} to obtain `dk[token]`.
 *
 * @param tokenMetaAddr the FA metadata address whose `dk` is being derived
 * @returns the bytes the device should sign
 */
export function hardwareDecryptionKeyDerivationMessage(tokenMetaAddr: AccountAddressInput): Uint8Array {
  // toStringLongWithoutPrefix renders the full 64-char hex (no `0x`); toStringWithoutPrefix
  // would short-form addresses like 0x…0a to "a", which would diverge from the convention.
  const addr = AccountAddress.from(tokenMetaAddr);
  const hex = addr.toStringLongWithoutPrefix().toLowerCase();
  return new TextEncoder().encode(`${HARDWARE_DECRYPTION_KEY_DERIVATION_MESSAGE_PREFIX}:${hex}`);
}

/**
 * Derive a keyless-backed `dk[account, token]` from the keyless pepper using
 * HKDF-SHA512 with the wallet-fixed salt and info layout.
 *
 * Concretely:
 *
 * ```
 * okm = HKDF-SHA512(
 *   ikm  = pepper,
 *   salt = utf8("movement-ca/v1"),
 *   info = utf8("dk:") || accountAddress || tokenMetadataAddress,  // 32+32 raw bytes
 *   L    = 64,
 * )
 * dk = TwistedEd25519PrivateKey.fromUniformBytes(okm)
 * ```
 *
 * Binding `accountAddress` into `info` lets a single keyless identity (one
 * pepper) safely back multiple distinct CA accounts — the keyless owner's
 * own account plus any number of multisigs the owner is a designated
 * proposer for — without `dk` collisions across them.
 *
 * The helper takes raw pepper bytes (not a higher-level keyless-account
 * object) so the SDK does not need to model OIDC state. The wallet feeds
 * 31-byte peppers from `@eigerco/movement-keyless` directly; HKDF accepts
 * any input length, so the helper is robust to a future change in
 * pepper-service byte width.
 *
 * @param pepper the keyless pepper (raw bytes; 31 bytes in current
 *   `@eigerco/movement-keyless` releases, but any length is accepted)
 * @param accountAddress the address whose on-chain `ek` slot this `dk` is
 *   for — the keyless wallet's own address for owner-account derivations,
 *   or a multisig address for multisig proposer-side derivations
 * @param tokenMetaAddr the FA metadata address whose `dk` is being derived
 * @returns a `TwistedEd25519PrivateKey` reduced from 64 bytes of HKDF output
 */
export function keylessDecryptionKey(
  pepper: Uint8Array,
  accountAddress: AccountAddressInput,
  tokenMetaAddr: AccountAddressInput,
): TwistedEd25519PrivateKey {
  if (!(pepper instanceof Uint8Array)) {
    throw new Error("keylessDecryptionKey: pepper must be a Uint8Array");
  }
  if (pepper.length === 0) {
    throw new Error("keylessDecryptionKey: pepper must be non-empty");
  }
  return deriveDkFromIkm(pepper, KEYLESS_HKDF_SALT, accountAddress, tokenMetaAddr);
}

/**
 * Derive a multisig-vault `dk[Vault, token]` from the shared 32-byte vault root
 * `dk[Vault]` using HKDF-SHA512 with the vault-scoped salt and the standard
 * info layout:
 *
 * ```
 * okm = HKDF-SHA512(
 *   ikm  = dkVault,                                                 // 32 bytes
 *   salt = utf8("movement-ca-vault/v1"),                           // 22 bytes
 *   info = utf8("dk:") || multisigAddress || tokenMetadataAddress, // 3 + 32 + 32 raw bytes
 *   L    = 64,
 * )
 * dk[Vault, token] = TwistedEd25519PrivateKey.fromUniformBytes(okm)
 * ```
 *
 * `dk[Vault]` is a uniformly random per-vault root generated once by the dealer
 * and bootstrapped to every co-owner through the off-chain envelope (see
 * {@link sealVaultDk} / {@link openVaultDk}). Every holder of `dk[Vault]` then
 * derives `dk[Vault, token]` locally for any asset the vault registers — no
 * further per-token sharing is required. Binding `multisigAddress` into `info`
 * domain-separates the derivation across vaults even in the unlikely event two
 * vaults end up with the same random root.
 *
 * Mirrors {@link keylessDecryptionKey}; the only differences are the
 * vault-scoped salt and that the IKM is the vault root rather than a keyless
 * pepper.
 *
 * @param dkVault the 32-byte vault root (`dk[Vault]`)
 * @param multisigAddress the multisig (vault) account address
 * @param tokenMetaAddr the FA metadata address whose `dk` is being derived
 * @returns a `TwistedEd25519PrivateKey` reduced from 64 bytes of HKDF output
 */
export function vaultDecryptionKey(
  dkVault: Uint8Array,
  multisigAddress: AccountAddressInput,
  tokenMetaAddr: AccountAddressInput,
): TwistedEd25519PrivateKey {
  if (!(dkVault instanceof Uint8Array)) {
    throw new Error("vaultDecryptionKey: dkVault must be a Uint8Array");
  }
  if (dkVault.length !== 32) {
    throw new Error(`vaultDecryptionKey: dkVault must be 32 bytes, got ${dkVault.length}`);
  }
  return deriveDkFromIkm(dkVault, VAULT_HKDF_SALT, multisigAddress, tokenMetaAddr);
}

// ───────────────────────────────────────────────────────────────────────────
// Multisig key derivation note
//
// There is no per-proposer multisig derivation helper. A multisig vault shares
// one random 32-byte root `dk[Vault]` across co-owners (bootstrapped via the
// off-chain envelope — see `sealVaultDk` / `openVaultDk` in `./vault`); every
// holder derives `dk[Vault, token]` locally with {@link vaultDecryptionKey}.
// This replaces the earlier proposer-derives-from-own-root model.
// ───────────────────────────────────────────────────────────────────────────

// ───────────────────────────────────────────────────────────────────────────
// Per-asset DK hex codec (versioned)
//
// `mv-dk-v1:` is the MIP's *per-asset* decryption-key export format: a single
// `dk[account, token]` (or `dk[Vault, token]`) leaf scalar rendered as hex for
// a user-initiated, single-`(account, token)` export (manual backup / recovery).
// It is NOT the multisig co-owner bootstrap mechanism — co-owners share the
// 32-byte *vault root* `dk[Vault]`, not per-token leaves, via the off-chain
// envelope (see `sealVaultDk` / `openVaultDk` in `./vault`), with
// `mv-dk-vault-raw-v1:` (see `encodeVaultDkRaw`) as the manual-recovery fallback
// for the root. The two codecs coexist by design (MIP, "Storage and export"):
// `mv-dk-v1:` carries a per-token leaf, `mv-dk-vault-raw-v1:` carries the root.
//
// A version tag in front of the hex makes future format changes (`mv-dk-v2`)
// unambiguously distinguishable from `v1` material, and lets importers reject
// material produced with a different protocol.
// ───────────────────────────────────────────────────────────────────────────

/** Magic prefix for exported per-asset `dk` material under the v1 layout. */
export const DK_EXPORT_V1_PREFIX = "mv-dk-v1:";

/**
 * Encode a `TwistedEd25519PrivateKey` as a version-tagged hex string for a
 * user-initiated per-asset (`one (account, token)`) export. The encoded form is:
 *
 * ```
 * mv-dk-v1:<64 lowercase hex chars>
 * ```
 *
 * Note that this is *not* address-bound — the receiving wallet must bind the
 * material to `(accountAddress, tokenMetaAddr)` at storage time via the
 * AAD-bound keystore entry. The version tag exists only to distinguish format
 * generations, not to authenticate the carrier. To export/import a multisig
 * *vault root* instead of a per-token leaf, use `encodeVaultDkRaw` /
 * `decodeVaultDkRaw` (`mv-dk-vault-raw-v1:`).
 */
export function encodeDecryptionKeyVersioned(dk: TwistedEd25519PrivateKey): string {
  return `${DK_EXPORT_V1_PREFIX}${dk.toStringWithoutPrefix().toLowerCase()}`;
}

/**
 * Inverse of {@link encodeDecryptionKeyVersioned}. Accepts either the
 * version-tagged form (`mv-dk-v1:<hex>`) or, for backwards compatibility with
 * pre-versioned exports, a bare 64-character hex string (with or without `0x`).
 * Rejects future-version prefixes (`mv-dk-v2:` etc.) with an explicit error so
 * a wallet running an older SDK cannot silently mis-import v2 material as v1.
 */
export function decodeDecryptionKeyVersioned(encoded: string): TwistedEd25519PrivateKey {
  const trimmed = encoded.trim();
  if (trimmed.startsWith(DK_EXPORT_V1_PREFIX)) {
    return new TwistedEd25519PrivateKey(trimmed.slice(DK_EXPORT_V1_PREFIX.length));
  }
  if (/^mv-dk-v\d+:/.test(trimmed)) {
    const tag = trimmed.slice(0, trimmed.indexOf(":") + 1);
    throw new Error(`Unsupported dk export version "${tag}". This SDK only understands "${DK_EXPORT_V1_PREFIX}".`);
  }
  // Bare-hex fallback (accept 0x-prefixed or not, lower or upper case).
  return new TwistedEd25519PrivateKey(trimmed);
}
