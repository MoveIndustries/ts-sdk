// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { hkdf } from "@noble/hashes/hkdf";
import { AccountAddress, AccountAddressInput } from "@moveindustries/ts-sdk";
import { TwistedEd25519PrivateKey } from "./twistedEd25519";

/**
 * BIP-44 sub-path constants for the wallet ↔ chain compatibility contract
 * specified in `confidential-assets/WALLET_INTEGRATION.md`. The
 * `coinType = 637` slot is the Aptos / Movement coin type; `branch = 1` is
 * the confidential-asset decryption-key branch (`0` is reserved for the
 * Ed25519 signing key).
 */
const APTOS_COIN_TYPE = 637;
const CA_BRANCH = 1;

/**
 * HKDF-SHA512 parameters used by {@link keylessDecryptionKey}. Locked here
 * because changing them yields a different `dk` / `ek` and orphans every
 * existing on-chain registration. The `v1` suffix in the salt reserves room
 * to introduce a `v2` layout in a future release without breaking `v1`
 * registrations.
 */
const KEYLESS_HKDF_SALT = new TextEncoder().encode("movement-ca/v1");
const KEYLESS_HKDF_INFO_PREFIX = new TextEncoder().encode("dk:");
const KEYLESS_HKDF_OUTPUT_LENGTH = 64;

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
 * HKDF-SHA512 with the wallet-fixed salt and info layout specified in
 * `confidential-assets/WALLET_INTEGRATION.md` § "HKDF layout for keyless
 * backings".
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
  const acctBytes = AccountAddress.from(accountAddress).toUint8Array();
  const tokBytes = AccountAddress.from(tokenMetaAddr).toUint8Array();
  const info = new Uint8Array(KEYLESS_HKDF_INFO_PREFIX.length + acctBytes.length + tokBytes.length);
  info.set(KEYLESS_HKDF_INFO_PREFIX, 0);
  info.set(acctBytes, KEYLESS_HKDF_INFO_PREFIX.length);
  info.set(tokBytes, KEYLESS_HKDF_INFO_PREFIX.length + acctBytes.length);
  const okm = hkdf(sha512, pepper, KEYLESS_HKDF_SALT, info, KEYLESS_HKDF_OUTPUT_LENGTH);
  return TwistedEd25519PrivateKey.fromUniformBytes(okm);
}
