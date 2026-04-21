import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { sha256 } from "@noble/hashes/sha256";
import { concatBytes } from "@noble/hashes/utils";
import { bcsU64 } from "./commitment";

const INCOMING_KEY = new TextEncoder().encode("SA_IVKEY_CHACHA_v1");
const OUTGOING_KEY = new TextEncoder().encode("SA_OVKEY_CHACHA_v1");

function randomNonce24(): Uint8Array {
  const n = new Uint8Array(24);
  globalThis.crypto.getRandomValues(n);
  return n;
}

function deriveIncomingKey(incomingViewKey32: Uint8Array): Uint8Array {
  return sha256(concatBytes(INCOMING_KEY, incomingViewKey32));
}

function deriveOutgoingKey(outgoingViewKey32: Uint8Array): Uint8Array {
  return sha256(concatBytes(OUTGOING_KEY, outgoingViewKey32));
}

/**
 * Plaintext indexed by incoming viewing keys (Zcash-style trial decryption on events).
 * Layout: `bcs(amount) || blinding(32) || metadata_address(32)`.
 */
export function encodeIncomingPlaintext(amount: bigint, blinding32: Uint8Array, metadataAddress32: Uint8Array): Uint8Array {
  if (blinding32.length !== 32 || metadataAddress32.length !== 32) {
    throw new Error("blinding and metadataAddress must be 32 bytes");
  }
  return concatBytes(bcsU64(amount), blinding32, metadataAddress32);
}

export function decodeIncomingPlaintext(plain: Uint8Array): { amount: bigint; blinding: Uint8Array; metadataAddress: Uint8Array } {
  if (plain.length !== 8 + 32 + 32) {
    throw new Error("invalid incoming plaintext length");
  }
  let amt = 0n;
  for (let i = 0; i < 8; i++) {
    amt |= BigInt(plain[i]!) << BigInt(8 * i);
  }
  return {
    amount: amt,
    blinding: plain.slice(8, 40),
    metadataAddress: plain.slice(40, 72),
  };
}

/**
 * Encrypt payload for `shield` `incoming_view_ciphertext` (auditors / wallet with IVK).
 * Format: `nonce(24) || ciphertext+tag` (XChaCha20-Poly1305).
 */
export function encryptIncomingViewPayload(incomingViewKey32: Uint8Array, plaintext: Uint8Array): Uint8Array {
  if (incomingViewKey32.length !== 32) {
    throw new Error("incoming viewing key must be 32 bytes");
  }
  const key = deriveIncomingKey(incomingViewKey32);
  const nonce = randomNonce24();
  const cipher = xchacha20poly1305(key, nonce);
  const ct = cipher.encrypt(plaintext);
  return concatBytes(nonce, ct);
}

/** Decrypt incoming payload; returns `null` if authentication fails (wrong IVK). */
export function decryptIncomingViewPayload(incomingViewKey32: Uint8Array, blob: Uint8Array): Uint8Array | null {
  if (blob.length < 24 + 16) {
    return null;
  }
  const key = deriveIncomingKey(incomingViewKey32);
  const nonce = blob.slice(0, 24);
  const ct = blob.slice(24);
  try {
    const cipher = xchacha20poly1305(key, nonce);
    return cipher.decrypt(ct);
  } catch {
    return null;
  }
}

/** Optional memo for outgoing viewing (unshield event). */
export function encodeOutgoingPlaintext(recipientAddress32: Uint8Array, memoUtf8?: string): Uint8Array {
  const memo = memoUtf8 ? new TextEncoder().encode(memoUtf8) : new Uint8Array(0);
  return concatBytes(recipientAddress32, memo);
}

export function encryptOutgoingViewPayload(outgoingViewKey32: Uint8Array, plaintext: Uint8Array): Uint8Array {
  if (outgoingViewKey32.length !== 32) {
    throw new Error("outgoing viewing key must be 32 bytes");
  }
  const key = deriveOutgoingKey(outgoingViewKey32);
  const nonce = randomNonce24();
  const cipher = xchacha20poly1305(key, nonce);
  const ct = cipher.encrypt(plaintext);
  return concatBytes(nonce, ct);
}

export function decryptOutgoingViewPayload(outgoingViewKey32: Uint8Array, blob: Uint8Array): Uint8Array | null {
  if (blob.length < 24 + 16) {
    return null;
  }
  const key = deriveOutgoingKey(outgoingViewKey32);
  const nonce = blob.slice(0, 24);
  const ct = blob.slice(24);
  try {
    const cipher = xchacha20poly1305(key, nonce);
    return cipher.decrypt(ct);
  } catch {
    return null;
  }
}

/** Random 32-byte viewing key (incoming or outgoing). */
export function randomViewingKey32(): Uint8Array {
  const k = new Uint8Array(32);
  globalThis.crypto.getRandomValues(k);
  return k;
}
