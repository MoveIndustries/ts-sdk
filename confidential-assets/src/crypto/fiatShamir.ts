// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import { sha512 } from "@noble/hashes/sha512";
import { bytesToNumberLE, concatBytes, numberToBytesLE } from "@noble/curves/abstract/utils";
import { ed25519modN } from "../utils";

/**
 * Domain-separated SHA2-512 hash.
 *
 * hash(dst, msg) = SHA2-512(dst_bytes || msg)
 *
 * The DST (domain separation tag) is prepended as raw UTF-8 bytes,
 * matching the on-chain `ristretto255::new_scalar_from_sha2_512(dst || msg)`.
 *
 * @param dst - The domain separation tag string
 * @param data - The message data to hash
 * @returns 64-byte SHA2-512 hash
 */
export function dstHash(dst: string, ...data: Uint8Array[]): Uint8Array {
  const dstBytes = new TextEncoder().encode(dst);
  return sha512(concatBytes(dstBytes, ...data));
}

/**
 * Generate a Fiat-Shamir challenge scalar using SHA2-512 with a DST prefix
 * and domain separation including chain ID and sender address.
 *
 * The challenge is computed as:
 *   e = SHA2-512("MovementConfidentialAsset/" + protocolId ||
 *                 chainId || senderAddress || ...publicInputs)
 *   reduced mod the ed25519 curve order l.
 *
 * This matches the on-chain construction:
 *   `ristretto255::new_scalar_from_sha2_512(DST || chain_id || sender || ... || msg)`
 *
 * Note: tokenAddress is NOT automatically included in the hash. For protocols
 * that need it (e.g. Registration: `contractAddress` then `tokenAddress`), pass
 * those as part of `publicInputs` in the same order as on-chain Move.
 *
 * @param protocolId - Protocol identifier (e.g. "Withdrawal", "Transfer", "Registration")
 * @param chainId - Chain ID for domain separation (prevents cross-chain replay)
 * @param senderAddress - 32-byte sender address
 * @param publicInputs - Additional public inputs (points, scalars, commitments)
 * @returns Challenge scalar as bigint, reduced mod curve order
 */
export function fiatShamirChallenge(
  protocolId: string,
  chainId: number,
  senderAddress: Uint8Array,
  ...publicInputs: Uint8Array[]
): bigint {
  const dst = `MovementConfidentialAsset/${protocolId}`;
  // Move passes `(chain_id::get() as u8)` into proofs; keep the transcript byte aligned.
  const chainIdBytes = numberToBytesLE(Number(chainId) & 0xff, 1);
  const hash = dstHash(dst, chainIdBytes, senderAddress, ...publicInputs);
  return ed25519modN(bytesToNumberLE(hash));
}
