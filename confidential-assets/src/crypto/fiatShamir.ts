// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import { sha3_512 } from "@noble/hashes/sha3";
import { bytesToNumberLE, concatBytes, numberToBytesLE } from "@noble/curves/abstract/utils";
import { ed25519modN } from "../utils";

/**
 * BIP-340-style tagged hash using SHA3-512.
 *
 * tagged_hash(tag, msg) = SHA3-512(SHA3-512(tag) || SHA3-512(tag) || msg)
 *
 * The double-tag prefix is pre-computable and serves as domain separation.
 * This differs from Aptos's approach (SHA2-512 with raw prefix concatenation)
 * and follows the well-established BIP-340 tagged hash pattern.
 *
 * @param tag - The domain separation tag string
 * @param data - The message data to hash
 * @returns 64-byte SHA3-512 hash
 */
export function taggedHash(tag: string, ...data: Uint8Array[]): Uint8Array {
  const tagBytes = new TextEncoder().encode(tag);
  const tagHash = sha3_512(tagBytes);
  return sha3_512(concatBytes(tagHash, tagHash, ...data));
}

/**
 * Generate a Fiat-Shamir challenge scalar using SHA3-512 tagged hashing
 * with domain separation including chain ID and session context.
 *
 * The challenge is computed as:
 *   e = taggedHash("MovementConfidentialAsset/" + protocolId,
 *                   chainId || senderAddress || tokenAddress || ...publicInputs)
 *   reduced mod the ed25519 curve order l.
 *
 * @param protocolId - Protocol identifier (e.g. "Withdrawal", "Transfer", "Registration")
 * @param chainId - Chain ID for domain separation (prevents cross-chain replay)
 * @param senderAddress - 32-byte sender address
 * @param tokenAddress - 32-byte token address
 * @param publicInputs - Additional public inputs (points, scalars, commitments)
 * @returns Challenge scalar as bigint, reduced mod curve order
 */
export function fiatShamirChallenge(
  protocolId: string,
  chainId: number,
  senderAddress: Uint8Array,
  tokenAddress: Uint8Array,
  ...publicInputs: Uint8Array[]
): bigint {
  const tag = `MovementConfidentialAsset/${protocolId}`;
  const chainIdBytes = numberToBytesLE(chainId, 1);
  const hash = taggedHash(tag, chainIdBytes, senderAddress, tokenAddress, ...publicInputs);
  return ed25519modN(bytesToNumberLE(hash));
}
