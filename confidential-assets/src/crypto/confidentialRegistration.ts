// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

/**
 * Registration proof: a Schnorr zero-knowledge proof of knowledge (ZKPoK)
 * that the registrant knows the decryption key `dk` corresponding to the
 * encryption key `ek` they are registering.
 *
 * The relation proved is: ek = dk^{-1} * H, i.e., the registrant knows dk
 * such that multiplying the inverse of dk by the secondary base point H
 * yields their public encryption key.
 *
 * This prevents registering an encryption key for which you don't hold the
 * corresponding decryption key.
 */

import { RistrettoPoint } from "@noble/curves/ed25519";
import { numberToBytesLE } from "@noble/curves/abstract/utils";
import { TwistedEd25519PrivateKey, H_RISTRETTO } from ".";
import { ed25519GenRandom, ed25519modN, ed25519InvertN } from "../utils";
import { fiatShamirChallenge } from "./fiatShamir";
import { PROTOCOL_ID_REGISTRATION } from "../consts";

export type RegistrationProof = {
  /** Commitment point R = k * H_RISTRETTO (compressed, 32 bytes) */
  commitment: Uint8Array;
  /** Response scalar s = k - e * dk_inv (32-byte LE) */
  response: Uint8Array;
};

/**
 * Generate a registration proof (ZKPoK of decryption key).
 *
 * Proves knowledge of dk such that ek = dk^{-1} * H.
 *
 * Protocol:
 * 1. Prover picks random k
 * 2. Computes R = k * H
 * 3. Computes e = fiatShamirChallenge("Registration", chainId, sender, token, ek, R)
 * 4. Computes s = k - e * dk^{-1}  (mod l)
 *
 * Verifier checks: s * H + e * ek == R
 *
 * @param dk - The decryption key (private key)
 * @param chainId - Chain ID for domain separation
 * @param senderAddress - 32-byte sender address
 * @param tokenAddress - 32-byte token address
 * @returns RegistrationProof with commitment and response
 */
export function genRegistrationProof(
  dk: TwistedEd25519PrivateKey,
  chainId: number,
  senderAddress: Uint8Array,
  tokenAddress: Uint8Array,
): RegistrationProof {
  const ek = dk.publicKey().toUint8Array();

  // Step 1: Pick random nonce k
  const k = ed25519GenRandom();

  // Step 2: Compute commitment R = k * H
  const R = H_RISTRETTO.multiply(k);
  const RBytes = R.toRawBytes();

  // Step 3: Fiat-Shamir challenge
  const e = fiatShamirChallenge(PROTOCOL_ID_REGISTRATION, chainId, senderAddress, tokenAddress, ek, RBytes);

  // Step 4: Response s = k - e * dk_inv (mod l)
  // Since ek = dk_inv * H, the secret being proved is dk_inv
  const dkBytes = dk.toUint8Array();
  const dkScalar = BigInt(`0x${Buffer.from(dkBytes).reverse().toString("hex")}`);
  const dkInv = ed25519InvertN(dkScalar);
  const s = ed25519modN(k - e * dkInv);

  return {
    commitment: RBytes,
    response: numberToBytesLE(s, 32),
  };
}

/**
 * Verify a registration proof locally.
 *
 * Checks: s * H + e * ek == R
 *
 * @param ek - The encryption key being registered
 * @param proof - The registration proof to verify
 * @param chainId - Chain ID used during proof generation
 * @param senderAddress - 32-byte sender address
 * @param tokenAddress - 32-byte token address
 * @returns true if the proof is valid
 */
export function verifyRegistrationProof(
  ek: Uint8Array,
  proof: RegistrationProof,
  chainId: number,
  senderAddress: Uint8Array,
  tokenAddress: Uint8Array,
): boolean {
  const ekPoint = RistrettoPoint.fromHex(ek);
  const R = RistrettoPoint.fromHex(proof.commitment);

  // Recompute challenge
  const e = fiatShamirChallenge(PROTOCOL_ID_REGISTRATION, chainId, senderAddress, tokenAddress, ek, proof.commitment);

  // Parse response scalar
  const s = BigInt(`0x${Buffer.from(proof.response).reverse().toString("hex")}`);

  // Verify: s * H + e * ek == R
  const lhs = H_RISTRETTO.multiply(s).add(ekPoint.multiply(e));

  return lhs.equals(R);
}
