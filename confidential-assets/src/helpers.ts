// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import { sha512 } from "@noble/hashes/sha512";
import { bytesToNumberLE, concatBytes } from "@noble/curves/abstract/utils";
import { ed25519modN } from "./utils";

/**
 * Generate Fiat-Shamir challenge using SHA2-512 with raw concatenation.
 * @deprecated Use {@link fiatShamirChallenge} from `./crypto/fiatShamir` instead,
 * which uses SHA2-512 with DST prefix, domain separation, and chain ID.
 */
export function genFiatShamirChallenge(...arrays: Uint8Array[]): bigint {
  const hash = sha512(concatBytes(...arrays));
  return ed25519modN(bytesToNumberLE(hash));
}
