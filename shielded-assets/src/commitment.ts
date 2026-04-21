import { keccak_256 } from "@noble/hashes/sha3";
import { concatBytes } from "@noble/hashes/utils";

const NOTE_LABEL = new TextEncoder().encode("SA_NOTE_v1");
const NULL_LABEL = new TextEncoder().encode("SA_NULL_v1");

/** BCS u64 little-endian — matches Move `bcs::to_bytes(&amount)` for `u64`. */
export function bcsU64(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  let v = value;
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Note commitment — matches Move `note_commitment`. */
export function noteCommitment(amount: bigint, blinding32: Uint8Array): Uint8Array {
  if (blinding32.length !== 32) {
    throw new Error("blinding must be 32 bytes");
  }
  return keccak_256(concatBytes(NOTE_LABEL, bcsU64(amount), blinding32));
}

/** Nullifier — matches Move `derive_nullifier`. */
export function deriveNullifier(blinding32: Uint8Array): Uint8Array {
  if (blinding32.length !== 32) {
    throw new Error("blinding must be 32 bytes");
  }
  return keccak_256(concatBytes(NULL_LABEL, blinding32));
}
