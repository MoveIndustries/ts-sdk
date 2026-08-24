export const PROOF_CHUNK_SIZE = 32; // bytes

/** Maximum `sender_auditor_hint` length (bytes) accepted by `confidential_transfer` on-chain. */
export const MAX_SENDER_AUDITOR_HINT_BYTES = 256;

export const SIGMA_PROOF_WITHDRAW_SIZE = PROOF_CHUNK_SIZE * 21; // bytes

/** 26 alpha scalars + 30 base X commitments (no auditor rows); matches Move `deserialize_transfer_sigma_proof` base layout. */
export const SIGMA_PROOF_TRANSFER_SIZE = PROOF_CHUNK_SIZE * 56; // bytes

export const SIGMA_PROOF_KEY_ROTATION_SIZE = PROOF_CHUNK_SIZE * 23; // bytes

export const SIGMA_PROOF_NORMALIZATION_SIZE = PROOF_CHUNK_SIZE * 21; // bytes

export const SIGMA_PROOF_REGISTRATION_SIZE = PROOF_CHUNK_SIZE * 2; // 1 point + 1 scalar = 64 bytes

/**
 * `confidential_asset` ships in the Aptos framework, so it is always at `0x1`. The on-chain
 * Fiat-Shamir transcript binds `@aptos_framework` as `contract_address`, so proofs generated
 * against any other address cannot verify.
 */
export const CONFIDENTIAL_ASSET_MODULE_ADDRESS = "0x1";
export const MODULE_NAME = "confidential_asset";

/** Fiat-Shamir protocol identifiers (used as DST suffix: "MovementConfidentialAsset/" + id). */
export const PROTOCOL_ID_WITHDRAWAL = "Withdrawal";
export const PROTOCOL_ID_TRANSFER = "Transfer";
export const PROTOCOL_ID_ROTATION = "Rotation";
export const PROTOCOL_ID_NORMALIZATION = "Normalization";
export const PROTOCOL_ID_REGISTRATION = "Registration";
