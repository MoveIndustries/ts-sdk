export const PROOF_CHUNK_SIZE = 32; // bytes

export const SIGMA_PROOF_WITHDRAW_SIZE = PROOF_CHUNK_SIZE * 21; // bytes

export const SIGMA_PROOF_TRANSFER_SIZE = PROOF_CHUNK_SIZE * 33; // bytes

export const SIGMA_PROOF_KEY_ROTATION_SIZE = PROOF_CHUNK_SIZE * 23; // bytes

export const SIGMA_PROOF_NORMALIZATION_SIZE = PROOF_CHUNK_SIZE * 21; // bytes

export const SIGMA_PROOF_REGISTRATION_SIZE = PROOF_CHUNK_SIZE * 2; // 1 point + 1 scalar = 64 bytes

/** Confidential asset module deployed at the framework address. */
export const DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS = "0x1";
export const MODULE_NAME = "confidential_asset";

/** Fiat-Shamir protocol identifiers for tagged hashing. */
export const PROTOCOL_ID_WITHDRAWAL = "Withdrawal";
export const PROTOCOL_ID_TRANSFER = "Transfer";
export const PROTOCOL_ID_ROTATION = "Rotation";
export const PROTOCOL_ID_NORMALIZATION = "Normalization";
export const PROTOCOL_ID_REGISTRATION = "Registration";
