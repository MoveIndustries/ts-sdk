// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import { AccountAddressInput, Hex, Movement, LedgerVersionArg } from "@moveindustries/ts-sdk";
import {
  TwistedEd25519PrivateKey,
  TwistedEd25519PublicKey,
  EncryptedAmount,
  TwistedElGamalCiphertext,
} from "../crypto";
import {
  getAvailableBalanceCacheKey,
  getCache,
  getPendingBalanceCacheKey,
  memoizeAsync,
  setCache,
} from "../utils/memoize";
import { DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS, MODULE_NAME } from "../consts";

type ViewFunctionParams = {
  client: Movement;
  accountAddress: AccountAddressInput;
  tokenAddress: AccountAddressInput;
  options?: LedgerVersionArg;
  moduleAddress?: string;
};

/** Normalize view hex (with or without `0x`) to bytes for Ristretto encodings. */
function ristrettoHexToBytes(data: string): Uint8Array {
  const normalized = data.startsWith("0x") || data.startsWith("0X") ? data : `0x${data}`;
  return Hex.fromHexInput(normalized).toUint8Array();
}

function viewRistrettoBytes(data: string | Uint8Array): Uint8Array {
  if (data instanceof Uint8Array) {
    return data;
  }
  return ristrettoHexToBytes(data);
}

/** BCS-decoded `CompressedConfidentialBalance` (single return value; the client wraps it in a one-element array). */
export type ConfidentialBalanceResponse = {
  chunks: {
    left: { data: string };
    right: { data: string };
  }[];
};

/**
 * Represents a confidential balance containing both available and pending amounts
 */
export class ConfidentialBalance {
  /**
   * Creates a new ConfidentialBalance instance
   * @param available - The available encrypted amount
   * @param pending - The pending encrypted amount
   */
  available: EncryptedAmount;
  pending: EncryptedAmount;

  constructor(available: EncryptedAmount, pending: EncryptedAmount) {
    this.available = available;
    this.pending = pending;
  }

  /**
   * Get the decrypted available balance amount
   * @returns The available balance as a bigint
   */
  availableBalance(): bigint {
    return this.available.getAmount();
  }

  /**
   * Get the decrypted pending balance amount
   * @returns The pending balance as a bigint
   */
  pendingBalance(): bigint {
    return this.pending.getAmount();
  }

  /**
   * Get the encrypted available balance ciphertext
   * @returns Array of TwistedElGamal ciphertexts representing the available balance
   */
  availableBalanceCipherText(): TwistedElGamalCiphertext[] {
    return this.available.getCipherText();
  }

  /**
   * Get the encrypted pending balance ciphertext
   * @returns Array of TwistedElGamal ciphertexts representing the pending balance
   */
  pendingBalanceCipherText(): TwistedElGamalCiphertext[] {
    return this.pending.getCipherText();
  }
}

/**
 * Get the balance for an account with optional caching
 *
 * @param args.client - The Movement client instance
 * @param args.accountAddress - The account address to get the balance for
 * @param args.tokenAddress - The token address of the asset
 * @param args.decryptionKey - The decryption key to decrypt the balance
 * @param args.useCachedValue - Whether to use cached balance values (defaults to false)
 * @param args.options - Optional ledger version for the view call
 * @param args.moduleAddress - Optional module address (defaults to DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS)
 * @returns The confidential balance containing available and pending amounts
 * @throws {Error} If the balance cannot be retrieved or decrypted
 */
export async function getBalance(
  args: ViewFunctionParams & {
    decryptionKey: TwistedEd25519PrivateKey;
    useCachedValue?: boolean;
  },
): Promise<ConfidentialBalance> {
  const { accountAddress, tokenAddress, useCachedValue = false } = args;
  try {
    if (useCachedValue) {
      const cachedAvailableBalance = getCache<EncryptedAmount>(
        getAvailableBalanceCacheKey(accountAddress, tokenAddress, args.client.config.network),
        1000 * 30, // 30 seconds
      );
      const cachedPendingBalance = getCache<EncryptedAmount>(
        getPendingBalanceCacheKey(accountAddress, tokenAddress, args.client.config.network),
        1000 * 30, // 30 seconds
      );
      if (cachedAvailableBalance !== undefined && cachedPendingBalance !== undefined) {
        return new ConfidentialBalance(cachedAvailableBalance, cachedPendingBalance);
      }
    }

    const balance = await getBalanceInternal(args);

    setCache(getAvailableBalanceCacheKey(accountAddress, tokenAddress, args.client.config.network), balance.available);
    setCache(getPendingBalanceCacheKey(accountAddress, tokenAddress, args.client.config.network), balance.pending);
    return balance;
  } catch (error) {
    throw error;
  }
}

/**
 * Internal helper function to get and decrypt balance
 *
 * @param args.client - The Movement client instance
 * @param args.accountAddress - The account address to get the balance for
 * @param args.tokenAddress - The token address of the asset
 * @param args.decryptionKey - The decryption key to decrypt the balance
 * @param args.options - Optional ledger version for the view call
 * @param args.moduleAddress - Optional module address
 * @returns The decrypted confidential balance
 */
async function getBalanceInternal(
  args: ViewFunctionParams & {
    decryptionKey: TwistedEd25519PrivateKey;
  },
): Promise<ConfidentialBalance> {
  const { decryptionKey } = args;
  const { available, pending } = await getBalanceCipherText(args);

  const decryptedActualBalance = await EncryptedAmount.fromCipherTextAndPrivateKey(available, decryptionKey);
  const decryptedPendingBalance = await EncryptedAmount.fromCipherTextAndPrivateKey(pending, decryptionKey);
  return new ConfidentialBalance(decryptedActualBalance, decryptedPendingBalance);
}

/**
 * Get the encrypted balance for an account
 * @param args.accountAddress - The account address to get the balance for
 * @param args.tokenAddress - The token address of the asset to get the balance for
 * @param args.options.ledgerVersion - The ledger version to use for the lookup
 * @returns The encrypted balance as an object with pending and available balances
 */
async function getBalanceCipherText(args: ViewFunctionParams): Promise<{
  pending: TwistedElGamalCiphertext[];
  available: TwistedElGamalCiphertext[];
}> {
  const {
    client,
    accountAddress,
    tokenAddress,
    options,
    moduleAddress = DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS,
  } = args;
  const [[chunkedPendingBalance], [chunkedActualBalances]] = await Promise.all([
    client.view<[ConfidentialBalanceResponse]>({
      payload: {
        function: `${moduleAddress}::${MODULE_NAME}::pending_balance`,
        typeArguments: [],
        functionArguments: [accountAddress, tokenAddress],
      },
      options,
    }),
    client.view<[ConfidentialBalanceResponse]>({
      payload: {
        function: `${moduleAddress}::${MODULE_NAME}::actual_balance`,
        typeArguments: [],
        functionArguments: [accountAddress, tokenAddress],
      },
      options,
    }),
  ]);

  return {
    pending: chunkedPendingBalance.chunks.map(
      (el) => new TwistedElGamalCiphertext(viewRistrettoBytes(el.left.data), viewRistrettoBytes(el.right.data)),
    ),
    available: chunkedActualBalances.chunks.map(
      (el) => new TwistedElGamalCiphertext(viewRistrettoBytes(el.left.data), viewRistrettoBytes(el.right.data)),
    ),
  };
}

export async function isBalanceNormalized(args: ViewFunctionParams): Promise<boolean> {
  const [isNormalized] = await args.client.view<[boolean]>({
    payload: {
      function: `${args.moduleAddress}::${MODULE_NAME}::is_normalized`,
      typeArguments: [],
      functionArguments: [args.accountAddress, args.tokenAddress],
    },
    options: args.options,
  });

  return isNormalized;
}

export async function isPendingBalanceFrozen(args: ViewFunctionParams): Promise<boolean> {
  const [isFrozen] = await args.client.view<[boolean]>({
    options: args.options,
    payload: {
      function: `${args.moduleAddress}::${MODULE_NAME}::is_frozen`,
      typeArguments: [],
      functionArguments: [args.accountAddress, args.tokenAddress],
    },
  });

  return isFrozen;
}

/**
 * Check if a user has registered a confidential asset balance
 *
 * @param args.client - The Movement client instance
 * @param args.accountAddress - The account address to check
 * @param args.tokenAddress - The token address of the asset
 * @param args.options - Optional ledger version for the view call
 * @param args.moduleAddress - Optional module address
 * @returns A boolean indicating if the user has registered
 */
export async function hasUserRegistered(args: ViewFunctionParams): Promise<boolean> {
  const [isRegistered] = await args.client.view<[boolean]>({
    payload: {
      function: `${args.moduleAddress}::${MODULE_NAME}::has_confidential_asset_store`,
      typeArguments: [],
      functionArguments: [args.accountAddress, args.tokenAddress],
    },
    options: args.options,
  });

  return isRegistered;
}

/**
 * Get the encryption key for an account with optional caching
 *
 * @param args.client - The Movement client instance
 * @param args.accountAddress - The account address to get the key for
 * @param args.tokenAddress - The token address of the asset
 * @param args.useCachedValue - Whether to use cached key value (defaults to false)
 * @param args.options - Optional ledger version for the view call
 * @param args.moduleAddress - Optional module address
 * @returns The encryption key as a TwistedEd25519PublicKey
 * @throws {Error} If the encryption key cannot be retrieved
 */
/**
 * `get_auditor` returns `Option<CompressedPubkey>`. The Movement client decodes Move `option::Option`
 * as `{ vec: [ inner ] }` where `inner` is `{ point: { data } }` (same shape as `encryption_key`), not raw bytes.
 */
function unwrapMoveOptionInner(wrapped: unknown): unknown {
  if (wrapped == null || wrapped === undefined) {
    return undefined;
  }
  if (typeof wrapped === "object" && wrapped !== null && "vec" in wrapped) {
    const vec = (wrapped as { vec: unknown }).vec;
    if (Array.isArray(vec)) {
      if (vec.length === 0) {
        return undefined;
      }
      return vec[0];
    }
  }
  return wrapped;
}

function compressedPubkeyToTwistedPublicKey(inner: unknown): TwistedEd25519PublicKey | undefined {
  if (inner == null || inner === undefined) {
    return undefined;
  }
  if (inner instanceof Uint8Array) {
    if (inner.length === 0) {
      return undefined;
    }
    const bytes = inner.length === 32 ? inner : inner.subarray(0, 32);
    return new TwistedEd25519PublicKey(bytes);
  }
  if (typeof inner === "object" && inner !== null && "point" in inner) {
    const pt = (inner as { point?: { data?: string | Uint8Array } }).point;
    if (!pt?.data) {
      return undefined;
    }
    return new TwistedEd25519PublicKey(viewRistrettoBytes(pt.data));
  }
  return undefined;
}

/**
 * Returns the token's configured asset auditor encryption key, if any.
 * Matches on-chain `get_auditor` / `Option<CompressedPubkey>` decoding.
 */
export async function getGlobalAuditorEncryptionKey(args: {
  client: Movement;
  tokenAddress: AccountAddressInput;
  options?: LedgerVersionArg;
  moduleAddress?: string;
}): Promise<TwistedEd25519PublicKey | undefined> {
  const moduleAddress = args.moduleAddress ?? DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS;
  const [raw] = await args.client.view<[unknown]>({
    options: args.options,
    payload: {
      function: `${moduleAddress}::${MODULE_NAME}::get_auditor`,
      functionArguments: [args.tokenAddress],
    },
  });
  const inner = unwrapMoveOptionInner(raw);
  return compressedPubkeyToTwistedPublicKey(inner);
}

export async function getEncryptionKey(
  args: ViewFunctionParams & {
    useCachedValue?: boolean;
  },
): Promise<TwistedEd25519PublicKey> {
  const { accountAddress, tokenAddress, options, useCachedValue = false } = args;
  try {
    return await memoizeAsync(
      async () => {
        const [{ point }] = await args.client.view<[{ point: { data: string } }]>({
          options,
          payload: {
            function: `${args.moduleAddress}::${MODULE_NAME}::encryption_key`,
            functionArguments: [accountAddress, tokenAddress],
          },
        });
        return new TwistedEd25519PublicKey(viewRistrettoBytes(point.data));
      },
      `${accountAddress}-encryption-key-for-${tokenAddress}-${args.client.config.network}`,
      1000 * 60 * 60, // 1 hour cache duration
      useCachedValue,
    )();
  } catch (error) {
    throw error;
  }
}

/**
 * Returns the chain ID byte used in confidential proof Fiat–Shamir transcripts.
 *
 * Move passes `(chain_id::get() as u8)` from `aptos_framework::chain_id` into verification.
 * The REST `ledger_info.chain_id` field can differ on some fullnodes; this helper prefers
 * the on-chain view. Prefer `options: undefined` when building proofs alongside balance/EK
 * views at the **latest** ledger: `chain_id` is immutable, while pinning other reads to
 * `getLedgerInfo().ledger_version` can lag execution and break transfer sigma proofs.
 */
export async function getChainIdByteForProofs(args: { client: Movement; options?: LedgerVersionArg }): Promise<number> {
  const { client, options } = args;
  try {
    const [id] = await client.view<[number | string | bigint]>({
      options,
      payload: {
        function: "0x1::chain_id::get",
        typeArguments: [],
        functionArguments: [],
      },
    });
    const n = typeof id === "bigint" ? Number(id) : Number(id);
    if (!Number.isFinite(n)) {
      throw new TypeError("chain_id view returned non-numeric value");
    }
    return n & 0xff;
  } catch {
    const ledgerInfo = await client.getLedgerInfo();
    const n = Number(ledgerInfo.chain_id);
    return (Number.isFinite(n) ? n : 0) & 0xff;
  }
}
