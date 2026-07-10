// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import {
  Account,
  AccountAddress,
  AccountAddressInput,
  AnyNumber,
  MovementConfig,
  CommittedTransactionResponse,
  InputGenerateTransactionOptions,
  LedgerVersionArg,
  Serializer,
  SimpleTransaction,
  TransactionPayloadEntryFunction,
} from "@moveindustries/ts-sdk";
import { TwistedEd25519PublicKey, TwistedEd25519PrivateKey, ConfidentialNormalization } from "../crypto";
import {
  clearBalanceCache,
  clearEncryptionKeyCache,
  getEncryptionKeyCacheKey,
  getAvailableBalanceCacheKey,
  getPendingBalanceCacheKey,
  setCache,
} from "../utils/memoize";
import {
  ConfidentialAssetTransactionBuilder,
  ConfidentialBalance,
  getBalance,
  getChainIdByteForProofs,
  getEncryptionKey,
  getAssetAuditorEncryptionKey,
  getChainAuditorEncryptionKey,
  isBalanceNormalized,
  isPendingBalanceFrozen,
} from "../internal";

// Constants
import { DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS, MODULE_NAME } from "../consts";

// Base param types
type ConfidentialAssetSubmissionParams = {
  signer: Account;
  tokenAddress: AccountAddressInput;
  withFeePayer?: boolean;
  options?: InputGenerateTransactionOptions;
};

type RegisterBalanceParams = ConfidentialAssetSubmissionParams & {
  decryptionKey: TwistedEd25519PrivateKey;
};

type DepositParams = ConfidentialAssetSubmissionParams & {
  amount: AnyNumber;
  recipient?: AccountAddressInput;
};

type RegisterAndDepositParams = ConfidentialAssetSubmissionParams & {
  amount: AnyNumber;
  decryptionKey: TwistedEd25519PrivateKey;
};

type WithdrawParams = ConfidentialAssetSubmissionParams & {
  senderDecryptionKey: TwistedEd25519PrivateKey;
  amount: AnyNumber;
  recipient?: AccountAddressInput;
};

type TransferParams = WithdrawParams & {
  additionalAuditorEncryptionKeys?: TwistedEd25519PublicKey[];
  /** Opaque hint bound into the transfer proof and emitted on `Transferred` (max 256 bytes). */
  senderAuditorHint?: Uint8Array;
};

type RolloverParams = ConfidentialAssetSubmissionParams & {
  senderDecryptionKey?: TwistedEd25519PrivateKey;
  withFreezeBalance?: boolean;
};

type RotateKeyParams = ConfidentialAssetSubmissionParams & {
  senderDecryptionKey: TwistedEd25519PrivateKey;
  newSenderDecryptionKey: TwistedEd25519PrivateKey;
};

type NormalizeBalanceParams = ConfidentialAssetSubmissionParams & {
  senderDecryptionKey: TwistedEd25519PrivateKey;
};

/**
 * Extracts the BCS-encoded `EntryFunction` bytes from a `SimpleTransaction`
 * built by {@link ConfidentialAssetTransactionBuilder}. Used by the
 * `build*` methods on {@link ConfidentialAsset} to return raw entry-function
 * bytes that callers can wrap in `MultiSigTransactionPayload` for the
 * multisig proposal flow.
 */
function extractEntryFunctionBcs(tx: SimpleTransaction): Uint8Array {
  const payload = tx.rawTransaction.payload;
  if (!(payload instanceof TransactionPayloadEntryFunction)) {
    throw new Error("Expected an entry-function transaction payload; got a different payload variant.");
  }
  const serializer = new Serializer();
  payload.entryFunction.serialize(serializer);
  return serializer.toUint8Array();
}

/**
 * A class to handle confidential balance operations
 *
 * TODO: Add key caching to avoid fetching the same key multiple times
 */
export class ConfidentialAsset {
  transaction: ConfidentialAssetTransactionBuilder;
  withFeePayer: boolean;
  constructor(args: { config: MovementConfig; confidentialAssetModuleAddress?: string; withFeePayer?: boolean }) {
    const { confidentialAssetModuleAddress = DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS } = args;
    let config = args.config;
    this.transaction = new ConfidentialAssetTransactionBuilder(config, confidentialAssetModuleAddress);
    this.withFeePayer = args.withFeePayer ?? false;
  }

  private client() {
    return this.transaction.client;
  }

  private moduleAddress() {
    return this.transaction.confidentialAssetModuleAddress;
  }

  async getBalance(args: {
    accountAddress: AccountAddressInput;
    tokenAddress: AccountAddressInput;
    decryptionKey: TwistedEd25519PrivateKey;
    useCachedValue?: boolean;
    options?: LedgerVersionArg;
  }): Promise<ConfidentialBalance> {
    return getBalance({
      client: this.client(),
      moduleAddress: this.moduleAddress(),
      ...args,
    });
  }

  /**
   * Register a confidential balance for an account
   *
   * @param args.signer - The address of the sender of the transaction
   * @param args.tokenAddress - The token address of the asset to register the balance for
   * @param args.decryptionKey - The decryption key for which the corresponding encryption key will be used registered for the balance
   * @param args.withFeePayer - Whether to use the fee payer for the transaction
   * @param args.options - Optional transaction options
   * @returns A SimpleTransaction to register the balance
   */
  async registerBalance(args: RegisterBalanceParams): Promise<CommittedTransactionResponse> {
    const { signer, withFeePayer = this.withFeePayer, ...rest } = args;
    const tx = await this.transaction.registerBalance({ ...rest, sender: signer.accountAddress, withFeePayer });
    return this.submitTxn({ signer, transaction: tx });
  }

  /**
   * Deposit an amount from a non-confidential asset balance into a confidential asset balance.
   *
   * This can be used by an account to convert their own non-confidential asset balance into a confidential asset balance if they have
   * already registered a balance for the token.
   *
   * @param args.signer - The account that will sign the transaction
   * @param args.tokenAddress - The token address of the asset to deposit to
   * @param args.amount - The amount to deposit
   * @param args.recipient - The account address to deposit to. This is the senders address if not set.
   * @param args.withFeePayer - Whether to use the fee payer for the transaction
   * @param args.options - Optional transaction options
   * @returns A SimpleTransaction to deposit the amount
   */
  async deposit(args: DepositParams): Promise<CommittedTransactionResponse> {
    const { signer, withFeePayer = this.withFeePayer, ...rest } = args;
    const tx = await this.transaction.deposit({ ...rest, sender: signer.accountAddress, withFeePayer });
    const result = await this.submitTxn({ signer, transaction: tx });
    clearBalanceCache(signer.accountAddress, args.tokenAddress, this.client().config.network);
    return result;
  }

  /**
   * First-time atomic register + deposit + rollover. Maps to the on-chain
   * `register_and_deposit_and_rollover_pending_balance` entrypoint. Use this for the first-time
   * "Make private" path: one wallet approval, one on-chain entry function call, funds land in
   * `actual_balance` (spendable), not pending.
   *
   * After this call the store's `normalized` flag is `false`. Subsequent deposit-then-rollover
   * flows must therefore route through {@link depositNormalizeAndRollover} until something
   * re-normalizes (`confidential_transfer`, `withdraw`, or a standalone `normalize`).
   *
   * See {@link ConfidentialAssetTransactionBuilder.registerAndDepositAndRollover} for why no
   * recipient ≠ sender variant exists, and why no normalize is required on this path.
   */
  async registerAndDepositAndRollover(args: RegisterAndDepositParams): Promise<CommittedTransactionResponse> {
    const { signer, withFeePayer = this.withFeePayer, ...rest } = args;
    const tx = await this.transaction.registerAndDepositAndRollover({
      ...rest,
      sender: signer.accountAddress,
      withFeePayer,
    });
    const result = await this.submitTxn({ signer, transaction: tx });
    clearBalanceCache(signer.accountAddress, args.tokenAddress, this.client().config.network);
    return result;
  }

  /**
   * Subsequent atomic deposit + rollover on a *currently-normalized* store. Maps to
   * `deposit_and_rollover_pending_balance`. Funds land spendable.
   *
   * Aborts with `ENORMALIZATION_REQUIRED` (3 << 16 | 10 = 196618) if the store is not normalized.
   * Callers that want a one-method "always lands spendable" entry should branch on the
   * `is_normalized` view and route to {@link depositNormalizeAndRollover} when needed.
   */
  async depositAndRollover(args: DepositParams): Promise<CommittedTransactionResponse> {
    const { signer, withFeePayer = this.withFeePayer, ...rest } = args;
    const tx = await this.transaction.depositAndRollover({
      ...rest,
      sender: signer.accountAddress,
      withFeePayer,
    });
    const result = await this.submitTxn({ signer, transaction: tx });
    clearBalanceCache(signer.accountAddress, args.tokenAddress, this.client().config.network);
    return result;
  }

  /**
   * Subsequent atomic deposit + normalize + rollover on a *not-currently-normalized* store. Maps
   * to `deposit_and_normalize_and_rollover_pending_balance`. Funds land spendable.
   *
   * The signer's `senderDecryptionKey` is required to construct the normalize proof off-chain.
   * Aborts with `EALREADY_NORMALIZED` (3 << 16 | 11 = 196619) if the store is already
   * normalized — callers should route to {@link depositAndRollover} for that case.
   */
  async depositNormalizeAndRollover(
    args: ConfidentialAssetSubmissionParams & {
      amount: AnyNumber;
      senderDecryptionKey: TwistedEd25519PrivateKey;
    },
  ): Promise<CommittedTransactionResponse> {
    const { signer, withFeePayer = this.withFeePayer, ...rest } = args;
    const tx = await this.transaction.depositNormalizeAndRollover({
      ...rest,
      sender: signer.accountAddress,
      withFeePayer,
    });
    const result = await this.submitTxn({ signer, transaction: tx });
    clearBalanceCache(signer.accountAddress, args.tokenAddress, this.client().config.network);
    return result;
  }

  /**
   * Withdraw an amount from a confidential asset balance.
   *
   * This can be used by an account to convert their own confidential asset balance into a non-confidential asset balance.
   *
   * @param args.signer - The account that will sign the transaction
   * @param args.senderDecryptionKey - The decryption key of the sender
   * @param args.tokenAddress - The token address of the asset to withdraw from
   * @param args.amount - The amount to withdraw
   * @param args.recipient - The account address to withdraw to. This is the signer's address if not set
   * @param args.withFeePayer - Whether to use the fee payer for the transaction
   * @param args.options - Optional transaction options
   * @returns A single transaction response, or array of responses if using pending balance
   * @throws {Error} If the amount to withdraw is greater than the available balance
   */
  async withdraw(
    args: ConfidentialAssetSubmissionParams & {
      senderDecryptionKey: TwistedEd25519PrivateKey;
      amount: AnyNumber;
      recipient?: AccountAddressInput;
    },
  ): Promise<CommittedTransactionResponse> {
    const { signer, withFeePayer = this.withFeePayer, ...rest } = args;

    const transaction = await this.transaction.withdraw({ ...rest, sender: signer.accountAddress, withFeePayer });
    const result = await this.submitTxn({
      signer,
      transaction,
    });
    clearBalanceCache(signer.accountAddress, args.tokenAddress, this.client().config.network);
    return result;
  }

  /**
   * Rollover an account's pending balance for an asset into the available balance.
   *
   * @param args.signer - The address of the sender of the transaction
   * @param args.tokenAddress - The token address of the asset to roll over
   * @param args.withFreezeBalance - Whether to freeze the balance after rolling over. Default is false.
   * @param args.checkNormalized - Whether to check if the balance is normalized before rolling over. Default is true.
   * @param args.withFeePayer - Whether to use the fee payer for the transaction
   * @returns A SimpleTransaction to roll over the balance
   * @throws {Error} If the balance is not normalized before rolling over, unless checkNormalized is false.
   */
  async rolloverPendingBalance(args: RolloverParams): Promise<CommittedTransactionResponse[]> {
    const { signer, withFeePayer = this.withFeePayer, ...rest } = args;
    const isNormalized = await this.isBalanceNormalized({
      accountAddress: signer.accountAddress,
      tokenAddress: args.tokenAddress,
    });

    let transaction;
    if (isNormalized) {
      transaction = await this.transaction.rolloverPendingBalance({
        ...rest,
        sender: signer.accountAddress,
        withFeePayer,
      });
    } else {
      if (!args.senderDecryptionKey) {
        throw new Error(
          "Rollover failed. Available balance is not normalized and no sender decryption key was provided.",
        );
      }
      // Single-tx path: on-chain `normalize_and_rollover_pending_balance` does both steps,
      // so the user only sees one wallet approval.
      transaction = await this.transaction.normalizeAndRolloverPendingBalance({
        sender: signer.accountAddress,
        senderDecryptionKey: args.senderDecryptionKey,
        tokenAddress: args.tokenAddress,
        withFeePayer,
        options: args.options,
      });
    }

    const committed = await this.submitTxn({ signer, transaction });
    clearBalanceCache(signer.accountAddress, args.tokenAddress, this.client().config.network);
    return [committed];
  }

  /**
   * Get the per-asset auditor encryption key for a given token address (slot [1] of `auditor_eks`).
   * Inclusion in transfers is handled automatically by the transaction builder; this method exists
   * for callers that want to display the configured auditor independently of any pending transfer.
   *
   * @param args.tokenAddress - The token address of the asset to get the auditor for
   * @param args.options.ledgerVersion - The ledger version to use for the view call
   * @returns The encryption key for the per-asset auditor, or `undefined` if no auditor is set
   */
  async getAssetAuditorEncryptionKey(args: {
    tokenAddress: AccountAddressInput;
    options?: LedgerVersionArg;
  }): Promise<TwistedEd25519PublicKey | undefined> {
    return getAssetAuditorEncryptionKey({
      client: this.client(),
      moduleAddress: this.moduleAddress(),
      tokenAddress: args.tokenAddress,
      options: args.options,
    });
  }

  /**
   * Get the chain-level auditor encryption key (slot [0] of every transfer's `auditor_eks`).
   * Inclusion in transfers is handled automatically by the transaction builder; this method exists
   * so callers can display the active chain auditor independently of any pending transfer.
   *
   * @param args.options.ledgerVersion - The ledger version to use for the view call
   * @returns The chain auditor's encryption key, or `undefined` when no chain auditor is configured
   */
  async getChainAuditorEncryptionKey(args?: {
    options?: LedgerVersionArg;
  }): Promise<TwistedEd25519PublicKey | undefined> {
    return getChainAuditorEncryptionKey({
      client: this.client(),
      moduleAddress: this.moduleAddress(),
      options: args?.options,
    });
  }

  /**
   * Transfer an amount from a confidential asset balance to a recipient.
   *
   * This can be used by an account to transfer their own confidential asset balance to a recipient.
   *
   * @param args.signer - The account that will sign the transaction
   * @param args.recipient - The address of the recipient
   * @param args.tokenAddress - The token address of the asset to transfer
   * @param args.amount - The amount to transfer
   * @param args.senderDecryptionKey - The decryption key of the sender
   * @param args.additionalAuditorEncryptionKeys - Optional additional auditor encryption keys
   * @param args.senderAuditorHint - Optional opaque bytes for the on-chain `sender_auditor_hint` argument
   * @param args.withFeePayer - Whether to use the fee payer for the transaction
   * @param args.options - Optional transaction options
   * @param args.signAndSubmitCallback - Optional callback for custom transaction submission
   * @returns A single transaction response, or array of responses if using pending balance
   * @throws {Error} If the recipient's encryption key cannot be found
   * @throws {Error} If the amount to transfer is greater than the available balance
   */
  async transfer(
    args: ConfidentialAssetSubmissionParams & {
      recipient: AccountAddressInput;
      amount: AnyNumber;
      senderDecryptionKey: TwistedEd25519PrivateKey;
      additionalAuditorEncryptionKeys?: TwistedEd25519PublicKey[];
      senderAuditorHint?: Uint8Array;
    },
  ): Promise<CommittedTransactionResponse> {
    const { signer, withFeePayer = this.withFeePayer, ...rest } = args;

    const transaction = await this.transaction.transfer({ ...rest, sender: signer.accountAddress, withFeePayer });
    const result = await this.submitTxn({
      signer,
      transaction,
    });
    clearBalanceCache(signer.accountAddress, args.tokenAddress, this.client().config.network);
    return result;
  }

  /**
   * Check if a user's balance is frozen.
   *
   * A user's balance would likely be frozen if they plan to rotate their encryption key after a rollover. Rotating the encryption key requires
   * the pending balance to be empty so a user may want to freeze their balance to prevent others from transferring into their pending balance
   * which would interfere with the rotation, as it would require a user to rollover their pending balance.
   *
   * @param args.accountAddress - The account address to check
   * @param args.tokenAddress - The token address of the asset to check
   * @param args.options.ledgerVersion - The ledger version to use for the view call
   * @returns A boolean indicating if the user's balance is frozen
   * @throws {AptosApiError} If the there is no registered confidential balance for token address on the account
   */
  async isPendingBalanceFrozen(args: {
    accountAddress: AccountAddressInput;
    tokenAddress: AccountAddressInput;
    options?: LedgerVersionArg;
  }): Promise<boolean> {
    return isPendingBalanceFrozen({
      client: this.client(),
      moduleAddress: this.moduleAddress(),
      ...args,
    });
  }

  /**
   * Rotate the encryption key for a confidential asset balance.
   *
   * This will check if the pending balance is empty and roll it over if needed. It also checks if the balance
   * is frozen and will unfreeze it if necessary.
   *
   * @param args.signer - The account that will sign the transaction
   * @param args.senderDecryptionKey - The current decryption key
   * @param args.newSenderDecryptionKey - The new decryption key to rotate to
   * @param args.tokenAddress - The token address of the asset
   * @param args.withFeePayer - Whether to use the fee payer for the transaction
   * @param args.options - Optional transaction options
   * @returns Array of transaction responses (may include rollover transactions)
   * @throws {Error} If the pending balance is not empty and cannot be rolled over
   */
  async rotateEncryptionKey(args: RotateKeyParams): Promise<CommittedTransactionResponse[]> {
    const {
      signer,
      senderDecryptionKey,
      newSenderDecryptionKey,
      tokenAddress,
      withFeePayer = this.withFeePayer,
      options,
    } = args;
    const results: CommittedTransactionResponse[] = [];

    const balance = await this.getBalance({
      accountAddress: signer.accountAddress,
      tokenAddress,
      decryptionKey: senderDecryptionKey,
    });
    if (balance.pendingBalance() > 0n) {
      const rolloverTxs = await this.rolloverPendingBalance({
        ...args,
        withFreezeBalance: true,
      });
      results.push(...rolloverTxs);
    }
    const transaction = await this.transaction.rotateEncryptionKey({
      ...args,
      withFeePayer,
      sender: signer.accountAddress,
    });
    results.push(
      await this.submitTxn({
        signer,
        transaction,
      }),
    );
    clearEncryptionKeyCache(signer.accountAddress, args.tokenAddress, this.client().config.network);
    setCache(
      getEncryptionKeyCacheKey(signer.accountAddress, args.tokenAddress, this.client().config.network),
      newSenderDecryptionKey,
    );
    return results;
  }

  /**
   * Check if a user has registered a confidential asset balance for a particular token.
   *
   * @param args.accountAddress - The account address to check
   * @param args.tokenAddress - The token address of the asset to check
   * @param args.options.ledgerVersion - The ledger version to use for the view call
   * @returns A boolean indicating if the user has registered a confidential asset balance
   */
  async hasUserRegistered(args: {
    accountAddress: AccountAddressInput;
    tokenAddress: AccountAddressInput;
    options?: LedgerVersionArg;
  }): Promise<boolean> {
    const [isRegistered] = await this.client().view<[boolean]>({
      payload: {
        function: `${this.moduleAddress()}::${MODULE_NAME}::has_confidential_asset_store`,
        typeArguments: [],
        functionArguments: [args.accountAddress, args.tokenAddress],
      },
      options: args.options,
    });

    return isRegistered;
  }

  /**
   * Check if a user's balance is normalized.
   *
   * This can be used to check if a user's balance is normalized for a given token address.
   *
   * @param args.accountAddress - The account address to check
   * @param args.tokenAddress - The token address of the asset to check
   * @param args.options.ledgerVersion - The ledger version to use for the view call
   * @returns A boolean indicating if the user's balance is normalized
   * @throws {AptosApiError} If the there is no registered confidential balance for token address on the account
   */
  async isBalanceNormalized(args: {
    accountAddress: AccountAddressInput;
    tokenAddress: AccountAddressInput;
    options?: LedgerVersionArg;
  }): Promise<boolean> {
    return isBalanceNormalized({
      client: this.client(),
      moduleAddress: this.moduleAddress(),
      ...args,
    });
  }

  /**
   * Get the encryption key for an account for a given token.
   *
   * @param args.accountAddress - The account address to get the encryption key for
   * @param args.tokenAddress - The token address of the asset
   * @param args.options - Optional ledger version for the view call
   * @returns The encryption key as a TwistedEd25519PublicKey
   * @throws {Error} If the encryption key cannot be found
   */
  async getEncryptionKey(args: {
    accountAddress: AccountAddressInput;
    tokenAddress: AccountAddressInput;
    options?: LedgerVersionArg;
  }): Promise<TwistedEd25519PublicKey> {
    return getEncryptionKey({
      client: this.client(),
      moduleAddress: this.moduleAddress(),
      ...args,
    });
  }

  /**
   * Normalize a user's balance.
   *
   * This can be used to normalize a user's balance for a given token address.
   *
   * @param args.signer - The account that will sign the transaction
   * @param args.senderDecryptionKey - The decryption key of the sender
   * @param args.tokenAddress - The token address of the asset to normalize
   * @param args.withFeePayer - Whether to use the fee payer for the transaction
   * @param args.options - Optional transaction options
   * @returns A committed transaction response
   * @throws {Error} If normalization fails
   */
  async normalizeBalance(args: NormalizeBalanceParams): Promise<CommittedTransactionResponse> {
    const { signer, senderDecryptionKey, tokenAddress, withFeePayer = this.withFeePayer, options } = args;
    const { available, pending } = await this.getBalance({
      accountAddress: signer.accountAddress,
      tokenAddress,
      decryptionKey: senderDecryptionKey,
      // Always read the latest ciphertext from chain; cached balances must not drive normalization proofs.
      useCachedValue: false,
    });

    const chainId = await getChainIdByteForProofs({ client: this.client() });
    const senderAddressBytes = AccountAddress.from(signer.accountAddress).toUint8Array();
    const contractAddressBytes = AccountAddress.from(this.transaction.confidentialAssetModuleAddress).toUint8Array();
    const tokenAddressBytes = AccountAddress.from(tokenAddress).toUint8Array();

    const confidentialNormalization = await ConfidentialNormalization.create({
      decryptionKey: senderDecryptionKey,
      unnormalizedAvailableBalance: available,
      chainId,
      senderAddress: senderAddressBytes,
      contractAddress: contractAddressBytes,
      tokenAddress: tokenAddressBytes,
    });

    const transaction = await confidentialNormalization.createTransaction({
      client: this.client(),
      sender: signer.accountAddress,
      confidentialAssetModuleAddress: this.transaction.confidentialAssetModuleAddress,
      tokenAddress,
      withFeePayer,
      options,
    });
    const committedTransaction = await this.submitTxn({
      signer,
      transaction,
    });
    const network = this.client().config.network;
    setCache(
      getAvailableBalanceCacheKey(signer.accountAddress, tokenAddress, network),
      confidentialNormalization.normalizedEncryptedAvailableBalance,
    );
    setCache(getPendingBalanceCacheKey(signer.accountAddress, tokenAddress, network), pending);
    return committedTransaction;
  }

  // ────────────────────────────────────────────────────────────────────────
  // Build-only API
  //
  // Each `build*` method below constructs the same proofs and the same
  // entry-function call that its submitting counterpart constructs, but
  // returns the BCS-encoded `EntryFunction` bytes instead of submitting a
  // transaction. The dApp / wallet wraps those bytes in a
  // `MultiSigTransactionPayload` and proposes the transaction through
  // `multisig_account::create_transaction`, so the multisig flow approves and
  // executes the same exact entry-function call the single-signer path would
  // have run.
  //
  // The `sender` is bound into every proof's Fiat–Shamir transcript and must
  // match the executor at chain-verification time. For multisig CA, callers
  // pass the multisig account's address as `sender`.
  // ────────────────────────────────────────────────────────────────────────

  /**
   * Build a `register` entry-function payload for the given `(sender, token)`
   * pair without submitting it. Returns BCS-encoded `EntryFunction` bytes.
   *
   * The `sender` must be the on-chain account whose `ek` slot is being
   * registered — typically a multisig account address.
   */
  async buildRegister(args: {
    sender: AccountAddressInput;
    tokenAddress: AccountAddressInput;
    decryptionKey: TwistedEd25519PrivateKey;
    options?: InputGenerateTransactionOptions;
  }): Promise<Uint8Array> {
    const tx = await this.transaction.registerBalance(args);
    return extractEntryFunctionBcs(tx);
  }

  /**
   * Build a `deposit_to` entry-function payload without submitting it.
   * Returns BCS-encoded `EntryFunction` bytes. Use {@link buildRegisterAndDeposit}
   * for the first-time path, or one of {@link buildDepositAndRollover} /
   * {@link buildDepositNormalizeAndRollover} when the caller wants funds to
   * land spendable.
   */
  async buildDeposit(args: {
    sender: AccountAddressInput;
    tokenAddress: AccountAddressInput;
    amount: AnyNumber;
    recipient?: AccountAddressInput;
    options?: InputGenerateTransactionOptions;
  }): Promise<Uint8Array> {
    const tx = await this.transaction.deposit(args);
    return extractEntryFunctionBcs(tx);
  }

  /**
   * Build a `register_and_deposit_and_rollover_pending_balance` entry-function
   * payload without submitting it. Returns BCS-encoded `EntryFunction` bytes.
   */
  async buildRegisterAndDeposit(args: {
    sender: AccountAddressInput;
    tokenAddress: AccountAddressInput;
    decryptionKey: TwistedEd25519PrivateKey;
    amount: AnyNumber;
    options?: InputGenerateTransactionOptions;
  }): Promise<Uint8Array> {
    const tx = await this.transaction.registerAndDepositAndRollover(args);
    return extractEntryFunctionBcs(tx);
  }

  /**
   * Build a `deposit_and_rollover_pending_balance` entry-function payload
   * (currently-normalized store) without submitting it. Returns BCS-encoded
   * `EntryFunction` bytes.
   */
  async buildDepositAndRollover(args: {
    sender: AccountAddressInput;
    tokenAddress: AccountAddressInput;
    amount: AnyNumber;
    options?: InputGenerateTransactionOptions;
  }): Promise<Uint8Array> {
    const tx = await this.transaction.depositAndRollover(args);
    return extractEntryFunctionBcs(tx);
  }

  /**
   * Build a `deposit_and_normalize_and_rollover_pending_balance` entry-function
   * payload (not-currently-normalized store) without submitting it. Returns
   * BCS-encoded `EntryFunction` bytes.
   */
  async buildDepositNormalizeAndRollover(args: {
    sender: AccountAddressInput;
    tokenAddress: AccountAddressInput;
    senderDecryptionKey: TwistedEd25519PrivateKey;
    amount: AnyNumber;
    options?: InputGenerateTransactionOptions;
  }): Promise<Uint8Array> {
    const tx = await this.transaction.depositNormalizeAndRollover(args);
    return extractEntryFunctionBcs(tx);
  }

  /**
   * Build a `withdraw_to` entry-function payload without submitting it.
   * Returns BCS-encoded `EntryFunction` bytes.
   *
   * Operates on the sender's actual (spendable) balance only. If the encrypted
   * actual balance fetched from chain decrypts to less than `amount`,
   * proof construction throws {@link InsufficientBalanceError} (code
   * `INSUFFICIENT_BALANCE`); the caller must accept incoming pending funds via a
   * separate `rolloverPendingBalance` proposal first.
   */
  async buildWithdraw(args: {
    sender: AccountAddressInput;
    senderDecryptionKey: TwistedEd25519PrivateKey;
    tokenAddress: AccountAddressInput;
    amount: AnyNumber;
    recipient?: AccountAddressInput;
    options?: InputGenerateTransactionOptions;
  }): Promise<Uint8Array> {
    const tx = await this.transaction.withdraw(args);
    return extractEntryFunctionBcs(tx);
  }

  /**
   * Build a `confidential_transfer` entry-function payload without submitting
   * it. Returns BCS-encoded `EntryFunction` bytes.
   *
   * Operates on the sender's actual (spendable) balance only, on the same
   * principle as {@link buildWithdraw}.
   */
  async buildConfidentialTransfer(args: {
    sender: AccountAddressInput;
    recipient: AccountAddressInput;
    tokenAddress: AccountAddressInput;
    amount: AnyNumber;
    senderDecryptionKey: TwistedEd25519PrivateKey;
    additionalAuditorEncryptionKeys?: TwistedEd25519PublicKey[];
    senderAuditorHint?: Uint8Array;
    options?: InputGenerateTransactionOptions;
  }): Promise<Uint8Array> {
    const tx = await this.transaction.transfer(args);
    return extractEntryFunctionBcs(tx);
  }

  /**
   * Build a `rollover_pending_balance` (or
   * `normalize_and_rollover_pending_balance` if needed) entry-function payload
   * without submitting it. Returns BCS-encoded `EntryFunction` bytes.
   *
   * Accepting incoming confidential transfers is a discrete user-authorized
   * action and must not be bundled with spends. Use this when the user has
   * explicitly chosen to accept pending funds.
   */
  async buildRolloverPending(args: {
    sender: AccountAddressInput;
    tokenAddress: AccountAddressInput;
    senderDecryptionKey?: TwistedEd25519PrivateKey;
    withFreezeBalance?: boolean;
    options?: InputGenerateTransactionOptions;
  }): Promise<Uint8Array> {
    const isNormalized = await this.isBalanceNormalized({
      accountAddress: args.sender,
      tokenAddress: args.tokenAddress,
    });
    let tx: SimpleTransaction;
    if (isNormalized) {
      tx = await this.transaction.rolloverPendingBalance(args);
    } else {
      if (!args.senderDecryptionKey) {
        throw new Error(
          "buildRolloverPending: actual balance is not normalized and no senderDecryptionKey was provided to construct the normalize proof.",
        );
      }
      tx = await this.transaction.normalizeAndRolloverPendingBalance({
        sender: args.sender,
        senderDecryptionKey: args.senderDecryptionKey,
        tokenAddress: args.tokenAddress,
        options: args.options,
      });
    }
    return extractEntryFunctionBcs(tx);
  }

  /**
   * Build a `normalize` entry-function payload without submitting it. Returns
   * BCS-encoded `EntryFunction` bytes.
   *
   * Normalization is a protocol implementation detail of "accept incoming
   * funds." Most callers should prefer {@link buildRolloverPending}, which
   * chains normalize automatically when required.
   */
  async buildNormalize(args: {
    sender: AccountAddressInput;
    senderDecryptionKey: TwistedEd25519PrivateKey;
    tokenAddress: AccountAddressInput;
    options?: InputGenerateTransactionOptions;
  }): Promise<Uint8Array> {
    const tx = await this.transaction.normalizeBalance(args);
    return extractEntryFunctionBcs(tx);
  }

  /**
   * Build a `rotate_encryption_key` entry-function payload without submitting
   * it. Returns BCS-encoded `EntryFunction` bytes.
   *
   * Preconditions are sender-address-driven (not signer-driven): the caller
   * supplies the multisig account address as `sender`, the current
   * `dk[multisig, token]` as `senderDecryptionKey`, and the freshly generated
   * `dk'` as `newSenderDecryptionKey`. The builder reads the multisig's
   * current encrypted balance with `senderDecryptionKey` and emits the sigma
   * + range proofs that re-encrypt it under `ek' = newSenderDecryptionKey.publicKey()`.
   *
   * Refuses if the multisig's pending balance is non-empty; the caller must
   * propose `rolloverPendingBalance` first via {@link buildRolloverPending}
   * and wait for it to be approved and executed before constructing the
   * rotation proposal. (`rotate_encryption_key` aborts on chain when pending
   * is non-empty, but failing fast off-chain avoids burning a multisig
   * proposal slot.)
   */
  async buildRotateEncryptionKey(args: {
    sender: AccountAddressInput;
    senderDecryptionKey: TwistedEd25519PrivateKey;
    newSenderDecryptionKey: TwistedEd25519PrivateKey;
    tokenAddress: AccountAddressInput;
    options?: InputGenerateTransactionOptions;
  }): Promise<Uint8Array> {
    const balance = await this.getBalance({
      accountAddress: args.sender,
      tokenAddress: args.tokenAddress,
      decryptionKey: args.senderDecryptionKey,
      useCachedValue: false,
    });
    if (balance.pendingBalance() > 0n) {
      throw new Error(
        "buildRotateEncryptionKey: sender's pending balance is non-empty. Propose rolloverPendingBalance " +
          "via buildRolloverPending and wait for it to execute before proposing rotation.",
      );
    }
    const tx = await this.transaction.rotateEncryptionKey(args);
    return extractEntryFunctionBcs(tx);
  }

  private async submitTxn(args: { signer: Account; transaction: SimpleTransaction }) {
    const { signer, transaction } = args;
    if (this.withFeePayer && !transaction.feePayerAddress) {
      throw new Error(
        "Fee payer is enabled but transaction has no fee payer address. Please set the fee payer address.",
      );
    }
    const senderAuthenticator = signer.signTransactionWithAuthenticator(transaction);

    const pendingTxResponse = await this.client().transaction.submit.simple({
      transaction,
      senderAuthenticator,
    });
    const transactionHash = pendingTxResponse.hash;
    const committedTx = await this.client().waitForTransaction({
      transactionHash,
      options: {
        checkSuccess: true,
      },
    });
    return committedTx;
  }
}
