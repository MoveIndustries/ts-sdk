// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import {
  AccountAddress,
  AccountAddressInput,
  AnyNumber,
  Movement,
  MovementConfig,
  InputGenerateTransactionOptions,
  LedgerVersionArg,
  Network,
  SimpleTransaction,
} from "@moveindustries/ts-sdk";
import { concatBytes } from "@noble/hashes/utils";
import {
  TwistedElGamal,
  ConfidentialNormalization,
  ConfidentialKeyRotation,
  ConfidentialTransfer,
  ConfidentialWithdraw,
  TwistedEd25519PublicKey,
  TwistedEd25519PrivateKey,
} from "../crypto";
import { genRegistrationProof } from "../crypto/confidentialRegistration";
import { DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS, MAX_SENDER_AUDITOR_HINT_BYTES, MODULE_NAME } from "../consts";
import {
  getBalance,
  getChainIdByteForProofs,
  getEncryptionKey,
  getAssetAuditorEncryptionKey,
  getChainAuditorEncryptionKey,
  isBalanceNormalized,
  isPendingBalanceFrozen,
} from "./viewFunctions";

/**
 * Assemble `auditor_eks` for a `confidential_transfer` per the fixed-prefix layout in
 * movementlabsxyz/aptos-core#328:
 *   [0]   chain auditor (mandatory; protocol aborts with ECHAIN_AUDITOR_NOT_SET if missing)
 *   [1]   per-asset auditor (mandatory iff configured for the token)
 *   [2..] voluntary per-transfer auditors (sender's choice; ordered as supplied)
 *
 * Slot identity is bound into the transfer's Fiat–Shamir transcript via the order of this list,
 * so callers must not reorder. Exported separately so the slot contract can be unit-tested
 * without standing up a chain.
 */
export function assembleAuditorEks(args: {
  chain: TwistedEd25519PublicKey;
  asset?: TwistedEd25519PublicKey;
  voluntary?: TwistedEd25519PublicKey[];
}): TwistedEd25519PublicKey[] {
  return [args.chain, ...(args.asset ? [args.asset] : []), ...(args.voluntary ?? [])];
}

/**
 * A class to handle creating transactions for confidential asset operations
 */
export class ConfidentialAssetTransactionBuilder {
  readonly client: Movement;
  readonly confidentialAssetModuleAddress: string;

  constructor(config: MovementConfig, confidentialAssetModuleAddress = DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS) {
    this.client = new Movement(config);
    this.confidentialAssetModuleAddress = confidentialAssetModuleAddress;
    TwistedElGamal.initializeKangaroos();
  }

  /**
   * Register a confidential balance for an account
   *
   * @param args.sender - The address of the sender of the transaction
   * @param args.tokenAddress - The token address of the asset to register the balance for
   * @param args.decryptionKey - The decryption key for which the corresponding encryption key will be used registered for the balance
   * @param args.withFeePayer - Whether to use the fee payer for the transaction
   * @param args.options - Optional transaction options
   * @returns A SimpleTransaction to register the balance
   */
  async registerBalance(args: {
    sender: AccountAddressInput;
    tokenAddress: AccountAddressInput;
    decryptionKey: TwistedEd25519PrivateKey;
    withFeePayer?: boolean;
    options?: InputGenerateTransactionOptions;
  }): Promise<SimpleTransaction> {
    const { tokenAddress, decryptionKey } = args;
    const chainId = await getChainIdByteForProofs({ client: this.client });
    const senderAddress = AccountAddress.from(args.sender).toUint8Array();
    const contractAddressBytes = AccountAddress.from(this.confidentialAssetModuleAddress).toUint8Array();
    const tokenAddressBytes = AccountAddress.from(tokenAddress).toUint8Array();

    const proof = genRegistrationProof(decryptionKey, chainId, senderAddress, contractAddressBytes, tokenAddressBytes);

    return this.client.transaction.build.simple({
      sender: args.sender,
      ...feePayerBuildOpts(args),
      data: {
        function: `${this.confidentialAssetModuleAddress}::${MODULE_NAME}::register`,
        functionArguments: [tokenAddress, decryptionKey.publicKey().toUint8Array(), proof.commitment, proof.response],
      },
    });
  }

  /**
   * Deposit an amount from a non-confidential asset balance into a confidential asset balance.
   *
   * This can be used by an account to convert their own non-confidential asset balance into a confidential asset balance if they have
   * already registered a balance for the token.
   *
   * @param args.tokenAddress - The token address of the asset to deposit to
   * @param args.amount - The amount to deposit
   * @param args.recipient - The account address to deposit to. This is the senders address if not set.
   * @param args.withFeePayer - Whether to use the fee payer for the transaction
   * @param args.options - Optional transaction options
   * @returns A SimpleTransaction to deposit the amount
   */
  async deposit(args: {
    sender: AccountAddressInput;
    tokenAddress: AccountAddressInput;
    amount: AnyNumber;
    /** If not set we will use the sender's address. */
    recipient?: AccountAddressInput;
    withFeePayer?: boolean;
    options?: InputGenerateTransactionOptions;
  }): Promise<SimpleTransaction> {
    const { tokenAddress, amount, recipient = args.sender } = args;
    validateAmount({ amount });

    const amountString = String(amount);

    return this.client.transaction.build.simple({
      sender: args.sender,
      ...feePayerBuildOpts(args),
      data: {
        function: `${this.confidentialAssetModuleAddress}::${MODULE_NAME}::deposit_to`,
        functionArguments: [tokenAddress, recipient, amountString],
      },
    });
  }

  /**
   * First-time atomic register + deposit + rollover. Targets the on-chain
   * `register_and_deposit_and_rollover_pending_balance` entrypoint, which composes
   * `register` + `deposit_to(self)` + `rollover_pending_balance` so the wallet UX is
   * "one click → one transaction → one on-chain entry function" with funds landing
   * spendable (in `actual_balance`), not pending.
   *
   * Why no normalize step here: `register_internal` creates a fresh store with an empty
   * (canonical-zero) `actual_balance` flagged `normalized = true`, and a single deposit of any
   * `u64 amount` produces a pending balance whose chunks each fit in 16 bits; rolling that into
   * the canonical-zero actual produces an actual whose chunks are still ≤ 16 bits. So the path
   * never needs a `normalize` step.
   *
   * After this call, `normalized = false` (every `rollover_pending_balance_internal` sets it).
   * The next deposit-then-rollover flow on the same store must therefore go through
   * {@link depositNormalizeAndRollover} until something re-normalizes (a `confidential_transfer`,
   * `withdraw`, or explicit `normalize`).
   *
   * Aborts identically to a separate `register` (registration-proof failure / token-allow-list
   * violations) and to `deposit_to` (allow-list violations); also aborts if the sender is already
   * registered. Callers that want a no-op-on-already-registered shape should branch on
   * `hasUserRegistered` client-side and route to {@link depositAndRollover} or
   * {@link depositNormalizeAndRollover} instead.
   */
  async registerAndDepositAndRollover(args: {
    sender: AccountAddressInput;
    tokenAddress: AccountAddressInput;
    decryptionKey: TwistedEd25519PrivateKey;
    amount: AnyNumber;
    withFeePayer?: boolean;
    options?: InputGenerateTransactionOptions;
  }): Promise<SimpleTransaction> {
    const { tokenAddress, decryptionKey, amount } = args;
    validateAmount({ amount });

    const chainId = await getChainIdByteForProofs({ client: this.client });
    const senderAddressBytes = AccountAddress.from(args.sender).toUint8Array();
    const contractAddressBytes = AccountAddress.from(this.confidentialAssetModuleAddress).toUint8Array();
    const tokenAddressBytes = AccountAddress.from(tokenAddress).toUint8Array();
    const proof = genRegistrationProof(
      decryptionKey,
      chainId,
      senderAddressBytes,
      contractAddressBytes,
      tokenAddressBytes,
    );

    return this.client.transaction.build.simple({
      sender: args.sender,
      ...feePayerBuildOpts(args),
      data: {
        function: `${this.confidentialAssetModuleAddress}::${MODULE_NAME}::register_and_deposit_and_rollover_pending_balance`,
        functionArguments: [
          tokenAddress,
          String(amount),
          decryptionKey.publicKey().toUint8Array(),
          proof.commitment,
          proof.response,
        ],
      },
    });
  }

  /**
   * Subsequent atomic deposit + rollover on a store whose `actual_balance` is currently
   * normalized. Targets `deposit_and_rollover_pending_balance`. Funds land in `actual_balance`
   * (spendable), not pending.
   *
   * Aborts with `ENORMALIZATION_REQUIRED` (3 << 16 | 10 = 196618) if the store's
   * `normalized` flag is `false`. Since every `rollover_pending_balance_internal` (including the
   * one in this entrypoint) sets `normalized = false`, callers should expect to use
   * {@link depositNormalizeAndRollover} on subsequent invocations until the store re-normalizes
   * via `confidential_transfer`, `withdraw`, or a standalone `normalize`.
   */
  async depositAndRollover(args: {
    sender: AccountAddressInput;
    tokenAddress: AccountAddressInput;
    amount: AnyNumber;
    withFeePayer?: boolean;
    options?: InputGenerateTransactionOptions;
  }): Promise<SimpleTransaction> {
    const { tokenAddress, amount } = args;
    validateAmount({ amount });
    return this.client.transaction.build.simple({
      sender: args.sender,
      ...feePayerBuildOpts(args),
      data: {
        function: `${this.confidentialAssetModuleAddress}::${MODULE_NAME}::deposit_and_rollover_pending_balance`,
        functionArguments: [tokenAddress, String(amount)],
      },
    });
  }

  /**
   * Subsequent atomic deposit + normalize + rollover on a store whose `actual_balance` is NOT
   * currently normalized. Targets `deposit_and_normalize_and_rollover_pending_balance`. Funds land
   * in `actual_balance` (spendable), not pending.
   *
   * The normalize proof is constructed off-chain against the *current* on-chain
   * `actual_balance`. `deposit_to_internal` only mutates `pending_balance`, so the on-chain
   * `actual_balance` at the moment `normalize_internal` runs is the same value the proof was
   * built against; the rollover then folds (just-deposited) pending into the now-normalized
   * actual.
   *
   * Aborts with `EALREADY_NORMALIZED` (3 << 16 | 11 = 196619) if the store is already
   * normalized — callers should route to {@link depositAndRollover} for that case. Aborts with
   * `ECA_STORE_NOT_PUBLISHED` if the sender is unregistered.
   */
  async depositNormalizeAndRollover(args: {
    sender: AccountAddressInput;
    tokenAddress: AccountAddressInput;
    senderDecryptionKey: TwistedEd25519PrivateKey;
    amount: AnyNumber;
    withFeePayer?: boolean;
    options?: InputGenerateTransactionOptions;
  }): Promise<SimpleTransaction> {
    const { sender, tokenAddress, senderDecryptionKey, amount } = args;
    validateAmount({ amount });

    const confidentialNormalization = await this.prepareNormalization({
      sender,
      senderDecryptionKey,
      tokenAddress,
    });
    const [{ sigmaProof, rangeProof }, normalizedCB] = await confidentialNormalization.authorizeNormalization();

    return this.client.transaction.build.simple({
      sender,
      ...feePayerBuildOpts(args),
      data: {
        function: `${this.confidentialAssetModuleAddress}::${MODULE_NAME}::deposit_and_normalize_and_rollover_pending_balance`,
        functionArguments: [
          tokenAddress,
          String(amount),
          normalizedCB.getCipherTextBytes(),
          rangeProof,
          ConfidentialNormalization.serializeSigmaProof(sigmaProof),
        ],
      },
    });
  }

  /**
   * Withdraw an amount from a confidential asset balance.
   *
   * This can be used by an account to convert their own confidential asset balance into a non-confidential asset balance.
   *
   * @param args.sender - The address of the sender of the transaction
   * @param args.senderDecryptionKey - The decryption key of the sender
   * @param args.tokenAddress - The token address of the asset to withdraw from
   * @param args.amount - The amount to withdraw
   * @param args.recipient - The account address to withdraw to. This is the senders address if not set.
   * @param args.withFeePayer - Whether to use the fee payer for the transaction
   * @returns A SimpleTransaction to withdraw the amount
   * @throws {Error} If the amount to withdraw is greater than the available balance
   */
  async withdraw(args: {
    sender: AccountAddressInput;
    senderDecryptionKey: TwistedEd25519PrivateKey;
    tokenAddress: AccountAddressInput;
    amount: AnyNumber;
    /** If not set we will use the sender's address. */
    recipient?: AccountAddressInput;
    withFeePayer?: boolean;
    options?: InputGenerateTransactionOptions;
  }): Promise<SimpleTransaction> {
    const { sender, tokenAddress, amount, senderDecryptionKey, recipient = args.sender, options } = args;
    validateAmount({ amount });

    // Get the sender's available balance from the chain (latest state; see transfer() comment on ledger pinning)
    const { available: senderEncryptedAvailableBalance } = await getBalance({
      client: this.client,
      moduleAddress: this.confidentialAssetModuleAddress,
      accountAddress: sender,
      tokenAddress,
      decryptionKey: senderDecryptionKey,
    });

    const chainId = await getChainIdByteForProofs({ client: this.client });
    const senderAddressBytes = AccountAddress.from(sender).toUint8Array();
    const contractAddressBytes = AccountAddress.from(this.confidentialAssetModuleAddress).toUint8Array();
    const tokenAddressBytes = AccountAddress.from(tokenAddress).toUint8Array();

    const confidentialWithdraw = await ConfidentialWithdraw.create({
      decryptionKey: senderDecryptionKey,
      senderAvailableBalanceCipherText: senderEncryptedAvailableBalance.getCipherText(),
      amount: BigInt(amount),
      chainId,
      senderAddress: senderAddressBytes,
      contractAddress: contractAddressBytes,
      tokenAddress: tokenAddressBytes,
    });

    const [{ sigmaProof, rangeProof }, encryptedAmountAfterWithdraw] = await confidentialWithdraw.authorizeWithdrawal();

    return this.client.transaction.build.simple({
      sender,
      ...feePayerBuildOpts(args),
      data: {
        function: `${this.confidentialAssetModuleAddress}::${MODULE_NAME}::withdraw_to`,
        functionArguments: [
          tokenAddress,
          recipient,
          String(amount),
          encryptedAmountAfterWithdraw.getCipherTextBytes(),
          rangeProof,
          ConfidentialWithdraw.serializeSigmaProof(sigmaProof),
        ],
      },
    });
  }

  /**
   * Rollover an account's pending balance for an asset into the available balance.
   *
   * @param args.sender - The address of the sender of the transaction
   * @param args.tokenAddress - The token address of the asset to roll over
   * @param args.withFreezeBalance - Whether to freeze the balance after rolling over. Default is false.
   * @param args.checkNormalized - Whether to check if the balance is normalized before rolling over. Default is true.
   * @param args.withFeePayer - Whether to use the fee payer for the transaction
   * @returns A SimpleTransaction to roll over the balance
   * @throws {Error} If the balance is not normalized before rolling over, unless checkNormalized is false.
   */
  async rolloverPendingBalance(args: {
    sender: AccountAddressInput;
    tokenAddress: AccountAddressInput;
    withFreezeBalance?: boolean;
    withFeePayer?: boolean;
    checkNormalized?: boolean;
    options?: InputGenerateTransactionOptions;
  }): Promise<SimpleTransaction> {
    const { checkNormalized = true, withFreezeBalance = false } = args;
    if (checkNormalized) {
      const isNormalized = await isBalanceNormalized({
        client: this.client,
        moduleAddress: this.confidentialAssetModuleAddress,
        accountAddress: args.sender,
        tokenAddress: args.tokenAddress,
      });
      if (!isNormalized) {
        throw new Error("Balance must be normalized before rollover");
      }
    }

    const functionName = withFreezeBalance ? "rollover_pending_balance_and_freeze" : "rollover_pending_balance";

    return this.client.transaction.build.simple({
      sender: args.sender,
      ...feePayerBuildOpts(args),
      data: {
        function: `${this.confidentialAssetModuleAddress}::${MODULE_NAME}::${functionName}`,
        functionArguments: [args.tokenAddress],
      },
    });
  }

  /**
   * Get the encryption key for the asset auditor for a given token address.
   *
   * @param args.tokenAddress - The token address of the asset to get the auditor for
   * @param args.options.ledgerVersion - The ledger version to use for the view call
   * @returns The encryption key for the asset auditor or undefined if no auditor is set
   */
  async getAssetAuditorEncryptionKey(args: {
    tokenAddress: AccountAddressInput;
    options?: LedgerVersionArg;
  }): Promise<TwistedEd25519PublicKey | undefined> {
    return getAssetAuditorEncryptionKey({
      client: this.client,
      moduleAddress: this.confidentialAssetModuleAddress,
      tokenAddress: args.tokenAddress,
      options: args.options,
    });
  }

  /**
   * Returns the chain-level auditor encryption key (slot [0] of every transfer's `auditor_eks`),
   * or `undefined` when no chain auditor is configured. See `getChainAuditorEncryptionKey` in
   * `viewFunctions` for the on-chain mapping (`get_chain_auditor`,
   * movementlabsxyz/aptos-core#328).
   */
  async getChainAuditorEncryptionKey(args?: {
    options?: LedgerVersionArg;
  }): Promise<TwistedEd25519PublicKey | undefined> {
    return getChainAuditorEncryptionKey({
      client: this.client,
      moduleAddress: this.confidentialAssetModuleAddress,
      options: args?.options,
    });
  }

  /**
   * Transfer an amount from a confidential asset balance to a recipient.
   *
   * This can be used by an account to transfer their own confidential asset balance to a recipient.
   *
   * TODO: Parallelize the view calls to get the encrypted balance and the encryption key
   *
   * @param args.sender - The address of the sender of the transaction
   * @param args.senderDecryptionKey - The decryption key of the sender
   * @param args.tokenAddress - The token address of the asset to transfer
   * @param args.amount - The amount to transfer
   * @param args.recipient - The address of the recipient
   * @param args.additionalAuditorEncryptionKeys - The encryption keys of the auditors. If not set we will fetch the encryption keys from the chain.
   * @param args.senderAuditorHint - Opaque bytes (max 256) bound into the transfer sigma proof and emitted on `Transferred`; default empty.
   * @param args.withFeePayer - Whether to use the fee payer for the transaction
   *
   * Views (balance, encryption keys, auditor) use the **latest** ledger state. Do not pin `ledgerVersion` to
   * `getLedgerInfo().ledger_version` when building proofs: that version can lag the state your transaction executes
   * on, producing a Fiat–Shamir / ciphertext mismatch (`ESIGMA_PROTOCOL_VERIFY_FAILED` on-chain).
   * @returns A SimpleTransaction to transfer the amount
   * @throws {Error} If the recipient's encryption key cannot be found
   * @throws {Error} If the amount to transfer is greater than the available balance
   */
  async transfer(args: {
    sender: AccountAddressInput;
    recipient: AccountAddressInput;
    tokenAddress: AccountAddressInput;
    amount: AnyNumber;
    senderDecryptionKey: TwistedEd25519PrivateKey;
    additionalAuditorEncryptionKeys?: TwistedEd25519PublicKey[];
    /**
     * Raw hint bytes (max 256). Bound into the sigma Fiat–Shamir transcript as `BCS(vector<u8>)` inside
     * {@link ConfidentialTransfer.genSigmaProof}; pass the same bytes here as the **payload** of Move `vector<u8>`
     * (the transaction builder encodes the vector — do not pre-BCS-wrap with a length prefix).
     */
    senderAuditorHint?: Uint8Array;
    withFeePayer?: boolean;
    options?: InputGenerateTransactionOptions;
  }): Promise<SimpleTransaction> {
    const {
      senderDecryptionKey,
      recipient,
      tokenAddress,
      amount,
      additionalAuditorEncryptionKeys = [],
      senderAuditorHint = new Uint8Array(),
    } = args;
    validateAmount({ amount });
    if (senderAuditorHint.length > MAX_SENDER_AUDITOR_HINT_BYTES) {
      throw new Error(`senderAuditorHint exceeds MAX_SENDER_AUDITOR_HINT_BYTES (${MAX_SENDER_AUDITOR_HINT_BYTES})`);
    }

    const chainId = await getChainIdByteForProofs({ client: this.client });

    // Fetch chain (slot [0]) and per-asset (slot [1]) auditors per movementlabsxyz/aptos-core#328's
    // fixed-prefix layout. Slot [0] is always reserved; the framework's slot-0 key-equality check
    // only fires when a chain auditor is configured. The per-asset auditor is mandatory only when
    // configured; when set, it must occupy slot [1]. Voluntary per-transfer auditors land at slot
    // [2..].
    const [chainAuditorPubKey, assetAuditorPubKey] = await Promise.all([
      this.getChainAuditorEncryptionKey(),
      this.getAssetAuditorEncryptionKey({ tokenAddress }),
    ]);
    // Testnet bring-up: the chain auditor isn't configured yet, and the framework patch on testnet
    // skips the slot-0 key-equality check while it's None. Fill slot [0] with the sender's own EK
    // as a placeholder so the wire format and Fiat–Shamir transcript layout stay stable. On every
    // other network, a missing chain auditor remains a hard error.
    let chainSlotPubKey: TwistedEd25519PublicKey;
    if (chainAuditorPubKey) {
      chainSlotPubKey = chainAuditorPubKey;
    } else if (this.client.config.network === Network.TESTNET) {
      chainSlotPubKey = senderDecryptionKey.publicKey();
    } else {
      throw new Error(
        "Chain auditor is not configured (get_chain_auditor returned None). " +
          "confidential_transfer aborts with ECHAIN_AUDITOR_NOT_SET in this state.",
      );
    }

    // For self-transfers, use the sender's derived encryption key. The on-chain verifier uses `encryption_key(to,
    // token)` which must match the exact bytes we bind into the transfer sigma Fiat–Shamir hash; re-fetching the
    // recipient key from a view can theoretically diverge from `senderDecryptionKey.publicKey()` encoding.
    let recipientEncryptionKey: TwistedEd25519PublicKey;
    if (AccountAddress.from(args.sender).equals(AccountAddress.from(recipient))) {
      recipientEncryptionKey = senderDecryptionKey.publicKey();
    } else {
      try {
        recipientEncryptionKey = await getEncryptionKey({
          client: this.client,
          moduleAddress: this.confidentialAssetModuleAddress,
          accountAddress: recipient,
          tokenAddress,
        });
      } catch (e) {
        throw new Error(`Failed to get encryption key for recipient - ${e}`);
      }
    }
    const isFrozen = await isPendingBalanceFrozen({
      client: this.client,
      moduleAddress: this.confidentialAssetModuleAddress,
      accountAddress: recipient,
      tokenAddress,
    });
    if (isFrozen) {
      throw new Error("Recipient balance is frozen");
    }
    // Get the sender's available balance from the chain (latest committed state; matches execution-time views)
    const { available: senderEncryptedAvailableBalance } = await getBalance({
      client: this.client,
      moduleAddress: this.confidentialAssetModuleAddress,
      accountAddress: args.sender,
      tokenAddress,
      decryptionKey: senderDecryptionKey,
    });
    const senderAddressBytes = AccountAddress.from(args.sender).toUint8Array();
    const contractAddressBytes = AccountAddress.from(this.confidentialAssetModuleAddress).toUint8Array();
    const tokenAddressBytes = AccountAddress.from(tokenAddress).toUint8Array();

    // Create the confidential transfer object
    const confidentialTransfer = await ConfidentialTransfer.create({
      senderDecryptionKey,
      senderAvailableBalanceCipherText: senderEncryptedAvailableBalance.getCipherText(),
      amount,
      recipientEncryptionKey,
      auditorEncryptionKeys: assembleAuditorEks({
        chain: chainSlotPubKey,
        asset: assetAuditorPubKey,
        voluntary: additionalAuditorEncryptionKeys,
      }),
      chainId,
      senderAddress: senderAddressBytes,
      contractAddress: contractAddressBytes,
      tokenAddress: tokenAddressBytes,
      senderAuditorHint,
    });

    const [
      {
        sigmaProof,
        rangeProof: { rangeProofAmount, rangeProofNewBalance },
      },
      encryptedAmountAfterTransfer,
      encryptedAmountByRecipient,
      auditorsCBList,
    ] = await confidentialTransfer.authorizeTransfer();

    const auditorEncryptionKeys = confidentialTransfer.auditorEncryptionKeys.map((pk) => pk.toUint8Array());
    const auditorBalances = auditorsCBList.map((el) => el.getCipherTextBytes());

    return this.client.transaction.build.simple({
      sender: args.sender,
      ...feePayerBuildOpts(args),
      data: {
        function: `${this.confidentialAssetModuleAddress}::${MODULE_NAME}::confidential_transfer`,
        functionArguments: [
          tokenAddress,
          recipient,
          encryptedAmountAfterTransfer.getCipherTextBytes(),
          confidentialTransfer.transferAmountEncryptedBySender.getCipherTextBytes(),
          encryptedAmountByRecipient.getCipherTextBytes(),
          concatBytes(...auditorEncryptionKeys),
          concatBytes(...auditorBalances),
          rangeProofNewBalance,
          rangeProofAmount,
          ConfidentialTransfer.serializeSigmaProof(sigmaProof),
          senderAuditorHint,
        ],
      },
    });
  }

  /**
   * Rotate the encryption key for a confidential asset balance.
   *
   * This will by default check if the pending balance is empty and throw an error if it is not. It also checks if the balance is frozen and
   * will unfreeze it if it is.
   *
   * TODO: Parallelize the view calls
   *
   * @param args.sender - The address of the sender of the transaction who's encryption key is being rotated
   * @param args.senderDecryptionKey - The decryption key of the sender
   * @param args.newDecryptionKey - The new decryption key
   * @param args.tokenAddress - The token address of the asset to rotate the encryption key for
   * @param args.checkPendingBalanceEmpty - Whether to check if the pending balance is empty before rotating the encryption key. Default is true.
   * @param args.withUnfreezeBalance - Whether to unfreeze the balance after rotating the encryption key. By default it will check the chain to
   * see if the balance is frozen and if so, will unfreeze it.
   * @param args.withFeePayer - Whether to use the fee payer for the transaction
   * @returns A SimpleTransaction to rotate the encryption key
   * @throws {Error} If the pending balance is not 0 before rotating the encryption key, unless checkPendingBalanceEmpty is false.
   */
  async rotateEncryptionKey(args: {
    sender: AccountAddressInput;
    senderDecryptionKey: TwistedEd25519PrivateKey;
    newSenderDecryptionKey: TwistedEd25519PrivateKey;
    tokenAddress: AccountAddressInput;
    checkPendingBalanceEmpty?: boolean;
    withUnfreezePendingBalance?: boolean;
    withFeePayer?: boolean;
    options?: InputGenerateTransactionOptions;
  }): Promise<SimpleTransaction> {
    const { sender, senderDecryptionKey, newSenderDecryptionKey, checkPendingBalanceEmpty = true, tokenAddress } = args;

    const chainId = await getChainIdByteForProofs({ client: this.client });

    const withUnfreezePendingBalance =
      args.withUnfreezePendingBalance ??
      (await isPendingBalanceFrozen({
        client: this.client,
        moduleAddress: this.confidentialAssetModuleAddress,
        accountAddress: sender,
        tokenAddress,
      }));

    // Get the sender's balance from the chain
    const { available: currentEncryptedAvailableBalance, pending: currentEncryptedPendingBalance } = await getBalance({
      client: this.client,
      moduleAddress: this.confidentialAssetModuleAddress,
      accountAddress: sender,
      tokenAddress,
      decryptionKey: senderDecryptionKey,
    });

    if (checkPendingBalanceEmpty) {
      if (currentEncryptedPendingBalance.getAmount() > 0n) {
        throw new Error("Pending balance must be 0 before rotating encryption key");
      }
    }
    const senderAddressBytes = AccountAddress.from(sender).toUint8Array();
    const contractAddressBytes = AccountAddress.from(this.confidentialAssetModuleAddress).toUint8Array();
    const tokenAddressBytes = AccountAddress.from(tokenAddress).toUint8Array();

    // Create the confidential key rotation object
    const confidentialKeyRotation = await ConfidentialKeyRotation.create({
      senderDecryptionKey,
      newSenderDecryptionKey,
      currentEncryptedAvailableBalance,
      chainId,
      senderAddress: senderAddressBytes,
      contractAddress: contractAddressBytes,
      tokenAddress: tokenAddressBytes,
    });

    // Create the sigma proof and range proof
    const [{ sigmaProof, rangeProof }, newEncryptedAvailableBalance] =
      await confidentialKeyRotation.authorizeKeyRotation();

    const newPublicKeyBytes = args.newSenderDecryptionKey.publicKey().toUint8Array();

    const method = withUnfreezePendingBalance ? "rotate_encryption_key_and_unfreeze" : "rotate_encryption_key";

    return this.client.transaction.build.simple({
      sender: args.sender,
      ...feePayerBuildOpts(args),
      data: {
        function: `${this.confidentialAssetModuleAddress}::${MODULE_NAME}::${method}`,
        functionArguments: [
          args.tokenAddress,
          newPublicKeyBytes,
          newEncryptedAvailableBalance.getCipherTextBytes(),
          rangeProof,
          ConfidentialKeyRotation.serializeSigmaProof(sigmaProof),
        ],
      },
    });
  }

  /**
   * Normalize a user's balance.
   *
   * This can be used to normalize a user's balance for a given token address.
   *
   * @param args.sender - The address of the sender of the transaction who's balance is being normalized
   * @param args.senderDecryptionKey - The decryption key of the sender
   * @param args.tokenAddress - The token address of the asset to normalize
   * @param args.withFeePayer - Whether to use the fee payer for the transaction
   * @returns A SimpleTransaction to normalize the balance
   */
  async normalizeBalance(args: {
    sender: AccountAddressInput;
    senderDecryptionKey: TwistedEd25519PrivateKey;
    tokenAddress: AccountAddressInput;
    withFeePayer?: boolean;
    options?: InputGenerateTransactionOptions;
  }): Promise<SimpleTransaction> {
    const confidentialNormalization = await this.prepareNormalization(args);
    return confidentialNormalization.createTransaction({
      client: this.client,
      sender: args.sender,
      confidentialAssetModuleAddress: this.confidentialAssetModuleAddress,
      tokenAddress: args.tokenAddress,
      withFeePayer: args.withFeePayer,
      options: args.options,
    });
  }

  /**
   * Build a single tx targeting the on-chain `normalize_and_rollover_pending_balance` entry.
   * Combines the normalize proof with an immediate rollover so callers can settle pending
   * balance from an unnormalized state in one wallet approval. Reuses the same proof inputs
   * as plain `normalize`.
   */
  async normalizeAndRolloverPendingBalance(args: {
    sender: AccountAddressInput;
    senderDecryptionKey: TwistedEd25519PrivateKey;
    tokenAddress: AccountAddressInput;
    withFeePayer?: boolean;
    options?: InputGenerateTransactionOptions;
  }): Promise<SimpleTransaction> {
    const confidentialNormalization = await this.prepareNormalization(args);
    return confidentialNormalization.createNormalizeAndRolloverTransaction({
      client: this.client,
      sender: args.sender,
      confidentialAssetModuleAddress: this.confidentialAssetModuleAddress,
      tokenAddress: args.tokenAddress,
      withFeePayer: args.withFeePayer,
      options: args.options,
    });
  }

  private async prepareNormalization(args: {
    sender: AccountAddressInput;
    senderDecryptionKey: TwistedEd25519PrivateKey;
    tokenAddress: AccountAddressInput;
  }): Promise<ConfidentialNormalization> {
    const { sender, senderDecryptionKey, tokenAddress } = args;
    const chainId = await getChainIdByteForProofs({ client: this.client });

    const { available } = await getBalance({
      client: this.client,
      moduleAddress: this.confidentialAssetModuleAddress,
      accountAddress: sender,
      tokenAddress,
      decryptionKey: senderDecryptionKey,
    });
    const senderAddressBytes = AccountAddress.from(sender).toUint8Array();
    const contractAddressBytes = AccountAddress.from(this.confidentialAssetModuleAddress).toUint8Array();
    const tokenAddressBytes = AccountAddress.from(tokenAddress).toUint8Array();

    return ConfidentialNormalization.create({
      decryptionKey: senderDecryptionKey,
      unnormalizedAvailableBalance: available,
      chainId,
      senderAddress: senderAddressBytes,
      contractAddress: contractAddressBytes,
      tokenAddress: tokenAddressBytes,
    });
  }
}

/** Only forwards options and `withFeePayer` when sponsored tx is explicitly requested (strict `=== true`). */
function feePayerBuildOpts(args: { withFeePayer?: boolean; options?: InputGenerateTransactionOptions }): {
  options?: InputGenerateTransactionOptions;
  withFeePayer?: true;
} {
  const out: { options?: InputGenerateTransactionOptions; withFeePayer?: true } = {};
  if (args.options !== undefined) {
    out.options = args.options;
  }
  if (args.withFeePayer === true) {
    out.withFeePayer = true;
  }
  return out;
}

function validateAmount(args: { amount: AnyNumber }) {
  if (BigInt(args.amount) < 0n) {
    throw new Error("Amount must not be negative");
  }
}
