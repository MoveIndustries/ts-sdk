// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

/**
 * This file contains the underlying implementations for exposed API surface in
 * the {@link api/faucet}. By moving the methods out into a separate file,
 * other namespaces and processes can access these methods without depending on the entire
 * faucet namespace and without having a dependency cycle error.
 * @group Implementation
 */

import { MovementConfig } from "../api/movementConfig";
import { postAptosFaucet } from "../client";
import { AccountAddress, AccountAddressInput } from "../core";
import { TransactionResponseType, UserTransactionResponse, WaitForTransactionOptions } from "../types";
import { DEFAULT_TXN_TIMEOUT_SEC } from "../utils/const";
import { waitForTransaction } from "./transaction";

/**
 * Funds an account with a specified amount of tokens from the Movement faucet.
 * This function is useful for quickly providing a new or existing account with tokens to facilitate transactions.
 *
 * Note that only devnet has a publicly accessible faucet. For testnet, you must use
 * the minting page at https://movement.dev/network/faucet.
 *
 * @param args - The arguments for funding the account.
 * @param args.movementConfig - The configuration settings for connecting to the Movement network.
 * @param args.accountAddress - The address of the account to be funded.
 * @param args.amount - The amount of tokens to fund the account with.
 * @param args.options - Optional parameters for the transaction.
 * @param args.options.timeoutSecs - The maximum time to wait for the transaction to complete, in seconds.
 * @param args.options.checkSuccess - A flag indicating whether to check if the transaction was successful.
 *
 * @throws Error if the transaction does not return a user transaction type.
 * @group Implementation
 */
export async function fundAccount(args: {
  movementConfig: MovementConfig;
  accountAddress: AccountAddressInput;
  amount: number;
  options?: WaitForTransactionOptions;
}): Promise<UserTransactionResponse> {
  const { movementConfig, accountAddress, amount, options } = args;
  const timeout = options?.timeoutSecs || DEFAULT_TXN_TIMEOUT_SEC;
  const { data } = await postAptosFaucet<any, { txn_hashes: Array<string> }>({
    movementConfig,
    path: "fund",
    body: {
      address: AccountAddress.from(accountAddress).toString(),
      amount,
    },
    originMethod: "fundAccount",
  });

  const txnHash = data.txn_hashes[0];

  const res = await waitForTransaction({
    movementConfig,
    transactionHash: txnHash,
    options: {
      timeoutSecs: timeout,
      checkSuccess: options?.checkSuccess,
    },
  });

  // Response is always User transaction for a user submitted transaction
  if (res.type === TransactionResponseType.User) {
    return res;
  }

  throw new Error(`Unexpected transaction received for fund account: ${res.type}`);
}
