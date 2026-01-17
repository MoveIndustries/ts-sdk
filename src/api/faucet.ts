// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import { AccountAddressInput } from "../core";
import { fundAccount } from "../internal/faucet";
import { waitForIndexer } from "../internal/transaction";
import { UserTransactionResponse, WaitForTransactionOptions } from "../types";
import { ProcessorType } from "../utils";
import { MovementConfig } from "./movementConfig";

/**
 * A class to query all `Faucet` related queries on Movement.
 * @group Faucet
 */
export class Faucet {
  /**
   * Initializes a new instance of the Movement client with the specified configuration.
   *
   * Note that only devnet has a publicly accessible faucet. For testnet, you must use
   * the minting page at https://movement.dev/network/faucet.
   *
   * @param config - The configuration settings for the Movement client.
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * async function runExample() {
   *     // Create a configuration for the Movement client
   *     const config = new MovementConfig({ network: Network.DEVNET }); // specify your own network if needed
   *
   *     // Initialize the Movement client with the configuration
   *     const movement = new Movement(config);
   *
   *     console.log("Movement client initialized:", aptos);
   * }
   * runExample().catch(console.error);
   * ```
   * @group Faucet
   */
  constructor(readonly config: MovementConfig) { }

  /**
   * This function creates an account if it does not exist and mints the specified amount of coins into that account.
   *
   * Note that only devnet has a publicly accessible faucet. For testnet, you must use
   * the minting page at https://movement.dev/network/faucet.
   *
   * @param args - The arguments for funding the account.
   * @param args.accountAddress - The address of the account to fund.
   * @param args.amount - The amount of tokens to fund the account with.
   * @param args.options - Configuration options for waiting for the transaction.
   * @returns Transaction hash of the transaction that funded the account.
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * const config = new MovementConfig({ network: Network.DEVNET });
   * const movement = new Movement(config);
   *
   * async function runExample() {
   *   // Fund an account with a specified amount of tokens
   *   const transaction = await movement.fundAccount({
   *     accountAddress: "0x1", // replace with your account address
   *     amount: 100,
   *   });
   *
   *   console.log("Transaction hash:", transaction.hash);
   * }
   * runExample().catch(console.error);
   * ```
   * @group Faucet
   */
  async fundAccount(args: {
    accountAddress: AccountAddressInput;
    amount: number;
    options?: WaitForTransactionOptions;
  }): Promise<UserTransactionResponse> {
    const fundTxn = await fundAccount({ movementConfig: this.config, ...args });

    // If the user explicitly says to NOT wait by setting waitForIndexer to false, then we skip this.
    // But, by default we want to wait for the indexer.
    if (args.options?.waitForIndexer === undefined || args.options?.waitForIndexer) {
      await waitForIndexer({
        movementConfig: this.config,
        minimumLedgerVersion: BigInt(fundTxn.version),
        processorType: ProcessorType.FUNGIBLE_ASSET_PROCESSOR,
      });
    }

    return fundTxn;
  }
}
