// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import {
  getChainTopUserTransactions,
  getIndexerLastSuccessVersion,
  getLedgerInfo,
  getProcessorStatus,
  queryIndexer,
} from "../internal/general";
import { getBlockByHeight, getBlockByVersion } from "../internal/transaction";
import { view, viewJson } from "../internal/view";
import { InputViewFunctionData, InputViewFunctionJsonData } from "../transactions";
import {
  AnyNumber,
  Block,
  GetChainTopUserTransactionsResponse,
  GetProcessorStatusResponse,
  GraphqlQuery,
  LedgerInfo,
  LedgerVersionArg,
  MoveValue,
} from "../types";
import { ProcessorType } from "../utils/const";
import { MovementConfig } from "./movementConfig";

/**
 * A class to query various Movement-related information and perform operations on the Movement blockchain.
 * @group General
 */
export class General {
  readonly config: MovementConfig;

  /**
   * Initializes a new instance of the Movement client with the specified configuration.
   * This allows users to interact with the Movement blockchain using the provided settings.
   *
   * @param config - The configuration settings for the Movement client.
   * @param config.network - The network to connect to (e.g., TESTNET, MAINNET).
   * @param config.nodeUrl - The URL of the Movement node to connect to.
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * async function runExample() {
   *     // Create a configuration for the Movement client
   *     const config = new MovementConfig({
   *         network: Network.TESTNET, // specify the network
   *         nodeUrl: "https://testnet.movement.dev" // specify the node URL
   *     });
   *
   *     // Initialize the Movement client with the configuration
   *     const movement = new Movement(config);
   *
   *     console.log("Movement client initialized:", aptos);
   * }
   * runExample().catch(console.error);
   * ```
   * @group General
   */
  constructor(config: MovementConfig) {
    this.config = config;
  }

  /**
   * Queries for the Movement ledger information.
   *
   * @returns The Movement Ledger Info, which includes details such as chain ID, epoch, and ledger version.
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * const config = new MovementConfig({ network: Network.TESTNET });
   * const movement = new Movement(config);
   *
   * async function runExample() {
   *   // Fetching the ledger information
   *   const ledgerInfo = await movement.getLedgerInfo();
   *
   *   console.log(ledgerInfo);
   * }
   * runExample().catch(console.error);
   * ```
   * @group General
   */
  async getLedgerInfo(): Promise<LedgerInfo> {
    return getLedgerInfo({ movementConfig: this.config });
  }

  /**
   * Retrieves the chain ID of the Movement blockchain.
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * const config = new MovementConfig({ network: Network.TESTNET });
   * const movement = new Movement(config);
   *
   * async function runExample() {
   *   // Fetching the chain ID
   *   const chainId = await movement.getChainId();
   *   console.log("Chain ID:", chainId);
   * }
   * runExample().catch(console.error);
   *
   * @returns The chain ID of the Movement blockchain.
   * ```
   * @group General
   */
  async getChainId(): Promise<number> {
    const result = await this.getLedgerInfo();
    return result.chain_id;
  }

  /**
   * Retrieves block information by the specified ledger version.
   *
   * @param args - The arguments for retrieving the block.
   * @param args.ledgerVersion - The ledger version to lookup block information for.
   * @param args.options - Optional parameters for the request.
   * @param args.options.withTransactions - If set to true, include all transactions in the block.
   *
   * @returns Block information with optional transactions.
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * const config = new MovementConfig({ network: Network.TESTNET });
   * const movement = new Movement(config);
   *
   * async function runExample() {
   *   // Retrieve block information for a specific ledger version
   *   const block = await movement.getBlockByVersion({ ledgerVersion: 5 });
   *   console.log(block);
   * }
   * runExample().catch(console.error);
   * ```
   * @group General
   */
  async getBlockByVersion(args: {
    ledgerVersion: AnyNumber;
    options?: { withTransactions?: boolean };
  }): Promise<Block> {
    return getBlockByVersion({
      movementConfig: this.config,
      ...args,
    });
  }

  /**
   * Retrieve a block by its height, allowing for the inclusion of transactions if specified.
   *
   * @param args - The parameters for the block retrieval.
   * @param args.blockHeight - The block height to look up, starting at 0.
   * @param args.options - Optional settings for the retrieval.
   * @param args.options.withTransactions - If set to true, includes all transactions in the block.
   *
   * @returns The block with optional transactions included.
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * const config = new MovementConfig({ network: Network.TESTNET });
   * const movement = new Movement(config);
   *
   * async function runExample() {
   *   // Retrieve the block at height 5, including transactions
   *   const block = await movement.getBlockByHeight({ blockHeight: 5, options: { withTransactions: true } });
   *   console.log(block);
   * }
   * runExample().catch(console.error);
   * ```
   * @group General
   */
  async getBlockByHeight(args: { blockHeight: AnyNumber; options?: { withTransactions?: boolean } }): Promise<Block> {
    return getBlockByHeight({ movementConfig: this.config, ...args });
  }

  /**
   * Queries for a Move view function
   * @param args.payload Payload for the view function
   * @param args.options.ledgerVersion The ledger version to query, if not provided it will get the latest version
   *
   * @example
   * const data = await movement.view({
   *  payload: {
   *   function: "0x1::coin::balance",
   *   typeArguments: ["0x1::aptos_coin::AptosCoin"],
   *   functionArguments: [accountAddress],
   *  }
   * })
   *
   * @returns an array of Move values
   * @group General
   */
  async view<T extends Array<MoveValue>>(args: {
    payload: InputViewFunctionData;
    options?: LedgerVersionArg;
  }): Promise<T> {
    return view<T>({ movementConfig: this.config, ...args });
  }

  /**
   * Queries for a Move view function with JSON, this provides compatability with the old `aptos` package
   * @param args.payload Payload for the view function
   * @param args.options.ledgerVersion The ledger version to query, if not provided it will get the latest version
   *
   * @example
   * const data = await movement.view({
   *  payload: {
   *   function: "0x1::coin::balance",
   *   typeArguments: ["0x1::aptos_coin::AptosCoin"],
   *   functionArguments: [accountAddress.toString()],
   *  }
   * })
   *
   * @returns an array of Move values
   * @group General
   */
  async viewJson<T extends Array<MoveValue>>(args: {
    payload: InputViewFunctionJsonData;
    options?: LedgerVersionArg;
  }): Promise<T> {
    return viewJson<T>({ movementConfig: this.config, ...args });
  }

  /**
   * Queries the top user transactions based on the specified limit.
   *
   * @param args - The arguments for querying top user transactions.
   * @param args.limit - The number of transactions to return.
   * @returns GetChainTopUserTransactionsResponse
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * const config = new MovementConfig({ network: Network.TESTNET });
   * const movement = new Movement(config);
   *
   * async function runExample() {
   *   // Fetch the top user transactions with a limit of 5
   *   const topUserTransactions = await movement.getChainTopUserTransactions({ limit: 5 });
   *
   *   console.log(topUserTransactions);
   * }
   * runExample().catch(console.error);
   * ```
   * @group General
   */
  async getChainTopUserTransactions(args: { limit: number }): Promise<GetChainTopUserTransactionsResponse> {
    return getChainTopUserTransactions({
      movementConfig: this.config,
      ...args,
    });
  }

  /**
   * Retrieves data from the Movement Indexer using a GraphQL query.
   * This function allows you to execute complex queries to fetch specific data from the Movement blockchain.
   *
   * @param args.query.query - A GraphQL query string.
   * @param args.query.variables - The variables for the query (optional).
   *
   * @return The provided T type.
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * const config = new MovementConfig({ network: Network.TESTNET });
   * const movement = new Movement(config);
   *
   * async function runExample() {
   *   // Querying the Movement Indexer for ledger information
   *   const topUserTransactions = await movement.queryIndexer({
   *     query: { query: `query MyQuery {
   *       ledger_infos {
   *         chain_id
   *       }
   *     }`}
   *   });
   *
   *   console.log(topUserTransactions);
   * }
   * runExample().catch(console.error);
   * ```
   * @group General
   */
  async queryIndexer<T extends {}>(args: { query: GraphqlQuery }): Promise<T> {
    return queryIndexer<T>({
      movementConfig: this.config,
      ...args,
    });
  }

  /**
   * Queries for the last successful indexer version, providing insight into the ledger version the indexer is updated to, which
   * may lag behind the full nodes.
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * const config = new MovementConfig({ network: Network.TESTNET });
   * const movement = new Movement(config);
   *
   * async function runExample() {
   *   // Get the last successful indexer version
   *   const version = await movement.getIndexerLastSuccessVersion();
   *   console.log(`Last successful indexer version: ${version}`);
   * }
   * runExample().catch(console.error);
   * ```
   * @group General
   */
  async getIndexerLastSuccessVersion(): Promise<bigint> {
    return getIndexerLastSuccessVersion({ movementConfig: this.config });
  }

  /**
   * Query the processor status for a specific processor type.
   *
   * @param processorType The processor type to query.
   * @returns The status of the specified processor type.
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * const config = new MovementConfig({ network: Network.TESTNET });
   * const movement = new Movement(config);
   *
   * async function runExample() {
   *   // Get the processor status for the account transactions processor
   *   const status = await movement.getProcessorStatus("account_transactions_processor");
   *   console.log(status);
   * }
   * runExample().catch(console.error);
   * ```
   * @group General
   */
  async getProcessorStatus(processorType: ProcessorType): Promise<GetProcessorStatusResponse[0]> {
    return getProcessorStatus({ movementConfig: this.config, processorType });
  }
}
