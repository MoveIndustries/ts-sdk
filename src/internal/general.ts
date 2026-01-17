// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

/**
 * This file contains the underlying implementations for exposed API surface in
 * the {@link api/general}. By moving the methods out into a separate file,
 * other namespaces and processes can access these methods without depending on the entire
 * general namespace and without having a dependency cycle error.
 * @group Implementation
 */

import { MovementConfig } from "../api/movementConfig";
import { getAptosFullNode, postAptosIndexer } from "../client";
import { GetChainTopUserTransactionsResponse, GetProcessorStatusResponse, GraphqlQuery, LedgerInfo } from "../types";
import { GetChainTopUserTransactionsQuery, GetProcessorStatusQuery } from "../types/generated/operations";
import { GetChainTopUserTransactions, GetProcessorStatus } from "../types/generated/queries";
import { ProcessorType } from "../utils/const";

/**
 * Retrieves information about the current ledger.
 *
 * @param args - The arguments for retrieving ledger information.
 * @param args.movementConfig - The configuration object for connecting to the Movement network.
 * @group Implementation
 */
export async function getLedgerInfo(args: { movementConfig: MovementConfig }): Promise<LedgerInfo> {
  const { movementConfig } = args;
  const { data } = await getAptosFullNode<{}, LedgerInfo>({
    movementConfig,
    originMethod: "getLedgerInfo",
    path: "",
  });
  return data;
}

/**
 * Retrieves the top user transactions for a specific blockchain chain.
 *
 * @param args - The arguments for the function.
 * @param args.movementConfig - The configuration object for Movement.
 * @param args.limit - The maximum number of transactions to retrieve.
 * @returns An array of user transactions.
 * @group Implementation
 */
export async function getChainTopUserTransactions(args: {
  movementConfig: MovementConfig;
  limit: number;
}): Promise<GetChainTopUserTransactionsResponse> {
  const { movementConfig, limit } = args;
  const graphqlQuery = {
    query: GetChainTopUserTransactions,
    variables: { limit },
  };

  const data = await queryIndexer<GetChainTopUserTransactionsQuery>({
    movementConfig,
    query: graphqlQuery,
    originMethod: "getChainTopUserTransactions",
  });

  return data.user_transactions;
}

/**
 * Executes a GraphQL query against the Movement indexer and retrieves the resulting data.
 *
 * @param args - The arguments for the query.
 * @param args.movementConfig - The configuration settings for the Movement client.
 * @param args.query - The GraphQL query to be executed.
 * @param args.originMethod - An optional string to specify the origin method for tracking purposes.
 * @returns The data returned from the query execution.
 * @group Implementation
 */
export async function queryIndexer<T extends {}>(args: {
  movementConfig: MovementConfig;
  query: GraphqlQuery;
  originMethod?: string;
}): Promise<T> {
  const { movementConfig, query, originMethod } = args;
  const { data } = await postAptosIndexer<GraphqlQuery, T>({
    movementConfig,
    originMethod: originMethod ?? "queryIndexer",
    path: "",
    body: query,
    overrides: { WITH_CREDENTIALS: false },
  });
  return data;
}

/**
 * Retrieves the current statuses of processors.
 *
 * @param args - The arguments for the function.
 * @param args.movementConfig - The configuration object for Movement.
 * @returns The statuses of the processors.
 * @group Implementation
 */
export async function getProcessorStatuses(args: { movementConfig: MovementConfig }): Promise<GetProcessorStatusResponse> {
  const { movementConfig } = args;

  const graphqlQuery = {
    query: GetProcessorStatus,
  };

  const data = await queryIndexer<GetProcessorStatusQuery>({
    movementConfig,
    query: graphqlQuery,
    originMethod: "getProcessorStatuses",
  });

  return data.processor_status;
}

/**
 * Retrieves the last success version from the indexer.
 *
 * @param args - The arguments for the function.
 * @param args.movementConfig - The configuration object for Movement.
 * @returns The last success version as a BigInt.
 * @group Implementation
 */
export async function getIndexerLastSuccessVersion(args: { movementConfig: MovementConfig }): Promise<bigint> {
  const response = await getProcessorStatuses({ movementConfig: args.movementConfig });
  return BigInt(response[0].last_success_version);
}

/**
 * Retrieves the status of a specified processor in the Movement network.
 * This function allows you to check the current operational status of a processor, which can be useful for monitoring and troubleshooting.
 *
 * @param args - The arguments for the function.
 * @param args.movementConfig - The configuration object for connecting to the Movement network.
 * @param args.processorType - The type of processor whose status you want to retrieve.
 * @returns The status of the specified processor.
 * @group Implementation
 */
export async function getProcessorStatus(args: {
  movementConfig: MovementConfig;
  processorType: ProcessorType;
}): Promise<GetProcessorStatusResponse[0]> {
  const { movementConfig, processorType } = args;

  const whereCondition: { processor: { _eq: string } } = {
    processor: { _eq: processorType },
  };

  const graphqlQuery = {
    query: GetProcessorStatus,
    variables: {
      where_condition: whereCondition,
    },
  };

  const data = await queryIndexer<GetProcessorStatusQuery>({
    movementConfig,
    query: graphqlQuery,
    originMethod: "getProcessorStatus",
  });

  return data.processor_status[0];
}
