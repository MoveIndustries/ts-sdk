import { MovementConfig } from "../api/movementConfig";
import { postAptosFullNode } from "../client";
import {
  GetTableItemsDataResponse,
  GetTableItemsMetadataResponse,
  LedgerVersionArg,
  OrderByArg,
  PaginationArgs,
  TableItemRequest,
  WhereArg,
} from "../types";
import { GetTableItemsDataQuery, GetTableItemsMetadataQuery } from "../types/generated/operations";
import { GetTableItemsData, GetTableItemsMetadata } from "../types/generated/queries";
import { TableItemsBoolExp, TableMetadatasBoolExp } from "../types/generated/types";
import { queryIndexer } from "./general";

/**
 * Retrieves a specific item from a table in the Movement blockchain.
 *
 * @param args - The arguments for retrieving the table item.
 * @param args.movementConfig - The configuration for connecting to the Movement blockchain.
 * @param args.handle - The identifier for the table from which to retrieve the item.
 * @param args.data - The request data for the table item.
 * @param args.options - Optional parameters for the request, including ledger version.
 * @group Implementation
 */
export async function getTableItem<T>(args: {
  movementConfig: MovementConfig;
  handle: string;
  data: TableItemRequest;
  options?: LedgerVersionArg;
}): Promise<T> {
  const { movementConfig, handle, data, options } = args;
  const response = await postAptosFullNode<TableItemRequest, any>({
    movementConfig,
    originMethod: "getTableItem",
    path: `tables/${handle}/item`,
    params: { ledger_version: options?.ledgerVersion },
    body: data,
  });
  return response.data as T;
}

/**
 * Retrieves table items data based on specified conditions and pagination options.
 *
 * @param args - The arguments for retrieving table items data.
 * @param args.movementConfig - The configuration object for Movement.
 * @param args.options - Optional parameters for pagination and filtering.
 * @param args.options.offset - The number of items to skip before starting to collect the result set.
 * @param args.options.limit - The maximum number of items to return.
 * @param args.options.where - Conditions to filter the table items.
 * @param args.options.orderBy - The criteria to sort the results.
 * @group Implementation
 */
export async function getTableItemsData(args: {
  movementConfig: MovementConfig;
  options?: PaginationArgs & WhereArg<TableItemsBoolExp> & OrderByArg<GetTableItemsDataResponse[0]>;
}) {
  const { movementConfig, options } = args;

  const graphqlQuery = {
    query: GetTableItemsData,
    variables: {
      where_condition: options?.where,
      offset: options?.offset,
      limit: options?.limit,
      order_by: options?.orderBy,
    },
  };

  const data = await queryIndexer<GetTableItemsDataQuery>({
    movementConfig,
    query: graphqlQuery,
    originMethod: "getTableItemsData",
  });

  return data.table_items;
}

/**
 * Retrieves metadata for table items based on specified options.
 *
 * @param args - The arguments for retrieving table items metadata.
 * @param args.movementConfig - The configuration object for Movement.
 * @param args.options - Optional parameters for pagination and filtering.
 * @param args.options.offset - The number of items to skip before starting to collect the result set.
 * @param args.options.limit - The maximum number of items to return.
 * @param args.options.where - Conditions to filter the results.
 * @param args.options.orderBy - The order in which to return the results.
 * @returns A promise that resolves to an array of table metadata.
 * @group Implementation
 */
export async function getTableItemsMetadata(args: {
  movementConfig: MovementConfig;
  options?: PaginationArgs & WhereArg<TableMetadatasBoolExp> & OrderByArg<GetTableItemsMetadataResponse[0]>;
}): Promise<GetTableItemsMetadataResponse> {
  const { movementConfig, options } = args;

  const graphqlQuery = {
    query: GetTableItemsMetadata,
    variables: {
      where_condition: options?.where,
      offset: options?.offset,
      limit: options?.limit,
      order_by: options?.orderBy,
    },
  };

  const data = await queryIndexer<GetTableItemsMetadataQuery>({
    movementConfig,
    query: graphqlQuery,
    originMethod: "getTableItemsMetadata",
  });

  return data.table_metadatas;
}
