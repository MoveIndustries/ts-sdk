// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

/**
 * This file contains the underlying implementations for exposed API surface in
 * the {@link api/account}. By moving the methods out into a separate file,
 * other namespaces and processes can access these methods without depending on the entire
 * account namespace and without having a dependency cycle error.
 * @group Implementation
 */
import {
  Account,
  Ed25519Account,
  FederatedKeylessAccount,
  KeylessAccount,
  MultiEd25519Account,
  MultiKeyAccount,
  SingleKeyAccount,
} from "../account";
import { MovementConfig } from "../api/movementConfig";
import { Deserializer, MoveVector, U8 } from "../bcs";
import {
  getAptosFullNode,
  getPageWithObfuscatedCursor,
  paginateWithCursor,
  paginateWithObfuscatedCursor,
} from "../client";
import { AuthenticationKey, createObjectAddress, Ed25519PrivateKey, Hex, Secp256k1PrivateKey } from "../core";
import { AccountAddress, AccountAddressInput } from "../core/accountAddress";
import {
  AbstractMultiKey,
  AccountPublicKey,
  AnyPublicKey,
  BaseAccountPublicKey,
  Ed25519PublicKey,
  MultiEd25519PublicKey,
  MultiKey,
  PrivateKeyInput,
} from "../core/crypto";
import { accountPublicKeyToBaseAccountPublicKey, accountPublicKeyToSigningScheme } from "../core/crypto/utils";
import { MovementApiError } from "../errors";
import {
  EntryFunctionABI,
  InputGenerateTransactionOptions,
  RotationProofChallenge,
  SimpleTransaction,
  TypeTagU8,
  TypeTagVector,
} from "../transactions";
import {
  AccountData,
  anyPublicKeyVariantToString,
  CommittedTransactionResponse,
  CursorPaginationArgs,
  GetAccountCoinsDataResponse,
  GetAccountCollectionsWithOwnedTokenResponse,
  GetAccountOwnedTokensFromCollectionResponse,
  GetAccountOwnedTokensQueryResponse,
  GetObjectDataQueryResponse,
  LedgerVersionArg,
  MoveModuleBytecode,
  MoveResource,
  MoveStructId,
  OrderByArg,
  PaginationArgs,
  TokenStandardArg,
  WhereArg
} from "../types";
import {
  GetAccountAddressesForAuthKeyQuery,
  GetAccountCoinsCountQuery,
  GetAccountCoinsDataQuery,
  GetAccountCollectionsWithOwnedTokensQuery,
  GetAccountOwnedTokensFromCollectionQuery,
  GetAccountOwnedTokensQuery,
  GetAccountTokensCountQuery,
  GetAccountTransactionsCountQuery,
  GetAuthKeysForPublicKeyQuery,
  GetObjectDataQuery,
} from "../types/generated/operations";
import {
  GetAccountAddressesForAuthKey,
  GetAccountCoinsCount,
  GetAccountCoinsData,
  GetAccountCollectionsWithOwnedTokens,
  GetAccountOwnedTokens,
  GetAccountOwnedTokensFromCollection,
  GetAccountTokensCount,
  GetAccountTransactionsCount,
  GetAuthKeysForPublicKey,
  GetObjectData,
} from "../types/generated/queries";
import { CurrentFungibleAssetBalancesBoolExp } from "../types/generated/types";
import { MOVEMENT_COIN } from "../utils";
import { queryIndexer } from "./general";
import { getTableItem } from "./table";
import { generateTransaction } from "./transactionSubmission";
import { getInfo as getInfoUtil, getModule as getModuleUtil } from "./utils";

/**
 * Retrieves account information for a specified account address.
 *
 * @param args - The arguments for retrieving account information.
 * @param args.movementConfig - The configuration object for Movement.
 * @param args.accountAddress - The address of the account to retrieve information for.
 * @group Implementation
 */
export async function getInfo(args: {
  movementConfig: MovementConfig;
  accountAddress: AccountAddressInput;
}): Promise<AccountData> {
  return getInfoUtil(args);
}

/**
 * Retrieves the modules associated with a specified account address.
 *
 * @param args - The arguments for retrieving modules.
 * @param args.movementConfig - The configuration for connecting to the Movement blockchain.
 * @param args.accountAddress - The address of the account whose modules are to be retrieved.
 * @param args.options - Optional parameters for pagination and ledger version.
 * @param args.options.limit - The maximum number of modules to retrieve (default is 1000).
 * @param args.options.offset - The starting point for pagination.  Note, this is obfuscated and is not an index.
 * @param args.options.ledgerVersion - The specific ledger version to query.
 * @group Implementation
 */
export async function getModules(args: {
  movementConfig: MovementConfig;
  accountAddress: AccountAddressInput;
  options?: { limit?: number } & LedgerVersionArg;
}): Promise<MoveModuleBytecode[]> {
  const { movementConfig, accountAddress, options } = args;
  return paginateWithObfuscatedCursor<{}, MoveModuleBytecode[]>({
    movementConfig,
    originMethod: "getModules",
    path: `accounts/${AccountAddress.from(accountAddress).toString()}/modules`,
    params: {
      ledger_version: options?.ledgerVersion,
      limit: options?.limit ?? 1000,
    },
  });
}

/**
 * Retrieves the modules associated with a specified account address.
 *
 * @param args - The arguments for retrieving modules.
 * @param args.movementConfig - The configuration for connecting to the Movement blockchain.
 * @param args.accountAddress - The address of the account whose modules are to be retrieved.
 * @param args.options - Optional parameters for pagination and ledger version.
 * @param args.options.cursor - The starting point for pagination.  Note, this is obfuscated and is not an index.
 * @param args.options.limit - The maximum number of modules to retrieve (default is 100).
 * @param args.options.ledgerVersion - The specific ledger version to query.
 * @group Implementation
 */
export async function getModulesPage(args: {
  movementConfig: MovementConfig;
  accountAddress: AccountAddressInput;
  options?: CursorPaginationArgs & LedgerVersionArg;
}): Promise<{ modules: MoveModuleBytecode[]; cursor: string | undefined }> {
  const { movementConfig, accountAddress, options } = args;
  const { response, cursor } = await getPageWithObfuscatedCursor<{}, MoveModuleBytecode[]>({
    movementConfig,
    originMethod: "getModulesPage",
    path: `accounts/${AccountAddress.from(accountAddress).toString()}/modules`,
    params: {
      ledger_version: options?.ledgerVersion,
      cursor: options?.cursor,
      limit: options?.limit ?? 100,
    },
  });

  return { modules: response.data, cursor };
}

/**
 * Queries for a move module given an account address and module name.
 * This function can help you retrieve the module's ABI and other relevant information.
 *
 * @param args - The arguments for retrieving the module.
 * @param args.movementConfig - The configuration for the Movement client.
 * @param args.accountAddress - The account address in hex-encoded 32 byte format.
 * @param args.moduleName - The name of the module to retrieve.
 * @param args.options - Optional parameters for the request.
 * @param args.options.ledgerVersion - Specifies the ledger version of transactions. By default, the latest version will be used.
 * @returns The move module.
 * @group Implementation
 */
export async function getModule(args: {
  movementConfig: MovementConfig;
  accountAddress: AccountAddressInput;
  moduleName: string;
  options?: LedgerVersionArg;
}): Promise<MoveModuleBytecode> {
  return getModuleUtil(args);
}

/**
 * Retrieves a list of transactions associated with a specific account address.
 * This function allows you to paginate through the transactions for better performance and usability.
 *
 * @param args - The arguments for retrieving transactions.
 * @param args.movementConfig - The configuration settings for Movement.
 * @param args.accountAddress - The account address for which to retrieve transactions.
 * @param args.options - Optional pagination parameters.
 * @param args.options.offset - The starting point for pagination.
 * @param args.options.limit - The maximum number of transactions to retrieve.
 * @group Implementation
 */
export async function getTransactions(args: {
  movementConfig: MovementConfig;
  accountAddress: AccountAddressInput;
  options?: PaginationArgs;
}): Promise<CommittedTransactionResponse[]> {
  const { movementConfig, accountAddress, options } = args;
  return paginateWithCursor<{}, CommittedTransactionResponse[]>({
    movementConfig,
    originMethod: "getTransactions",
    path: `accounts/${AccountAddress.from(accountAddress).toString()}/transactions`,
    params: { start: options?.offset, limit: options?.limit },
  });
}

/**
 * Retrieves a list of resources associated with a specific account address.
 *
 * @param args - The arguments for retrieving resources.
 * @param args.movementConfig - The configuration settings for Movement.
 * @param args.accountAddress - The address of the account to fetch resources for.
 * @param args.options - Optional pagination and ledger version parameters.
 * @param args.options.limit - The maximum number of resources to retrieve (default is 999).
 * @param args.options.ledgerVersion - The specific ledger version to query.
 * @group Implementation
 */
export async function getResources(args: {
  movementConfig: MovementConfig;
  accountAddress: AccountAddressInput;
  options?: { limit?: number } & LedgerVersionArg;
}): Promise<MoveResource[]> {
  const { movementConfig, accountAddress, options } = args;
  return paginateWithObfuscatedCursor<{}, MoveResource[]>({
    movementConfig,
    originMethod: "getResources",
    path: `accounts/${AccountAddress.from(accountAddress).toString()}/resources`,
    params: {
      ledger_version: options?.ledgerVersion,
      limit: options?.limit ?? 999,
    },
  });
}

/**
 * Retrieves a page of resources associated with a specific account address.
 *
 * @param args - The arguments for retrieving resources.
 * @param args.movementConfig - The configuration settings for Movement.
 * @param args.accountAddress - The address of the account to fetch resources for.
 * @param args.options - Optional pagination and ledger version parameters.
 * @param args.options.cursor - The starting point for pagination.  Note, this is obfuscated and is not an index.
 * @param args.options.limit - The maximum number of resources to retrieve (default is 100).
 * @param args.options.ledgerVersion - The specific ledger version to query.
 * @group Implementation
 */
export async function getResourcesPage(args: {
  movementConfig: MovementConfig;
  accountAddress: AccountAddressInput;
  options?: CursorPaginationArgs & LedgerVersionArg;
}): Promise<{ resources: MoveResource[]; cursor: string | undefined }> {
  const { movementConfig, accountAddress, options } = args;
  const { response, cursor } = await getPageWithObfuscatedCursor<{}, MoveResource[]>({
    movementConfig,
    originMethod: "getResourcesPage",
    path: `accounts/${AccountAddress.from(accountAddress).toString()}/resources`,
    params: {
      ledger_version: options?.ledgerVersion,
      cursor: options?.cursor,
      limit: options?.limit ?? 100,
    },
  });

  return { resources: response.data, cursor };
}

/**
 * Retrieves a specific resource of a given type for the specified account address.
 *
 * @param args - The arguments for retrieving the resource.
 * @param args.movementConfig - The configuration settings for Movement.
 * @param args.accountAddress - The address of the account from which to retrieve the resource.
 * @param args.resourceType - The type of the resource to retrieve, specified as a MoveStructId.
 * @param args.options - Optional parameters for specifying the ledger version.
 * @group Implementation
 */
export async function getResource<T extends {}>(args: {
  movementConfig: MovementConfig;
  accountAddress: AccountAddressInput;
  resourceType: MoveStructId;
  options?: LedgerVersionArg;
}): Promise<T> {
  const { movementConfig, accountAddress, resourceType, options } = args;
  const { data } = await getAptosFullNode<{}, MoveResource>({
    movementConfig,
    originMethod: "getResource",
    path: `accounts/${AccountAddress.from(accountAddress).toString()}/resource/${resourceType}`,
    params: { ledger_version: options?.ledgerVersion },
  });
  return data.data as T;
}

/**
 * Retrieves the original account address associated with a given authentication key, which is useful for handling key rotations.
 *
 * @param args - The arguments for the lookup.
 * @param args.movementConfig - The configuration for the Movement client.
 * @param args.authenticationKey - The authentication key for which to look up the original address.
 * @param args.options - Optional parameters for specifying the ledger version.
 * @returns The original account address or the provided authentication key address if not found.
 * @throws Throws an error if the lookup fails for reasons other than the address not being found.
 * @group Implementation
 */
export async function lookupOriginalAccountAddress(args: {
  movementConfig: MovementConfig;
  authenticationKey: AccountAddressInput;
  options?: LedgerVersionArg;
}): Promise<AccountAddress> {
  const { movementConfig, authenticationKey, options } = args;
  type OriginatingAddress = {
    address_map: { handle: string };
  };
  const resource = await getResource<OriginatingAddress>({
    movementConfig,
    accountAddress: "0x1",
    resourceType: "0x1::account::OriginatingAddress",
    options,
  });

  const {
    address_map: { handle },
  } = resource;

  const authKeyAddress = AccountAddress.from(authenticationKey);

  // If the address is not found in the address map, which means its not rotated
  // then return the address as is
  try {
    const originalAddress = await getTableItem<string>({
      movementConfig,
      handle,
      data: {
        key: authKeyAddress.toString(),
        key_type: "address",
        value_type: "address",
      },
      options,
    });

    return AccountAddress.from(originalAddress);
  } catch (err) {
    if (err instanceof MovementApiError && err.data.error_code === "table_item_not_found") {
      return authKeyAddress;
    }

    throw err;
  }
}

/**
 * Retrieves the count of tokens owned by a specific account address.
 *
 * @param args - The arguments for retrieving the account tokens count.
 * @param args.movementConfig - The configuration settings for the Movement network.
 * @param args.accountAddress - The address of the account for which to count the tokens.
 * @returns The count of tokens owned by the specified account.
 * @group Implementation
 */
export async function getAccountTokensCount(args: {
  movementConfig: MovementConfig;
  accountAddress: AccountAddressInput;
}): Promise<number> {
  const { movementConfig, accountAddress } = args;

  const address = AccountAddress.from(accountAddress).toStringLong();

  const whereCondition: { owner_address: { _eq: string }; amount: { _gt: number } } = {
    owner_address: { _eq: address },
    amount: { _gt: 0 },
  };

  const graphqlQuery = {
    query: GetAccountTokensCount,
    variables: { where_condition: whereCondition },
  };

  const data = await queryIndexer<GetAccountTokensCountQuery>({
    movementConfig,
    query: graphqlQuery,
    originMethod: "getAccountTokensCount",
  });

  // commonjs (aka cjs) doesn't handle Nullish Coalescing for some reason
  // might be because of how ts infer the graphql generated scheme type
  return data.current_token_ownerships_v2_aggregate.aggregate
    ? data.current_token_ownerships_v2_aggregate.aggregate.count
    : 0;
}

/**
 * Retrieves the tokens owned by a specified account address.
 *
 * @param args - The arguments for retrieving the account's tokens.
 * @param args.movementConfig - The configuration for the Movement client.
 * @param args.accountAddress - The address of the account whose tokens are being queried.
 * @param args.options - Optional parameters for filtering and pagination.
 * @param args.options.tokenStandard - The specific token standard to filter the results.
 * @param args.options.offset - The number of records to skip before starting to collect the result set.
 * @param args.options.limit - The maximum number of records to return.
 * @param args.options.orderBy - The criteria for ordering the results.
 * @returns A promise that resolves to the current token ownerships of the specified account.
 * @group Implementation
 */
export async function getAccountOwnedTokens(args: {
  movementConfig: MovementConfig;
  accountAddress: AccountAddressInput;
  options?: TokenStandardArg & PaginationArgs & OrderByArg<GetAccountOwnedTokensQueryResponse[0]>;
}): Promise<GetAccountOwnedTokensQueryResponse> {
  const { movementConfig, accountAddress, options } = args;
  const address = AccountAddress.from(accountAddress).toStringLong();

  const whereCondition: { owner_address: { _eq: string }; amount: { _gt: number }; token_standard?: { _eq: string } } =
  {
    owner_address: { _eq: address },
    amount: { _gt: 0 },
  };

  if (options?.tokenStandard) {
    whereCondition.token_standard = { _eq: options?.tokenStandard };
  }

  const graphqlQuery = {
    query: GetAccountOwnedTokens,
    variables: {
      where_condition: whereCondition,
      offset: options?.offset,
      limit: options?.limit,
      order_by: options?.orderBy,
    },
  };

  const data = await queryIndexer<GetAccountOwnedTokensQuery>({
    movementConfig,
    query: graphqlQuery,
    originMethod: "getAccountOwnedTokens",
  });

  return data.current_token_ownerships_v2;
}

/**
 * Retrieves the tokens owned by a specific account from a particular collection address.
 *
 * @param args - The parameters required to fetch the owned tokens.
 * @param args.movementConfig - The Movement configuration object.
 * @param args.accountAddress - The address of the account whose tokens are being queried.
 * @param args.collectionAddress - The address of the collection from which tokens are being retrieved.
 * @param args.options - Optional parameters for filtering and pagination, including token standard, pagination arguments, and
 * order by options.
 * @group Implementation
 */
export async function getAccountOwnedTokensFromCollectionAddress(args: {
  movementConfig: MovementConfig;
  accountAddress: AccountAddressInput;
  collectionAddress: AccountAddressInput;
  options?: TokenStandardArg & PaginationArgs & OrderByArg<GetAccountOwnedTokensFromCollectionResponse[0]>;
}): Promise<GetAccountOwnedTokensFromCollectionResponse> {
  const { movementConfig, accountAddress, collectionAddress, options } = args;
  const ownerAddress = AccountAddress.from(accountAddress).toStringLong();
  const collAddress = AccountAddress.from(collectionAddress).toStringLong();

  const whereCondition: {
    owner_address: { _eq: string };
    current_token_data: { collection_id: { _eq: string } };
    amount: { _gt: number };
    token_standard?: { _eq: string };
  } = {
    owner_address: { _eq: ownerAddress },
    current_token_data: { collection_id: { _eq: collAddress } },
    amount: { _gt: 0 },
  };

  if (options?.tokenStandard) {
    whereCondition.token_standard = { _eq: options?.tokenStandard };
  }

  const graphqlQuery = {
    query: GetAccountOwnedTokensFromCollection,
    variables: {
      where_condition: whereCondition,
      offset: options?.offset,
      limit: options?.limit,
      order_by: options?.orderBy,
    },
  };

  const data = await queryIndexer<GetAccountOwnedTokensFromCollectionQuery>({
    movementConfig,
    query: graphqlQuery,
    originMethod: "getAccountOwnedTokensFromCollectionAddress",
  });

  return data.current_token_ownerships_v2;
}

/**
 * Retrieves the collections owned by a specified account along with the tokens in those collections.
 *
 * @param args - The arguments for the function.
 * @param args.movementConfig - The configuration for the Movement client.
 * @param args.accountAddress - The address of the account whose collections are being queried.
 * @param args.options - Optional parameters for filtering and pagination.
 * @param args.options.tokenStandard - An optional token standard to filter the collections.
 * @param args.options.offset - An optional offset for pagination.
 * @param args.options.limit - An optional limit for the number of results returned.
 * @param args.options.orderBy - An optional parameter to specify the order of the results.
 * @group Implementation
 */
export async function getAccountCollectionsWithOwnedTokens(args: {
  movementConfig: MovementConfig;
  accountAddress: AccountAddressInput;
  options?: TokenStandardArg & PaginationArgs & OrderByArg<GetAccountCollectionsWithOwnedTokenResponse[0]>;
}): Promise<GetAccountCollectionsWithOwnedTokenResponse> {
  const { movementConfig, accountAddress, options } = args;
  const address = AccountAddress.from(accountAddress).toStringLong();

  const whereCondition: {
    owner_address: { _eq: string };
    current_collection?: { token_standard: { _eq: string } };
  } = {
    owner_address: { _eq: address },
  };

  if (options?.tokenStandard) {
    whereCondition.current_collection = {
      token_standard: { _eq: options?.tokenStandard },
    };
  }

  const graphqlQuery = {
    query: GetAccountCollectionsWithOwnedTokens,
    variables: {
      where_condition: whereCondition,
      offset: options?.offset,
      limit: options?.limit,
      order_by: options?.orderBy,
    },
  };

  const data = await queryIndexer<GetAccountCollectionsWithOwnedTokensQuery>({
    movementConfig,
    query: graphqlQuery,
    originMethod: "getAccountCollectionsWithOwnedTokens",
  });

  return data.current_collection_ownership_v2_view;
}

/**
 * Retrieves the count of transactions associated with a specified account.
 *
 * @param args - The arguments for the function.
 * @param args.movementConfig - The configuration settings for Movement.
 * @param args.accountAddress - The address of the account for which to retrieve the transaction count.
 * @returns The number of transactions associated with the specified account.
 * @group Implementation
 */
export async function getAccountTransactionsCount(args: {
  movementConfig: MovementConfig;
  accountAddress: AccountAddressInput;
}): Promise<number> {
  const { movementConfig, accountAddress } = args;

  const address = AccountAddress.from(accountAddress).toStringLong();

  const graphqlQuery = {
    query: GetAccountTransactionsCount,
    variables: { address },
  };

  const data = await queryIndexer<GetAccountTransactionsCountQuery>({
    movementConfig,
    query: graphqlQuery,
    originMethod: "getAccountTransactionsCount",
  });

  // commonjs (aka cjs) doesn't handle Nullish Coalescing for some reason
  // might be because of how ts infer the graphql generated scheme type
  return data.account_transactions_aggregate.aggregate ? data.account_transactions_aggregate.aggregate.count : 0;
}

/**
 * Retrieves the amount of a specific coin held by an account.
 *
 * @param args - The parameters for the request.
 * @param args.movementConfig - The Movement configuration object.
 * @param args.accountAddress - The address of the account to query.
 * @param args.coinType - Optional; the type of coin to check the amount for.
 * @param args.faMetadataAddress - Optional; the address of the fungible asset metadata.
 * @returns The amount of the specified coin held by the account, or 0 if none is found.
 * @throws Error if neither coinType nor faMetadataAddress is provided.
 * @group Implementation
 */
export async function getAccountCoinAmount(args: {
  movementConfig: MovementConfig;
  accountAddress: AccountAddressInput;
  coinType?: MoveStructId;
  faMetadataAddress?: AccountAddressInput;
}): Promise<number> {
  const { movementConfig, accountAddress, coinType, faMetadataAddress } = args;

  let coinAssetType: string | undefined = coinType;
  let faAddress: string;

  if (coinType !== undefined && faMetadataAddress !== undefined) {
    faAddress = AccountAddress.from(faMetadataAddress).toStringLong();
  } else if (coinType !== undefined && faMetadataAddress === undefined) {
    // TODO Move to a separate function as defined in the AIP for coin migration
    if (coinType === MOVEMENT_COIN) {
      faAddress = AccountAddress.A.toStringLong();
    } else {
      faAddress = createObjectAddress(AccountAddress.A, coinType).toStringLong();
    }
  } else if (coinType === undefined && faMetadataAddress !== undefined) {
    const addr = AccountAddress.from(faMetadataAddress);
    faAddress = addr.toStringLong();
    if (addr === AccountAddress.A) {
      coinAssetType = MOVEMENT_COIN;
    }
    // The paired CoinType should be populated outside of this function in another
    // async call. We cannot do this internally due to dependency cycles issue.
  } else {
    throw new Error("Either coinType, fungibleAssetAddress, or both must be provided");
  }
  const address = AccountAddress.from(accountAddress).toStringLong();

  // Search by fungible asset address, unless it has a coin it migrated from
  let where: any = { asset_type: { _eq: faAddress } };
  if (coinAssetType !== undefined) {
    where = { asset_type: { _in: [coinAssetType, faAddress] } };
  }

  const data = await getAccountCoinsData({
    movementConfig,
    accountAddress: address,
    options: {
      where,
    },
  });

  // commonjs (aka cjs) doesn't handle Nullish Coalescing for some reason
  // might be because of how ts infer the graphql generated scheme type
  return data[0] ? data[0].amount : 0;
}

/**
 * Retrieves the current fungible asset balances for a specified account.
 *
 * @param args - The arguments for retrieving account coins data.
 * @param args.movementConfig - The configuration for connecting to the Movement network.
 * @param args.accountAddress - The address of the account for which to retrieve coin data.
 * @param args.options - Optional parameters for pagination and filtering the results.
 * @param args.options.offset - The number of items to skip before starting to collect the result set.
 * @param args.options.limit - The maximum number of items to return.
 * @param args.options.orderBy - The criteria for ordering the results.
 * @param args.options.where - Conditions to filter the results based on the current fungible asset balances.
 * @group Implementation
 */
export async function getAccountCoinsData(args: {
  movementConfig: MovementConfig;
  accountAddress: AccountAddressInput;
  options?: PaginationArgs & OrderByArg<GetAccountCoinsDataResponse[0]> & WhereArg<CurrentFungibleAssetBalancesBoolExp>;
}): Promise<GetAccountCoinsDataResponse> {
  const { movementConfig, accountAddress, options } = args;
  const address = AccountAddress.from(accountAddress).toStringLong();

  const whereCondition: { owner_address: { _eq: string } } = {
    ...options?.where,
    owner_address: { _eq: address },
  };

  const graphqlQuery = {
    query: GetAccountCoinsData,
    variables: {
      where_condition: whereCondition,
      offset: options?.offset,
      limit: options?.limit,
      order_by: options?.orderBy,
    },
  };

  const data = await queryIndexer<GetAccountCoinsDataQuery>({
    movementConfig,
    query: graphqlQuery,
    originMethod: "getAccountCoinsData",
  });

  return data.current_fungible_asset_balances;
}

/**
 * Retrieves the count of fungible asset coins held by a specified account.
 *
 * @param args - The arguments for the function.
 * @param args.movementConfig - The configuration settings for the Movement network.
 * @param args.accountAddress - The address of the account for which to retrieve the coin count.
 * @throws Error if the count of account coins cannot be retrieved.
 * @group Implementation
 */
export async function getAccountCoinsCount(args: {
  movementConfig: MovementConfig;
  accountAddress: AccountAddressInput;
}): Promise<number> {
  const { movementConfig, accountAddress } = args;
  const address = AccountAddress.from(accountAddress).toStringLong();

  const graphqlQuery = {
    query: GetAccountCoinsCount,
    variables: { address },
  };

  const data = await queryIndexer<GetAccountCoinsCountQuery>({
    movementConfig,
    query: graphqlQuery,
    originMethod: "getAccountCoinsCount",
  });

  if (!data.current_fungible_asset_balances_aggregate.aggregate) {
    throw Error("Failed to get the count of account coins");
  }

  return data.current_fungible_asset_balances_aggregate.aggregate.count;
}

/**
 * Retrieves an account's balance for the given asset via the fullnode REST API.
 *
 * - `asset` may be a coin type (Move struct ID, e.g. `0x1::aptos_coin::AptosCoin`) or an FA metadata address.
 * - Calls: `GET /accounts/{accountAddress}/balance/{asset}` and returns the numeric balance.
 *
 * @param args - The parameters for the request.
 * @param args.movementConfig - The Movement configuration object.
 * @param args.accountAddress - The account address to query.
 * @param args.asset - The asset identifier (coin type or FA metadata address).
 * @returns The balance as a number.
 * @group Implementation
 */
export async function getBalance(args: {
  movementConfig: MovementConfig;
  accountAddress: AccountAddressInput;
  asset: MoveStructId | AccountAddressInput;
}): Promise<number> {
  const { movementConfig, accountAddress, asset } = args;

  const response = await getAptosFullNode<{}, number>({
    movementConfig,
    originMethod: "getBalance",
    path: `accounts/${accountAddress}/balance/${asset}`,
    params: {
      accountAddress: accountAddress.toString(),
      asset: asset instanceof Uint8Array ? AccountAddress.from(asset).toString() : asset.toString(),
    },
  });

  return parseInt(response.data.toString(), 10);
}

/**
 * Retrieves the objects owned by a specified account.
 *
 * @param args - The parameters for the request.
 * @param args.movementConfig - The configuration for the Movement client.
 * @param args.accountAddress - The address of the account whose owned objects are to be retrieved.
 * @param args.options - Optional parameters for pagination and ordering of the results.
 * @param args.options.offset - The number of items to skip before starting to collect the result set.
 * @param args.options.limit - The maximum number of items to return.
 * @param args.options.orderBy - The criteria to order the results by.
 * @returns A promise that resolves to the current objects owned by the specified account.
 * @group Implementation
 */
export async function getAccountOwnedObjects(args: {
  movementConfig: MovementConfig;
  accountAddress: AccountAddressInput;
  options?: PaginationArgs & OrderByArg<GetObjectDataQueryResponse[0]>;
}): Promise<GetObjectDataQueryResponse> {
  const { movementConfig, accountAddress, options } = args;
  const address = AccountAddress.from(accountAddress).toStringLong();

  const whereCondition: { owner_address: { _eq: string } } = {
    owner_address: { _eq: address },
  };
  const graphqlQuery = {
    query: GetObjectData,
    variables: {
      where_condition: whereCondition,
      offset: options?.offset,
      limit: options?.limit,
      order_by: options?.orderBy,
    },
  };
  const data = await queryIndexer<GetObjectDataQuery>({
    movementConfig,
    query: graphqlQuery,
    originMethod: "getAccountOwnedObjects",
  });

  return data.current_objects;
}

/**
 * Derives an account from the provided private key and Movement configuration.
 *
 * This function queries all owned accounts for the provided private key and returns the most
 * recently used account. If no account is found, it will throw an error unless `throwIfNoAccountFound` is set to false.
 *
 * If `throwIfNoAccountFound` is set to false, the function will return the default account for the private key via `Account.fromPrivateKey`.
 *
 * NOTE: There is a potential issue once the unified single signer scheme is adopted by the community.
 * Because one could create two accounts with the same private key with this new authenticator type,
 * we'll need to determine the order in which we look up the accounts: first unified scheme and then legacy scheme,
 * or first legacy scheme and then unified scheme.
 *
 * @param args - The arguments for deriving the account.
 * @param args.movementConfig - The Movement configuration used for account lookup.
 * @param args.privateKey - The private key used to derive the account.
 * @param args.options.throwIfNoAccountFound - If true, throw an error if no existing account is found on chain. Default is false.
 * @throws Error if the account cannot be derived from the private key.
 * @group Implementation
 * @deprecated Note that more inspection is needed by the user to determine which account exists on-chain
 */
export async function deriveAccountFromPrivateKey(args: {
  movementConfig: MovementConfig;
  privateKey: PrivateKeyInput;
  options?: {
    throwIfNoAccountFound?: boolean;
  };
}): Promise<Account> {
  const { movementConfig, privateKey, options } = args;
  const throwIfNoAccountFound = options?.throwIfNoAccountFound ?? false;

  const accounts = await deriveOwnedAccountsFromPrivateKey({ movementConfig, privateKey });
  if (accounts.length === 0) {
    if (throwIfNoAccountFound) {
      throw new Error(`No existing account found for private key.`);
    }
    // If no account is found, return the default account. This is a legacy account for Ed25519 private keys.
    return Account.fromPrivateKey({ privateKey });
  }
  return accounts[0];
}

/**
 * Checks if an account exists by verifying its information against the Movement blockchain.
 *
 * @param args - The arguments for the function.
 * @param args.movementConfig - The configuration for connecting to the Movement blockchain.
 * @param args.authKey - The authentication key used to derive the account address.
 * @returns A promise that resolves to a boolean indicating whether the account exists.
 *
 * @throws Throws an Error if there is an issue while looking for account information.
 * @group Implementation
 */
export async function isAccountExist(args: { movementConfig: MovementConfig; authKey: AuthenticationKey }): Promise<boolean> {
  const { movementConfig, authKey } = args;
  const accountAddress = await lookupOriginalAccountAddress({
    movementConfig,
    authenticationKey: authKey.derivedAddress(),
  });

  return doesAccountExistAtAddress({ movementConfig, accountAddress });
}

/**
 * Checks if an account exists at a given address.
 *
 * @param args - The arguments for checking account existence.
 * @param args.movementConfig - The configuration for the Movement client.
 * @param args.accountAddress - The address of the account to check.
 * @param args.options.withAuthKey - An optional authentication key which will also be checked against if provided.
 * @returns A promise that resolves to a boolean indicating whether the account exists.
 * @group Implementation
 */
async function doesAccountExistAtAddress(args: {
  movementConfig: MovementConfig;
  accountAddress: AccountAddress;
  options?: { withAuthKey?: AuthenticationKey };
}): Promise<boolean> {
  const { movementConfig, accountAddress, options } = args;
  try {
    // Get the account resources and the balance of the account.  We need to check both because
    // an account resource can exist with 0 balance and a balance can exist without an account resource (light accounts).
    const [resources, ownedObjects] = await Promise.all([
      getResources({
        movementConfig,
        accountAddress,
      }),
      getAccountOwnedObjects({
        movementConfig,
        accountAddress,
        options: {
          limit: 1,
        },
      }),
    ]);

    const accountResource: MoveResource<{ authentication_key: string }> | undefined = resources.find(
      (r) => r.type === "0x1::account::Account",
    ) as MoveResource<{ authentication_key: string }> | undefined;

    // If the account resource is not found and the balance is 0, then the account does not exist.
    if (!accountResource && ownedObjects.length === 0) {
      return false;
    }

    // If no auth key is provided as an argument, return true.
    if (!options?.withAuthKey) {
      return true;
    }

    // Get the auth key from the account resource if it exists. If the account resource does not exist,
    // then the auth key is the account address by default.
    let authKey;
    if (accountResource) {
      authKey = accountResource.data.authentication_key;
    } else {
      authKey = accountAddress.toStringLong();
    }

    if (authKey !== options.withAuthKey.toString()) {
      return false;
    }

    // Else the account exists and the auth key matches.
    return true;
  } catch (error: any) {
    throw new Error(`Error while checking if account exists at ${accountAddress.toString()}: ${error}`);
  }
}

const rotateAuthKeyAbi: EntryFunctionABI = {
  typeParameters: [],
  parameters: [
    new TypeTagU8(),
    TypeTagVector.u8(),
    new TypeTagU8(),
    TypeTagVector.u8(),
    TypeTagVector.u8(),
    TypeTagVector.u8(),
  ],
};

/**
 * Rotates the authentication key for a given account.
 *
 * @param args - The arguments for rotating the authentication key.
 * @param args.movementConfig - The configuration settings for the Movement network.
 * @param args.fromAccount - The account from which the authentication key will be rotated.
 * @param args.toAccount - (Optional) The target account to rotate to. Required if not using toNewPrivateKey.
 * @param args.toNewPrivateKey - (Optional) The new private key to rotate to. Required if not using toAccount.
 *
 * @remarks
 * This function supports three modes of rotation:
 * 1. Using a target Account object (toAccount)
 * 2. Using a new private key (toNewPrivateKey)
 *
 * @returns A simple transaction object that can be submitted to the network.
 * @throws Error if the rotation fails or verification fails.
 *
 * @group Implementation
 */
export async function rotateAuthKey(
  args: {
    movementConfig: MovementConfig;
    fromAccount: Account;
    options?: InputGenerateTransactionOptions;
  } & ({ toAccount: Ed25519Account | MultiEd25519Account } | { toNewPrivateKey: Ed25519PrivateKey }),
): Promise<SimpleTransaction> {
  const { movementConfig, fromAccount, options } = args;
  if ("toNewPrivateKey" in args) {
    return rotateAuthKeyWithChallenge({
      movementConfig,
      fromAccount,
      toNewPrivateKey: args.toNewPrivateKey,
      options,
    });
  } else if ("toAccount" in args) {
    if (args.toAccount instanceof Ed25519Account) {
      return rotateAuthKeyWithChallenge({
        movementConfig,
        fromAccount,
        toNewPrivateKey: args.toAccount.privateKey,
        options,
      });
    } else {
      return rotateAuthKeyWithChallenge({ movementConfig, fromAccount, toAccount: args.toAccount, options });
    }
  } else {
    throw new Error("Invalid arguments");
  }
}

async function rotateAuthKeyWithChallenge(
  args: {
    movementConfig: MovementConfig;
    fromAccount: Account;
    options?: InputGenerateTransactionOptions;
  } & ({ toNewPrivateKey: Ed25519PrivateKey } | { toAccount: MultiEd25519Account }),
): Promise<SimpleTransaction> {
  const { movementConfig, fromAccount, options } = args;
  const accountInfo = await getInfo({
    movementConfig,
    accountAddress: fromAccount.accountAddress,
  });

  let newAccount: Account;
  if ("toNewPrivateKey" in args) {
    newAccount = Account.fromPrivateKey({ privateKey: args.toNewPrivateKey, legacy: true });
  } else {
    newAccount = args.toAccount;
  }

  const challenge = new RotationProofChallenge({
    sequenceNumber: BigInt(accountInfo.sequence_number),
    originator: fromAccount.accountAddress,
    currentAuthKey: AccountAddress.from(accountInfo.authentication_key),
    newPublicKey: newAccount.publicKey,
  });

  // Sign the challenge
  const challengeHex = challenge.bcsToBytes();
  const proofSignedByCurrentKey = fromAccount.sign(challengeHex);
  const proofSignedByNewKey = newAccount.sign(challengeHex);

  // Generate transaction
  return generateTransaction({
    movementConfig,
    sender: fromAccount.accountAddress,
    data: {
      function: "0x1::account::rotate_authentication_key",
      functionArguments: [
        new U8(fromAccount.signingScheme), // from scheme
        MoveVector.U8(fromAccount.publicKey.toUint8Array()),
        new U8(newAccount.signingScheme), // to scheme
        MoveVector.U8(newAccount.publicKey.toUint8Array()),
        MoveVector.U8(proofSignedByCurrentKey.toUint8Array()),
        MoveVector.U8(proofSignedByNewKey.toUint8Array()),
      ],
      abi: rotateAuthKeyAbi,
    },
    options,
  });
}

const rotateAuthKeyUnverifiedAbi: EntryFunctionABI = {
  typeParameters: [],
  parameters: [new TypeTagU8(), TypeTagVector.u8()],
};

/**
 * Rotates the authentication key for a given account without verifying the new key.
 *
 * @param args - The arguments for rotating the authentication key.
 * @param args.movementConfig - The configuration settings for the Movement network.
 * @param args.fromAccount - The account from which the authentication key will be rotated.
 * @param args.toNewPublicKey - The new public key to rotate to.
 * @returns A simple transaction object that can be submitted to the network.
 * @throws Error if the rotation fails or verification fails.
 *
 * @group Implementation
 */
export async function rotateAuthKeyUnverified(args: {
  movementConfig: MovementConfig;
  fromAccount: Account;
  toNewPublicKey: AccountPublicKey;
  options?: InputGenerateTransactionOptions;
}): Promise<SimpleTransaction> {
  const { movementConfig, fromAccount, toNewPublicKey, options } = args;

  return generateTransaction({
    movementConfig,
    sender: fromAccount.accountAddress,
    data: {
      function: "0x1::account::rotate_authentication_key_from_public_key",
      functionArguments: [
        new U8(accountPublicKeyToSigningScheme(toNewPublicKey)), // to scheme
        MoveVector.U8(accountPublicKeyToBaseAccountPublicKey(toNewPublicKey).toUint8Array()),
      ],
      abi: rotateAuthKeyUnverifiedAbi,
    },
    options,
  });
}

export type AccountInfo = {
  accountAddress: AccountAddress;
  publicKey: BaseAccountPublicKey;
  lastTransactionVersion: number;
};

export async function getAccountsForPublicKey(args: {
  movementConfig: MovementConfig;
  publicKey: BaseAccountPublicKey;
  options?: { includeUnverified?: boolean; noMultiKey?: boolean };
}): Promise<AccountInfo[]> {
  const { movementConfig, publicKey, options } = args;
  const noMultiKey = options?.noMultiKey ?? false;
  if (noMultiKey && publicKey instanceof AbstractMultiKey) {
    throw new Error("Multi-key accounts are not supported when noMultiKey is true.");
  }
  const allPublicKeys: BaseAccountPublicKey[] = [publicKey];

  // For Ed25519, we add the both the legacy Ed25519PublicKey and the new AnyPublicKey form.
  if (publicKey instanceof AnyPublicKey && publicKey.publicKey instanceof Ed25519PublicKey) {
    allPublicKeys.push(publicKey.publicKey);
  } else if (publicKey instanceof Ed25519PublicKey) {
    allPublicKeys.push(new AnyPublicKey(publicKey));
  }

  // Run both operations in parallel
  const [defaultAccountData, multiPublicKeys] = await Promise.all([
    // Check the provided public key for the default account. In the case of Ed25519, this will check both the legacy Ed25519PublicKey
    // and the AnyPublicKey form and may an existing account for each.
    Promise.all(
      allPublicKeys.map(async (publicKey) => {
        const addressAndLastTxnVersion = await getDefaultAccountInfoForPublicKey({ movementConfig, publicKey });
        if (addressAndLastTxnVersion) {
          return { ...addressAndLastTxnVersion, publicKey };
        }
        return undefined;
      }),
    ),
    // Get multi-keys for the provided public key if not already a multi-key.
    !(publicKey instanceof AbstractMultiKey) && !noMultiKey
      ? getMultiKeysForPublicKey({ movementConfig, publicKey, options })
      : Promise.resolve([]),
  ]);

  const result: {
    accountAddress: AccountAddress;
    publicKey: BaseAccountPublicKey;
    lastTransactionVersion: number;
  }[] = [];

  // Add any default accounts that exist to the result.
  for (const data of defaultAccountData) {
    if (data) {
      result.push(data);
    }
  }

  // Add any multi-keys to allPublicKeys
  allPublicKeys.push(...multiPublicKeys);

  // Get a map of the auth key to the public key for all public keys.
  const authKeyToPublicKey = new Map(allPublicKeys.map((key) => [key.authKey().toString(), key]));

  // Get the account addresses for the auth keys.
  const authKeyAccountAddressPairs = await getAccountAddressesForAuthKeys({
    movementConfig,
    authKeys: allPublicKeys.map((key) => key.authKey()),
    options,
  });

  for (const authKeyAccountAddressPair of authKeyAccountAddressPairs) {
    // Skip if the account address is already in the result.
    // This can happen in the rare edge case where the default account has been rotated but has been rotated back to the original auth key.
    if (result.find((r) => r.accountAddress === authKeyAccountAddressPair.accountAddress)) {
      continue;
    }
    // Get the public key for the auth key using the map we created earlier.
    const publicKey = authKeyToPublicKey.get(authKeyAccountAddressPair.authKey.toString());
    if (!publicKey) {
      throw new Error(
        `No publicKey found for authentication key ${authKeyAccountAddressPair.authKey}. This should never happen.`,
      );
    }
    result.push({
      accountAddress: authKeyAccountAddressPair.accountAddress,
      publicKey,
      lastTransactionVersion: authKeyAccountAddressPair.lastTransactionVersion,
    });
  }
  // Sort the result by the last transaction version in descending order (most recent first).
  return result.sort((a, b) => b.lastTransactionVersion - a.lastTransactionVersion);
}

export async function deriveOwnedAccountsFromSigner(args: {
  movementConfig: MovementConfig;
  signer: Account | PrivateKeyInput;
  options?: { includeUnverified?: boolean; noMultiKey?: boolean };
}): Promise<Account[]> {
  const { movementConfig, signer, options } = args;

  if (signer instanceof Ed25519PrivateKey || signer instanceof Secp256k1PrivateKey) {
    return deriveOwnedAccountsFromPrivateKey({ movementConfig, privateKey: signer, options });
  }

  if (signer instanceof Ed25519Account || signer instanceof SingleKeyAccount) {
    return deriveOwnedAccountsFromPrivateKey({ movementConfig, privateKey: signer.privateKey, options });
  }

  if (signer instanceof KeylessAccount || signer instanceof FederatedKeylessAccount) {
    return deriveOwnedAccountsFromKeylessSigner({ movementConfig, keylessAccount: signer, options });
  }

  if (signer instanceof MultiKeyAccount) {
    if (signer.signers.length === 1) {
      return deriveOwnedAccountsFromSigner({ movementConfig, signer: signer.signers[0], options });
    }
  }

  if (signer instanceof MultiEd25519Account) {
    if (signer.signers.length === 1) {
      return deriveOwnedAccountsFromPrivateKey({ movementConfig, privateKey: signer.signers[0], options });
    }
  }

  throw new Error("Unknown signer type");
}

async function deriveOwnedAccountsFromKeylessSigner(args: {
  movementConfig: MovementConfig;
  keylessAccount: KeylessAccount | FederatedKeylessAccount;
  options?: { includeUnverified?: boolean; noMultiKey?: boolean };
}): Promise<Account[]> {
  const { movementConfig, keylessAccount, options } = args;
  const addressesAndPublicKeys = await getAccountsForPublicKey({
    movementConfig,
    publicKey: keylessAccount.getAnyPublicKey(),
    options,
  });

  const keylessAccountParams = {
    proof: keylessAccount.proofOrPromise,
    jwt: keylessAccount.jwt,
    ephemeralKeyPair: keylessAccount.ephemeralKeyPair,
    pepper: keylessAccount.pepper,
    verificationKeyHash: keylessAccount.verificationKeyHash,
  };

  const accounts: Account[] = [];
  for (const { accountAddress, publicKey } of addressesAndPublicKeys) {
    if (publicKey instanceof AbstractMultiKey) {
      if (publicKey.getSignaturesRequired() > 1) {
        continue;
      }
      if (publicKey instanceof MultiEd25519PublicKey) {
        throw new Error("Keyless authentication cannot be used for multi-ed25519 accounts. This should never happen.");
      } else if (publicKey instanceof MultiKey) {
        accounts.push(new MultiKeyAccount({ multiKey: publicKey, signers: [keylessAccount], address: accountAddress }));
      }
    } else {
      if (keylessAccount instanceof FederatedKeylessAccount) {
        accounts.push(
          FederatedKeylessAccount.create({
            ...keylessAccountParams,
            address: accountAddress,
            jwkAddress: keylessAccount.publicKey.jwkAddress,
          }),
        );
      } else {
        accounts.push(
          KeylessAccount.create({
            ...keylessAccountParams,
            address: accountAddress,
          }),
        );
      }
    }
  }
  return accounts;
}

async function deriveOwnedAccountsFromPrivateKey(args: {
  movementConfig: MovementConfig;
  privateKey: Ed25519PrivateKey | Secp256k1PrivateKey;
  options?: { includeUnverified?: boolean; noMultiKey?: boolean };
}): Promise<Account[]> {
  const { movementConfig, privateKey, options } = args;
  const singleKeyAccount = Account.fromPrivateKey({ privateKey, legacy: false });
  const addressesAndPublicKeys = await getAccountsForPublicKey({
    movementConfig,
    publicKey: new AnyPublicKey(privateKey.publicKey()),
    options,
  });

  const accounts: Account[] = [];

  // Iterate through the addressesAndPublicKeys and construct the accounts.
  for (const { accountAddress, publicKey } of addressesAndPublicKeys) {
    if (publicKey instanceof AbstractMultiKey) {
      // Skip multi-key accounts with more than 1 signature required as the user does not have full ownership with just 1 private key.
      if (publicKey.getSignaturesRequired() > 1) {
        continue;
      }
      // Construct the appropriate multi-key type.
      if (publicKey instanceof MultiEd25519PublicKey) {
        accounts.push(
          new MultiEd25519Account({ publicKey, signers: [privateKey as Ed25519PrivateKey], address: accountAddress }),
        );
      } else if (publicKey instanceof MultiKey) {
        accounts.push(
          new MultiKeyAccount({ multiKey: publicKey, signers: [singleKeyAccount], address: accountAddress }),
        );
      }
    } else {
      // Check if the public key is a legacy Ed25519PublicKey, if so, we need to use the legacy account constructor.
      const isLegacy = publicKey instanceof Ed25519PublicKey;
      accounts.push(Account.fromPrivateKey({ privateKey, address: accountAddress, legacy: isLegacy }));
    }
  }
  return accounts;
}

/**
 * Gets the multi-keys for a given public key.
 *
 * This function retrieves the multi-keys that contain the provided public key.
 * It performs the following steps:
 * 1. Constructs a where condition for the public key where the public key matches the provided public key.
 * 2. Queries the indexer for the multi-keys.
 * 3. Returns the multi-keys.
 *
 * @param args.movementConfig - The configuration settings for the Movement network.
 * @param args.publicKey - The public key to get the multi-keys for. This public key cannot itself be a multi-key.
 * @returns The multi-keys (MultiKey or MultiEd25519PublicKey) that contain the given public key.
 */
async function getMultiKeysForPublicKey(args: {
  movementConfig: MovementConfig;
  publicKey: Ed25519PublicKey | AnyPublicKey;
  options?: { includeUnverified?: boolean };
}): Promise<(MultiKey | MultiEd25519PublicKey)[]> {
  const { movementConfig, publicKey, options } = args;
  if (publicKey instanceof AbstractMultiKey) {
    throw new Error("Public key is a multi-key.");
  }
  const includeUnverified = options?.includeUnverified ?? false;
  const anyPublicKey = publicKey instanceof AnyPublicKey ? publicKey : new AnyPublicKey(publicKey);
  const baseKey = anyPublicKey.publicKey;
  const variant = anyPublicKeyVariantToString(anyPublicKey.variant);

  const whereCondition: any = {
    public_key: { _eq: baseKey.toString() },
    public_key_type: { _eq: variant },
    ...(includeUnverified ? {} : { is_public_key_used: { _eq: true } }),
  };

  const graphqlQuery = {
    query: GetAuthKeysForPublicKey,
    variables: {
      where_condition: whereCondition,
    },
  };

  const { public_key_auth_keys: data } = await queryIndexer<GetAuthKeysForPublicKeyQuery>({
    movementConfig,
    query: graphqlQuery,
    originMethod: "getMultiKeysForPublicKey",
  });

  const authKeys = data.map((entry) => {
    switch (entry.signature_type) {
      case "multi_ed25519_signature":
        return MultiEd25519PublicKey.deserializeWithoutLength(Deserializer.fromHex(entry.account_public_key!));
      case "multi_key_signature":
        return MultiKey.deserialize(Deserializer.fromHex(entry.account_public_key!));
      default:
        throw new Error(`Unknown multi-signature type: ${entry.signature_type}`);
    }
  });
  return authKeys;
}

/**
 * Gets the account addresses for the given authentication keys.
 *
 * This function retrieves the account addresses that are associated with the provided authentication keys.
 * It performs the following steps:
 * 1. Constructs a where condition for the authentication keys where auth key matches any of the provided auth keys.
 * 2. Queries the indexer for the account addresses and gets the results ordered by the last transaction version (most recent first).
 * 3. Returns the account addresses.
 *
 * @param args.movementConfig - The configuration settings for the Movement network.
 * @param args.authKeys - The authentication keys to get the account addresses for.
 * @param args.options.includeUnverified - Whether to include unverified accounts in the results. Unverified accounts
 * are accounts that can be authenticated with the signer, but there is no history of the signer using the account.
 * Default is false.
 * @returns The account addresses associated with the given authentication keys.
 */
async function getAccountAddressesForAuthKeys(args: {
  movementConfig: MovementConfig;
  authKeys: AuthenticationKey[];
  options?: { includeUnverified?: boolean };
}): Promise<{ authKey: AuthenticationKey; accountAddress: AccountAddress; lastTransactionVersion: number }[]> {
  const { movementConfig, authKeys, options } = args;
  const includeUnverified = options?.includeUnverified ?? false;
  if (authKeys.length === 0) {
    throw new Error("No authentication keys provided");
  }
  const whereCondition: any = {
    auth_key: { _in: authKeys.map((authKey) => authKey.toString()) },
    ...(includeUnverified ? {} : { is_auth_key_used: { _eq: true } }),
  };

  const graphqlQuery = {
    query: GetAccountAddressesForAuthKey,
    variables: {
      where_condition: whereCondition,
      order_by: [{ last_transaction_version: "desc" }],
    },
  };
  const { auth_key_account_addresses: data } = await queryIndexer<GetAccountAddressesForAuthKeyQuery>({
    movementConfig,
    query: graphqlQuery,
    originMethod: "getAccountAddressesForAuthKeys",
  });
  return data.map((entry) => ({
    authKey: new AuthenticationKey({ data: entry.auth_key }),
    accountAddress: new AccountAddress(Hex.hexInputToUint8Array(entry.account_address)),
    lastTransactionVersion: Number(entry.last_transaction_version),
  }));
}

/**
 * Returns the last transaction version that was signed by an account.
 *
 * If an account was created but has not signed any transactions, the last transaction version will be 0.
 *
 * @param args.movementConfig - The configuration settings for the Movement network.
 * @param args.accountAddress - The account address to get the latest transaction version for.
 * @returns The last transaction version that was signed by the account.
 */
async function getLatestTransactionVersionForAddress(args: {
  movementConfig: MovementConfig;
  accountAddress: AccountAddressInput;
}): Promise<number> {
  const { movementConfig, accountAddress } = args;
  const transactions = await getTransactions({ movementConfig, accountAddress, options: { limit: 1 } });
  if (transactions.length === 0) {
    return 0;
  }
  return Number(transactions[0].version);
}

/**
 * Gets the default account info for a given public key. 'Default account' means the account
 * is address is the same as the auth key derived from the public key and the account auth key has
 * not been rotated.
 *
 * @param args - The arguments for getting the default account info for a given public key.
 * @param args.movementConfig - The configuration settings for the Movement network.
 * @param args.publicKey - The public key to use to derive the address.
 * @returns An object containing the account address and the last transaction version, or undefined if the account does not exist.
 */
async function getDefaultAccountInfoForPublicKey(args: {
  movementConfig: MovementConfig;
  publicKey: AccountPublicKey;
}): Promise<{ accountAddress: AccountAddress; lastTransactionVersion: number } | undefined> {
  const { movementConfig, publicKey } = args;
  const derivedAddress = publicKey.authKey().derivedAddress();

  const [lastTransactionVersion, exists] = await Promise.all([
    getLatestTransactionVersionForAddress({
      movementConfig,
      accountAddress: derivedAddress,
    }),
    doesAccountExistAtAddress({
      movementConfig,
      accountAddress: derivedAddress,
      options: { withAuthKey: publicKey.authKey() },
    }),
  ]);
  if (exists) {
    return { accountAddress: derivedAddress, lastTransactionVersion };
  }
  return undefined;
}
