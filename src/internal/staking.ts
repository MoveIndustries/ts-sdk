// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

/**
 * This file contains the underlying implementations for exposed API surface in
 * the {@link api/staking}. By moving the methods out into a separate file,
 * other namespaces and processes can access these methods without depending on the entire
 * staking namespace and without having a dependency cycle error.
 * @group Implementation
 */

import { MovementConfig } from "../api/movementConfig";
import { AccountAddress, AccountAddressInput } from "../core";
import { GetDelegatedStakingActivitiesResponse, GetNumberOfDelegatorsResponse, OrderByArg } from "../types";
import { GetDelegatedStakingActivitiesQuery, GetNumberOfDelegatorsQuery } from "../types/generated/operations";
import { GetDelegatedStakingActivities, GetNumberOfDelegators } from "../types/generated/queries";
import { queryIndexer } from "./general";

/**
 * Retrieves the number of active delegators for a specified pool address.
 *
 * @param args - The arguments for the function.
 * @param args.movementConfig - The configuration object for Movement.
 * @param args.poolAddress - The address of the pool for which to retrieve the number of delegators.
 * @returns The number of active delegators for the specified pool address.
 * @group Implementation
 */
export async function getNumberOfDelegators(args: {
  movementConfig: MovementConfig;
  poolAddress: AccountAddressInput;
}): Promise<number> {
  const { movementConfig, poolAddress } = args;
  const address = AccountAddress.from(poolAddress).toStringLong();
  const query = {
    query: GetNumberOfDelegators,
    variables: { where_condition: { pool_address: { _eq: address } } },
  };
  const data = await queryIndexer<GetNumberOfDelegatorsQuery>({ movementConfig, query });

  // commonjs (aka cjs) doesn't handle Nullish Coalescing for some reason
  // might be because of how ts infer the graphql generated scheme type
  return data.num_active_delegator_per_pool[0] ? data.num_active_delegator_per_pool[0].num_active_delegator : 0;
}

/**
 * Retrieves the number of active delegators for all pools.
 *
 * @param args - The arguments for the function.
 * @param args.movementConfig - The configuration for the Movement client.
 * @param [args.options] - Optional parameters for ordering the results.
 * @param args.options.orderBy - Specifies the order in which to return the results.
 * @returns The number of active delegators per pool.
 * @group Implementation
 */
export async function getNumberOfDelegatorsForAllPools(args: {
  movementConfig: MovementConfig;
  options?: OrderByArg<GetNumberOfDelegatorsResponse[0]>;
}): Promise<GetNumberOfDelegatorsResponse> {
  const { movementConfig, options } = args;
  const query = {
    query: GetNumberOfDelegators,
    variables: { order_by: options?.orderBy },
  };
  const data = await queryIndexer<GetNumberOfDelegatorsQuery>({
    movementConfig,
    query,
  });
  return data.num_active_delegator_per_pool;
}

/**
 * Retrieves the delegated staking activities for a specified delegator and pool.
 *
 * @param args - The parameters for the query.
 * @param args.movementConfig - The configuration object for Movement.
 * @param args.delegatorAddress - The address of the delegator whose activities are being queried.
 * @param args.poolAddress - The address of the pool associated with the delegated staking activities.
 * @returns The delegated staking activities for the specified delegator and pool.
 * @group Implementation
 */
export async function getDelegatedStakingActivities(args: {
  movementConfig: MovementConfig;
  delegatorAddress: AccountAddressInput;
  poolAddress: AccountAddressInput;
}): Promise<GetDelegatedStakingActivitiesResponse> {
  const { movementConfig, delegatorAddress, poolAddress } = args;
  const query = {
    query: GetDelegatedStakingActivities,
    variables: {
      delegatorAddress: AccountAddress.from(delegatorAddress).toStringLong(),
      poolAddress: AccountAddress.from(poolAddress).toStringLong(),
    },
  };
  const data = await queryIndexer<GetDelegatedStakingActivitiesQuery>({ movementConfig, query });
  return data.delegated_staking_activities;
}
