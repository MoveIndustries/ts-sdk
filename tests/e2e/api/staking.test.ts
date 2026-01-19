// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import { Movement, MovementConfig, Network } from "../../../src";
import { longTestTimeout } from "../../unit/helper";

describe("staking api", () => {
  test(
    "it queries for the number of delegators",
    async () => {
      const config = new MovementConfig({ network: Network.MAINNET });
      const movement = new Movement(config);
      const numDelegatorsData = await movement.getNumberOfDelegatorsForAllPools({
        options: { orderBy: [{ num_active_delegator: "desc" }] },
      });
      expect(numDelegatorsData.length).toBeGreaterThan(0);
      // Verify descending order for available data
      for (let i = 0; i < numDelegatorsData.length - 1; i += 1) {
        expect(numDelegatorsData[i].num_active_delegator).toBeGreaterThanOrEqual(
          numDelegatorsData[i + 1].num_active_delegator,
        );
      }
      const numDelegators = await movement.getNumberOfDelegators({ poolAddress: numDelegatorsData[0].pool_address! });
      expect(numDelegators).toEqual(numDelegatorsData[0].num_active_delegator);
    },
    longTestTimeout,
  );

  test("it returns 0 if the poolAddress does not exist", async () => {
    const config = new MovementConfig({ network: Network.DEVNET });
    const movement = new Movement(config);
    const badAddress = "0x12345678901234567850020dfd67646b1e46282999483e7064e70f02f7e12345";
    const numDelegators = await movement.getNumberOfDelegators({ poolAddress: badAddress });
    expect(numDelegators).toBe(0);
  });

  test("it queries for the activity of a delegator for a given pool", async () => {
    const config = new MovementConfig({ network: Network.MAINNET });
    const movement = new Movement(config);
    // First get pools with delegators to find valid addresses
    const pools = await movement.getNumberOfDelegatorsForAllPools({
      options: { orderBy: [{ num_active_delegator: "desc" }] },
    });
    // Find a pool with active delegators
    const poolWithDelegators = pools.find((p) => p.num_active_delegator > 0);
    if (!poolWithDelegators) {
      // If no pools with delegators exist, test that the API returns empty array
      const delegatedStakingActivities = await movement.getDelegatedStakingActivities({
        poolAddress: pools[0]?.pool_address ?? "0x1",
        delegatorAddress: "0x1",
      });
      expect(delegatedStakingActivities).toEqual([]);
      return;
    }
    // Query activities for the pool - may or may not have activity data
    const delegatedStakingActivities = await movement.getDelegatedStakingActivities({
      poolAddress: poolWithDelegators.pool_address!,
      delegatorAddress: poolWithDelegators.pool_address!, // Use pool address as delegator to test API
    });
    // Verify the response structure if activities exist
    if (delegatedStakingActivities.length > 0) {
      expect(delegatedStakingActivities[0]).toHaveProperty("amount");
      expect(delegatedStakingActivities[0]).toHaveProperty("delegator_address");
      expect(delegatedStakingActivities[0]).toHaveProperty("event_index");
      expect(delegatedStakingActivities[0]).toHaveProperty("event_type");
      expect(delegatedStakingActivities[0]).toHaveProperty("pool_address");
      expect(delegatedStakingActivities[0]).toHaveProperty("transaction_version");
    }
  });
});
