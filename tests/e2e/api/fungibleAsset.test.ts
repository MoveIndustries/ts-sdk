// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import { Account, MOVEMENT_COIN, MOVEMENT_FA } from "../../../src";
import { getMovementClient } from "../helper";

const { movement } = getMovementClient();

describe("FungibleAsset", () => {
  test("it should fetch fungible asset metadata", async () => {
    const data = await movement.getFungibleAssetMetadata({
      options: {
        where: {
          asset_type: { _eq: MOVEMENT_COIN },
        },
      },
    });
    expect(data.length).toEqual(1);
    expect(data[0]).toHaveProperty("asset_type");
    expect(data[0].asset_type).toEqual(MOVEMENT_COIN);
  });

  test("it should fetch a specific fungible asset metadata by an asset type", async () => {
    let data = await movement.getFungibleAssetMetadataByAssetType({ assetType: MOVEMENT_COIN });
    expect(data.asset_type).toEqual(MOVEMENT_COIN);

    // fetch by something that doesn't exist
    data = await movement.getFungibleAssetMetadataByAssetType({ assetType: "0x1::aptos_coin::testnotexist" });
    expect(data).toBeUndefined();
  });

  test("it should fetch a specific fungible asset metadata by a creator address", async () => {
    let data = await movement.getFungibleAssetMetadataByCreatorAddress({
      creatorAddress: "0x0000000000000000000000000000000000000000000000000000000000000001",
    });
    expect(data[1].asset_type).toEqual(MOVEMENT_FA);

    // fetch by something that doesn't exist
    data = await movement.getFungibleAssetMetadataByCreatorAddress({ creatorAddress: "0xc" });
    expect(data).toEqual([]);
  });

  test("it should fetch fungible asset activities with correct number and asset type ", async () => {
    const data = await movement.getFungibleAssetActivities({
      options: {
        limit: 2,
        where: {
          asset_type: { _eq: MOVEMENT_COIN },
        },
      },
    });
    expect(data.length).toEqual(2);
    expect(data[0].asset_type).toEqual(MOVEMENT_COIN);
    expect(data[1].asset_type).toEqual(MOVEMENT_COIN);
  });

  test("it should fetch current fungible asset balance", async () => {
    const userAccount = Account.generate();
    await movement.fundAccount({ accountAddress: userAccount.accountAddress, amount: 1_000 });

    const MOVE_COIN_TYPE = "0x1::aptos_coin::AptosCoin";
    const data = await movement.getCurrentFungibleAssetBalances({
      options: {
        where: {
          owner_address: { _eq: userAccount.accountAddress.toString() },
          asset_type: { _eq: MOVEMENT_COIN },
        },
      },
    });
    expect(data.length).toEqual(1);
    expect(data[0].asset_type).toEqual(MOVE_COIN_TYPE);
    expect(data[0].amount).toEqual(1_000);
  });
});
