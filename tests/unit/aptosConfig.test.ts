// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import {
  MovementConfig,
  MovementSettings,
  Network,
  NetworkToFaucetAPI,
  NetworkToIndexerAPI,
  NetworkToNodeAPI
} from "../../src";

describe("aptos config", () => {
  test("it should set urls based on a local network", async () => {
    const settings: MovementSettings = {
      network: Network.LOCAL,
    };
    const movementConfig = new MovementConfig(settings);
    expect(movementConfig.network).toEqual("local");
    expect(movementConfig.getRequestUrl(MovementApiType.FULLNODE)).toBe(NetworkToNodeAPI[Network.LOCAL]);
    expect(movementConfig.getRequestUrl(MovementApiType.FAUCET)).toBe(NetworkToFaucetAPI[Network.LOCAL]);
    expect(movementConfig.getRequestUrl(MovementApiType.INDEXER)).toBe(NetworkToIndexerAPI[Network.LOCAL]);
  });

  test("it should set urls based on testnet", async () => {
    const settings: MovementSettings = {
      network: Network.TESTNET,
    };
    const movementConfig = new MovementConfig(settings);
    expect(movementConfig.network).toEqual("testnet");
    expect(movementConfig.getRequestUrl(MovementApiType.FULLNODE)).toBe(NetworkToNodeAPI[Network.TESTNET]);
    expect(() => movementConfig.getRequestUrl(MovementApiType.FAUCET)).toThrow();
    expect(movementConfig.getRequestUrl(MovementApiType.INDEXER)).toBe(NetworkToIndexerAPI[Network.TESTNET]);
  });

  test("it should set urls based on mainnet", async () => {
    const settings: MovementSettings = {
      network: Network.MAINNET,
    };
    const movementConfig = new MovementConfig(settings);
    expect(movementConfig.network).toEqual("mainnet");
    expect(movementConfig.getRequestUrl(MovementApiType.FULLNODE)).toBe(NetworkToNodeAPI[Network.MAINNET]);
    expect(() => movementConfig.getRequestUrl(MovementApiType.FAUCET)).toThrow();
    expect(movementConfig.getRequestUrl(MovementApiType.INDEXER)).toBe(NetworkToIndexerAPI[Network.MAINNET]);
  });

  test("it should have undefined urls when network is custom and no urls provided", async () => {
    const settings: MovementSettings = {
      network: Network.CUSTOM,
    };
    const movementConfig = new MovementConfig(settings);
    expect(movementConfig.network).toBe("custom");
    expect(movementConfig.fullnode).toBeUndefined();
    expect(movementConfig.faucet).toBeUndefined();
    expect(movementConfig.indexer).toBeUndefined();
  });

  test("getRequestUrl should throw when network is custom and no urls provided", async () => {
    const settings: MovementSettings = {
      network: Network.CUSTOM,
    };
    const movementConfig = new MovementConfig(settings);
    expect(movementConfig.network).toBe("custom");
    expect(() => movementConfig.getRequestUrl(MovementApiType.FULLNODE)).toThrow();
    expect(() => movementConfig.getRequestUrl(MovementApiType.FAUCET)).toThrow();
    expect(() => movementConfig.getRequestUrl(MovementApiType.INDEXER)).toThrow();
  });

  test("it should set urls when network is custom and urls provided", async () => {
    const settings: MovementSettings = {
      network: Network.CUSTOM,
      fullnode: "my-fullnode-url",
      faucet: "my-faucet-url",
      indexer: "my-indexer-url",
    };
    const movementConfig = new MovementConfig(settings);
    expect(movementConfig.network).toBe("custom");
    expect(movementConfig.fullnode).toBe("my-fullnode-url");
    expect(movementConfig.faucet).toBe("my-faucet-url");
    expect(movementConfig.indexer).toBe("my-indexer-url");
  });

  test("it sets the correct configs", () => {
    const movementConfig = new MovementConfig({
      clientConfig: {
        HEADERS: { clientConfig: "header" },
        API_KEY: "api-key",
      },
      faucetConfig: { HEADERS: { faucet: "header" }, AUTH_TOKEN: "auth-token" },
      indexerConfig: { HEADERS: { indexer: "header" } },
      fullnodeConfig: { HEADERS: { fullnode: "header" } },
    });

    expect(movementConfig.clientConfig?.HEADERS).toStrictEqual({ clientConfig: "header" });
    expect(movementConfig.clientConfig?.API_KEY).toStrictEqual("api-key");
    expect(movementConfig.faucetConfig).toStrictEqual({ HEADERS: { faucet: "header" }, AUTH_TOKEN: "auth-token" });
    expect(movementConfig.indexerConfig).toStrictEqual({ HEADERS: { indexer: "header" } });
    expect(movementConfig.fullnodeConfig).toStrictEqual({ HEADERS: { fullnode: "header" } });
  });
});
