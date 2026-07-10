import { LedgerInfo, MovementConfig, Network, getAptosFullNode } from "../../../src";
import { getMovementClient } from "../helper";

const partialConfig = new MovementConfig({
  // Unreachable fullnode so the request fails fast locally instead of hitting a live network
  // (the config default would otherwise send this to devnet, making the test flaky on devnet outages).
  network: Network.CUSTOM,
  fullnode: "http://127.0.0.1:9/v1",
  clientConfig: {
    HEADERS: { clientConfig: "clientConfig-header" },
    API_KEY: "api-key",
  },
  fullnodeConfig: { HEADERS: { fullnodeHeader: "fullnode-header" } },
  indexerConfig: { HEADERS: { indexerHeader: "indexer-header" } },
  faucetConfig: { HEADERS: { faucetHeader: "faucet-header" }, AUTH_TOKEN: "auth-token" },
});
const { config: movementConfig } = getMovementClient(partialConfig);

// All tests are expected to catch becuase server call will fail
// due to a fake API_KEY. But that is ok because we just want
// to test the config we set
describe("get request", () => {
  describe("fullnode", () => {
    test("it sets correct headers on get request", async () => {
      try {
        await getAptosFullNode<{}, LedgerInfo>({
          movementConfig,
          originMethod: "testGetFullnodeQuery",
          path: "",
        });
      } catch (e: any) {
        // The request fails (unreachable host), so we assert the configured overrides were
        // applied to the outgoing request's headers. The client API key becomes the bearer token,
        // and only the client + fullnode headers should be present (not faucet/indexer ones).
        const headers = e?.request?.options?.headers ?? {};
        expect(headers.authorization).toEqual("Bearer api-key");
        expect(headers.clientconfig).toEqual("clientConfig-header");
        expect(headers.fullnodeheader).toEqual("fullnode-header");
        expect(headers).not.toHaveProperty("faucetheader");
        expect(headers).not.toHaveProperty("indexerheader");
      }
    });
  });
});
