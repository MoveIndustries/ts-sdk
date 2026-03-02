const { LocalNode } = require("../src/cli");

module.exports = async function setup() {
  // Skip localnet startup if using a remote network
  const network = process.env.MOVEMENT_NETWORK;
  // "local" means an external localnet is already running (e.g., started by CI action)
  const skipLocalnetNetworks = ["testnet", "devnet", "mainnet", "shelbynet", "netna", "local"];

  if (network && skipLocalnetNetworks.includes(network)) {
    console.log(`Using external network: ${network}, skipping localnet startup`);
    globalThis.__LOCAL_NODE__ = { process: null };
    return;
  }

  const localNode = new LocalNode();
  globalThis.__LOCAL_NODE__ = localNode;
  await localNode.run();
};
