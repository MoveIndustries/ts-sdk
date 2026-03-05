const { LocalNode } = require("../src/cli");

let localNode = null;

beforeAll(async () => {
  // Skip localnet startup if using a remote network
  const network = process.env.MOVEMENT_NETWORK;
  const skipLocalnetNetworks = ["testnet", "devnet", "mainnet", "shelbynet", "netna", "local"];

  if (network && skipLocalnetNetworks.includes(network)) {
    console.log(`Using external network: ${network}, skipping localnet startup`);
    return;
  }

  console.log("Starting localnet for test file...");
  localNode = new LocalNode();
  await localNode.run();
}, 120000); // 2 minute timeout for localnet startup

afterAll(async () => {
  if (localNode?.process) {
    console.log("Stopping localnet after test file...");
    localNode.stop();
    // Give it a moment to clean up
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
});
