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

function isPortFree(port) {
  const { execSync } = require("child_process");
  try {
    execSync(`lsof -i :${port}`, { stdio: "ignore" });
    return false;
  } catch (e) {
    return true;
  }
}

async function waitForPortRelease(port, timeout = 20000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    if (isPortFree(port)) return true;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  return false;
}

afterAll(async () => {
  if (localNode?.process) {
    console.log("Stopping localnet...");

    const { execSync } = require("child_process");
    const pid = localNode.process.pid;

    // Stop via the localNode API first
    localNode.stop();

    // Kill the process group (negative PID kills the group)
    try {
      process.kill(-pid, "SIGKILL");
    } catch (e) {
      // Process group may not exist or already dead
    }

    // Also try killing direct children
    try {
      execSync(`pkill -9 -P ${pid}`, { stdio: "ignore" });
    } catch (e) {}

    // Wait for main port to be released
    const released = await waitForPortRelease(8080);
    if (!released) {
      console.log("Warning: Port 8080 not released in time");
    }
  }
}, 30000);
