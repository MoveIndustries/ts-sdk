/**
 * This example demonstrates how we can use `movement.publishPackageTransaction()` method to publish a move package
 * read from a local path.
 *
 * Before running this example, we should compile the package locally:
 * 1. Acquire the Movement CLI, see https://movement.dev/cli-tools/aptos-cli/use-cli/install-aptos-cli
 * 2. cd `~/aptos-ts-sdk/examples/typescript`
 * 3. Run `pnpm run publish_package_from_filepath` and follow the prompt
 */
/* eslint-disable no-console */
/* eslint-disable max-len */
import dotenv from "dotenv";
dotenv.config();

import { Account, Hex, MovementConfig, Network, NetworkToNetworkName } from "@moveindustries/ts-sdk";
import assert from "assert";
import { compilePackage, getPackageBytesToPublish } from "./utils";

const MOVEMENT_NETWORK: Network = NetworkToNetworkName[process.env.MOVEMENT_NETWORK ?? Network.DEVNET];

/** run our demo! */
async function main() {
  const config = new MovementConfig({ network: MOVEMENT_NETWORK });
  const movement = new Movement(config);

  const alice = Account.generate();

  console.log("\n=== Addresses ===");
  console.log(`Alice: ${alice.accountAddress}`);

  await movement.fundAccount({ accountAddress: alice.accountAddress, amount: 100_000_000 });

  // Please ensure you have the aptos CLI installed
  console.log("\n=== Compiling the package locally ===");
  compilePackage("move/facoin", "move/facoin/publish_payload.json", [
    { name: "FACoin", address: alice.accountAddress },
  ]);

  const { metadataBytes, byteCode } = getPackageBytesToPublish("move/facoin/publish_payload.json");

  console.log("\n===Publishing FAcoin package===");
  const transaction = await movement.publishPackageTransaction({
    account: alice.accountAddress,
    metadataBytes,
    moduleBytecode: byteCode,
  });
  const response = await movement.signAndSubmitTransaction({
    signer: alice,
    transaction,
  });
  console.log(`Transaction hash: ${response.hash}`);
  await movement.waitForTransaction({
    transactionHash: response.hash,
  });

  console.log("\n===Checking modules onchain===");
  const accountModules = await movement.getAccountModules({
    accountAddress: alice.accountAddress,
  });
  // published 4 modules
  assert(accountModules.length === 4);
  // first account's module bytecode equals the published bytecode
  assert(accountModules[0].bytecode === `${Hex.fromHexInput(byteCode[0]).toString()}`);
  // second account's module bytecode equals the published bytecode
  assert(accountModules[1].bytecode === `${Hex.fromHexInput(byteCode[1]).toString()}`);
  console.log("Modules onchain check passed");
}

if (require.main === module) {
  main();
}
