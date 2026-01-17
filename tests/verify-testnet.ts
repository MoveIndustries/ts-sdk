// Simple script to verify transaction submission works on testnet
import { Movement, MovementConfig, Account, Network } from "../src";

async function main() {
  console.log("Creating Movement client for testnet...");
  const config = new MovementConfig({ network: Network.TESTNET });
  const movement = new Movement(config);

  // Generate accounts
  const sender = Account.generate();
  const receiver = Account.generate();

  console.log("Sender address:", sender.accountAddress.toString());
  console.log("Receiver address:", receiver.accountAddress.toString());

  // Fund sender
  console.log("Funding sender account...");
  const fundResult = await movement.fundAccount({
    accountAddress: sender.accountAddress,
    amount: 100_000_000,
    options: { waitForIndexer: false }  // Skip indexer wait
  });
  console.log("Fund transaction hash:", fundResult.hash);

  // Wait for fund transaction
  console.log("Waiting for fund transaction...");
  const fundTx = await movement.waitForTransaction({ transactionHash: fundResult.hash });
  console.log("Fund transaction success:", fundTx.success);

  // Build a simple transfer transaction
  console.log("Building transfer transaction...");
  const transaction = await movement.transaction.build.simple({
    sender: sender.accountAddress,
    data: {
      function: "0x1::aptos_account::transfer",
      functionArguments: [receiver.accountAddress, 1000],
    },
  });

  // Sign and submit
  console.log("Signing and submitting transaction...");
  const response = await movement.signAndSubmitTransaction({
    signer: sender,
    transaction,
  });
  console.log("Transaction hash:", response.hash);

  // Wait for transaction
  console.log("Waiting for transaction...");
  const committedTx = await movement.waitForTransaction({
    transactionHash: response.hash,
  });

  console.log("Transaction success:", committedTx.success);
  console.log("Transaction version:", committedTx.version);
  console.log("Gas used:", committedTx.gas_used);

  if (committedTx.success) {
    console.log("\n✓ Transaction submission on Movement testnet works!");
  } else {
    console.log("\n✗ Transaction failed");
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Error:", err);
  process.exit(1);
});
