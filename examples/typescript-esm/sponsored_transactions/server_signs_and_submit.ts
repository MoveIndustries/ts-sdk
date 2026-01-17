/* eslint-disable no-console */

/**
 * This example demonstrates how one can generate and sign a transaction
 * on one server (for example, frontend) and have it serialized and send
 * it to another server (for example, backend) to deserialize and submit.
 */
import {
  Account,
  AccountAuthenticator,
  Deserializer,
  MovementConfig,
  Network,
  NetworkToNetworkName,
  SimpleTransaction
} from "@moveindustries/ts-sdk";
import dotenv from "dotenv";
dotenv.config();

const INITIAL_BALANCE = 100_000_000;
const TRANSFER_AMOUNT = 100;

// Default to devnet, but allow for overriding
const MOVEMENT_NETWORK: Network = NetworkToNetworkName[process.env.MOVEMENT_NETWORK] || Network.DEVNET;
// Set up the client
const config = new MovementConfig({ network: MOVEMENT_NETWORK });
const movement = new Movement(config);

const sendToOtherServer = async (
  serializedTransaction: Uint8Array,
  senderAuth: Uint8Array,
  sponsorAuth: Uint8Array,
) => {
  // deserialize transaction
  const deserializer = new Deserializer(serializedTransaction);
  const transaction = SimpleTransaction.deserialize(deserializer);

  // deserialize sender authenticator
  const deserializer2 = new Deserializer(senderAuth);
  const senderAuthenticator = AccountAuthenticator.deserialize(deserializer2);

  // deserialize fee payer authenticator
  const deserializer3 = new Deserializer(sponsorAuth);
  const feePayerAuthenticator = AccountAuthenticator.deserialize(deserializer3);

  const response = await movement.transaction.submit.simple({
    transaction,
    senderAuthenticator,
    feePayerAuthenticator,
  });

  const executedTransaction = await movement.waitForTransaction({ transactionHash: response.hash });
  console.log("executed transaction", executedTransaction.hash);
};

const example = async () => {
  // Create two accounts
  const alice = Account.generate();
  const bob = Account.generate();
  const sponsor = Account.generate();

  console.log("=== Addresses ===\n");
  console.log(`Alice's address is: ${alice.accountAddress}`);
  console.log(`Bob's address is: ${bob.accountAddress}`);
  console.log(`Sponsor's address is: ${sponsor.accountAddress}`);

  // Fund the accounts
  console.log("\n=== Funding accounts ===\n");

  await movement.fundAccount({
    accountAddress: alice.accountAddress,
    amount: INITIAL_BALANCE,
  });

  await movement.fundAccount({ accountAddress: sponsor.accountAddress, amount: INITIAL_BALANCE });

  console.log("\n=== Accounts funded ===\n");

  const transaction = await movement.transaction.build.simple({
    sender: alice.accountAddress,
    withFeePayer: true,
    data: {
      function: "0x1::aptos_account::transfer",
      functionArguments: [bob.accountAddress, TRANSFER_AMOUNT],
    },
  });

  // Alice signs
  const senderAuth = movement.transaction.sign({ signer: alice, transaction });

  // Sponsor signs
  const sponsorAuth = movement.transaction.signAsFeePayer({ signer: sponsor, transaction });

  // Send serialized data to server
  await sendToOtherServer(transaction.bcsToBytes(), senderAuth.bcsToBytes(), sponsorAuth.bcsToBytes());
};

example();
