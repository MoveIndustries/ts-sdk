import { Account, MovementConfig, Network } from '@moveindustries/ts-sdk';
import axios from 'axios';

const main = async () => {
  const config = new MovementConfig({ network: Network.DEVNET });
  const movement = new Movement(config);

  // Create sender and recipient accounts
  const alice = Account.generate();
  const bob = Account.generate();

  console.log("Alice's address:", alice.accountAddress.toStringLong());
  console.log("Bob's address:", bob.accountAddress.toStringLong());

  // Fund Alice's account
  await movement.fundAccount({ accountAddress: alice.accountAddress, amount: 100_000_000 });

  const transaction = await movement.transaction.build.simple({
    sender: alice.accountAddress,
    withFeePayer: true,
    data: {
      function: "0x1::aptos_account::transfer",
      functionArguments: [bob.accountAddress, 100],
    },
  });

  // Sign the transaction as Alice
  const senderAuthenticator = movement.transaction.sign({ signer: alice, transaction });

  // Send the transaction to the sponsor server
  const response = await axios.post(
    "http://localhost:3000/signAndSubmit",
    {
      transactionBytes: Array.from(transaction.bcsToBytes()),
      senderAuthenticator: Array.from(senderAuthenticator.bcsToBytes()),
    },
    {
      headers: {
        "Content-Type": "application/json",
      },
    }
  );


  const { transactionHash } = response.data;

  console.log("Transaction submitted. Hash:", transactionHash);
  const executedTx = await movement.waitForTransaction({ transactionHash: transactionHash });
  console.log("Executed transaction:", executedTx);
};

main();
