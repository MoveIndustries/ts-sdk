/* eslint-disable no-console */

/**
 * This example demonstrates how a client can utilize the TransactionWorker class.
 *
 * The TransactionWorker provides a simple framework for receiving payloads to be processed. It
 * acquires an account new sequence number, produces a signed transaction and
 * then submits the transaction. In other tasks, it waits for resolution of the submission
 * process or get pre-execution validation error and waits for the resolution of the execution process
 * or get an execution validation error.
 *
 * The TransactionWorker constructor accepts
 * @param movementConfig - a config object
 * @param sender - the sender account
 * @param maxWaitTime - the max wait time to wait before restarting the local sequence number to the current on-chain state
 * @param maximumInFlight - submit up to `maximumInFlight` transactions per account
 * @param sleepTime - If `maximumInFlight` are in flight, wait `sleepTime` seconds before re-evaluating
 *
 * Read more about it here {@link https://movement.dev/guides/transaction-management}
 */
import {
  Account,
  InputGenerateTransactionPayloadData,
  MovementConfig,
  Network,
  NetworkToNetworkName,
  TransactionWorkerEventsEnum,
  UserTransactionResponse
} from "@moveindustries/ts-sdk";

const MOVEMENT_NETWORK: Network = NetworkToNetworkName[process.env.MOVEMENT_NETWORK ?? Network.DEVNET];

const config = new MovementConfig({ network: MOVEMENT_NETWORK });
const movement = new Movement(config);
const COLLECTION_NAME = "My batch collection!";
const tokensToMint = 100;

async function main() {
  const sender: Account = Account.generate();
  console.log(`sender ${sender.accountAddress}`);

  // fund sender accounts
  const funds: Array<Promise<UserTransactionResponse>> = [];

  funds.push(movement.fundAccount({ accountAddress: sender.accountAddress, amount: 10000000000 }));

  await Promise.all(funds);

  // First need to create a collection on chain
  console.log("creating collection...");
  const transaction = await movement.createCollectionTransaction({
    creator: sender,
    description: "Batch Collection",
    name: COLLECTION_NAME,
    uri: "https://movement.dev",
  });
  const pendingTxn = await movement.signAndSubmitTransaction({ signer: sender, transaction });
  await movement.waitForTransaction({ transactionHash: pendingTxn.hash });
  console.log("collection has been created");

  const payloads: InputGenerateTransactionPayloadData[] = [];

  for (let i = 0; i < tokensToMint; i += 1) {
    const payload: InputGenerateTransactionPayloadData = {
      function: "0x4::aptos_token::mint",
      functionArguments: [
        COLLECTION_NAME,
        `my ${i} token description`,
        `my ${i} token`,
        "https://movement.dev/nft",
        [],
        [],
        [],
      ],
    };
    payloads.push(payload);
  }

  // batch mint token transactions
  movement.transaction.batch.forSingleAccount({ sender, data: payloads });

  movement.transaction.batch.on(TransactionWorkerEventsEnum.ExecutionFinish, async (data) => {
    // log event output
    console.log(data);

    // verify account sequence number
    const account = await movement.getAccountInfo({ accountAddress: sender.accountAddress });
    console.log(`account sequence number is 101: ${account.sequence_number === "101"}`);

    // worker finished execution, we can now unsubscribe from event listeners
    movement.transaction.batch.removeAllListeners();
    process.exit(0);
  });
}

main();
