/* eslint-disable no-console */
import {
  AbstractedAccount,
  Account,
  MovementConfig,
  Network,
  NetworkToNetworkName,
  UserTransactionResponse
} from "@moveindustries/ts-sdk";
import dotenv from "dotenv";
import { compilePackage, getPackageBytesToPublish } from "./utils";
dotenv.config();

const MOVEMENT_NETWORK: Network = NetworkToNetworkName[process.env.MOVEMENT_NETWORK ?? Network.DEVNET];
const movement = new Movement(new MovementConfig({ network: MOVEMENT_NETWORK }));

const main = async () => {
  const alice = Account.generate();

  console.log("\n=== Addresses ===");
  console.log(`Alice: ${alice.accountAddress.toString()}`);

  console.log("\n=== Funding Accounts ===");
  await movement.fundAccount({ accountAddress: alice.accountAddress, amount: 1000000000000000 });
  console.log("Finished funding accounts!");

  console.log("\n=== Compiling hello_world_authenticator package locally ===");
  compilePackage("move/account_abstraction", "move/account_abstraction/hello_world_authenticator.json", [
    { name: "deployer", address: alice.accountAddress },
  ]);
  const { metadataBytes, byteCode } = getPackageBytesToPublish(
    "move/account_abstraction/hello_world_authenticator.json",
  );
  console.log(`\n=== Publishing hello_world_authenticator package to ${movement.config.network} network ===`);
  const publishTxn = await movement.publishPackageTransaction({
    account: alice.accountAddress,
    metadataBytes,
    moduleBytecode: byteCode,
  });
  const pendingPublishTxn = await movement.signAndSubmitTransaction({ signer: alice, transaction: publishTxn });
  console.log(`Publish package transaction hash: ${pendingPublishTxn.hash}`);
  await movement.waitForTransaction({ transactionHash: pendingPublishTxn.hash });

  console.log("\n=== Dispatchable authentication function info ===");

  const authenticationFunction = `${alice.accountAddress}::hello_world_authenticator::authenticate`;
  const [moduleAddress, moduleName, functionName] = authenticationFunction.split("::");

  console.log(`Module address: ${moduleAddress}`);
  console.log(`Module name: ${moduleName}`);
  console.log(`Function name: ${functionName}`);

  console.log(
    `\n=== Changing ${alice.accountAddress.toString()} to use any_authenticator's AccountAbstraction function ===`,
  );
  const enableAccountAbstractionTransaction = await movement.abstraction.enableAccountAbstractionTransaction({
    accountAddress: alice.accountAddress,
    authenticationFunction,
  });
  const pendingEnableAccountAbstractionTransaction = await movement.signAndSubmitTransaction({
    signer: alice,
    transaction: enableAccountAbstractionTransaction,
  });
  console.log(`Enable account abstraction transaction hash: ${pendingEnableAccountAbstractionTransaction.hash}`);
  await movement.waitForTransaction({ transactionHash: pendingEnableAccountAbstractionTransaction.hash });

  console.log("\n=== Signing a transaction with the abstracted account ===");

  const abstractedAccount = new AbstractedAccount({
    accountAddress: alice.accountAddress,
    signer: () => new TextEncoder().encode("hello world"),
    authenticationFunction,
  });
  const pendingTransferTxn = await movement.signAndSubmitTransaction({
    signer: abstractedAccount,
    transaction: await movement.transferCoinTransaction({
      sender: abstractedAccount.accountAddress,
      recipient: abstractedAccount.accountAddress,
      amount: 100,
    }),
  });

  const response = await movement.waitForTransaction({ transactionHash: pendingTransferTxn.hash });
  console.log(`Committed transaction: ${response.hash}`);

  const txn = (await movement.getTransactionByHash({
    transactionHash: pendingTransferTxn.hash,
  })) as UserTransactionResponse;
  console.log(`Transaction Signature: ${JSON.stringify(txn.signature, null, 2)}`);
};

main();
