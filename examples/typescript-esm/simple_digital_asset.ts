/* eslint-disable no-console */
/* eslint-disable max-len */

/**
 * This example shows how to use the Movement client to mint and transfer a Digital Asset.
 */

import { Account, MovementConfig, Network, NetworkToNetworkName } from "@moveindustries/ts-sdk";
import dotenv from "dotenv";
dotenv.config();

const INITIAL_BALANCE = 100_000_000;

// Set up the client
const MOVEMENT_NETWORK: Network = NetworkToNetworkName[process.env.MOVEMENT_NETWORK] || Network.DEVNET;
const config = new MovementConfig({ network: MOVEMENT_NETWORK });
const movement = new Movement(config);

const example = async () => {
  console.log(
    "This example will create and fund Alice and Bob, then Alice account will create a collection and a digital asset in that collection and transfer it to Bob.",
  );

  // Create Alice and Bob accounts
  const alice = Account.generate();
  const bob = Account.generate();

  console.log("=== Addresses ===\n");
  console.log(`Alice's address is: ${alice.accountAddress}`);

  // Fund and create the accounts
  await movement.fundAccount({
    accountAddress: alice.accountAddress,
    amount: INITIAL_BALANCE,
  });
  await movement.fundAccount({
    accountAddress: bob.accountAddress,
    amount: INITIAL_BALANCE,
  });

  const collectionName = "Example Collection";
  const collectionDescription = "Example description.";
  const collectionURI = "movement.dev";

  // Create the collection
  const createCollectionTransaction = await movement.createCollectionTransaction({
    creator: alice,
    description: collectionDescription,
    name: collectionName,
    uri: collectionURI,
  });

  console.log("\n=== Create the collection ===\n");
  let committedTxn = await movement.signAndSubmitTransaction({ signer: alice, transaction: createCollectionTransaction });

  let pendingTxn = await movement.waitForTransaction({ transactionHash: committedTxn.hash });

  const aliceCollection = await movement.getCollectionData({
    creatorAddress: alice.accountAddress,
    collectionName,
    minimumLedgerVersion: BigInt(pendingTxn.version),
  });
  console.log(`Alice's collection: ${JSON.stringify(aliceCollection, null, 4)}`);

  const tokenName = "Example Asset";
  const tokenDescription = "Example asset description.";
  const tokenURI = "movement.dev/asset";

  console.log("\n=== Alice Mints the digital asset ===\n");

  const mintTokenTransaction = await movement.mintDigitalAssetTransaction({
    creator: alice,
    collection: collectionName,
    description: tokenDescription,
    name: tokenName,
    uri: tokenURI,
  });

  committedTxn = await movement.signAndSubmitTransaction({ signer: alice, transaction: mintTokenTransaction });
  pendingTxn = await movement.waitForTransaction({ transactionHash: committedTxn.hash });

  const aliceDigitalAsset = await movement.getOwnedDigitalAssets({
    ownerAddress: alice.accountAddress,
    minimumLedgerVersion: BigInt(pendingTxn.version),
  });
  console.log(`Alice's digital assets balance: ${aliceDigitalAsset.length}`);

  console.log(`Alice's digital asset: ${JSON.stringify(aliceDigitalAsset[0], null, 4)}`);

  console.log("\n=== Transfer the digital asset to Bob ===\n");

  const transferTransaction = await movement.transferDigitalAssetTransaction({
    sender: alice,
    digitalAssetAddress: aliceDigitalAsset[0].token_data_id,
    recipient: bob.accountAddress,
  });
  committedTxn = await movement.signAndSubmitTransaction({ signer: alice, transaction: transferTransaction });
  pendingTxn = await movement.waitForTransaction({ transactionHash: committedTxn.hash });

  const aliceDigitalAssetsAfter = await movement.getOwnedDigitalAssets({
    ownerAddress: alice.accountAddress,
    minimumLedgerVersion: BigInt(pendingTxn.version),
  });
  console.log(`Alice's digital assets balance: ${aliceDigitalAssetsAfter.length}`);

  const bobDigitalAssetsAfter = await movement.getOwnedDigitalAssets({
    ownerAddress: bob.accountAddress,
    minimumLedgerVersion: BigInt(pendingTxn.version),
  });
  console.log(`Bob's digital assets balance: ${bobDigitalAssetsAfter.length}`);
};

example();
