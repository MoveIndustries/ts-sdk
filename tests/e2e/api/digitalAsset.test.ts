// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import { Account, Bool, MoveString, MoveVector, U8 } from "../../../src";
import { FUND_AMOUNT } from "../../unit/helper";
import { getAptosClient } from "../helper";

const { aptos } = getAptosClient();

const collectionName = "Test Collection";
const collectionDescription = "My new collection!";
const collectionUri = "http://movement.dev";

const tokenName = "Test Token";
const tokenDescription = "my first nft";
const tokenUri = "http://movement.dev/nft";

const creator = Account.generate();
const creatorAddress = creator.accountAddress.toString();

async function setupCollection(): Promise<string> {
  await movement.fundAccount({ accountAddress: creator.accountAddress, amount: FUND_AMOUNT });
  const transaction = await movement.createCollectionTransaction({
    creator,
    description: collectionDescription,
    name: collectionName,
    uri: collectionUri,
  });
  const pendingTxn = await movement.signAndSubmitTransaction({ signer: creator, transaction });
  const response = await movement.waitForTransaction({ transactionHash: pendingTxn.hash });
  const data = await movement.getCollectionData({
    collectionName,
    creatorAddress,
    minimumLedgerVersion: BigInt(response.version),
  });
  return data.collection_id;
}

async function setupToken(): Promise<string> {
  const transaction = await movement.mintDigitalAssetTransaction({
    creator,
    collection: collectionName,
    description: tokenDescription,
    name: tokenName,
    uri: tokenUri,
    propertyKeys: ["my bool key", "my array key"],
    propertyTypes: ["BOOLEAN", "ARRAY"],
    propertyValues: [false, "[value]"],
  });
  const pendingTxn = await movement.signAndSubmitTransaction({ signer: creator, transaction });
  const response = await movement.waitForTransaction({ transactionHash: pendingTxn.hash });
  return (
    await movement.getOwnedDigitalAssets({
      ownerAddress: creator.accountAddress.toString(),
      minimumLedgerVersion: BigInt(response.version),
    })
  )[0].current_token_data?.token_data_id!;
}

jest.setTimeout(20000);

describe("DigitalAsset", () => {
  let tokenAddress: string;

  beforeAll(async () => {
    await setupCollection();
    tokenAddress = await setupToken();
  });

  test("it gets digital asset data for a digital asset's address", async () => {
    const tokenData = await movement.getDigitalAssetData({ digitalAssetAddress: tokenAddress });

    expect(tokenData.token_data_id).toEqual(tokenAddress);
    expect(tokenData.description).toEqual(tokenDescription);
    expect(tokenData.token_name).toEqual(tokenName);
    expect(tokenData.token_data_id).toEqual(tokenAddress);
    expect(tokenData.current_collection?.collection_name).toEqual(collectionName);
    expect(tokenData.current_collection?.creator_address).toEqual(creatorAddress);
  });

  test("it gets an owner's digital assets", async () => {
    const tokenData = (await movement.getOwnedDigitalAssets({ ownerAddress: creatorAddress }))[0];

    expect(tokenData.token_data_id).toEqual(tokenAddress);
    expect(tokenData.owner_address).toEqual(creatorAddress);
    expect(tokenData.current_token_data?.description).toEqual(tokenDescription);
    expect(tokenData.current_token_data?.token_name).toEqual(tokenName);
    expect(tokenData.current_token_data?.token_uri).toEqual(tokenUri);
  });

  test("it gets ownership data given a digital asset's address", async () => {
    const tokenOwnershipData = await movement.getCurrentDigitalAssetOwnership({ digitalAssetAddress: tokenAddress });

    expect(tokenOwnershipData.token_data_id).toEqual(tokenAddress);
    expect(tokenOwnershipData.owner_address).toEqual(creatorAddress);
    expect(tokenOwnershipData.current_token_data?.description).toEqual(tokenDescription);
    expect(tokenOwnershipData.current_token_data?.token_name).toEqual(tokenName);
    expect(tokenOwnershipData.current_token_data?.token_uri).toEqual(tokenUri);
  });

  test("it gets activity data given a digital asset's address", async () => {
    const tokenActivityData = await movement.getDigitalAssetActivity({ digitalAssetAddress: tokenAddress });

    expect(tokenActivityData[0].entry_function_id_str).toEqual("0x4::aptos_token::mint");
    expect(tokenActivityData[0].token_data_id).toEqual(tokenAddress);
    expect(tokenActivityData[0].from_address).toEqual(creatorAddress);
    expect(tokenActivityData[0].is_fungible_v2).toEqual(null);
  });
  test("it fetches collection data", async () => {
    const data = await movement.getCollectionData({ collectionName, creatorAddress });

    expect(data.collection_name).toEqual(collectionName);
    expect(data.creator_address).toEqual(creatorAddress);
    expect(data.description).toEqual(collectionDescription);
    expect(data.uri).toEqual(collectionUri);
    expect(data.current_supply).toEqual(1);
    expect(data.mutable_description).toEqual(true);
    expect(data.mutable_uri).toEqual(true);
    expect(data.token_standard).toEqual("v2");

    const collectionDataByCreatorAddressAndCollectionName =
      await movement.getCollectionDataByCreatorAddressAndCollectionName({ collectionName, creatorAddress });
    expect(data.collection_name).toEqual(collectionDataByCreatorAddressAndCollectionName.collection_name);

    const collectionDataByCreatorAddress = await movement.getCollectionDataByCreatorAddress({
      creatorAddress,
    });
    expect(data.collection_name).toEqual(collectionDataByCreatorAddress.collection_name);

    expect(data).toHaveProperty("max_supply");
    expect(data).toHaveProperty("collection_id");
    expect(data).toHaveProperty("last_transaction_timestamp");
    expect(data).toHaveProperty("last_transaction_version");
    expect(data).toHaveProperty("table_handle_v1");
    expect(data).toHaveProperty("total_minted_v2");

    const address = await movement.getCollectionId({ collectionName, creatorAddress });
    expect(address).toEqual(data.collection_id);

    const collectionDataByCollectionId = await movement.getCollectionDataByCollectionId({ collectionId: address });
    expect(address).toEqual(collectionDataByCollectionId.collection_id);
  });

  test("it freezes transfer ability", async () => {
    const transaction = await movement.freezeDigitalAssetTransaferTransaction({
      creator,
      digitalAssetAddress: tokenAddress,
    });
    const commitedTransaction = await movement.signAndSubmitTransaction({ signer: creator, transaction });
    await movement.waitForTransaction({ transactionHash: commitedTransaction.hash });
  });

  test("it unfreezes transfer ability", async () => {
    const transaction = await movement.unfreezeDigitalAssetTransaferTransaction({
      creator,
      digitalAssetAddress: tokenAddress,
    });
    const commitedTransaction = await movement.signAndSubmitTransaction({ signer: creator, transaction });
    await movement.waitForTransaction({ transactionHash: commitedTransaction.hash });
  });

  test("it sets digital asset descripion", async () => {
    const transaction = await movement.setDigitalAssetDescriptionTransaction({
      creator,
      description: "my new description",
      digitalAssetAddress: tokenAddress,
    });
    const commitedTransaction = await movement.signAndSubmitTransaction({ signer: creator, transaction });
    await movement.waitForTransaction({ transactionHash: commitedTransaction.hash });
  });

  test("it sets digital asset name", async () => {
    const transaction = await movement.setDigitalAssetNameTransaction({
      creator,
      name: "my new name",
      digitalAssetAddress: tokenAddress,
    });
    const commitedTransaction = await movement.signAndSubmitTransaction({ signer: creator, transaction });
    await movement.waitForTransaction({ transactionHash: commitedTransaction.hash });
  });

  test("it sets digital asset uri", async () => {
    const transaction = await movement.setDigitalAssetURITransaction({
      creator,
      uri: "my.new.uri",
      digitalAssetAddress: tokenAddress,
    });
    const commitedTransaction = await movement.signAndSubmitTransaction({ signer: creator, transaction });
    await movement.waitForTransaction({ transactionHash: commitedTransaction.hash });
  });

  test("it adds digital asset property", async () => {
    const transaction = await movement.addDigitalAssetPropertyTransaction({
      creator,
      propertyKey: "newKey",
      propertyType: "BOOLEAN",
      propertyValue: true,
      digitalAssetAddress: tokenAddress,
    });
    const commitedTransaction = await movement.signAndSubmitTransaction({ signer: creator, transaction });
    await movement.waitForTransaction({ transactionHash: commitedTransaction.hash });
  });

  test("it updates digital asset property", async () => {
    const transaction = await movement.updateDigitalAssetPropertyTransaction({
      creator,
      propertyKey: "newKey",
      propertyType: "BOOLEAN",
      propertyValue: false,
      digitalAssetAddress: tokenAddress,
    });
    const commitedTransaction = await movement.signAndSubmitTransaction({ signer: creator, transaction });
    await movement.waitForTransaction({ transactionHash: commitedTransaction.hash });
  });

  test("it removes digital asset property", async () => {
    const transaction = await movement.removeDigitalAssetPropertyTransaction({
      creator,
      propertyKey: "newKey",
      propertyType: "BOOLEAN",
      propertyValue: true,
      digitalAssetAddress: tokenAddress,
    });
    const commitedTransaction = await movement.signAndSubmitTransaction({ signer: creator, transaction });
    await movement.waitForTransaction({ transactionHash: commitedTransaction.hash });
  });

  test("it adds typed digital asset property", async () => {
    const transaction = await movement.addDigitalAssetTypedPropertyTransaction({
      creator,
      propertyKey: "typedKey",
      propertyType: "STRING",
      propertyValue: "hello",
      digitalAssetAddress: tokenAddress,
    });
    const commitedTransaction = await movement.signAndSubmitTransaction({ signer: creator, transaction });
    await movement.waitForTransaction({ transactionHash: commitedTransaction.hash });
  });

  test("it updates typed digital asset property", async () => {
    const transaction = await movement.updateDigitalAssetTypedPropertyTransaction({
      creator,
      propertyKey: "typedKey",
      propertyType: "U8",
      propertyValue: 2,
      digitalAssetAddress: tokenAddress,
    });
    const commitedTransaction = await movement.signAndSubmitTransaction({ signer: creator, transaction });
    await movement.waitForTransaction({ transactionHash: commitedTransaction.hash });
  });

  test("it mints soul bound token", async () => {
    const bob = Account.generate();
    await movement.fundAccount({ accountAddress: bob.accountAddress, amount: FUND_AMOUNT });
    const transaction = await movement.mintSoulBoundTransaction({
      account: creator,
      collection: collectionName,
      description: "soul bound token description",
      name: "soul bound token",
      uri: "https://movement.dev/img/nyan.jpeg",
      recipient: bob.accountAddress,
      propertyKeys: [
        "bool key",
        "U8 key",
        "U16 key",
        "U32 key",
        "U64 key",
        "U128 key",
        "U256 key",
        "ADDRESS key",
        "STRING key",
        "ARRAY of bytes key",
      ],
      propertyTypes: ["BOOLEAN", "U8", "U16", "U32", "U64", "U128", "U256", "ADDRESS", "STRING", "ARRAY"],
      propertyValues: [
        true,
        1,
        1,
        1,
        1,
        1,
        1,
        bob.accountAddress,
        "hi",
        new MoveVector([new MoveString("hello"), new U8(1), new Bool(true), new MoveString("world")]).bcsToBytes(),
      ],
    });
    await movement.signAndSubmitTransaction({ signer: creator, transaction });
  });

  test("it transfers digital asset ownership", async () => {
    const digitalAssetReciever = Account.generate();
    await movement.fundAccount({ accountAddress: digitalAssetReciever.accountAddress, amount: FUND_AMOUNT });

    const transaction = await movement.transferDigitalAssetTransaction({
      sender: creator,
      digitalAssetAddress: tokenAddress,
      recipient: digitalAssetReciever.accountAddress,
    });
    const commitedTransaction = await movement.signAndSubmitTransaction({ signer: creator, transaction });
    const res = await movement.waitForTransaction({ transactionHash: commitedTransaction.hash });

    const tokenData = (
      await movement.getOwnedDigitalAssets({
        ownerAddress: digitalAssetReciever.accountAddress,
        minimumLedgerVersion: BigInt(res.version),
      })
    )[0];
    expect(tokenData.token_data_id).toEqual(tokenAddress);
    expect(tokenData.owner_address).toEqual(digitalAssetReciever.accountAddress.toString());
  });

  test("it burns digital asset", async () => {
    const transaction = await movement.burnDigitalAssetTransaction({
      creator,
      digitalAssetAddress: tokenAddress,
    });
    const commitedTransaction = await movement.signAndSubmitTransaction({ signer: creator, transaction });
    await movement.waitForTransaction({ transactionHash: commitedTransaction.hash });
  });
});
