import {
  Account,
  AccountAddress,
  MimeType,
  generateSignedTransaction,
  getAptosFullNode,
  postAptosFaucet,
  postAptosFullNode,
} from "../../../src";
import { customClient } from "../../unit/helper";
import { getAptosClient } from "../helper";

describe("custom client", () => {
  test("it uses default client when it doesnt set in MovementConfig", () => {
    const { aptos } = getAptosClient();
    expect(movement.config.client.provider).toBeInstanceOf(Function);
    expect(movement.config.client.provider.name).toBe("movementClient");
  });
  test("it uses a custom client set in MovementConfig", () => {
    const { aptos } = getAptosClient({ client: { provider: customClient } });
    expect(movement.config.client.provider).toBeInstanceOf(Function);
    expect(movement.config.client.provider.name).toBe("customClient");
  });

  test("it uses custom client for fetch queries", async () => {
    const { config } = getAptosClient({ client: { provider: customClient } });
    const response = await getAptosFullNode<{ headers?: { customClient?: any } }, {}>({
      movementConfig: config,
      originMethod: "getInfo",
      path: "accounts/0x1",
    });
    expect(response?.request?.headers?.customClient).toBeTruthy();
  });

  test("it uses custom client for post queries", async () => {
    const { config } = getAptosClient({ client: { provider: customClient } });
    const account = Account.generate();
    const response = await postAptosFaucet<{ headers?: { customClient?: any } }, {}>({
      movementConfig: config,
      path: "fund",
      body: {
        address: AccountAddress.from(account.accountAddress).toString(),
        amount: 100_000_000,
      },
      originMethod: "testFundAccount",
    });
    expect(response?.request?.headers?.customClient).toBeTruthy();
  });

  test("it uses custom client for transaction submission", async () => {
    const { aptos, config } = getAptosClient({ client: { provider: customClient } });
    const account = Account.generate();
    const recipient = Account.generate();
    await movement.fundAccount({ accountAddress: account.accountAddress, amount: 100_000_000 });
    const transaction = await movement.transferCoinTransaction({
      sender: account.accountAddress,
      recipient: recipient.accountAddress,
      amount: 10,
    });
    const authenticator = movement.transaction.sign({ signer: account, transaction });
    const signedTransaction = generateSignedTransaction({ transaction, senderAuthenticator: authenticator });
    const response = await postAptosFullNode<{ headers?: { customClient?: any } }, {}>({
      movementConfig: config,
      body: signedTransaction,
      path: "transactions",
      originMethod: "testSubmitTransaction",
      contentType: MimeType.BCS_SIGNED_TRANSACTION,
    });
    expect(response?.request?.headers?.customClient).toBeTruthy();
  });
});
