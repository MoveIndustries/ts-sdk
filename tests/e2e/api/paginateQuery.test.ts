import { getMovementClient } from "../helper";
import { Account } from "../../../src";

describe("PaginateQuery", () => {
  const { movement } = getMovementClient();

  beforeAll(async () => {
    // Generate transactions to test pagination
    for (let i = 0; i < 15; i++) {
      const account = Account.generate();
      await movement.fundAccount({ accountAddress: account.accountAddress, amount: 1000 });
    }
  }, 60000);

  test("it should paginate correctly on fullnode queries", async () => {
    const transactions = await movement.getTransactions();
    // Expect more than 10 transactions
    expect(transactions.length).toBeGreaterThan(10);
    const firstTenTxs = await movement.getTransactions({ options: { offset: 0, limit: 10 } });
    // Expect fetch only first 10 transactions
    expect(firstTenTxs.length).toBe(10);
    // expect last transaction data is not the same as the last transaction data from previous call
    expect(firstTenTxs[firstTenTxs.length - 1]).not.toStrictEqual(transactions[transactions.length - 1]);
    const onlyNextTwentyTxs = await movement.getTransactions({ options: { offset: 10, limit: 10 } });
    // expect only next 10 transactions
    expect(onlyNextTwentyTxs.length).toBe(10);
    // expect first transaction data is not the same as the first transaction data from previous call
    expect(firstTenTxs[0]).not.toStrictEqual(onlyNextTwentyTxs[0]);
  });
});
