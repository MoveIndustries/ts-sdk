// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import {
  Account,
  AccountAddress,
  CommittedTransactionResponse,
  Ed25519PrivateKey,
  MOVEMENT_COIN,
  MovementConfig,
  MultiEd25519Account,
  MultiEd25519PublicKey,
  MultiKeyAccount,
  Network,
  SigningSchemeInput,
  U64
} from "../../../src";
import { getMovementClient } from "../helper";
import { simpleCoinTransactionHeler } from "../transaction/helper";

describe("account api", () => {
  const FUND_AMOUNT = 100_000_000;

  describe("fetch data", () => {
    test("it fetches account data", async () => {
      const { movement } = getMovementClient();
      const data = await movement.getAccountInfo({
        accountAddress: "0x1",
      });
      expect(data).toHaveProperty("sequence_number");
      expect(data.sequence_number).toBe("0");
      expect(data).toHaveProperty("authentication_key");
      expect(data.authentication_key).toBe("0x0000000000000000000000000000000000000000000000000000000000000001");
    });

    test("it fetches account modules", async () => {
      const { movement } = getMovementClient();
      const data = await movement.getAccountModules({
        accountAddress: "0x1",
      });
      expect(data.length).toBeGreaterThan(0);
    });

    test("it fetches account modules with a limit", async () => {
      const { movement, config } = getMovementClient();
      const data = await movement.getAccountModules({
        accountAddress: "0x1",
        options: {
          limit: 1,
        },
      });
      expect(data.length).toEqual(1);
    });

    test("it fetches account modules with pagination", async () => {
      const { movement, config } = getMovementClient();
      let { modules, cursor } = await movement.getAccountModulesPage({
        accountAddress: "0x1",
        options: {
          limit: 1,
        },
      });
      expect(modules.length).toEqual(1);
      expect(cursor).toBeDefined();
      while (true) {
        const { modules: modules2, cursor: cursor2 } = await movement.getAccountModulesPage({
          accountAddress: "0x1",
          options: {
            cursor,
          },
        });
        expect(modules2.length).toBeGreaterThan(0);
        expect(modules2).not.toContain(modules[0]);
        if (cursor2 === undefined) {
          break;
        }
        cursor = cursor2;
      }
    });

    test("it fetches an account module", async () => {
      const { movement, config } = getMovementClient();
      const data = await movement.getAccountModule({
        accountAddress: "0x1",
        moduleName: "coin",
      });
      expect(data).toHaveProperty("bytecode");
    });

    test("it fetches account resources", async () => {
      const { movement, config } = getMovementClient();
      const data = await movement.getAccountResources({
        accountAddress: "0x1",
      });
      expect(data.length).toBeGreaterThan(0);
    });

    test("it fetches account resources with a limit", async () => {
      const { movement, config } = getMovementClient();
      const data = await movement.getAccountResources({
        accountAddress: "0x1",
        options: {
          limit: 1,
        },
      });
      expect(data.length).toEqual(1);
    });

    test("it fetches account resources with pagination", async () => {
      const { movement, config } = getMovementClient();
      const { resources, cursor } = await movement.getAccountResourcesPage({
        accountAddress: "0x1",
        options: {
          limit: 1,
        },
      });
      expect(resources.length).toEqual(1);
      expect(cursor).toBeDefined();

      const { resources: resources2, cursor: cursor2 } = await movement.getAccountResourcesPage({
        accountAddress: "0x1",
        options: {
          cursor,
        },
      });
      expect(resources2.length).toBeGreaterThan(0);
      expect(cursor2).toBeUndefined();
      expect(resources2).not.toContain(resources[0]);
    });

    test("it fetches an account resource without a type", async () => {
      const { movement, config } = getMovementClient();
      const data = await movement.getAccountResource({
        accountAddress: "0x1",
        resourceType: "0x1::account::Account",
      });
      expect(data).toHaveProperty("sequence_number");
      expect(data.sequence_number).toBe("0");
      expect(data).toHaveProperty("authentication_key");
      expect(data.authentication_key).toBe("0x0000000000000000000000000000000000000000000000000000000000000001");
    });

    test("it fetches an account resource typed", async () => {
      const { movement, config } = getMovementClient();
      type AccountRes = {
        authentication_key: string;
        coin_register_events: {
          counter: string;
          guid: {
            id: {
              addr: string;
              creation_num: string;
            };
          };
        };
        guid_creation_num: string;
        key_rotation_events: {
          counter: string;
          guid: {
            id: {
              addr: string;
              creation_num: string;
            };
          };
        };
        sequence_number: string;
      };

      const resource = await movement.getAccountResource<AccountRes>({
        accountAddress: "0x1",
        resourceType: "0x1::account::Account",
      });
      expect(resource).toHaveProperty("sequence_number");
      expect(resource.sequence_number).toBe("0");
      expect(resource).toHaveProperty("authentication_key");
      expect(resource.authentication_key).toBe("0x0000000000000000000000000000000000000000000000000000000000000001");
    });

    test("it fetches account transactions", async () => {
      const { movement, config } = getMovementClient();
      const senderAccount = Account.generate();
      await movement.fundAccount({
        accountAddress: senderAccount.accountAddress,
        amount: FUND_AMOUNT,
      });
      const bob = Account.generate();
      const rawTxn = await movement.transaction.build.simple({
        sender: senderAccount.accountAddress,
        data: {
          function: "0x1::aptos_account::transfer",
          functionArguments: [bob.accountAddress, new U64(10)],
        },
      });
      const authenticator = movement.transaction.sign({
        signer: senderAccount,
        transaction: rawTxn,
      });
      const response = await movement.transaction.submit.simple({
        transaction: rawTxn,
        senderAuthenticator: authenticator,
      });
      const txn = await movement.waitForTransaction({ transactionHash: response.hash });
      const accountTransactions = await movement.getAccountTransactions({
        accountAddress: senderAccount.accountAddress,
      });
      expect(accountTransactions[0]).toStrictEqual(txn);
    });

    test("it fetches account transactions count", async () => {
      const { movement, config } = getMovementClient();
      const senderAccount = Account.generate();
      const response = await movement.fundAccount({
        accountAddress: senderAccount.accountAddress,
        amount: FUND_AMOUNT,
      });

      await movement.waitForTransaction({ transactionHash: response.hash });
      const accountTransactionsCount = await movement.getAccountTransactionsCount({
        accountAddress: senderAccount.accountAddress,
      });
      expect(accountTransactionsCount).toBe(1);
    });

    test("it fetches account coins data", async () => {
      const { movement, config } = getMovementClient();
      const senderAccount = Account.generate();
      const fundTxn = await movement.fundAccount({
        accountAddress: senderAccount.accountAddress,
        amount: FUND_AMOUNT,
      });

      await movement.waitForTransaction({ transactionHash: fundTxn.hash });
      const accountCoinData = await movement.getAccountCoinsData({
        accountAddress: senderAccount.accountAddress,
      });
      expect(accountCoinData[0].amount).toBe(FUND_AMOUNT);
      expect(accountCoinData[0].asset_type).toBe("0x1::aptos_coin::AptosCoin");
    });

    test("it fetches account coins count", async () => {
      const { movement, config } = getMovementClient();
      const senderAccount = Account.generate();
      const fundTxn = await movement.fundAccount({
        accountAddress: senderAccount.accountAddress,
        amount: FUND_AMOUNT,
      });

      await movement.waitForTransaction({ transactionHash: fundTxn.hash });
      const accountCoinsCount = await movement.getAccountCoinsCount({
        accountAddress: senderAccount.accountAddress,
      });
      expect(accountCoinsCount).toBe(1);
    });

    test("it fetches account's coin amount", async () => {
      const { movement, config } = getMovementClient();
      const senderAccount = Account.generate();
      const fundTxn = await movement.fundAccount({
        accountAddress: senderAccount.accountAddress,
        amount: FUND_AMOUNT,
      });

      await movement.waitForTransaction({ transactionHash: fundTxn.hash });
      // custom coin type that doesn't exist, will throw an error
      const getInvalidCoinAmount = movement.getAccountCoinAmount({
        accountAddress: senderAccount.accountAddress,
        coinType: "0x12345::coin::Coin",
      });
      await expect(getInvalidCoinAmount).rejects.toThrow();
      // custom coin type struct that does exist, but is not a coin, will return 0, similar to a coin that exists
      const getOtherCoinAmount = await movement.getAccountCoinAmount({
        accountAddress: senderAccount.accountAddress,
        coinType: "0x1::string::String",
      });
      expect(getOtherCoinAmount).toBe(0);

      // MOVE Movement coin
      const accountMOVEAmount = await movement.getAccountCoinAmount({
        accountAddress: senderAccount.accountAddress,
        coinType: MOVEMENT_COIN,
      });
      expect(accountMOVEAmount).toBe(100000000);

      // MOVE Movement coin by fungible asset metadata
      const accountMOVEAmount2 = await movement.getAccountCoinAmount({
        accountAddress: senderAccount.accountAddress,
        faMetadataAddress: AccountAddress.A,
      });
      expect(accountMOVEAmount2).toBe(100000000);
      // By both
      // MOVE Movement coin by fungible asset metadata
      const accountMOVEAmount3 = await movement.getAccountCoinAmount({
        accountAddress: senderAccount.accountAddress,
        coinType: MOVEMENT_COIN,
        faMetadataAddress: "0xA",
      });
      expect(accountMOVEAmount3).toBe(100000000);
      // By neither
      const failForNoCoinTypeGiven = movement.getAccountCoinAmount({
        accountAddress: senderAccount.accountAddress,
      });
      await expect(failForNoCoinTypeGiven).rejects.toThrow();
    });

    test("it fetches account balance by coin type (MOVE)", async () => {
      const { movement, config } = getMovementClient();
      const account = Account.generate();

      const fundTxn = await movement.fundAccount({
        accountAddress: account.accountAddress,
        amount: FUND_AMOUNT,
      });
      await movement.waitForTransaction({ transactionHash: fundTxn.hash });

      const balance = await movement.getBalance({
        accountAddress: account.accountAddress,
        asset: MOVEMENT_COIN,
      });
      expect(balance).toBe(FUND_AMOUNT);
    });

    test("it fetches account balance by FA metadata address (MOVE)", async () => {
      const { movement, config } = getMovementClient();
      const account = Account.generate();

      const fundTxn = await movement.fundAccount({
        accountAddress: account.accountAddress,
        amount: FUND_AMOUNT,
      });
      await movement.waitForTransaction({ transactionHash: fundTxn.hash });

      const balance = await movement.getBalance({
        accountAddress: account.accountAddress,
        asset: AccountAddress.A,
      });
      expect(balance).toBe(FUND_AMOUNT);
    });

    test("lookupOriginalAccountAddress - Look up account address before key rotation", async () => {
      const { movement, config } = getMovementClient();
      const account = Account.generate();

      // Fund and create account on-chain
      await movement.fundAccount({ accountAddress: account.accountAddress, amount: FUND_AMOUNT });

      const lookupAccount = await movement.lookupOriginalAccountAddress({
        authenticationKey: account.accountAddress,
      });
      expect(lookupAccount).toStrictEqual(account.accountAddress);
    });

    test("it fetches account owned token from collection", async () => {
      const { movement, config } = getMovementClient();
      const creator = Account.generate();
      await movement.fundAccount({ accountAddress: creator.accountAddress, amount: FUND_AMOUNT });
      const collectionCreationTransaction = await movement.createCollectionTransaction({
        creator,
        description: "My new collection!",
        name: "Test Collection",
        uri: "Test Collection",
      });
      const pendingCollectionCreationTransaction = await movement.signAndSubmitTransaction({
        signer: creator,
        transaction: collectionCreationTransaction,
      });
      await movement.waitForTransaction({ transactionHash: pendingCollectionCreationTransaction.hash });
      const transaction = await movement.mintDigitalAssetTransaction({
        creator,
        collection: "Test Collection",
        description: "My new collection!",
        name: "Test Token",
        uri: "http://movement.dev/nft",
        propertyKeys: ["my bool key", "my array key"],
        propertyTypes: ["BOOLEAN", "ARRAY"],
        propertyValues: [false, "[value]"],
      });
      const pendingTxn = await movement.signAndSubmitTransaction({ signer: creator, transaction });
      const response = await movement.waitForTransaction({ transactionHash: pendingTxn.hash });

      const address = await movement.getCollectionId({
        collectionName: "Test Collection",
        creatorAddress: creator.accountAddress,
      });
      const tokens = await movement.getAccountOwnedTokensFromCollectionAddress({
        accountAddress: creator.accountAddress,
        collectionAddress: address,
        minimumLedgerVersion: BigInt(response.version),
      });

      expect(tokens.length).toBe(1);
      expect(tokens[0].current_token_data?.token_name).toBe("Test Token");
    });

    describe("it derives an account from a private key", () => {
      const config = new MovementConfig({
        network: Network.LOCAL,
      });

      test("single sender ed25519", async () => {
        const account = Account.generate({ scheme: SigningSchemeInput.Ed25519, legacy: false });
        await movement.fundAccount({ accountAddress: account.accountAddress, amount: 100 });

        const derivedAccount = await movement.deriveAccountFromPrivateKey({ privateKey: account.privateKey });
        expect(derivedAccount.accountAddress.equals(account.accountAddress)).toEqual(true);
      }, 15000);
      test("single sender secp256k1", async () => {
        const account = Account.generate({ scheme: SigningSchemeInput.Secp256k1Ecdsa });
        await movement.fundAccount({ accountAddress: account.accountAddress, amount: 100 });

        const derivedAccount = await movement.deriveAccountFromPrivateKey({ privateKey: account.privateKey });
        expect(derivedAccount).toStrictEqual(account);
      });
      test("legacy ed25519", async () => {
        const account = Account.generate({ scheme: SigningSchemeInput.Ed25519, legacy: true });
        await movement.fundAccount({ accountAddress: account.accountAddress, amount: 100 });

        const derivedAccount = await movement.deriveAccountFromPrivateKey({ privateKey: account.privateKey });
        expect(derivedAccount).toStrictEqual(account);
      });
      test("fails when account not created/funded and throwIfNoAccountFound is true", async () => {
        const account = Account.generate({ scheme: SigningSchemeInput.Ed25519, legacy: true });

        expect(async () => {
          await movement.deriveAccountFromPrivateKey({
            privateKey: account.privateKey,
            options: { throwIfNoAccountFound: true },
          });
        }).rejects.toThrow("No existing account found for private key.");
      });
      test("returns default legacy ed25519 account if no account exists", async () => {
        const account = Account.generate({ scheme: SigningSchemeInput.Ed25519, legacy: true });

        const derivedAccount = await movement.deriveAccountFromPrivateKey({
          privateKey: account.privateKey,
        });
        expect(derivedAccount).toStrictEqual(account);
      });
    });
  });

  describe("Key Rotation", () => {
    test("it should rotate ed25519 to ed25519 auth key correctly", async () => {
      const { movement, config } = getMovementClient();

      // Current Account
      const account = Account.generate({ scheme: SigningSchemeInput.Ed25519, legacy: true });
      await movement.fundAccount({ accountAddress: account.accountAddress, amount: 1_000_000_000 });

      // account that holds the new key
      const rotateToPrivateKey = Ed25519PrivateKey.generate();

      // Rotate the key
      const txn = await movement.rotateAuthKey({ fromAccount: account, toNewPrivateKey: rotateToPrivateKey });
      const pendingTxn = await movement.signAndSubmitTransaction({ signer: account, transaction: txn });
      const response = await movement.waitForTransaction({ transactionHash: pendingTxn.hash });

      // lookup original account address
      const lookupAccountAddress = await movement.lookupOriginalAccountAddress({
        authenticationKey: rotateToPrivateKey.publicKey().authKey().derivedAddress(),
        minimumLedgerVersion: BigInt(response.version),
      });

      // Check if the lookup account address is the same as the original account address
      expect(lookupAccountAddress).toStrictEqual(account.accountAddress);

      const rotatedAccount = Account.fromPrivateKey({
        privateKey: rotateToPrivateKey,
        address: account.accountAddress,
      });
      await simpleCoinTransactionHeler(movement, rotatedAccount, Account.generate());
    }, 10000);

    test("it should rotate ed25519 to multi-ed25519 auth key correctly", async () => {
      const { movement, config } = getMovementClient();

      // Current Account
      const account = Account.generate({ scheme: SigningSchemeInput.Ed25519, legacy: true });
      await movement.fundAccount({ accountAddress: account.accountAddress, amount: 1_000_000_000 });

      const mk1 = Account.generate({ scheme: SigningSchemeInput.Ed25519, legacy: true });
      const mk2 = Account.generate({ scheme: SigningSchemeInput.Ed25519, legacy: true });
      const multiEdAccount = new MultiEd25519Account({
        publicKey: new MultiEd25519PublicKey({
          publicKeys: [mk1.publicKey, mk2.publicKey],
          threshold: 1,
        }),
        signers: [mk1.privateKey],
      });

      // Rotate the key
      const txn = await movement.rotateAuthKey({ fromAccount: account, toAccount: multiEdAccount });
      const pendingTxn = await movement.signAndSubmitTransaction({ signer: account, transaction: txn });
      await movement.waitForTransaction({ transactionHash: pendingTxn.hash });

      const accountInfo = await movement.account.getAccountInfo({
        accountAddress: account.accountAddress,
      });
      expect(accountInfo.authentication_key).toEqual(multiEdAccount.publicKey.authKey().toString());

      const rotatedAccount = new MultiEd25519Account({
        publicKey: new MultiEd25519PublicKey({
          publicKeys: [mk1.publicKey, mk2.publicKey],
          threshold: 1,
        }),
        signers: [mk1.privateKey],
        address: account.accountAddress,
      });
      await simpleCoinTransactionHeler(movement, rotatedAccount, Account.generate());
    }, 10000);

    test("it should rotate ed25519 to multikey auth key correctly", async () => {
      const { movement, config } = getMovementClient();

      // Current Account
      const account = Account.generate({ scheme: SigningSchemeInput.Ed25519, legacy: true });
      await movement.fundAccount({ accountAddress: account.accountAddress, amount: 1_000_000_000 });

      const mk1 = Account.generate({ scheme: SigningSchemeInput.Ed25519, legacy: true });
      const mk2 = Account.generate({ scheme: SigningSchemeInput.Ed25519, legacy: true });
      const multiKeyAccount = MultiKeyAccount.fromPublicKeysAndSigners({
        publicKeys: [mk1.publicKey, mk2.publicKey],
        signaturesRequired: 1,
        signers: [mk1],
      });

      // Rotate the key
      const txn = await movement.rotateAuthKeyUnverified({
        fromAccount: account,
        toNewPublicKey: multiKeyAccount.publicKey,
      });
      const pendingTxn = await movement.signAndSubmitTransaction({ signer: account, transaction: txn });
      await movement.waitForTransaction({ transactionHash: pendingTxn.hash });

      const accountInfo = await movement.account.getAccountInfo({
        accountAddress: account.accountAddress,
      });
      expect(accountInfo.authentication_key).toEqual(multiKeyAccount.publicKey.authKey().toString());

      const rotatedAccount = MultiKeyAccount.fromPublicKeysAndSigners({
        address: account.accountAddress,
        publicKeys: [mk1.publicKey, mk2.publicKey],
        signaturesRequired: 1,
        signers: [mk1],
      });
      await simpleCoinTransactionHeler(movement, rotatedAccount, Account.generate());
    }, 10000);

    test("it should rotate ed25519 to unverified auth key correctly", async () => {
      const { movement, config } = getMovementClient();

      // Current Account
      const account = Account.generate({ scheme: SigningSchemeInput.Ed25519, legacy: true });
      await movement.fundAccount({ accountAddress: account.accountAddress, amount: 1_000_000_000 });

      // account that holds the new key
      const newAccount = Account.generate();
      const newAuthKey = newAccount.publicKey.authKey();

      // Rotate the key
      const txn = await movement.rotateAuthKeyUnverified({
        fromAccount: account,
        toNewPublicKey: newAccount.publicKey,
      });
      const pendingTxn = await movement.signAndSubmitTransaction({ signer: account, transaction: txn });
      await movement.waitForTransaction({ transactionHash: pendingTxn.hash });

      const accountInfo = await movement.account.getAccountInfo({
        accountAddress: account.accountAddress,
      });
      expect(accountInfo.authentication_key).toEqual(newAuthKey.toString());

      const rotatedAccount = Account.fromPrivateKey({
        privateKey: newAccount.privateKey,
        address: newAccount.accountAddress,
      });
      await simpleCoinTransactionHeler(movement, rotatedAccount, Account.generate());
    }, 10000);
  });

  describe("Account Derivation APIs", () => {
    const { movement, config } = getMovementClient();

    const minterAccount = Account.generate();

    beforeAll(async () => {
      await movement.fundAccount({
        accountAddress: minterAccount.accountAddress,
        amount: FUND_AMOUNT,
      });
    }, 10000);

    const checkAccountsMatch = (
      accounts: { accountAddress: AccountAddress }[],
      expectedAddresses: { accountAddress: AccountAddress }[],
    ) => {
      expect(accounts.length).toBe(expectedAddresses.length);
      accounts.forEach((account, index) => {
        expect(account.accountAddress.equals(expectedAddresses[index].accountAddress)).toEqual(true);
      });
    };

    const DEFAULT_MAX_GAS_AMOUNT = 2000;
    async function createAccount(recipient: Account): Promise<CommittedTransactionResponse> {
      const transaction = await movement.transferCoinTransaction({
        sender: minterAccount.accountAddress,
        recipient: recipient.accountAddress,
        amount: FUND_AMOUNT / 100,
        options: {
          maxGasAmount: DEFAULT_MAX_GAS_AMOUNT,
        },
      });
      const pendingTxn = await movement.signAndSubmitTransaction({ signer: minterAccount, transaction });
      return await movement.waitForTransaction({ transactionHash: pendingTxn.hash });
    }

    async function sendNoopTxn(sender: Account): Promise<CommittedTransactionResponse> {
      const transaction = await movement.transferCoinTransaction({
        sender: sender.accountAddress,
        recipient: sender.accountAddress,
        amount: 0,
        options: {
          maxGasAmount: DEFAULT_MAX_GAS_AMOUNT,
        },
      });
      const pendingTxn = await movement.signAndSubmitTransaction({ signer: sender, transaction });
      return await movement.waitForTransaction({ transactionHash: pendingTxn.hash });
    }

    test("it derives accounts correctly", async () => {
      const account1 = Account.generate({ scheme: SigningSchemeInput.Ed25519, legacy: true });
      const account2 = Account.generate({ scheme: SigningSchemeInput.Ed25519, legacy: true });
      const account3 = Account.generate({ scheme: SigningSchemeInput.Ed25519, legacy: true });
      const multiKeyAccount = MultiKeyAccount.fromPublicKeysAndSigners({
        publicKeys: [account1.publicKey, account2.publicKey, account3.publicKey],
        signaturesRequired: 1,
        signers: [account3],
      });
      const multiEdAccount = new MultiEd25519Account({
        publicKey: new MultiEd25519PublicKey({
          publicKeys: [account3.publicKey, account1.publicKey],
          threshold: 1,
        }),
        signers: [account3.privateKey],
      });
      const multiEdAccountTwoSigners = new MultiEd25519Account({
        publicKey: new MultiEd25519PublicKey({
          publicKeys: [account1.publicKey, account2.publicKey, account3.publicKey],
          threshold: 2,
        }),
        signers: [account1.privateKey, account2.privateKey],
      });
      for (const account of [account1, account2, account3, multiKeyAccount, multiEdAccount, multiEdAccountTwoSigners]) {
        await createAccount(account);
      }
      // Rotate account2 to account1's auth key, skipping verification.
      const rotateTxn = await movement.rotateAuthKeyUnverified({
        fromAccount: account2,
        toNewPublicKey: account1.publicKey,
        options: {
          maxGasAmount: DEFAULT_MAX_GAS_AMOUNT,
        },
      });
      const pendingTxn = await movement.signAndSubmitTransaction({ signer: account2, transaction: rotateTxn });
      await movement.waitForTransaction({ transactionHash: pendingTxn.hash });

      // Send noop txns for the multikey accounts with account3 as the signer. These accounts
      // are not verified as owned by account1.
      await sendNoopTxn(multiKeyAccount);
      await sendNoopTxn(multiEdAccount);
      await sendNoopTxn(multiEdAccountTwoSigners);
      let accounts = await movement.deriveOwnedAccountsFromSigner({ signer: account1 });
      expect(accounts.length).toBe(1);
      expect(accounts[0].accountAddress.equals(account1.accountAddress)).toEqual(true);

      // Include unverified accounts.
      accounts = await movement.deriveOwnedAccountsFromSigner({
        signer: account1,
        options: {
          includeUnverified: true,
        },
      });
      checkAccountsMatch(accounts, [multiEdAccount, multiKeyAccount, account2, account1]);

      // Send txn with multiKeyAccount and account2 from the derived accounts. This will mark them as verified and
      // be returned even when includeUnverified is false (default).
      await sendNoopTxn(accounts[1]);
      const { version } = await sendNoopTxn(accounts[2]);

      accounts = await movement.deriveOwnedAccountsFromSigner({
        signer: account1,
        minimumLedgerVersion: BigInt(version),
        options: {
          includeUnverified: false,
        },
      });
      checkAccountsMatch(accounts, [account2, multiKeyAccount, account1]);

      // Send txn with account1 which will change the ordering
      await sendNoopTxn(account1);

      accounts = await movement.deriveOwnedAccountsFromSigner({ signer: account1 });
      checkAccountsMatch(accounts, [account1, account2, multiKeyAccount]);

      // Check the noMultiKey works.
      accounts = await movement.deriveOwnedAccountsFromSigner({ signer: account1, options: { noMultiKey: true } });
      checkAccountsMatch(accounts, [account1, account2]);
    }, 20000);

    test("it derives account that has been rotated", async () => {
      const account1 = Account.generate({ scheme: SigningSchemeInput.Ed25519 });
      const account2 = Account.generate({ scheme: SigningSchemeInput.Ed25519 });

      for (const account of [account1, account2]) {
        await createAccount(account);
      }

      let accounts = await movement.deriveOwnedAccountsFromSigner({ signer: account1 });
      expect(accounts.length).toBe(1);
      expect(accounts[0].accountAddress.equals(account1.accountAddress)).toEqual(true);

      // Verified rotation. Should be derivable immediately.
      const rotateTxn = await movement.rotateAuthKey({
        fromAccount: account2,
        toNewPrivateKey: account1.privateKey,
        options: {
          maxGasAmount: DEFAULT_MAX_GAS_AMOUNT,
        },
      });
      const pendingTxn = await movement.signAndSubmitTransaction({ signer: account2, transaction: rotateTxn });
      const response = await movement.waitForTransaction({ transactionHash: pendingTxn.hash });

      accounts = await movement.deriveOwnedAccountsFromSigner({
        signer: account1,
        minimumLedgerVersion: BigInt(response.version),
      });
      expect(accounts.length).toBe(2);
      expect(accounts[0].accountAddress.equals(account2.accountAddress)).toEqual(true);
      expect(accounts[1].accountAddress.equals(account1.accountAddress)).toEqual(true);
    }, 20000);

    test("it returns both legacy and single-signer accounts by default for ed25519", async () => {
      const key = Ed25519PrivateKey.generate();
      const legacyAccount = Account.fromPrivateKey({
        privateKey: key,
        legacy: true,
      });
      const singleSignerAccount = Account.fromPrivateKey({
        privateKey: key,
        legacy: false,
      });
      let txn: CommittedTransactionResponse;
      const defaultAccounts = [legacyAccount, singleSignerAccount];
      for (const account of [legacyAccount, singleSignerAccount]) {
        txn = await createAccount(account);
      }

      let accounts = await movement.deriveOwnedAccountsFromSigner({
        signer: key,
        minimumLedgerVersion: Number(txn!.version),
      });
      checkAccountsMatch(accounts, defaultAccounts.reverse());
    }, 20000);

    test("it doesn't return default account if it is rotated", async () => {
      const account1 = Account.generate({ scheme: SigningSchemeInput.Ed25519 });
      const account2 = Account.generate({ scheme: SigningSchemeInput.Ed25519 });

      for (const account of [account1, account2]) {
        await createAccount(account);
      }

      let accounts = await movement.deriveOwnedAccountsFromSigner({ signer: account1 });
      expect(accounts.length).toBe(1);
      expect(accounts[0].accountAddress.equals(account1.accountAddress)).toEqual(true);

      // Verified rotation. Should be derivable immediately.
      const rotateTxn = await movement.rotateAuthKey({
        fromAccount: account1,
        toNewPrivateKey: Ed25519PrivateKey.generate(),
        options: {
          maxGasAmount: DEFAULT_MAX_GAS_AMOUNT,
        },
      });
      const pendingTxn = await movement.signAndSubmitTransaction({ signer: account1, transaction: rotateTxn });
      const response = await movement.waitForTransaction({ transactionHash: pendingTxn.hash });

      accounts = await movement.deriveOwnedAccountsFromSigner({
        signer: account1,
        minimumLedgerVersion: BigInt(response.version),
      });
      expect(accounts.length).toBe(0);
    }, 20000);

    test("getAccountsFromPublicKey returns accounts", async () => {
      const account1 = Account.generate({ scheme: SigningSchemeInput.Ed25519, legacy: true });
      const account2 = Account.generate({ scheme: SigningSchemeInput.Ed25519, legacy: true });
      const account3 = Account.generate({ scheme: SigningSchemeInput.Ed25519, legacy: true });
      const multiKeyAccount = MultiKeyAccount.fromPublicKeysAndSigners({
        publicKeys: [account1.publicKey, account2.publicKey, account3.publicKey],
        signaturesRequired: 2,
        signers: [account3, account2],
      });
      const multiEdAccount = new MultiEd25519Account({
        publicKey: new MultiEd25519PublicKey({
          publicKeys: [account3.publicKey, account1.publicKey],
          threshold: 2,
        }),
        signers: [account3.privateKey, account1.privateKey],
      });
      for (const account of [account1, account2, account3, multiKeyAccount, multiEdAccount]) {
        await createAccount(account);
      }
      // Rotate account2 to account1's auth key, skipping verification.
      const rotateTxn = await movement.rotateAuthKeyUnverified({
        fromAccount: account2,
        toNewPublicKey: account1.publicKey,
        options: {
          maxGasAmount: DEFAULT_MAX_GAS_AMOUNT,
        },
      });
      const pendingTxn = await movement.signAndSubmitTransaction({ signer: account2, transaction: rotateTxn });
      await movement.waitForTransaction({ transactionHash: pendingTxn.hash });

      // Send noop txns for the multikey accounts
      // The multiEdAccount has account1 as a signer.
      await sendNoopTxn(multiKeyAccount);
      let { version } = await sendNoopTxn(multiEdAccount);

      let accounts = await movement.getAccountsForPublicKey({
        publicKey: account1.publicKey,
        minimumLedgerVersion: BigInt(version),
      });
      expect(accounts.length).toBe(2);
      checkAccountsMatch(accounts, [multiEdAccount, account1]);

      // Check that the multiKeyAccount is not included.
      accounts = await movement.getAccountsForPublicKey({
        publicKey: account1.publicKey,
        options: {
          includeUnverified: true,
        },
      });
      checkAccountsMatch(accounts, [multiEdAccount, multiKeyAccount, account2, account1]);
    }, 20000);
  });
});
