import {
  Account,
  AccountAddress,
  AnyRawTransaction,
  Movement,
  MovementConfig,
  CommittedTransactionResponse,
  Ed25519Account,
  Ed25519PrivateKey,
  InputGenerateTransactionPayloadData,
  InputSubmitTransactionData,
  Network,
  NetworkToNetworkName,
  PendingTransactionResponse,
  PrivateKey,
  PrivateKeyVariants,
  TransactionSubmitter,
  TransactionWorkerEventsEnum,
} from "@moveindustries/ts-sdk";
import fs from "fs";
import path from "path";
import { ConfidentialAsset, TwistedEd25519PrivateKey } from "../../src";

export const longTestTimeout = 120 * 1000;

/**
 * Address MOVE token to be used for testing.
 */
export const TOKEN_ADDRESS = "0x000000000000000000000000000000000000000000000000000000000000000a";

// Use MOVEMENT_NETWORK env var if set, otherwise default to LOCAL for CI
const networkRaw = process.env.MOVEMENT_NETWORK;
const MOVEMENT_NETWORK: Network = networkRaw ? NetworkToNetworkName[networkRaw] : Network.LOCAL;

// Address of the module that contains `confidential_asset`. It now lives in the framework at 0x1.
// Override with CONFIDENTIAL_MODULE_ADDRESS only if testing against a chain that publishes it elsewhere.
const CONFIDENTIAL_MODULE_ADDRESS = process.env.CONFIDENTIAL_MODULE_ADDRESS || "0x1";

export const feePayerAccount = Account.generate();

// Submitter that signs as fee payer only when the transaction was actually built with one.
// Default flow is sender-pays; tests opt into sponsored mode by passing `withFeePayer: true`.
class CustomTransactionSubmitter implements TransactionSubmitter {
  async submitTransaction(
    args: {
      movementConfig: MovementConfig;
    } & Omit<InputSubmitTransactionData, "transactionSubmitter">,
  ): Promise<PendingTransactionResponse> {
    const newConfig = new MovementConfig({
      ...args.movementConfig,
    });
    const movement = new Movement(newConfig);
    if (args.transaction.feePayerAddress !== undefined) {
      const feePayerAuthenticator = movement.signAsFeePayer({ signer: feePayerAccount, transaction: args.transaction });
      return movement.transaction.submit.simple({
        transaction: args.transaction,
        senderAuthenticator: args.senderAuthenticator,
        feePayerAuthenticator,
      });
    }
    return movement.transaction.submit.simple({
      transaction: args.transaction,
      senderAuthenticator: args.senderAuthenticator,
    });
  }
}

const config = new MovementConfig({
  network: MOVEMENT_NETWORK,
  pluginSettings: {
    TRANSACTION_SUBMITTER: new CustomTransactionSubmitter(),
  },
});
export const confidentialAsset = new ConfidentialAsset({
  config,
  confidentialAssetModuleAddress: CONFIDENTIAL_MODULE_ADDRESS,
});
export const movement = new Movement(config);

const rootDir = path.resolve(__dirname, "../../../");

export const addNewContentLineToFile = (filename: string, data: string) => {
  const filePath = path.resolve(rootDir, filename);

  const content = `\n#TESTNET_DK=${data}\n`;

  fs.appendFileSync(filePath, content);
};

export const getBalances = async (
  decryptionKey: TwistedEd25519PrivateKey,
  accountAddress: AccountAddress,
  tokenAddress = TOKEN_ADDRESS,
) => {
  return confidentialAsset.getBalance({
    decryptionKey,
    accountAddress,
    tokenAddress,
  });
};

/**
 * Migrate native coins to fungible asset store.
 * This is needed because the faucet funds native coins, but confidential assets
 * work with fungible assets which are stored separately.
 */
export const migrateCoinsToFungibleStore = async (account: Account): Promise<CommittedTransactionResponse> => {
  const transaction = await movement.transaction.build.simple({
    sender: account.accountAddress,
    data: {
      function: "0x1::coin::migrate_to_fungible_store",
      typeArguments: ["0x1::aptos_coin::AptosCoin"],
      functionArguments: [],
    },
  });
  return sendAndWaitTx(transaction, account);
};

export const sendAndWaitTx = async (
  transaction: AnyRawTransaction,
  signer: Account,
): Promise<CommittedTransactionResponse> => {
  const pendingTxn = await movement.signAndSubmitTransaction({ signer, transaction });
  return movement.waitForTransaction({ transactionHash: pendingTxn.hash });
};

export const sendAndWaitBatchTxs = async (
  txPayloads: InputGenerateTransactionPayloadData[],
  sender: Account,
): Promise<CommittedTransactionResponse[]> => {
  movement.transaction.batch.forSingleAccount({
    sender,
    data: txPayloads,
  });

  let allTxSentPromiseResolve: (value: void | PromiseLike<void>) => void;

  const txHashes: string[] = [];
  movement.transaction.batch.on(TransactionWorkerEventsEnum.TransactionSent, async (data) => {
    txHashes.push(data.transactionHash);

    if (txHashes.length === txPayloads.length) {
      allTxSentPromiseResolve();
    }
  });

  await new Promise<void>((resolve) => {
    allTxSentPromiseResolve = resolve;
  });

  return Promise.all(txHashes.map((txHash) => movement.waitForTransaction({ transactionHash: txHash })));
};

export const getTestAccount = () => {
  if (process.env.TESTNET_PK) {
    return Account.fromPrivateKey({
      privateKey: new Ed25519PrivateKey(
        PrivateKey.formatPrivateKey(process.env.TESTNET_PK, PrivateKeyVariants.Ed25519),
      ),
    });
  }

  console.log("Generating new account");
  const account = Account.generate();
  console.log(`Account generated: ${account.accountAddress}`);
  return account;
};

export const getTestConfidentialAccount = (account?: Ed25519Account) => {
  if (process.env.TESTNET_DK) {
    return new TwistedEd25519PrivateKey(process.env.TESTNET_DK);
  }

  if (!account) return TwistedEd25519PrivateKey.generate();

  const signature = account.sign(TwistedEd25519PrivateKey.decryptionKeyDerivationMessage);

  return TwistedEd25519PrivateKey.fromSignature(signature);
};
