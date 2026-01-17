import { MovementConfig } from "../api/movementConfig";
import { AccountAddressInput } from "../core";
import { TypeTagAddress, TypeTagU64 } from "../transactions";
import { SimpleTransaction } from "../transactions/instances/simpleTransaction";
import { EntryFunctionABI, InputGenerateTransactionOptions } from "../transactions/types";
import { AnyNumber, MoveStructId } from "../types";
import { APTOS_COIN } from "../utils/const";
import { generateTransaction } from "./transactionSubmission";

const coinTransferAbi: EntryFunctionABI = {
  typeParameters: [{ constraints: [] }],
  parameters: [new TypeTagAddress(), new TypeTagU64()],
};

/**
 * Generates a transaction to transfer coins from one account to another.
 * This function allows you to specify the sender, recipient, amount, and coin type for the transaction.
 *
 * @param args - The parameters for the transaction.
 * @param args.movementConfig - The Movement configuration object.
 * @param args.sender - The address of the account sending the coins.
 * @param args.recipient - The address of the account receiving the coins.
 * @param args.amount - The amount of coins to transfer.
 * @param args.coinType - (Optional) The type of coin to transfer, defaults to Movement Coin if not specified.
 * @param args.options - (Optional) Options for generating the transaction.
 * @group Implementation
 */
export async function transferCoinTransaction(args: {
  movementConfig: MovementConfig;
  sender: AccountAddressInput;
  recipient: AccountAddressInput;
  amount: AnyNumber;
  coinType?: MoveStructId;
  options?: InputGenerateTransactionOptions;
}): Promise<SimpleTransaction> {
  const { movementConfig, sender, recipient, amount, coinType, options } = args;
  const coinStructType = coinType ?? APTOS_COIN;
  return generateTransaction({
    movementConfig,
    sender,
    data: {
      function: "0x1::aptos_account::transfer_coins",
      typeArguments: [coinStructType],
      functionArguments: [recipient, amount],
      abi: coinTransferAbi,
    },
    options,
  });
}
