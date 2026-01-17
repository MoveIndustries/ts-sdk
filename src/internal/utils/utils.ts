import { MovementConfig } from "../../api/movementConfig";
import { getAptosFullNode } from "../../client";
import { AccountAddress, AccountAddressInput } from "../../core/accountAddress";
import { AccountData, LedgerVersionArg, MoveModuleBytecode } from "../../types/types";
import { memoizeAsync } from "../../utils/memoize";

/**
 * Retrieves account information for a specified account address.
 *
 * @param args - The arguments for retrieving account information.
 * @param args.movementConfig - The configuration object for Movement.
 * @param args.accountAddress - The address of the account to retrieve information for.
 * @group Implementation
 */
export async function getInfo(args: {
  movementConfig: MovementConfig;
  accountAddress: AccountAddressInput;
}): Promise<AccountData> {
  const { movementConfig, accountAddress } = args;
  const { data } = await getAptosFullNode<{}, AccountData>({
    movementConfig,
    originMethod: "getInfo",
    path: `accounts/${AccountAddress.from(accountAddress).toString()}`,
  });
  return data;
}

/**
 * Queries for a move module given an account address and module name.
 * This function can help you retrieve the module's ABI and other relevant information.
 *
 * @param args - The arguments for retrieving the module.
 * @param args.movementConfig - The configuration for the Movement client.
 * @param args.accountAddress - The account address in hex-encoded 32 byte format.
 * @param args.moduleName - The name of the module to retrieve.
 * @param args.options - Optional parameters for the request.
 * @param args.options.ledgerVersion - Specifies the ledger version of transactions. By default, the latest version will be used.
 * @returns The move module.
 * @group Implementation
 */
export async function getModule(args: {
  movementConfig: MovementConfig;
  accountAddress: AccountAddressInput;
  moduleName: string;
  options?: LedgerVersionArg;
}): Promise<MoveModuleBytecode> {
  // We don't memoize the account module by ledger version, as it's not a common use case, this would be handled
  // by the developer directly
  if (args.options?.ledgerVersion !== undefined) {
    return getModuleInner(args);
  }

  return memoizeAsync(
    async () => getModuleInner(args),
    `module-${args.accountAddress}-${args.moduleName}`,
    1000 * 60 * 5, // 5 minutes
  )();
}

/**
 * Retrieves the bytecode of a specified module from a given account address.
 *
 * @param args - The parameters for retrieving the module bytecode.
 * @param args.movementConfig - The configuration for connecting to the Movement network.
 * @param args.accountAddress - The address of the account from which to retrieve the module.
 * @param args.moduleName - The name of the module to retrieve.
 * @param args.options - Optional parameters for specifying the ledger version.
 * @param args.options.ledgerVersion - The specific ledger version to query.
 * @group Implementation
 */
async function getModuleInner(args: {
  movementConfig: MovementConfig;
  accountAddress: AccountAddressInput;
  moduleName: string;
  options?: LedgerVersionArg;
}): Promise<MoveModuleBytecode> {
  const { movementConfig, accountAddress, moduleName, options } = args;

  const { data } = await getAptosFullNode<{}, MoveModuleBytecode>({
    movementConfig,
    originMethod: "getModule",
    path: `accounts/${AccountAddress.from(accountAddress).toString()}/module/${moduleName}`,
    params: { ledger_version: options?.ledgerVersion },
  });
  return data;
}
