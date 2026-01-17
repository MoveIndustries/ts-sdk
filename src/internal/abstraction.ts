import { MovementConfig } from "../api/movementConfig";
import { AccountAddressInput } from "../core";
import {
  InputGenerateTransactionOptions,
  SimpleTransaction,
  TypeTagAddress,
  TypeTagStruct,
  stringStructTag,
} from "../transactions";
import { MoveFunctionId } from "../types";
import { getFunctionParts } from "../utils/helpers";
import { generateTransaction } from "./transactionSubmission";

export async function addAuthenticationFunctionTransaction(args: {
  movementConfig: MovementConfig;
  sender: AccountAddressInput;
  authenticationFunction: string;
  options?: InputGenerateTransactionOptions;
}): Promise<SimpleTransaction> {
  const { movementConfig, sender, authenticationFunction, options } = args;
  const { moduleAddress, moduleName, functionName } = getFunctionParts(authenticationFunction as MoveFunctionId);
  return generateTransaction({
    movementConfig,
    sender,
    data: {
      function: "0x1::account_abstraction::add_authentication_function",
      typeArguments: [],
      functionArguments: [moduleAddress, moduleName, functionName],
      abi: {
        typeParameters: [],
        parameters: [new TypeTagAddress(), new TypeTagStruct(stringStructTag()), new TypeTagStruct(stringStructTag())],
      },
    },
    options,
  });
}

export async function removeAuthenticationFunctionTransaction(args: {
  movementConfig: MovementConfig;
  sender: AccountAddressInput;
  authenticationFunction: string;
  options?: InputGenerateTransactionOptions;
}) {
  const { movementConfig, sender, authenticationFunction, options } = args;
  const { moduleAddress, moduleName, functionName } = getFunctionParts(authenticationFunction as MoveFunctionId);
  return generateTransaction({
    movementConfig,
    sender,
    data: {
      function: "0x1::account_abstraction::remove_authentication_function",
      typeArguments: [],
      functionArguments: [moduleAddress, moduleName, functionName],
      abi: {
        typeParameters: [],
        parameters: [new TypeTagAddress(), new TypeTagStruct(stringStructTag()), new TypeTagStruct(stringStructTag())],
      },
    },
    options,
  });
}

export async function removeDispatchableAuthenticatorTransaction(args: {
  movementConfig: MovementConfig;
  sender: AccountAddressInput;
  options?: InputGenerateTransactionOptions;
}) {
  const { movementConfig, sender, options } = args;
  return generateTransaction({
    movementConfig,
    sender,
    data: {
      function: "0x1::account_abstraction::remove_authenticator",
      typeArguments: [],
      functionArguments: [],
      abi: { typeParameters: [], parameters: [] },
    },
    options,
  });
}
