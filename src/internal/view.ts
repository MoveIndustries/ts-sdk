// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import { MovementConfig } from "../api/movementConfig";
import { Serializer } from "../bcs";
import { postAptosFullNode } from "../client";
import {
  generateViewFunctionPayload,
  InputViewFunctionData,
  InputViewFunctionJsonData,
  ViewFunctionJsonPayload,
} from "../transactions";
import { LedgerVersionArg, MimeType, MoveValue } from "../types";

export async function view<T extends Array<MoveValue> = Array<MoveValue>>(args: {
  movementConfig: MovementConfig;
  payload: InputViewFunctionData;
  options?: LedgerVersionArg;
}): Promise<T> {
  const { movementConfig, payload, options } = args;
  const viewFunctionPayload = await generateViewFunctionPayload({
    ...payload,
    movementConfig,
  });

  const serializer = new Serializer();
  viewFunctionPayload.serialize(serializer);
  const bytes = serializer.toUint8Array();

  const { data } = await postAptosFullNode<Uint8Array, MoveValue[]>({
    movementConfig,
    path: "view",
    originMethod: "view",
    contentType: MimeType.BCS_VIEW_FUNCTION,
    params: { ledger_version: options?.ledgerVersion },
    body: bytes,
  });

  return data as T;
}

export async function viewJson<T extends Array<MoveValue> = Array<MoveValue>>(args: {
  movementConfig: MovementConfig;
  payload: InputViewFunctionJsonData;
  options?: LedgerVersionArg;
}): Promise<T> {
  const { movementConfig, payload, options } = args;
  const { data } = await postAptosFullNode<ViewFunctionJsonPayload, MoveValue[]>({
    movementConfig,
    originMethod: "viewJson",
    path: "view",
    params: { ledger_version: options?.ledgerVersion },
    body: {
      function: payload.function,
      type_arguments: payload.typeArguments ?? [],
      arguments: payload.functionArguments ?? [],
    },
  });

  return data as T;
}
