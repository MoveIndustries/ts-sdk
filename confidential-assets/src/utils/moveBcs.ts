// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import { Serializer } from "@moveindustries/ts-sdk";

/**
 * BCS encoding of Move `vector<u8>` (uleb128 length + raw bytes), matching `std::bcs::to_bytes` for that type.
 */
export function bcsSerializeMoveVectorU8(bytes: Uint8Array): Uint8Array {
  const ser = new Serializer();
  ser.serializeBytes(bytes);
  return ser.toUint8Array();
}
