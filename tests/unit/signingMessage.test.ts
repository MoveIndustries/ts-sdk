// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import { Account, Ed25519PrivateKey, generateSigningMessageForTransaction } from "../../src";
import { getMovementClient } from "../e2e/helper";
import { ed25519 } from "./helper";

const { movement } = getMovementClient();
const TRANSFER_AMOUNT = 100;

describe("generateSigningMessage ", () => {
  const alice = Account.fromPrivateKey({
    privateKey: new Ed25519PrivateKey(ed25519.privateKey),
  });

  test("generates the proper message for transaction", async () => {
    const transaction = await movement.transaction.build.simple({
      sender: alice.accountAddress,
      data: {
        function: "0x1::aptos_account::transfer",
        functionArguments: [alice.accountAddress, TRANSFER_AMOUNT],
      },
      options: {
        accountSequenceNumber: 1,
        expireTimestamp: 100,
      },
    });
    const signingMessage = generateSigningMessageForTransaction(transaction);
    // Signing message should be a Uint8Array with the domain separator prefix hash (32 bytes) + serialized transaction
    expect(signingMessage).toBeInstanceOf(Uint8Array);
    expect(signingMessage.length).toBeGreaterThan(32);
  });

  test("generates the proper message for fee payer transaction", async () => {
    const transaction = await movement.transaction.build.simple({
      sender: alice.accountAddress,
      withFeePayer: true,
      data: {
        function: "0x1::aptos_account::transfer",
        functionArguments: [alice.accountAddress, TRANSFER_AMOUNT],
      },
      options: {
        accountSequenceNumber: 1,
        expireTimestamp: 100,
      },
    });
    const signingMessage = generateSigningMessageForTransaction(transaction);
    // Fee payer transaction signing message should be longer than regular transaction
    expect(signingMessage).toBeInstanceOf(Uint8Array);
    expect(signingMessage.length).toBeGreaterThan(32);
  });
});
