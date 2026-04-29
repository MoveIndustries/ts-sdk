// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import { Deserializer, Hex, KeylessAccount, KeylessConfiguration, KeylessPublicKey, KeylessSignature } from "../../src";
import { keylessTestConfig, keylessTestObject } from "./helper";

const groth16VkResponseFixture = {
  alpha_g1: "0xe2f26dbea299f5223b646cb1fb33eadb059d9407559d7441dfd902e3a79a4d2d",
  beta_g2:
    "0xabb73dc17fbc13021e2471e0c08bd67d8401f52b73d6d07483794cad4778180e0c06f33bbc4c79a9cadef253a68084d382f17788f885c9afd176f7cb2f036789",
  delta_g2:
    "0xb106619932d0ef372c46909a2492e246d5de739aa140e27f2c71c0470662f125219049cfe15e4d140d7e4bb911284aad1cad19880efb86f2d9dd4b1bb344ef8f",
  gamma_abc_g1: [
    "0x6123b6fea40de2a7e3595f9c35210da8a45a7e8c2f7da9eb4548e9210cfea81a",
    "0x32a9b8347c512483812ee922dc75952842f8f3083edb6fe8d5c3c07e1340b683",
  ] as [string, string],
  gamma_g2:
    "0xedf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19",
};

const baseConfigResponseFixture = {
  max_commited_epk_bytes: 93,
  max_extra_field_bytes: 350,
  max_iss_val_bytes: 120,
  max_jwt_header_b64_bytes: 300,
  max_signatures_per_txn: 3,
  override_aud_vals: [] as string[],
  training_wheels_pubkey: { vec: ["0x1388de358cf4701696bd58ed4b96e9d670cbbb914b888be1ceda6374a3098ed4"] as [string] },
};
describe("Keyless", () => {
  describe("keylessPublicKey", () => {
    it("should create the instance correctly without error", () => {
      // Create from inputs
      const publicKey = new KeylessPublicKey(keylessTestObject.iss, keylessTestObject.idCommitment);
      expect(publicKey).toBeInstanceOf(KeylessPublicKey);
      expect(publicKey.toString()).toEqual(keylessTestObject.publicKey);

      // Create from JWT and pepper
      const publicKey2 = KeylessPublicKey.fromJwtAndPepper({
        jwt: keylessTestObject.JWT,
        pepper: keylessTestObject.pepper,
      });
      expect(publicKey2).toBeInstanceOf(KeylessPublicKey);
      expect(publicKey2.toString()).toEqual(keylessTestObject.publicKey);
    });

    it("should verify the signature correctly", () => {
      const publicKey = new KeylessPublicKey(keylessTestObject.iss, keylessTestObject.idCommitment);
      const signature = KeylessSignature.deserialize(
        new Deserializer(Hex.hexInputToUint8Array(keylessTestObject.signatureHex)),
      );

      // Convert message to hex
      const hexMsg = Hex.fromHexString(keylessTestObject.messageEncoded);

      // Verify with correct signed message
      expect(
        publicKey.verifySignature({
          message: hexMsg.toUint8Array(),
          signature,
          jwk: keylessTestObject.jwk,
          keylessConfig: keylessTestConfig,
        }),
      ).toBe(true);
    });
  });

  describe("KeylessConfiguration.create", () => {
    // Regression: max_exp_horizon_secs is a u64 on chain but exposed as a JS `number`
    // elsewhere in the keyless API. If an on-chain value were ever to exceed
    // Number.MAX_SAFE_INTEGER, a bare Number(...) cast would silently truncate. The
    // helper used during deserialization must throw instead.
    it("throws when max_exp_horizon_secs exceeds Number.MAX_SAFE_INTEGER", () => {
      const unsafe = (BigInt(Number.MAX_SAFE_INTEGER) + 1n).toString();
      expect(() =>
        KeylessConfiguration.create(groth16VkResponseFixture, {
          ...baseConfigResponseFixture,
          max_exp_horizon_secs: unsafe,
        }),
      ).toThrowError(/safe integer range/);
    });

    it("accepts max_exp_horizon_secs at the safe-integer boundary", () => {
      const config = KeylessConfiguration.create(groth16VkResponseFixture, {
        ...baseConfigResponseFixture,
        max_exp_horizon_secs: Number.MAX_SAFE_INTEGER.toString(),
      });
      expect(config.maxExpHorizonSecs).toBe(Number.MAX_SAFE_INTEGER);
    });
  });

  describe("keylessAccount", () => {
    it("should sign and verify a message correctly", () => {
      const account = KeylessAccount.create({
        jwt: keylessTestObject.JWT,
        pepper: keylessTestObject.pepper,
        ephemeralKeyPair: keylessTestObject.ephemeralKeyPair,
        proof: keylessTestObject.proof,
      });
      const message = "hello";
      const signature = account.sign(message);
      expect(signature).toBeInstanceOf(KeylessSignature);
      expect(
        account.publicKey.verifySignature({
          message,
          signature,
          jwk: keylessTestObject.jwk,
          keylessConfig: keylessTestConfig,
        }),
      ).toBe(true);
      expect(
        account.verifySignature({
          message,
          signature,
          jwk: keylessTestObject.jwk,
          keylessConfig: keylessTestConfig,
        }),
      ).toBe(true);
    });
  });
});
