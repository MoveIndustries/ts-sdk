// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import { AccountAddressInput } from "../core";
import { getObjectDataByObjectAddress } from "../internal/object";
import { AnyNumber, GetObjectDataQueryResponse, OrderByArg, PaginationArgs } from "../types";
import { ProcessorType } from "../utils";
import { MovementConfig } from "./movementConfig";
import { waitForIndexerOnVersion } from "./utils";

/**
 * A class to query all `Object` related queries on Movement.
 * @group Object
 */
export class MovementObject {
  /**
   * Creates an instance of the Movement client with the provided configuration.
   * This allows interaction with the Movement blockchain using the specified settings.
   *
   * @param config - The configuration settings for the Movement client.
   * @param config.network - The network to connect to (e.g., mainnet, testnet).
   * @param config.nodeUrl - The URL of the Movement node to connect to.
   * @param config.faucetUrl - The URL of the faucet for funding accounts (optional).
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * async function runExample() {
   *     // Create a configuration for the Movement client
   *     const config = new MovementConfig({
   *         network: Network.TESTNET, // Specify the desired network
   *         nodeUrl: "https://testnet.movement.dev", // Replace with your node URL
   *     });
   *
   *     // Create an instance of the Movement client
   *     const movement = new Movement(config);
   *
   *     console.log("Movement client created successfully", aptos);
   * }
   * runExample().catch(console.error);
   * ```
   * @group Object
   */
  constructor(readonly config: MovementConfig) { }

  /**
   * Fetches the object data based on the specified object address.
   *
   * @param args.objectAddress - The object address to retrieve data for.
   * @param args.minimumLedgerVersion - Optional minimum ledger version to wait for.
   * @param args.options - Optional configuration options for pagination and ordering.
   *
   * @returns The object data corresponding to the provided address.
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * const config = new MovementConfig({ network: Network.TESTNET });
   * const movement = new Movement(config);
   *
   * async function runExample() {
   *   // Fetching object data by object address
   *   const objectData = await movement.getObjectDataByObjectAddress({
   *     objectAddress: "0x1", // replace with a real object address
   *   });
   *
   *   console.log(objectData);
   * }
   * runExample().catch(console.error);
   * ```
   * @group Object
   */
  async getObjectDataByObjectAddress(args: {
    objectAddress: AccountAddressInput;
    minimumLedgerVersion?: AnyNumber;
    options?: PaginationArgs & OrderByArg<GetObjectDataQueryResponse[0]>;
  }): Promise<GetObjectDataQueryResponse[0]> {
    await waitForIndexerOnVersion({
      config: this.config,
      minimumLedgerVersion: args.minimumLedgerVersion,
      processorType: ProcessorType.OBJECT_PROCESSOR,
    });
    return getObjectDataByObjectAddress({
      movementConfig: this.config,
      ...args,
    });
  }
}
