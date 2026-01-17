// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import { Account } from "./account";
import { AccountAbstraction } from "./account/abstraction";
import { ANS } from "./ans";
import { Coin } from "./coin";
import { DigitalAsset } from "./digitalAsset";
import { Faucet } from "./faucet";
import { FungibleAsset } from "./fungibleAsset";
import { General } from "./general";
import { Keyless } from "./keyless";
import { MovementConfig } from "./movementConfig";
import { MovementObject } from "./object";
import { Staking } from "./staking";
import { Table } from "./table";
import { Transaction } from "./transaction";

/**
 * The main entry point for interacting with the Movement APIs,
 * providing access to various functionalities organized into
 * distinct namespaces.
 *
 * To utilize the SDK, instantiate a new Movement object to gain
 * access to the complete range of SDK features.
 *
 * @example
 * ```typescript
 * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
 *
 * async function runExample() {
 *     // Create a configuration for connecting to the Movement testnet
 *     const config = new MovementConfig({ network: Network.TESTNET });
 *
 *     // Initialize the Movement client with the configuration
 *     const movement = new Movement(config);
 *
 *     console.log("Movement client initialized:", aptos);
 * }
 * runExample().catch(console.error);
 * ```
 * @group Client
 */
export class Movement {
  readonly config: MovementConfig;

  readonly account: Account;

  readonly ans: ANS;

  readonly coin: Coin;

  readonly digitalAsset: DigitalAsset;

  readonly faucet: Faucet;

  readonly fungibleAsset: FungibleAsset;

  readonly general: General;

  readonly staking: Staking;

  readonly transaction: Transaction;

  readonly table: Table;

  readonly keyless: Keyless;

  readonly object: MovementObject;

  /**
   * Initializes a new instance of the Movement client with the provided configuration settings.
   * This allows you to interact with various Movement functionalities such as accounts, transactions, and events.
   *
   * @param settings - Configuration settings for the Movement client.
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * async function runExample() {
   *     // Create a new Movement client with default settings
   *     const config = new MovementConfig({ network: Network.TESTNET }); // Specify your own settings if needed
   *     const movement = new Movement(config);
   *
   *     console.log("Movement client initialized:", aptos);
   * }
   * runExample().catch(console.error);
   * ```
   * @group Client
   */
  constructor(config?: MovementConfig) {
    this.config = config ?? new MovementConfig();
    this.account = new Account(this.config);
    this.abstraction = new AccountAbstraction(this.config);
    this.ans = new ANS(this.config);
    this.coin = new Coin(this.config);
    this.digitalAsset = new DigitalAsset(this.config);
    this.faucet = new Faucet(this.config);
    this.fungibleAsset = new FungibleAsset(this.config);
    this.general = new General(this.config);
    this.staking = new Staking(this.config);
    this.transaction = new Transaction(this.config);
    this.table = new Table(this.config);
    this.keyless = new Keyless(this.config);
    this.object = new MovementObject(this.config);
  }

  setIgnoreTransactionSubmitter(ignore: boolean) {
    this.config.setIgnoreTransactionSubmitter(ignore);
  }
}

// extends Movement interface so all the methods and properties
// from the other classes will be recognized by typescript.
export interface Movement
  extends Account,
  ANS,
  Coin,
  DigitalAsset,
  Event,
  Faucet,
  FungibleAsset,
  General,
  Keyless,
  Staking,
  Table,
  MovementObject,
  Omit<Transaction, "build" | "simulate" | "submit" | "batch"> { }

/**
In TypeScript, we can’t inherit or extend from more than one class,
Mixins helps us to get around that by creating a partial classes
that we can combine to form a single class that contains all the methods and properties from the partial classes.
{@link https://www.typescriptlang.org/docs/handbook/mixins.html#alternative-pattern}

Here, we combine any subclass and the Movement class.
 * @group Client
*/
function applyMixin(targetClass: any, baseClass: any, baseClassProp: string) {
  // Mixin instance methods
  Object.getOwnPropertyNames(baseClass.prototype).forEach((propertyName) => {
    const propertyDescriptor = Object.getOwnPropertyDescriptor(baseClass.prototype, propertyName);
    if (!propertyDescriptor) return;

    // Define new method that calls through baseClassProp
    Object.defineProperty(targetClass.prototype, propertyName, {
      value: function (...args: any[]) {
        return (this as any)[baseClassProp][propertyName](...args);
      },
      writable: propertyDescriptor.writable,
      configurable: propertyDescriptor.configurable,
      enumerable: propertyDescriptor.enumerable,
    });
  });
}

applyMixin(Movement, Account, "account");
applyMixin(Movement, AccountAbstraction, "abstraction");
applyMixin(Movement, ANS, "ans");
applyMixin(Movement, Coin, "coin");
applyMixin(Movement, DigitalAsset, "digitalAsset");
applyMixin(Movement, Event, "event");
applyMixin(Movement, Faucet, "faucet");
applyMixin(Movement, FungibleAsset, "fungibleAsset");
applyMixin(Movement, General, "general");
applyMixin(Movement, Staking, "staking");
applyMixin(Movement, Transaction, "transaction");
applyMixin(Movement, Table, "table");
applyMixin(Movement, Keyless, "keyless");
applyMixin(Movement, MovementObject, "object");
