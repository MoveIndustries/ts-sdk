// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import { Account } from "../account";
import { AccountAddress, AccountAddressInput } from "../core";
import {
  getAccountDomains,
  GetAccountDomainsArgs,
  getAccountNames,
  GetAccountNamesArgs,
  getAccountSubdomains,
  GetAccountSubdomainsArgs,
  getDomainSubdomains,
  GetDomainSubdomainsArgs,
  getExpiration,
  getName,
  getOwnerAddress,
  getPrimaryName,
  getTargetAddress,
  registerName,
  RegisterNameParameters,
  renewDomain,
  setPrimaryName,
  setTargetAddress,
  // Subdomain key staking functions
  getKeyBuyPrice,
  getKeySellPrice,
  buyAndStakeKeyForSubdomain,
  stakeKeyForSubdomain,
  unstakeKeyForSubdomain,
  unstakeAndSellKeyForSubdomain,
  // Additional router functions
  canRegister,
  isNameOwner,
  getTokenAddress,
  clearTargetAddress,
  buyKeys,
  sellKeys,
  getDomainPrice,
} from "../internal/mns";
import { SimpleTransaction } from "../transactions/instances/simpleTransaction";
import { InputGenerateTransactionOptions } from "../transactions/types";
import { GetMNSNameResponse } from "../types";
import { MovementConfig } from "./movementConfig";

/**
 * A class to handle all `MNS` (Movement Name Service) operations.
 * @group MNS
 */
export class MNS {
  /**
   * Initializes a new instance of the Movement class with the provided configuration.
   * This allows you to interact with the Movement blockchain using the specified network settings.
   *
   * @param config - The configuration settings for the Movement client.
   * @param config.network - The network to connect to (e.g., mainnet, testnet).
   * @param config.nodeUrl - The URL of the Movement node to connect to.
   * @param config.faucetUrl - The URL of the faucet to use for funding accounts.
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
   *     console.log("Movement client initialized:", movement);
   * }
   * runExample().catch(console.error);
   * ```
   * @group MNS
   */
  constructor(readonly config: MovementConfig) { }

  /**
   * Retrieve the owner address of a specified domain name or subdomain name from the contract.
   *
   * @param args - The arguments for retrieving the owner address.
   * @param args.name - A string representing the name of the domain or subdomain to retrieve the owner address for.
   *
   * @returns AccountAddress if the name is owned, undefined otherwise.
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * const config = new MovementConfig({ network: Network.TESTNET });
   * const movement = new Movement(config);
   *
   * async function runExample() {
   *   // Retrieve the owner address of "test.move"
   *   const owner = await movement.getOwnerAddress({ name: "test.move" });
   *   console.log(owner); // Logs the owner address or undefined if not owned
   * }
   * runExample().catch(console.error);
   * ```
   * @group MNS
   */
  async getOwnerAddress(args: { name: string }): Promise<AccountAddress | undefined> {
    return getOwnerAddress({ movementConfig: this.config, ...args });
  }

  /**
   * Retrieve the expiration time of a domain name or subdomain name from the contract.
   *
   * @param args - The arguments for retrieving the expiration.
   * @param args.name - A string of the name to retrieve.
   *
   * @returns number as a unix timestamp in milliseconds.
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * const config = new MovementConfig({ network: Network.TESTNET });
   * const movement = new Movement(config);
   *
   * async function runExample() {
   *   // Get the expiration time for the domain "test.move"
   *   const exp = await movement.getExpiration({ name: "test.move" });
   *
   *   // Log the expiration date
   *   console.log(new Date(exp)); // Outputs the expiration date
   * }
   * runExample().catch(console.error);
   * ```
   * @group MNS
   */
  async getExpiration(args: { name: string }): Promise<number | undefined> {
    return getExpiration({ movementConfig: this.config, ...args });
  }

  /**
   * Retrieve the target address of a domain or subdomain name, which indicates the address the name points to for use on-chain.
   * Note that the target address can point to addresses that do not own the name.
   *
   * @param args - The arguments for retrieving the target address.
   * @param args.name - A string representing the name, which can be a primary name, a subdomain, or a combination (e.g.,
   * "primary", "primary.move", "secondary.primary", "secondary.primary.move").
   *
   * @returns AccountAddress if the name has a target, undefined otherwise.
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * const config = new MovementConfig({ network: Network.TESTNET });
   * const movement = new Movement(config);
   *
   * async function runExample() {
   *   // Retrieve the target address for the specified domain name
   *   const targetAddr = await movement.getTargetAddress({ name: "test.move" });
   *
   *   console.log(targetAddr); // Logs the target address, e.g., 0x123...
   * }
   * runExample().catch(console.error);
   * ```
   * @group MNS
   */
  async getTargetAddress(args: { name: string }): Promise<AccountAddress | undefined> {
    return getTargetAddress({ movementConfig: this.config, ...args });
  }

  /**
   * Sets the target address of a domain or subdomain name, pointing it to a specified address for use on-chain.
   * The target address can be different from the owner of the name.
   *
   * @param args - The arguments for setting the target address.
   * @param args.sender - The account initiating the transaction.
   * @param args.name - A string representing the domain or subdomain name (e.g., "test.move").
   * @param args.address - The AccountAddressInput of the address to set the domain or subdomain to.
   * @param args.options - Optional settings for generating the transaction.
   *
   * @returns SimpleTransaction
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * const config = new MovementConfig({ network: Network.TESTNET });
   * const movement = new Movement(config);
   *
   * async function runExample() {
   *   // Setting the target address for a domain name
   *   const sender = Account.generate(); // replace with a real account
   *   const address = "0x1"; // replace with a real account address
   *
   *   await movement.setTargetAddress({
   *     sender: sender,
   *     name: "test.move",
   *     address: address,
   *   });
   *
   *   const targetAddress = await movement.getTargetAddress({ name: "test.move" });
   *   console.log(targetAddress); // Should log the address set for "test.move"
   * }
   * runExample().catch(console.error);
   * ```
   * @group MNS
   */
  async setTargetAddress(args: {
    sender: Account;
    name: string;
    address: AccountAddressInput;
    options?: InputGenerateTransactionOptions;
  }): Promise<SimpleTransaction> {
    return setTargetAddress({ movementConfig: this.config, ...args });
  }

  /**
   * Retrieve the primary name for an account. An account can have multiple names, but only one primary name, which may not exist.
   *
   * @param args - The arguments for retrieving the primary name.
   * @param args.address - An AccountAddressInput (address) of the account.
   *
   * @returns A string if the account has a primary name, undefined otherwise.
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * const config = new MovementConfig({ network: Network.TESTNET });
   * const movement = new Movement(config);
   *
   * async function runExample() {
   *   // Retrieve the primary name for the specified account address
   *   const name = await movement.getPrimaryName({ address: "0x1" }); // replace with a real account address
   *   console.log(name);
   * }
   * runExample().catch(console.error);
   * ```
   * @group MNS
   */
  async getPrimaryName(args: { address: AccountAddressInput }): Promise<string | undefined> {
    return getPrimaryName({ movementConfig: this.config, ...args });
  }

  /**
   * Sets the primary name for the sender account, allowing them to designate a single primary name among potentially multiple
   * names. An account may not have a primary name.
   *
   * @param args - The arguments for setting the primary name.
   * @param args.sender - The sender account.
   * @param args.name - A string representing the name to set as primary (e.g., "test.move").
   * @param args.options - Optional transaction options.
   *
   * @returns SimpleTransaction
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * const config = new MovementConfig({ network: Network.TESTNET });
   * const movement = new Movement(config);
   *
   * async function runExample() {
   *   // Set the primary name for the sender account
   *   const sender = Account.generate(); // replace with a real account
   *   await movement.setPrimaryName({ sender, name: "test.move" });
   *
   *   const primaryName = await movement.getPrimaryName({ address: sender.accountAddress });
   *   console.log("Primary Name:", primaryName); // Should log: "Primary Name: test.move"
   * }
   * runExample().catch(console.error);
   * ```
   * @group MNS
   */
  async setPrimaryName(args: {
    sender: Account;
    name?: string;
    options?: InputGenerateTransactionOptions;
  }): Promise<SimpleTransaction> {
    return setPrimaryName({ movementConfig: this.config, ...args });
  }

  /**
   * Registers a new name.
   *
   * This function allows you to register a domain or subdomain name with specific expiration policies and options.
   *
   * @param args.sender - The sender account.
   * @param args.name - A string of the name to register. This can be inclusive or exclusive of the .move suffix. Examples include:
   * "test", "test.move", "test.movement.move", etc.
   * @param args.expiration  - An object with the expiration policy of the name.
   * @param args.expiration.policy - 'domain' | 'subdomain:follow-domain' | 'subdomain:independent'.
   * - domain: Years is required and the name will expire after the given number of years.
   * - subdomain:follow-domain: The name will expire at the same time as the domain name.
   * - subdomain:independent: The name will expire at the given date.
   * @param args.expiration.expirationDate - An epoch number in milliseconds of the date when the subdomain will expire. Only
   * applicable when the policy is set to 'subdomain:independent'.
   * @param args.transferable  - Determines if the subdomain being minted is soul-bound. Applicable only to subdomains.
   * @param args.targetAddress optional - The address the domain name will resolve to. If not provided, the sender's address will
   * be used.
   * @param args.toAddress optional - The address to send the domain name to. If not provided, the transaction will be sent to the
   * router.
   *
   * @returns SimpleTransaction
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * const config = new MovementConfig({ network: Network.TESTNET });
   * const movement = new Movement(config);
   *
   * async function runExample() {
   *   // Registering a subdomain name assuming def.move is already registered and belongs to the sender alice.
   *   const txn = await movement.registerName({
   *     sender: "0x1", // replace with a real sender account
   *     name: "test.movement.move",
   *     expiration: {
   *       policy: "subdomain:independent",
   *       expirationDate: Date.now() + 30 * 24 * 60 * 60 * 1000, // expires in 30 days
   *     },
   *   });
   *
   *   console.log("Transaction:", txn);
   * }
   * runExample().catch(console.error);
   * ```
   * @group MNS
   */
  async registerName(args: Omit<RegisterNameParameters, "movementConfig">): Promise<SimpleTransaction> {
    return registerName({ movementConfig: this.config, ...args });
  }

  /**
   * Renews a domain name for one year.
   * If a domain name was minted with V1 of the contract, it will automatically be upgraded to V2 via this transaction.
   *
   * @param args - The arguments for renewing the domain.
   * @param args.sender - The sender account, which must be the domain owner.
   * @param args.name - A string representing the domain to renew. Subdomains cannot be renewed.
   * @param args.years - The number of years to renew the name. Currently, only one year is permitted.
   * @param args.options - Optional transaction options.
   *
   * @returns SimpleTransaction
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * const config = new MovementConfig({ network: Network.TESTNET });
   * const movement = new Movement(config);
   *
   * async function runExample() {
   *   // Renew the domain "test" for one year
   *   const transaction = await movement.renewDomain({
   *     sender: Account.generate(), // replace with a real account
   *     name: "test"
   *   });
   *
   *   console.log(transaction);
   * }
   * runExample().catch(console.error);
   * ```
   * @group MNS
   */
  async renewDomain(args: {
    sender: Account;
    name: string;
    years?: 1;
    options?: InputGenerateTransactionOptions;
  }): Promise<SimpleTransaction> {
    return renewDomain({ movementConfig: this.config, ...args });
  }

  /**
   * Fetches a single name from the indexer based on the provided name argument.
   *
   * @param args - The arguments for retrieving the name.
   * @param args.name - A string of the name to retrieve, e.g. "test.movement.move" or "test.move" or "test".
   *                    Can be inclusive or exclusive of the .move suffix and can be a subdomain.
   *
   * @returns A promise of an MNSName or undefined if the name is not active.
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * const config = new MovementConfig({ network: Network.TESTNET });
   * const movement = new Movement(config);
   *
   * async function runExample() {
   *     // Fetching a name from the indexer
   *     const name = await movement.getName({ name: "test.move" }); // replace with a real name
   *     console.log(name);
   * }
   * runExample().catch(console.error);
   * ```
   * @group MNS
   */
  async getName(args: { name: string }): Promise<GetMNSNameResponse[0] | undefined> {
    return getName({ movementConfig: this.config, ...args });
  }

  /**
   * Fetches all names for an account, including both top-level domains and subdomains.
   *
   * @param args - The arguments for fetching account names.
   * @param args.accountAddress - An AccountAddressInput of the address to retrieve names for.
   * @param args.options - Optional parameters for fetching names.
   * @param args.options.offset - Optional, the offset to start from when fetching names.
   * @param args.options.limit - Optional, a number of the names to fetch per request.
   * @param args.options.orderBy - The order to sort the names by.
   * @param args.options.where - Additional filters to apply to the query.
   *
   * @returns A promise of an array of MNSName.
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * const config = new MovementConfig({ network: Network.TESTNET });
   * const movement = new Movement(config);
   *
   * async function runExample() {
   *   // Fetch account names for a specific address
   *   const accountNames = await movement.getAccountNames({
   *     accountAddress: "0x1", // replace with a real account address
   *     options: {
   *       limit: 10, // specify how many names to fetch
   *       orderBy: "name", // specify the order by which to sort the names
   *     },
   *   });
   *
   *   console.log(accountNames);
   * }
   * runExample().catch(console.error);
   * ```
   * @group MNS
   */
  async getAccountNames(args: GetAccountNamesArgs): Promise<GetMNSNameResponse> {
    return getAccountNames({ movementConfig: this.config, ...args });
  }

  /**
   * Fetches all top-level domain names for a specified account.
   *
   * @param args - The arguments for retrieving account domains.
   * @param args.accountAddress - An AccountAddressInput of the address to retrieve domain names for.
   * @param args.options.offset - Optional, the offset to start from when fetching names.
   * @param args.options.limit - Optional, a number of the names to fetch per request.
   * @param args.options.orderBy - The order to sort the names by.
   * @param args.options.where - Additional filters to apply to the query.
   *
   * @returns A promise of an array of MNSName.
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * const config = new MovementConfig({ network: Network.TESTNET });
   * const movement = new Movement(config);
   *
   * async function runExample() {
   *   // Fetching all top-level domain names for a specific account
   *   const domains = await movement.getAccountDomains({
   *     accountAddress: "0x1", // replace with a real account address
   *     options: {
   *       limit: 10, // specify the number of names to fetch
   *       offset: 0, // specify the offset for pagination
   *       orderBy: "created_at", // specify the order by which to sort the names
   *       where: {
   *         // additional filters can be specified here
   *       },
   *     },
   *   });
   *
   *   console.log(domains);
   * }
   * runExample().catch(console.error);
   * ```
   * @group MNS
   */
  async getAccountDomains(args: GetAccountDomainsArgs): Promise<GetMNSNameResponse> {
    return getAccountDomains({ movementConfig: this.config, ...args });
  }

  /**
   * Fetches all subdomain names for a specified account.
   *
   * @param args - The arguments for retrieving subdomains.
   * @param args.accountAddress - The address to retrieve subdomain names for.
   * @param args.options - Optional parameters for fetching subdomains.
   * @param args.options.offset - The offset to start from when fetching names.
   * @param args.options.limit - The number of names to fetch per request.
   * @param args.options.orderBy - The order to sort the names by.
   * @param args.options.where - Additional filters to apply to the query.
   *
   * @returns A promise of an array of MNSName.
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * const config = new MovementConfig({ network: Network.TESTNET });
   * const movement = new Movement(config);
   *
   * async function runExample() {
   *     // Fetching subdomain names for a specific account
   *     const subdomains = await movement.getAccountSubdomains({
   *         accountAddress: "0x1", // replace with a real account address
   *         options: {
   *             limit: 10, // specify the number of subdomains to fetch
   *             offset: 0, // specify the offset for pagination
   *             orderBy: "name", // specify the order by which to sort the names
   *         },
   *     });
   *
   *     console.log(subdomains);
   * }
   * runExample().catch(console.error);
   * ```
   * @group MNS
   */
  async getAccountSubdomains(args: GetAccountSubdomainsArgs): Promise<GetMNSNameResponse> {
    return getAccountSubdomains({ movementConfig: this.config, ...args });
  }

  /**
   * Fetches all subdomain names for a given domain, excluding the domain itself.
   *
   * @param args - The arguments for fetching subdomains.
   * @param args.domain - A string of the domain name, e.g., "test.move" or "test" (without the suffix of .move).
   * @param args.options - Optional parameters for fetching subdomains.
   * @param args.options.offset - Optional, the offset to start from when fetching names.
   * @param args.options.limit - Optional, the number of names to fetch per request.
   * @param args.options.orderBy - The order to sort the names by.
   * @param args.options.where - Additional filters to apply to the query.
   *
   * @returns A promise that resolves to an array of MNSName.
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * const config = new MovementConfig({ network: Network.TESTNET });
   * const movement = new Movement(config);
   *
   * async function runExample() {
   *   // Fetching subdomains for a specific domain
   *   const subdomains = await movement.getDomainSubdomains({
   *     domain: "test", // replace with your domain
   *     options: {
   *       limit: 10, // specify the number of subdomains to fetch
   *       offset: 0, // specify the starting point for fetching
   *       orderBy: "name", // specify the order by which to sort the results
   *     },
   *   });
   *
   *   console.log(subdomains);
   * }
   * runExample().catch(console.error);
   * ```
   * @group MNS
   */
  async getDomainSubdomains(args: GetDomainSubdomainsArgs): Promise<GetMNSNameResponse> {
    return getDomainSubdomains({ movementConfig: this.config, ...args });
  }

  // ============================================================================
  // Subdomain Key Staking Functions
  // ============================================================================
  // Movement MNS uses a bonding curve mechanism for subdomains where users must
  // buy and stake "keys" to own subdomains.
  // ============================================================================

  /**
   * Get the price to buy keys for a domain. Each domain has tradeable keys that
   * follow a bonding curve - price increases as more keys are bought.
   *
   * @param args - The arguments for the function.
   * @param args.domainName - The domain name to get the key price for.
   * @param args.amount - The number of keys to get the price for (default: 1).
   *
   * @returns The price in octas to buy the specified number of keys.
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * const config = new MovementConfig({ network: Network.TESTNET });
   * const movement = new Movement(config);
   *
   * async function runExample() {
   *   // Get the price to buy 1 key for the "test" domain
   *   const price = await movement.getKeyBuyPrice({ domainName: "test" });
   *   console.log(`Price to buy 1 key: ${price} octas`);
   * }
   * runExample().catch(console.error);
   * ```
   * @group MNS
   */
  async getKeyBuyPrice(args: { domainName: string; amount?: number }): Promise<bigint> {
    return getKeyBuyPrice({ movementConfig: this.config, ...args });
  }

  /**
   * Get the price when selling keys for a domain.
   *
   * @param args - The arguments for the function.
   * @param args.domainName - The domain name to get the sell price for.
   * @param args.amount - The number of keys to get the price for (default: 1).
   *
   * @returns The price in octas received when selling the specified number of keys.
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";
   *
   * const config = new MovementConfig({ network: Network.TESTNET });
   * const movement = new Movement(config);
   *
   * async function runExample() {
   *   // Get the price when selling 1 key for the "test" domain
   *   const price = await movement.getKeySellPrice({ domainName: "test" });
   *   console.log(`Price when selling 1 key: ${price} octas`);
   * }
   * runExample().catch(console.error);
   * ```
   * @group MNS
   */
  async getKeySellPrice(args: { domainName: string; amount?: number }): Promise<bigint> {
    return getKeySellPrice({ movementConfig: this.config, ...args });
  }

  /**
   * Buy a key for a domain and stake it to claim a subdomain in one transaction.
   * This is the primary way to register a subdomain on Movement.
   *
   * The price follows a bonding curve - use getKeyBuyPrice() to check the current price.
   *
   * @param args - The arguments for the function.
   * @param args.sender - The account buying and staking the key.
   * @param args.domainName - The parent domain name (e.g., "test" for "sub.test.move").
   * @param args.subdomainName - The subdomain to claim (e.g., "sub" for "sub.test.move").
   * @param args.targetAddress - Optional address this subdomain will resolve to (defaults to sender).
   * @param args.toAddress - Optional address that will own this subdomain (defaults to sender).
   * @param args.referrer - Optional referrer address for fee sharing.
   * @param args.options - Optional transaction options.
   *
   * @returns A transaction object to be signed and submitted.
   *
   * @example
   * ```typescript
   * import { Movement, MovementConfig, Network, Account } from "@moveindustries/ts-sdk";
   *
   * const config = new MovementConfig({ network: Network.TESTNET });
   * const movement = new Movement(config);
   *
   * async function runExample() {
   *   const alice = Account.generate();
   *   await movement.fundAccount({ accountAddress: alice.accountAddress, amount: 100_000_000 });
   *
   *   // Buy a key and stake it to claim "mysubdomain.test.move"
   *   const txn = await movement.buyAndStakeKeyForSubdomain({
   *     sender: alice,
   *     domainName: "test",
   *     subdomainName: "mysubdomain",
   *   });
   *
   *   const result = await movement.signAndSubmitTransaction({ signer: alice, transaction: txn });
   *   console.log("Subdomain claimed:", result.hash);
   * }
   * runExample().catch(console.error);
   * ```
   * @group MNS
   */
  async buyAndStakeKeyForSubdomain(args: {
    sender: Account;
    domainName: string;
    subdomainName: string;
    targetAddress?: AccountAddressInput;
    toAddress?: AccountAddressInput;
    referrer?: AccountAddressInput;
    options?: InputGenerateTransactionOptions;
  }): Promise<SimpleTransaction> {
    return buyAndStakeKeyForSubdomain({ movementConfig: this.config, ...args });
  }

  /**
   * Stake an existing key to claim a subdomain. You must already own a key for
   * the parent domain.
   *
   * @param args - The arguments for the function.
   * @param args.sender - The account staking the key.
   * @param args.domainName - The parent domain name.
   * @param args.subdomainName - The subdomain to claim.
   * @param args.targetAddress - Optional address this subdomain will resolve to.
   * @param args.toAddress - Optional address that will own this subdomain.
   * @param args.options - Optional transaction options.
   *
   * @returns A transaction object to be signed and submitted.
   * @group MNS
   */
  async stakeKeyForSubdomain(args: {
    sender: Account;
    domainName: string;
    subdomainName: string;
    targetAddress?: AccountAddressInput;
    toAddress?: AccountAddressInput;
    options?: InputGenerateTransactionOptions;
  }): Promise<SimpleTransaction> {
    return stakeKeyForSubdomain({ movementConfig: this.config, ...args });
  }

  /**
   * Unstake a key from a subdomain, giving up ownership but keeping the key.
   * You can sell the key later or stake it for a different subdomain.
   *
   * @param args - The arguments for the function.
   * @param args.sender - The account unstaking the key.
   * @param args.domainName - The parent domain name.
   * @param args.subdomainName - The subdomain to release.
   * @param args.options - Optional transaction options.
   *
   * @returns A transaction object to be signed and submitted.
   * @group MNS
   */
  async unstakeKeyForSubdomain(args: {
    sender: Account;
    domainName: string;
    subdomainName: string;
    options?: InputGenerateTransactionOptions;
  }): Promise<SimpleTransaction> {
    return unstakeKeyForSubdomain({ movementConfig: this.config, ...args });
  }

  /**
   * Unstake a key from a subdomain and sell it in one transaction.
   * This gives up the subdomain and converts the key back to MOVE tokens.
   *
   * @param args - The arguments for the function.
   * @param args.sender - The account unstaking and selling the key.
   * @param args.domainName - The parent domain name.
   * @param args.subdomainName - The subdomain to release.
   * @param args.referrer - Optional referrer address for fee sharing.
   * @param args.options - Optional transaction options.
   *
   * @returns A transaction object to be signed and submitted.
   * @group MNS
   */
  async unstakeAndSellKeyForSubdomain(args: {
    sender: Account;
    domainName: string;
    subdomainName: string;
    referrer?: AccountAddressInput;
    options?: InputGenerateTransactionOptions;
  }): Promise<SimpleTransaction> {
    return unstakeAndSellKeyForSubdomain({ movementConfig: this.config, ...args });
  }

  // ============================================================================
  // Additional Router Functions
  // ============================================================================

  /**
   * Check if a name (domain or subdomain) is available for registration.
   *
   * @param args - The arguments for the function.
   * @param args.name - The name to check (e.g., "test" or "sub.test").
   * @param args.account - The account address that would register the name.
   *
   * @returns True if the name can be registered by the account, false otherwise.
   *
   * @example
   * ```typescript
   * const canReg = await movement.canRegister({
   *   name: "mynewdomain",
   *   account: alice.accountAddress,
   * });
   * console.log(canReg ? "Available!" : "Already taken");
   * ```
   * @group MNS
   */
  async canRegister(args: { name: string; account: AccountAddressInput }): Promise<boolean> {
    return canRegister({ movementConfig: this.config, ...args });
  }

  /**
   * Check if a specific address owns a name.
   *
   * @param args - The arguments for the function.
   * @param args.name - The name to check ownership of.
   * @param args.account - The account address to check.
   *
   * @returns True if the account owns the name, false otherwise.
   *
   * @example
   * ```typescript
   * const isOwner = await movement.isNameOwner({
   *   name: "test.move",
   *   account: alice.accountAddress,
   * });
   * ```
   * @group MNS
   */
  async isNameOwner(args: { name: string; account: AccountAddressInput }): Promise<boolean> {
    return isNameOwner({ movementConfig: this.config, ...args });
  }

  /**
   * Get the NFT token address for a domain or subdomain.
   *
   * @param args - The arguments for the function.
   * @param args.name - The name to get the token address for.
   *
   * @returns The token address, or undefined if the name doesn't exist.
   * @group MNS
   */
  async getTokenAddress(args: { name: string }): Promise<AccountAddress | undefined> {
    return getTokenAddress({ movementConfig: this.config, ...args });
  }

  /**
   * Clear the target address for a domain or subdomain, stopping it from resolving.
   *
   * @param args - The arguments for the function.
   * @param args.sender - The account that owns the name.
   * @param args.name - The name to clear the target address for.
   * @param args.options - Optional transaction options.
   *
   * @returns A transaction object to be signed and submitted.
   *
   * @example
   * ```typescript
   * // Stop "test.move" from resolving to any address
   * const txn = await movement.clearTargetAddress({
   *   sender: alice,
   *   name: "test.move",
   * });
   * ```
   * @group MNS
   */
  async clearTargetAddress(args: {
    sender: Account;
    name: string;
    options?: InputGenerateTransactionOptions;
  }): Promise<SimpleTransaction> {
    return clearTargetAddress({ movementConfig: this.config, ...args });
  }

  /**
   * Buy keys for a domain without staking them for a subdomain.
   * Keys can be held for speculation or staked later via stakeKeyForSubdomain.
   *
   * @param args - The arguments for the function.
   * @param args.sender - The account buying the keys.
   * @param args.domainName - The domain to buy keys for.
   * @param args.amount - The number of keys to buy.
   * @param args.referrer - Optional referrer address for fee sharing.
   * @param args.options - Optional transaction options.
   *
   * @returns A transaction object to be signed and submitted.
   *
   * @example
   * ```typescript
   * // Buy 2 keys for speculation
   * const txn = await movement.buyKeys({
   *   sender: alice,
   *   domainName: "popular-domain",
   *   amount: 2,
   * });
   * ```
   * @group MNS
   */
  async buyKeys(args: {
    sender: Account;
    domainName: string;
    amount: number;
    referrer?: AccountAddressInput;
    options?: InputGenerateTransactionOptions;
  }): Promise<SimpleTransaction> {
    return buyKeys({ movementConfig: this.config, ...args });
  }

  /**
   * Sell keys for a domain back to the bonding curve.
   *
   * @param args - The arguments for the function.
   * @param args.sender - The account selling the keys.
   * @param args.domainName - The domain to sell keys for.
   * @param args.amount - The number of keys to sell.
   * @param args.referrer - Optional referrer address for fee sharing.
   * @param args.options - Optional transaction options.
   *
   * @returns A transaction object to be signed and submitted.
   *
   * @example
   * ```typescript
   * // Sell 1 key back
   * const txn = await movement.sellKeys({
   *   sender: alice,
   *   domainName: "popular-domain",
   *   amount: 1,
   * });
   * ```
   * @group MNS
   */
  async sellKeys(args: {
    sender: Account;
    domainName: string;
    amount: number;
    referrer?: AccountAddressInput;
    options?: InputGenerateTransactionOptions;
  }): Promise<SimpleTransaction> {
    return sellKeys({ movementConfig: this.config, ...args });
  }

  /**
   * Get the registration price for a domain name.
   * Price varies based on domain length and registration duration.
   *
   * @param args - The arguments for the function.
   * @param args.name - The domain name to get the price for.
   * @param args.years - Number of years to register (default: 1).
   *
   * @returns The price in octas to register the domain.
   *
   * @example
   * ```typescript
   * // Check price before registering
   * const price = await movement.getDomainPrice({ name: "mynewdomain" });
   * console.log(`Registration costs ${price} octas (${Number(price) / 1e8} MOVE)`);
   * ```
   * @group MNS
   */
  async getDomainPrice(args: { name: string; years?: number }): Promise<bigint> {
    return getDomainPrice({ movementConfig: this.config, ...args });
  }
}
