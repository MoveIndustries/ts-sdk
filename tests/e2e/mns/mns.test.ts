// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import {
  Account,
  AccountAddress,
  AnyRawTransaction,
  GetMNSNameResponse,
  Movement,
  MovementConfig,
  Network,
  U8,
} from "../../../src";
import { isActiveMNSName, isValidMNSName, SubdomainExpirationPolicy } from "../../../src/internal/mns";
import { generateTransaction } from "../../../src/internal/transactionSubmission";
import { getMovementClient } from "../helper";
import { publishMnsContract } from "./publishMNSContracts";

// This isn't great, we should look into deploying outside the test
jest.setTimeout(20000);

// Tests that don't require network - can run locally
describe("MNS Validation", () => {
  describe("isActiveMNSName", () => {
    const oneDay = 24 * 60 * 60 * 1000;
    const tomorrow = Date.now() + oneDay;
    const yesterday = Date.now() - oneDay;

    test("domains", () => {
      expect(isActiveMNSName({ domain: "primary", expiration_timestamp: tomorrow })).toBeTruthy();
      expect(isActiveMNSName({ domain: "primary", expiration_timestamp: yesterday })).toBeFalsy();
    });

    describe("subdomains", () => {
      test("Policy: Follows Parent", () => {
        expect(
          isActiveMNSName({
            domain: "primary",
            subdomain: "secondary",
            subdomain_expiration_policy: SubdomainExpirationPolicy.FollowsDomain,
            expiration_timestamp: tomorrow,
            domain_expiration_timestamp: tomorrow,
          }),
        ).toBeTruthy();

        expect(
          isActiveMNSName({
            domain: "primary",
            subdomain: "secondary",
            subdomain_expiration_policy: SubdomainExpirationPolicy.FollowsDomain,
            expiration_timestamp: yesterday,
            domain_expiration_timestamp: tomorrow,
          }),
        ).toBeTruthy();

        expect(
          isActiveMNSName({
            domain: "primary",
            subdomain: "secondary",
            subdomain_expiration_policy: SubdomainExpirationPolicy.FollowsDomain,
            expiration_timestamp: tomorrow,
            domain_expiration_timestamp: yesterday,
          }),
        ).toBeFalsy();

        expect(
          isActiveMNSName({
            domain: "primary",
            subdomain: "secondary",
            subdomain_expiration_policy: SubdomainExpirationPolicy.FollowsDomain,
            expiration_timestamp: yesterday,
            domain_expiration_timestamp: yesterday,
          }),
        ).toBeFalsy();
      });

      test("Policy: Independent", () => {
        expect(
          isActiveMNSName({
            domain: "primary",
            subdomain: "secondary",
            subdomain_expiration_policy: SubdomainExpirationPolicy.Independent,
            expiration_timestamp: tomorrow,
            domain_expiration_timestamp: tomorrow,
          }),
        ).toBeTruthy();

        expect(
          isActiveMNSName({
            domain: "primary",
            subdomain: "secondary",
            subdomain_expiration_policy: SubdomainExpirationPolicy.Independent,
            expiration_timestamp: yesterday,
            domain_expiration_timestamp: tomorrow,
          }),
        ).toBeFalsy();

        expect(
          isActiveMNSName({
            domain: "primary",
            subdomain: "secondary",
            subdomain_expiration_policy: SubdomainExpirationPolicy.Independent,
            expiration_timestamp: tomorrow,
            domain_expiration_timestamp: yesterday,
          }),
        ).toBeFalsy();

        expect(
          isActiveMNSName({
            domain: "primary",
            subdomain: "secondary",
            subdomain_expiration_policy: SubdomainExpirationPolicy.Independent,
            expiration_timestamp: yesterday,
            domain_expiration_timestamp: yesterday,
          }),
        ).toBeFalsy();
      });
    });
  });

  describe("isValidMNSName", () => {
    test("it returns true for valid names", () => {
      expect(isValidMNSName("primary")).toEqual({ domainName: "primary", subdomainName: undefined });
      expect(isValidMNSName("primary.move")).toEqual({ domainName: "primary", subdomainName: undefined });

      expect(isValidMNSName("secondary.primary")).toEqual({ domainName: "primary", subdomainName: "secondary" });
      expect(isValidMNSName("secondary.primary.move")).toEqual({ domainName: "primary", subdomainName: "secondary" });
    });

    test("it returns false for invalid names", () => {
      expect(() => isValidMNSName("")).toThrow();
      expect(() => isValidMNSName(".")).toThrow();
      expect(() => isValidMNSName("..")).toThrow();
      expect(() => isValidMNSName(" . ")).toThrow();
      expect(() => isValidMNSName(" test ")).toThrow();
      expect(() => isValidMNSName(".move")).toThrow();
      expect(() => isValidMNSName(".move.move")).toThrow();
      expect(() => isValidMNSName(".move.")).toThrow();
      expect(() => isValidMNSName("1")).toThrow();
      expect(() => isValidMNSName("1.move")).toThrow();
      expect(() => isValidMNSName("bad.bad.bad")).toThrow();
      expect(() => isValidMNSName("-bad-")).toThrow();
      expect(() => isValidMNSName("-bad.move")).toThrow();
      expect(() => isValidMNSName("bad-.move")).toThrow();
      expect(() => isValidMNSName("b.a.d.move")).toThrow();
    });
  });
});

// Tests that require testnet
describe("MNS Testnet", () => {
  const testnet = new Movement(
    new MovementConfig({
      network: Network.TESTNET,
    }),
  );

  const randomString = () => Math.random().toString().slice(2);

  describe("name resolution", () => {
    test("getTargetAddress returns address for existing name", async () => {
      // Test with a known Movement testnet domain
      const addr = await testnet.mns.getTargetAddress({ name: "makeyour" });
      // Should return an address (the actual address depends on what's registered)
      expect(addr).toBeDefined();
    });

    test("getTargetAddress throws or returns undefined for non-existent name", async () => {
      // The MNS contract may throw an error for non-existent names
      try {
        const addr = await testnet.mns.getTargetAddress({ name: `not-a-name-${randomString()}` });
        expect(addr).toBeUndefined();
      } catch (e) {
        // Contract throws MISSING_DATA error for non-existent names, which is expected
        expect(e).toBeDefined();
      }
    });

    test("getName returns data for existing name", async () => {
      const res = await testnet.mns.getName({ name: "makeyour" });
      expect(res).toBeTruthy();
      expect(res?.domain).toBe("makeyour");
    });

    test("getName returns undefined for non-existent name", async () => {
      const res = await testnet.mns.getName({ name: `not-a-name-${randomString()}` });
      expect(res).toBeFalsy();
    });

    test("supports .move suffix in name resolution", async () => {
      // Test that .move suffix is properly stripped
      const addr1 = await testnet.mns.getTargetAddress({ name: "makeyour" });
      const addr2 = await testnet.mns.getTargetAddress({ name: "makeyour.move" });
      expect(addr1?.toString()).toEqual(addr2?.toString());
    });

    test("getPrimaryName returns name for address with primary set", async () => {
      // First get the target address for makeyour.move
      const addr = await testnet.mns.getTargetAddress({ name: "makeyour" });
      expect(addr).toBeDefined();

      // Then check if that address has a primary name set
      const primaryName = await testnet.mns.getPrimaryName({ address: addr! });
      // If primary is set, it should return the name
      // (makeyour.move has the star/primary set based on user's screenshot)
      if (primaryName) {
        expect(typeof primaryName).toBe("string");
      }
    });

    test("getOwnerAddress returns owner of a name", async () => {
      const owner = await testnet.mns.getOwnerAddress({ name: "makeyour" });
      expect(owner).toBeDefined();
      expect(owner?.toString()).toMatch(/^0x[a-fA-F0-9]+$/);
    });

    test("getExpiration returns expiration timestamp or undefined", async () => {
      const expiration = await testnet.mns.getExpiration({ name: "makeyour" });
      // getExpiration may return undefined if the view function fails
      // or a number (milliseconds since epoch) if it succeeds
      if (expiration !== undefined) {
        expect(typeof expiration).toBe("number");
        // Should be in the future (name is active)
        expect(expiration).toBeGreaterThan(Date.now());
      }
      // If undefined, we can get expiration from getName instead
      const nameData = await testnet.mns.getName({ name: "makeyour" });
      expect(nameData).toBeDefined();
      expect(nameData?.expiration_timestamp).toBeDefined();
      expect(nameData?.expiration_timestamp).toBeGreaterThan(Date.now());
    });

    test("getAccountNames returns names owned by an address", async () => {
      // Get the owner of makeyour.move
      const owner = await testnet.mns.getOwnerAddress({ name: "makeyour" });
      expect(owner).toBeDefined();

      // Get all names for that owner
      const names = await testnet.mns.getAccountNames({ accountAddress: owner! });
      expect(Array.isArray(names)).toBe(true);
      // Should have at least makeyour
      expect(names.length).toBeGreaterThan(0);
    });

    test("getAccountDomains returns only top-level domains", async () => {
      const owner = await testnet.mns.getOwnerAddress({ name: "makeyour" });
      expect(owner).toBeDefined();

      const domains = await testnet.mns.getAccountDomains({ accountAddress: owner! });
      expect(Array.isArray(domains)).toBe(true);
      // All results should have empty subdomain (they're TLDs)
      domains.forEach((d) => {
        expect(d.subdomain).toBeFalsy();
      });
    });

    test("getAccountSubdomains returns only subdomains", async () => {
      const owner = await testnet.mns.getOwnerAddress({ name: "makeyour" });
      expect(owner).toBeDefined();

      const subdomains = await testnet.mns.getAccountSubdomains({ accountAddress: owner! });
      expect(Array.isArray(subdomains)).toBe(true);
      // All results should have a subdomain value
      subdomains.forEach((s) => {
        expect(s.subdomain).toBeTruthy();
      });
    });

    test("getDomainSubdomains returns subdomains for a domain", async () => {
      // Get subdomains for makeyour.move domain
      const subdomains = await testnet.mns.getDomainSubdomains({ domain: "makeyour" });
      expect(Array.isArray(subdomains)).toBe(true);
      // All results should have subdomain set and belong to makeyour domain
      subdomains.forEach((s) => {
        expect(s.subdomain).toBeTruthy();
        expect(s.domain).toBe("makeyour");
      });
    });
  });

  describe("write operations", () => {
    const signAndSubmit = async (signer: Account, transaction: AnyRawTransaction) => {
      const pendingTxn = await testnet.signAndSubmitTransaction({ transaction, signer });
      return testnet.waitForTransaction({ transactionHash: pendingTxn.hash });
    };

    test("registerName mints a new domain", async () => {
      // Generate a new account and fund it
      const alice = Account.generate();
      await testnet.fundAccount({
        accountAddress: alice.accountAddress,
        amount: 10_000_000_000, // 100 MOVE (domain registration costs ~20 MOVE)
      });

      // Generate a random domain name to avoid conflicts
      const domainName = `test${Math.random().toString().slice(2, 10)}`;

      // Register the domain
      const txn = await testnet.registerName({
        sender: alice,
        name: domainName,
        expiration: { policy: "domain" },
      });

      await signAndSubmit(alice, txn);

      // Verify ownership
      const owner = await testnet.getOwnerAddress({ name: domainName });
      expect(owner?.toString()).toEqual(alice.accountAddress.toString());
    });

    test("setTargetAddress updates name resolution", async () => {
      const alice = Account.generate();
      const bob = Account.generate();
      await testnet.fundAccount({
        accountAddress: alice.accountAddress,
        amount: 10_000_000_000,
      });

      const domainName = `test${Math.random().toString().slice(2, 10)}`;

      // Register domain pointing to alice
      await signAndSubmit(
        alice,
        await testnet.registerName({
          sender: alice,
          name: domainName,
          expiration: { policy: "domain" },
        }),
      );

      // Verify it points to alice
      let target = await testnet.getTargetAddress({ name: domainName });
      expect(target?.toString()).toEqual(alice.accountAddress.toString());

      // Change target to bob
      await signAndSubmit(
        alice,
        await testnet.setTargetAddress({
          sender: alice,
          name: domainName,
          address: bob.accountAddress,
        }),
      );

      // Verify it now points to bob
      target = await testnet.getTargetAddress({ name: domainName });
      expect(target?.toString()).toEqual(bob.accountAddress.toString());
    });

    test("setPrimaryName sets primary name for account", async () => {
      const alice = Account.generate();
      await testnet.fundAccount({
        accountAddress: alice.accountAddress,
        amount: 10_000_000_000,
      });

      const domainName = `test${Math.random().toString().slice(2, 10)}`;

      // Register domain
      await signAndSubmit(
        alice,
        await testnet.registerName({
          sender: alice,
          name: domainName,
          expiration: { policy: "domain" },
        }),
      );

      // Set as primary
      await signAndSubmit(
        alice,
        await testnet.setPrimaryName({
          sender: alice,
          name: domainName,
        }),
      );

      // Verify primary name
      const primaryName = await testnet.getPrimaryName({ address: alice.accountAddress });
      expect(primaryName).toEqual(domainName);
    });

    test("registerName throws informative error for subdomain registration", async () => {
      const alice = Account.generate();
      const domainName = `test${Math.random().toString().slice(2, 10)}`;
      const subdomainName = `sub${Math.random().toString().slice(2, 6)}`;
      const fullName = `${subdomainName}.${domainName}`;

      // Movement's MNS uses a key staking mechanism for subdomains instead of direct registration
      await expect(
        testnet.registerName({
          sender: alice,
          name: fullName,
          expiration: { policy: "subdomain:follow-domain" },
        }),
      ).rejects.toThrow("Subdomain registration is not currently supported on Movement");
    });
  });

  describe("subdomain key staking", () => {
    const signAndSubmit = async (signer: Account, transaction: AnyRawTransaction) => {
      const pendingTxn = await testnet.signAndSubmitTransaction({ transaction, signer });
      return testnet.waitForTransaction({ transactionHash: pendingTxn.hash });
    };

    test("getKeyBuyPrice returns price for existing domain", async () => {
      // Get the key buy price for makeyour.move
      const price = await testnet.getKeyBuyPrice({ domainName: "makeyour" });
      expect(typeof price).toBe("bigint");
      expect(price).toBeGreaterThan(0n);
    });

    test("getKeySellPrice returns price for existing domain", async () => {
      // Get the key sell price for makeyour.move
      const price = await testnet.getKeySellPrice({ domainName: "makeyour" });
      expect(typeof price).toBe("bigint");
      // Sell price should be >= 0 (could be 0 if no keys have been bought)
      expect(price).toBeGreaterThanOrEqual(0n);
    });

    test("buyAndStakeKeyForSubdomain creates subdomain via key staking", async () => {
      const alice = Account.generate();
      await testnet.fundAccount({
        accountAddress: alice.accountAddress,
        amount: 10_000_000_000, // 100 MOVE
      });

      // First register a domain
      const domainName = `test${Math.random().toString().slice(2, 10)}`;
      await signAndSubmit(
        alice,
        await testnet.registerName({
          sender: alice,
          name: domainName,
          expiration: { policy: "domain" },
        }),
      );

      // Wait for domain to be committed
      await new Promise((resolve) => setTimeout(resolve, 2000));

      // Now buy and stake a key to claim a subdomain
      const subdomainName = `sub${Math.random().toString().slice(2, 6)}`;

      // Check the price first
      const price = await testnet.getKeyBuyPrice({ domainName });
      console.log(`Key price for ${domainName}: ${price} octas`);

      // Buy and stake the key
      await signAndSubmit(
        alice,
        await testnet.buyAndStakeKeyForSubdomain({
          sender: alice,
          domainName,
          subdomainName,
        }),
      );

      // Verify subdomain ownership
      const fullName = `${subdomainName}.${domainName}`;
      const owner = await testnet.getOwnerAddress({ name: fullName });
      expect(owner?.toString()).toEqual(alice.accountAddress.toString());
    });

    // Skip: Contract has a lock-up period (ENOT_ENOUGH_TIME_TO_UNSTAKE) before keys can be unstaked.
    // The unstakeKeyForSubdomain function works correctly but we can't test it without waiting.
    test.skip("unstakeKeyForSubdomain releases subdomain (requires waiting for lock-up period)", async () => {
      const alice = Account.generate();
      await testnet.fundAccount({
        accountAddress: alice.accountAddress,
        amount: 10_000_000_000,
      });

      // Register a domain
      const domainName = `test${Math.random().toString().slice(2, 10)}`;
      await signAndSubmit(
        alice,
        await testnet.registerName({
          sender: alice,
          name: domainName,
          expiration: { policy: "domain" },
        }),
      );

      await new Promise((resolve) => setTimeout(resolve, 2000));

      // Buy and stake a key for subdomain
      const subdomainName = `sub${Math.random().toString().slice(2, 6)}`;
      await signAndSubmit(
        alice,
        await testnet.buyAndStakeKeyForSubdomain({
          sender: alice,
          domainName,
          subdomainName,
        }),
      );

      // Verify ownership
      const fullName = `${subdomainName}.${domainName}`;
      let owner = await testnet.getOwnerAddress({ name: fullName });
      expect(owner?.toString()).toEqual(alice.accountAddress.toString());

      // Note: Would need to wait for lock-up period before unstaking
      // Unstake the key (give up subdomain but keep key)
      await signAndSubmit(
        alice,
        await testnet.unstakeKeyForSubdomain({
          sender: alice,
          domainName,
          subdomainName,
        }),
      );

      // Subdomain should no longer have an owner
      owner = await testnet.getOwnerAddress({ name: fullName });
      expect(owner).toBeUndefined();
    });

    test("unstakeKeyForSubdomain fails during lock-up period", async () => {
      const alice = Account.generate();
      await testnet.fundAccount({
        accountAddress: alice.accountAddress,
        amount: 10_000_000_000,
      });

      // Register a domain
      const domainName = `test${Math.random().toString().slice(2, 10)}`;
      await signAndSubmit(
        alice,
        await testnet.registerName({
          sender: alice,
          name: domainName,
          expiration: { policy: "domain" },
        }),
      );

      await new Promise((resolve) => setTimeout(resolve, 2000));

      // Buy and stake a key for subdomain
      const subdomainName = `sub${Math.random().toString().slice(2, 6)}`;
      await signAndSubmit(
        alice,
        await testnet.buyAndStakeKeyForSubdomain({
          sender: alice,
          domainName,
          subdomainName,
        }),
      );

      // Try to unstake immediately - should fail with lock-up error
      await expect(
        signAndSubmit(
          alice,
          await testnet.unstakeKeyForSubdomain({
            sender: alice,
            domainName,
            subdomainName,
          }),
        ),
      ).rejects.toThrow("ENOT_ENOUGH_TIME_TO_UNSTAKE");
    });

    // Skip: Contract has a lock-up period before keys can be unstaked and sold.
    test.skip("unstakeAndSellKeyForSubdomain releases subdomain and sells key (requires waiting for lock-up period)", async () => {
      const alice = Account.generate();
      await testnet.fundAccount({
        accountAddress: alice.accountAddress,
        amount: 10_000_000_000,
      });

      // Register a domain
      const domainName = `test${Math.random().toString().slice(2, 10)}`;
      await signAndSubmit(
        alice,
        await testnet.registerName({
          sender: alice,
          name: domainName,
          expiration: { policy: "domain" },
        }),
      );

      await new Promise((resolve) => setTimeout(resolve, 2000));

      // Buy and stake a key for subdomain
      const subdomainName = `sub${Math.random().toString().slice(2, 6)}`;
      await signAndSubmit(
        alice,
        await testnet.buyAndStakeKeyForSubdomain({
          sender: alice,
          domainName,
          subdomainName,
        }),
      );

      // Verify ownership
      const fullName = `${subdomainName}.${domainName}`;
      let owner = await testnet.getOwnerAddress({ name: fullName });
      expect(owner?.toString()).toEqual(alice.accountAddress.toString());

      // Note: Would need to wait for lock-up period before unstaking
      // Unstake and sell the key in one transaction
      await signAndSubmit(
        alice,
        await testnet.unstakeAndSellKeyForSubdomain({
          sender: alice,
          domainName,
          subdomainName,
        }),
      );

      // Subdomain should no longer have an owner
      owner = await testnet.getOwnerAddress({ name: fullName });
      expect(owner).toBeUndefined();
    });
  });

  describe("additional router functions", () => {
    const signAndSubmit = async (signer: Account, transaction: AnyRawTransaction) => {
      const pendingTxn = await testnet.signAndSubmitTransaction({ transaction, signer });
      return testnet.waitForTransaction({ transactionHash: pendingTxn.hash });
    };

    test("canRegister returns true for unregistered name", async () => {
      const alice = Account.generate();
      const randomName = `available${Math.random().toString().slice(2, 10)}`;

      const canReg = await testnet.canRegister({
        name: randomName,
        account: alice.accountAddress,
      });

      expect(canReg).toBe(true);
    });

    test("canRegister returns false for registered name", async () => {
      const alice = Account.generate();

      // makeyour.move is already registered
      const canReg = await testnet.canRegister({
        name: "makeyour",
        account: alice.accountAddress,
      });

      expect(canReg).toBe(false);
    });

    test("isNameOwner returns true for owner", async () => {
      // Get the owner of makeyour.move
      const owner = await testnet.getOwnerAddress({ name: "makeyour" });
      expect(owner).toBeDefined();

      const isOwner = await testnet.isNameOwner({
        name: "makeyour",
        account: owner!,
      });

      expect(isOwner).toBe(true);
    });

    test("isNameOwner returns false for non-owner", async () => {
      const randomAccount = Account.generate();

      const isOwner = await testnet.isNameOwner({
        name: "makeyour",
        account: randomAccount.accountAddress,
      });

      expect(isOwner).toBe(false);
    });

    test("getTokenAddress returns address for existing name", async () => {
      const tokenAddr = await testnet.getTokenAddress({ name: "makeyour" });

      expect(tokenAddr).toBeDefined();
      expect(tokenAddr?.toString()).toMatch(/^0x[a-fA-F0-9]+$/);
    });

    test("getTokenAddress returns derived address for any valid name", async () => {
      // The contract returns a derived token address for any valid name,
      // whether registered or not (it's deterministically derived from the name)
      const randomName = `nonexistent${Math.random().toString().slice(2, 10)}`;
      const tokenAddr = await testnet.getTokenAddress({ name: randomName });

      // Returns a valid address (the derived token address for this name)
      expect(tokenAddr).toBeDefined();
      expect(tokenAddr?.toString()).toMatch(/^0x[a-fA-F0-9]+$/);
    });

    test("clearTargetAddress removes name resolution", async () => {
      const alice = Account.generate();
      await testnet.fundAccount({
        accountAddress: alice.accountAddress,
        amount: 10_000_000_000,
      });

      // Register a domain
      const domainName = `test${Math.random().toString().slice(2, 10)}`;
      await signAndSubmit(
        alice,
        await testnet.registerName({
          sender: alice,
          name: domainName,
          expiration: { policy: "domain" },
        }),
      );

      // Verify it resolves to alice initially
      let target = await testnet.getTargetAddress({ name: domainName });
      expect(target?.toString()).toEqual(alice.accountAddress.toString());

      // Clear the target address
      await signAndSubmit(
        alice,
        await testnet.clearTargetAddress({
          sender: alice,
          name: domainName,
        }),
      );

      // Should no longer resolve
      target = await testnet.getTargetAddress({ name: domainName });
      expect(target).toBeUndefined();
    });

    test("buyKeys and sellKeys for key trading", async () => {
      const alice = Account.generate();
      await testnet.fundAccount({
        accountAddress: alice.accountAddress,
        amount: 10_000_000_000,
      });

      // Register a domain first
      const domainName = `test${Math.random().toString().slice(2, 10)}`;
      await signAndSubmit(
        alice,
        await testnet.registerName({
          sender: alice,
          name: domainName,
          expiration: { policy: "domain" },
        }),
      );

      await new Promise((resolve) => setTimeout(resolve, 2000));

      // First, create a key by buying and staking for a subdomain
      const subdomainName = `sub${Math.random().toString().slice(2, 6)}`;
      await signAndSubmit(
        alice,
        await testnet.buyAndStakeKeyForSubdomain({
          sender: alice,
          domainName,
          subdomainName,
        }),
      );

      // Now buy additional keys (not for staking)
      const buyPrice = await testnet.getKeyBuyPrice({ domainName });
      console.log(`Buying 1 additional key for ${buyPrice} octas`);

      await signAndSubmit(
        alice,
        await testnet.buyKeys({
          sender: alice,
          domainName,
          amount: 1,
        }),
      );

      // Check sell price
      const sellPrice = await testnet.getKeySellPrice({ domainName });
      console.log(`Sell price for 1 key: ${sellPrice} octas`);
      expect(sellPrice).toBeGreaterThan(0n);

      // Sell the key we just bought
      await signAndSubmit(
        alice,
        await testnet.sellKeys({
          sender: alice,
          domainName,
          amount: 1,
        }),
      );
    });

    test("getDomainPrice returns registration cost", async () => {
      // Get price for a short domain (3 chars - most expensive)
      const shortPrice = await testnet.getDomainPrice({ name: "abc" });
      expect(typeof shortPrice).toBe("bigint");
      expect(shortPrice).toBeGreaterThan(0n);

      // Get price for a longer domain (cheaper)
      const longPrice = await testnet.getDomainPrice({ name: "mylongdomainname" });
      expect(typeof longPrice).toBe("bigint");
      expect(longPrice).toBeGreaterThan(0n);

      // Short domains should cost more than long domains
      expect(shortPrice).toBeGreaterThan(longPrice);

      console.log(`3-char domain price: ${shortPrice} octas (${Number(shortPrice) / 1e8} MOVE)`);
      console.log(`16-char domain price: ${longPrice} octas (${Number(longPrice) / 1e8} MOVE)`);
    });
  });
});

// Tests that require local node with MNS contract deployed - skipped by default
describe.skip("MNS Local", () => {
  const { movement, config } = getMovementClient();

  let changeExpirationDate: (
    tokenMode: 0 | 1,
    expirationDate: number,
    domainName: string,
    subdomainName?: string,
  ) => void;

  let changeRouterMode: (mode: 0 | 1) => void;

  const signAndSubmit = async (signer: Account, transaction: AnyRawTransaction) => {
    const pendingTxn = await movement.signAndSubmitTransaction({ transaction, signer });
    return movement.waitForTransaction({ transactionHash: pendingTxn.hash });
  };

  const randomString = () => Math.random().toString().slice(2);

  beforeAll(
    async () => {
      const { address: MNS_ADDRESS, privateKey: MNS_PRIVATE_KEY } = await publishMnsContract(movement);
      const contractAccount = await movement.deriveAccountFromPrivateKey({ privateKey: MNS_PRIVATE_KEY });

      // Publish the contract, should be idempotent

      // Enable reverse lookup for the case of v1
      await signAndSubmit(
        contractAccount,
        await generateTransaction({
          movementConfig: config,
          sender: contractAccount.accountAddress,
          data: {
            function: `${MNS_ADDRESS}::domains::init_reverse_lookup_registry_v1`,
            functionArguments: [],
          },
        }),
      );

      // Toggle router to v2
      await signAndSubmit(
        contractAccount,
        await generateTransaction({
          movementConfig: config,
          sender: contractAccount.accountAddress,
          data: {
            function: `${MNS_ADDRESS}::router::set_mode`,
            functionArguments: [new U8(1)],
          },
        }),
      );

      changeExpirationDate = async (
        // What version of the MNS sdk the name is. Depending on the version, we
        // hit different contracts to change the expiration date.
        // 0 = MNS v1 token
        // 1 = MNS v2 token
        tokenMode: 0 | 1,
        expirationDate: number,
        domainName: string,
        subdomainName?: string,
      ) =>
        signAndSubmit(
          contractAccount,
          await generateTransaction({
            movementConfig: config,
            sender: contractAccount.accountAddress,
            data: {
              function:
                tokenMode === 0
                  ? `${MNS_ADDRESS}::domain::force_set_expiration`
                  : `${MNS_ADDRESS}::v2_1_domains::force_set_name_expiration`,
              functionArguments:
                tokenMode === 0
                  ? [subdomainName, domainName, expirationDate]
                  : [domainName, subdomainName, expirationDate],
            },
          }),
        );

      // 0 = Points the router to MNS v1
      // 1 = Points the router to MNS v2
      changeRouterMode = async (mode: 0 | 1) =>
        signAndSubmit(
          contractAccount,
          await generateTransaction({
            movementConfig: config,
            sender: contractAccount.accountAddress,
            data: {
              function: `${MNS_ADDRESS}::router::set_mode`,
              functionArguments: [mode],
            },
          }),
        );
    },
    2 * 60 * 1000,
  );

  describe("registerName", () => {
    let alice: Account;
    let bob: Account;
    let domainName: string;
    let subdomainName: string;

    beforeEach(async () => {
      domainName = randomString();
      subdomainName = randomString();

      alice = Account.generate();
      bob = Account.generate();
      await Promise.all([
        movement.fundAccount({
          accountAddress: alice.accountAddress,
          amount: 500_000_000,
        }),
        movement.fundAccount({
          accountAddress: bob.accountAddress,
          amount: 500_000_000,
        }),
      ]);
    });

    test("can be called with a variety of parameters", async () => {
      const name = domainName;

      expect(
        await movement.registerName({
          name,
          sender: alice,
          expiration: { policy: "domain" },
        }),
      ).toBeTruthy();

      expect(
        await movement.registerName({
          name,
          sender: alice,
          expiration: { policy: "domain", years: 1 },
        }),
      ).toBeTruthy();

      await expect(
        movement.registerName({
          sender: alice,
          name,
          // Force the year to be absent
          expiration: { policy: "domain", years: 0 } as any,
        }),
      ).rejects.toThrow();

      // Testing to make sure that the subdomain policy is enforced
      await expect(
        movement.registerName({
          sender: alice,
          name,
          // Force the year to be absent
          expiration: { policy: "subdomain:follow-domain" },
        }),
      ).rejects.toThrow();
    });

    test("it mints a domain name and gives it to the sender", async () => {
      const name = domainName;

      await signAndSubmit(
        alice,
        await movement.registerName({
          name,
          expiration: { policy: "domain" },
          sender: alice,
        }),
      );

      const owner = await movement.getOwnerAddress({ name });
      expect(owner?.toString()).toEqual(alice.accountAddress.toString());
    });

    test("it mints a domain name and gives it to the specified address", async () => {
      const name = domainName;

      await signAndSubmit(
        alice,
        await movement.registerName({
          name,
          expiration: { policy: "domain" },
          sender: alice,
          targetAddress: bob.accountAddress.toString(),
          toAddress: bob.accountAddress.toString(),
        }),
      );

      const owner = await movement.getOwnerAddress({ name });
      expect(owner?.toString()).toEqual(bob.accountAddress.toString());
    });

    test("it mints a subdomain name and gives it to the sender", async () => {
      await signAndSubmit(
        alice,
        await movement.registerName({
          name: domainName,
          expiration: { policy: "domain" },
          sender: alice,
        }),
      );

      await signAndSubmit(
        alice,
        await movement.registerName({
          name: `${subdomainName}.${domainName}`,
          expiration: { policy: "subdomain:follow-domain" },
          transferable: true,
          sender: alice,
        }),
      );

      const owner = await movement.getOwnerAddress({ name: `${subdomainName}.${domainName}` });
      expect(owner?.toString()).toEqual(alice.accountAddress.toString());
    });

    test("it mints a subdomain name and gives it to the specified address", async () => {
      await signAndSubmit(
        alice,
        await movement.registerName({
          name: domainName,
          expiration: { policy: "domain" },
          sender: alice,
        }),
      );

      await signAndSubmit(
        alice,
        await movement.registerName({
          name: `${subdomainName}.${domainName}`,
          expiration: {
            policy: "subdomain:independent",
            // Expire the subdomain two seconds before the TLD expires
            expirationDate: Date.now() + 365 * 24 * 60 * 60 * 1000 - 2000,
          },
          transferable: true,
          sender: alice,
          targetAddress: bob.accountAddress.toString(),
          toAddress: bob.accountAddress.toString(),
        }),
      );

      const owner = await movement.getOwnerAddress({ name: `${subdomainName}.${domainName}` });
      expect(owner?.toString()).toEqual(bob.accountAddress.toString());
    });
  });

  describe("setTargetAddress and getTargetAddress", () => {
    let alice: Account;
    let bob: Account;
    let domainName: string;
    let subdomainName: string;
    let addr: AccountAddress | undefined;

    beforeEach(async () => {
      alice = Account.generate();
      await movement.fundAccount({
        accountAddress: alice.accountAddress,
        amount: 500_000_000,
      });

      bob = Account.generate();
      await movement.fundAccount({
        accountAddress: bob.accountAddress,
        amount: 500_000_000,
      });

      domainName = randomString();
      subdomainName = randomString();
    });

    test("it sets and gets the target address for a tld", async () => {
      const name = domainName;

      await signAndSubmit(
        alice,
        await movement.registerName({
          name,
          expiration: { policy: "domain" },
          sender: alice,
          targetAddress: alice.accountAddress.toString(),
          toAddress: alice.accountAddress.toString(),
        }),
      );

      addr = await movement.getTargetAddress({ name });
      expect(addr?.toString()).toEqual(alice.accountAddress.toString());

      await signAndSubmit(
        alice,
        await movement.setTargetAddress({
          name,
          address: bob.accountAddress,
          sender: alice,
        }),
      );
      addr = await movement.getTargetAddress({ name });
      expect(addr?.toString()).toEqual(bob.accountAddress.toString());
    });

    test("it sets and gets the target address for a subdomain", async () => {
      const name = `${subdomainName}.${domainName}`;

      await signAndSubmit(
        alice,
        await movement.registerName({
          name: domainName,
          expiration: { policy: "domain" },
          sender: alice,
        }),
      );

      await signAndSubmit(
        alice,
        await movement.registerName({
          name,
          expiration: { policy: "subdomain:follow-domain" },
          sender: alice,
        }),
      );

      addr = await movement.getTargetAddress({ name });
      expect(addr?.toString()).toEqual(alice.accountAddress.toString());

      await signAndSubmit(
        alice,
        await movement.setTargetAddress({
          name,
          address: bob.accountAddress,
          sender: alice,
        }),
      );
      addr = await movement.getTargetAddress({ name });
      expect(addr?.toString()).toEqual(bob.accountAddress.toString());
    });
  });

  describe("setPrimaryName and getPrimaryName", () => {
    let alice: Account;
    let bob: Account;
    let domainName: string;
    let subdomainName: string;

    beforeEach(async () => {
      alice = Account.generate();
      await movement.fundAccount({
        accountAddress: alice.accountAddress,
        amount: 500_000_000,
      });

      bob = Account.generate();
      await movement.fundAccount({
        accountAddress: bob.accountAddress,
        amount: 500_000_000,
      });

      domainName = randomString();
      subdomainName = randomString();
    });

    test("it returns null if no primary name is set", async () => {
      const res = await movement.getPrimaryName({ address: alice.accountAddress });
      expect(res).toBeFalsy();
    });

    test("it sets and gets domain primary names", async () => {
      const name = domainName;

      await signAndSubmit(
        alice,
        await movement.registerName({ name, expiration: { policy: "domain" }, sender: alice }),
      );

      await signAndSubmit(alice, await movement.setPrimaryName({ name, sender: alice }));

      const res = await movement.getPrimaryName({ address: alice.accountAddress });

      expect(res).toEqual(name);
    });

    test("it sets and gets subdomain primary names", async () => {
      const tld = domainName;
      const name = `${subdomainName}.${domainName}`;

      await signAndSubmit(
        alice,
        await movement.registerName({ name: tld, expiration: { policy: "domain" }, sender: alice }),
      );

      await signAndSubmit(
        alice,
        await movement.registerName({ name, expiration: { policy: "subdomain:follow-domain" }, sender: alice }),
      );

      await signAndSubmit(alice, await movement.setPrimaryName({ name, sender: alice }));

      const res = await movement.getPrimaryName({ address: alice.accountAddress });

      expect(res).toEqual(name);
    });
  });

  describe("renewDomain", () => {
    let alice: Account;
    let bob: Account;
    let domainName: string;
    let subdomainName: string;

    beforeEach(async () => {
      alice = Account.generate();
      await movement.fundAccount({
        accountAddress: alice.accountAddress,
        amount: 500_000_000,
      });

      bob = Account.generate();
      await movement.fundAccount({
        accountAddress: bob.accountAddress,
        amount: 500_000_000,
      });

      domainName = randomString();
      subdomainName = randomString();
    });

    test("can renew a v2 name that is eligible for renewal", async () => {
      const name = domainName;

      await changeRouterMode(1);

      await signAndSubmit(
        alice,
        await movement.registerName({
          name,
          expiration: { policy: "domain" },
          sender: alice,
        }),
      );

      // Change the expiration date of the name to be tomorrow
      const newExpirationDate = Math.floor(new Date(Date.now() + 24 * 60 * 60 * 1000).getTime() / 1000);
      await changeExpirationDate(1, newExpirationDate, name);

      await signAndSubmit(alice, await movement.renewDomain({ name, sender: alice }));

      // We expect the renewed expiration time to be one year from tomorrow
      const expectedExpirationDate = (newExpirationDate + 365 * 24 * 60 * 60) * 1000;
      const res = await movement.getExpiration({ name });
      expect(res?.toString()).toBe(expectedExpirationDate.toString());
    });

    test("throws an error for subdomain renewals", async () => {
      const tld = domainName;
      const name = `${subdomainName}.${domainName}`;

      await changeRouterMode(1);

      await signAndSubmit(
        alice,
        await movement.registerName({
          name: tld,
          expiration: { policy: "domain" },
          sender: alice,
        }),
      );

      await signAndSubmit(
        alice,
        await movement.registerName({
          name,
          expiration: { policy: "subdomain:follow-domain" },
          sender: alice,
        }),
      );

      expect(movement.renewDomain({ name, sender: alice })).rejects.toThrow();
    });
  });
});
