# Movement TypeScript SDK

The official TypeScript SDK for interacting with the Movement blockchain.

> [!NOTE]
> This Movement TS SDK repo is forked from github.com/aptos-labs prior to the date on which the Aptos Foundation implemented its Innovation-Enabling Source Code License in substitution for the prior Apache License, Version 2.0 governing this repository.
>
> Move Industries continues to maintain, develop, modify, and distribute this repository solely under the Apache License, Version 2.0, as existed at the time of the fork and without application of the license instituted by the Aptos Foundation.

## Installation

```bash
npm install @moveindustries/ts-sdk
# or
pnpm add @moveindustries/ts-sdk
```

## Quick Start

```typescript
import { Movement, MovementConfig, Network } from "@moveindustries/ts-sdk";

// Initialize the client
const config = new MovementConfig({ network: Network.TESTNET });
const movement = new Movement(config);

// Get account balance
const balance = await movement.getAccountAPTAmount({
  accountAddress: "0x1",
});
```

## Features

### Account Management

Create and manage accounts on Movement:

```typescript
import { Account, Ed25519PrivateKey } from "@moveindustries/ts-sdk";

// Generate a new account
const account = Account.generate();

// Or from an existing private key
const privateKey = new Ed25519PrivateKey("0x...");
const account = Account.fromPrivateKey({ privateKey });

// Fund account on testnet
await movement.fundAccount({
  accountAddress: account.accountAddress,
  amount: 100_000_000, // 1 MOVE
});
```

### Transactions

Build, sign, and submit transactions:

```typescript
// Simple coin transfer
const txn = await movement.transaction.build.simple({
  sender: sender.accountAddress,
  data: {
    function: "0x1::aptos_account::transfer",
    functionArguments: [recipientAddress, 1_000_000],
  },
});

const signedTxn = await movement.transaction.sign({ signer: sender, transaction: txn });
const result = await movement.transaction.submit.simple({ transaction: signedTxn });
await movement.waitForTransaction({ transactionHash: result.hash });
```

### Movement Name Service (MNS)

The SDK includes full support for Movement Name Service (MNS), allowing you to register and manage `.move` domain names.

#### Domain Registration

```typescript
// Check registration price before registering
const price = await movement.getDomainPrice({ name: "mydomain", years: 1 });
console.log(`Registration cost: ${Number(price) / 1e8} MOVE`);

// Check if a name is available
const canRegister = await movement.canRegister({ name: "mydomain" });

// Register a domain
const txn = await movement.registerName({
  name: "mydomain.move",
  sender: account,
  expiration: { policy: "domain" },
});
```

#### Name Resolution

```typescript
// Resolve name to address
const address = await movement.getTargetAddress({ name: "mydomain.move" });

// Reverse lookup - get primary name for address
const name = await movement.getPrimaryName({ address: "0x123..." });

// Get all names owned by an address
const names = await movement.getAccountNames({ accountAddress: "0x123..." });
```

#### Managing Names

```typescript
// Set target address for name resolution
await movement.setTargetAddress({
  sender: account,
  name: "mydomain.move",
  address: targetAddress,
});

// Clear target address
await movement.clearTargetAddress({
  sender: account,
  name: "mydomain.move",
});

// Set primary name for account
await movement.setPrimaryName({
  sender: account,
  name: "mydomain.move",
});

// Check if address owns a name
const isOwner = await movement.isNameOwner({
  name: "mydomain.move",
  address: account.accountAddress,
});
```

### Fungible Assets

```typescript
// Get fungible asset balance
const balance = await movement.getCurrentFungibleAssetBalances({
  ownerAddress: account.accountAddress,
});

// Transfer fungible assets
const txn = await movement.transferFungibleAsset({
  sender: account,
  fungibleAssetMetadataAddress: assetAddress,
  recipient: recipientAddress,
  amount: 1000,
});
```

### Digital Assets (NFTs)

```typescript
// Get owned digital assets
const assets = await movement.getOwnedDigitalAssets({
  ownerAddress: account.accountAddress,
});

// Transfer digital asset
const txn = await movement.transferDigitalAssetTransaction({
  sender: account,
  digitalAssetAddress: assetAddress,
  recipient: recipientAddress,
});
```

### View Functions

Call read-only Move functions:

```typescript
const result = await movement.view({
  payload: {
    function: "0x1::coin::balance",
    typeArguments: ["0x1::aptos_coin::AptosCoin"],
    functionArguments: [accountAddress],
  },
});
```

## Networks

The SDK supports multiple networks:

```typescript
import { Network } from "@moveindustries/ts-sdk";

// Testnet
const testnetConfig = new MovementConfig({ network: Network.TESTNET });

// Mainnet
const mainnetConfig = new MovementConfig({ network: Network.MAINNET });

// Custom network
const customConfig = new MovementConfig({
  fullnode: "https://your-node-url",
  indexer: "https://your-indexer-url",
});
```

## API Reference

### Movement Client

The main entry point providing access to all SDK functionality:

| Namespace | Description |
|-----------|-------------|
| `movement.account` | Account management and queries |
| `movement.mns` | Movement Name Service operations |
| `movement.coin` | Coin operations |
| `movement.transaction` | Transaction building, signing, and submission |
| `movement.fungibleAsset` | Fungible asset operations |
| `movement.digitalAsset` | Digital asset (NFT) operations |
| `movement.staking` | Staking operations |
| `movement.general` | General blockchain queries |
| `movement.faucet` | Testnet faucet |
| `movement.keyless` | Keyless account operations |

### MNS Methods

| Method | Description |
|--------|-------------|
| `registerName` | Register a new domain name |
| `getTargetAddress` | Resolve name to address |
| `getPrimaryName` | Get primary name for address |
| `setTargetAddress` | Set resolution target for name |
| `clearTargetAddress` | Remove resolution target |
| `setPrimaryName` | Set primary name for account |
| `getName` | Get name details |
| `getOwnerAddress` | Get owner of a name |
| `getExpiration` | Get expiration timestamp |
| `getAccountNames` | Get all names owned by address |
| `getAccountDomains` | Get domains owned by address |
| `renewDomain` | Renew domain registration |
| `canRegister` | Check if name is available |
| `isNameOwner` | Check if address owns name |
| `getTokenAddress` | Get token address for name |
| `getDomainPrice` | Get registration cost |

## Development

```bash
# Install dependencies
pnpm install

# Build
pnpm build

# Run tests
pnpm test

# Run tests on testnet
MOVEMENT_NETWORK=testnet pnpm test
```

## License

Apache License 2.0
