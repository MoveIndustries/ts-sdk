# @moveindustries/confidential-assets

Confidential Assets SDK for Movement Network. Enables privacy-preserving token transfers where **amounts are hidden** using zero-knowledge proofs while addresses remain visible.

## Network Support


| Network                         | Module Address                                                       | Status       |
| ------------------------------- | -------------------------------------------------------------------- | ------------ |
| Movement Testnet (experimental) | `0xd38fc33916098866c4f18e6c80e75dd6b5af0d397acd063214bf3e78673ce25f` | Live         |
| Movement Mainnet                | -                                                                    | Coming soon? |


## Installation

```bash
npm install @moveindustries/confidential-assets @moveindustries/ts-sdk
```

## Quick Start

```typescript
import { ConfidentialAsset, TwistedEd25519PrivateKey } from "@moveindustries/confidential-assets";
import { Account, MovementConfig, Network } from "@moveindustries/ts-sdk";

// Initialize
const config = new MovementConfig({ network: Network.TESTNET });
const confidentialAsset = new ConfidentialAsset({ config });

// Generate a decryption key (store this securely!)
const decryptionKey = TwistedEd25519PrivateKey.generate();

// Register for confidential balances
await confidentialAsset.registerBalance({
  signer: account,
  tokenAddress: "0xa", // MOVE token
  decryptionKey,
});

// Deposit public tokens into confidential balance
await confidentialAsset.deposit({
  signer: account,
  tokenAddress: "0xa",
  amount: 1_000_000_000n, // 10 MOVE
});

// Rollover pending balance to available (required before spending)
await confidentialAsset.rolloverPendingBalance({
  signer: account,
  tokenAddress: "0xa",
  decryptionKey,
});

// Transfer confidentially (amount is hidden on-chain)
await confidentialAsset.transfer({
  signer: account,
  recipient: "0xrecipient...",
  tokenAddress: "0xa",
  amount: 500_000_000n, // 5 MOVE (hidden)
  senderDecryptionKey: decryptionKey,
});

// Withdraw back to public balance
await confidentialAsset.withdraw({
  signer: account,
  tokenAddress: "0xa",
  amount: 500_000_000n,
  senderDecryptionKey: decryptionKey,
});
```

## Key Concepts

### Decryption Key

A `TwistedEd25519PrivateKey` that allows you to decrypt your confidential balance. **Keep this secret** - anyone with this key can see your balance (but not spend it).

### Pending vs Available Balance

- **Pending**: Where deposits and incoming transfers land
- **Available**: Spendable balance for transfers/withdrawals
- Use `rolloverPendingBalance()` to move pending → available

### Privacy Model

- **Hidden**: Transfer amounts
- **Visible**: Sender and recipient addresses
- This is different from Monero/Zcash which can hide both

## API Reference

### Core Operations


| Method                     | Description                                               |
| -------------------------- | --------------------------------------------------------- |
| `registerBalance()`        | Register an account for confidential balances for a token |
| `deposit()`                | Move public tokens into confidential balance (pending)    |
| `withdraw()`               | Move confidential tokens back to public balance           |
| `transfer()`               | Send tokens confidentially (amount hidden)                |
| `rolloverPendingBalance()` | Move pending balance to available                         |


### With Auto-Rollover


| Method                       | Description                                |
| ---------------------------- | ------------------------------------------ |
| `withdrawWithTotalBalance()` | Withdraw with automatic rollover if needed |
| `transferWithTotalBalance()` | Transfer with automatic rollover if needed |


### Balance & State Queries


| Method                     | Description                                  |
| -------------------------- | -------------------------------------------- |
| `getBalance()`             | Get decrypted available and pending balances |
| `hasUserRegistered()`      | Check if account has registered for a token  |
| `isPendingBalanceFrozen()` | Check if pending balance is frozen           |
| `isBalanceNormalized()`    | Check if balance is normalized               |
| `getEncryptionKey()`       | Get the public encryption key for an account |


### Advanced Operations


| Method                           | Description                              |
| -------------------------------- | ---------------------------------------- |
| `rotateEncryptionKey()`          | Rotate to a new decryption key           |
| `normalizeBalance()`             | Normalize an unnormalized balance        |
| `getAssetAuditorEncryptionKey()` | Get the auditor key for a token (if set) |


## Auditors

Confidential assets support optional **auditors** - trusted parties who can decrypt transfer amounts for compliance purposes. This enables regulated privacy where authorities can audit transactions when required.

```typescript
// Transfer with auditor visibility
await confidentialAsset.transfer({
  signer: account,
  recipient: "0xrecipient...",
  tokenAddress: "0xa",
  amount: 500_000_000n,
  senderDecryptionKey: decryptionKey,
  additionalAuditorEncryptionKeys: [auditorPublicKey],
});
```

## Custom Module Address

If deploying your own confidential asset module:

```typescript
const confidentialAsset = new ConfidentialAsset({
  config,
  confidentialAssetModuleAddress: "0xyour_module_address",
});
```

## License

Apache-2.0