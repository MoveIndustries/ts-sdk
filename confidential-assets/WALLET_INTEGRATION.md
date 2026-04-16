# Confidential Assets — Wallet Integration Design

> **Status:** Draft / proposal — for alignment before implementation.
>
> **Companion spec:** [`WALLET_AND_APPLICATION_APIS.md`](./WALLET_AND_APPLICATION_APIS.md) is the normative specification for wallet/dApp conformance. This document focuses on **practical integration design**: what the wallet needs to do, how the application talks to it, and the open questions we should settle before writing code.

---

## Table of contents

1. [Guiding principles](#guiding-principles)
2. [Trust boundary](#trust-boundary)
3. [Decryption key lifecycle](#decryption-key-lifecycle)
4. [Operation-by-operation design](#operation-by-operation-design)
   - [Register](#register)
   - [Deposit](#deposit)
   - [Withdraw](#withdraw)
   - [Confidential transfer](#confidential-transfer)
   - [Rollover & normalization](#rollover--normalization)
   - [Key rotation](#key-rotation)
5. [Wallet UX decisions](#wallet-ux-decisions)
6. [Auditor support](#auditor-support)
7. [Safety & loss-of-funds analysis](#safety--loss-of-funds-analysis)
8. [Wallet ↔ application interface](#wallet--application-interface)
9. [Open questions](#open-questions)

---

## Guiding principles

1. **The decryption key (`dk`) never leaves the wallet.** It has the same security posture as the Ed25519 signing key. Browser dApps must not derive, hold, or see it.
2. **Proof generation happens inside the wallet.** Every ZK proof (registration, transfer, withdraw, normalize, rotate) requires `dk`. Since `dk` stays in the wallet, proofs are built there too.
3. **The wallet owns rollover and normalization.** These are protocol bookkeeping that users should not think about. The wallet chains them automatically before spends.
4. **The application sends intents, not transactions.** The dApp says "transfer 50 tokens to Alice"; the wallet figures out whether it needs to rollover, normalize, build proofs, and submit.

---

## Trust boundary

```
┌─────────────────────────────────────────────────────────┐
│  Wallet (privileged process / extension background)     │
│                                                         │
│  • Ed25519 signing key                                  │
│  • TwistedEd25519PrivateKey (dk) — derived, not stored  │
│  • ZK proof construction (registration, sigma, range)   │
│  • Balance decryption                                   │
│  • Transaction building, signing, submission             │
│  • Rollover / normalize orchestration                   │
│  • Auditor key lookup                                   │
│                                                         │
│  Exposes: ca_* methods (§5 of spec)                     │
└──────────────────────┬──────────────────────────────────┘
                       │ ca_register, ca_transfer, ...
                       │ (intents in, tx hashes out)
┌──────────────────────▼──────────────────────────────────┐
│  Application (browser dApp)                             │
│                                                         │
│  • Token selection UI                                   │
│  • Recipient / amount input                             │
│  • Balance display (from wallet-decrypted values)       │
│  • Auditor address input (optional)                     │
│  • Transaction status / history                         │
│                                                         │
│  MUST NOT: hold dk, build proofs, call SDK directly     │
└─────────────────────────────────────────────────────────┘
```

---

## Decryption key lifecycle

### Derivation (wallet-internal)

The wallet derives `dk` from existing root material — it is never generated independently or stored as a separate secret.

| Account type | Derivation | Reference |
|---|---|---|
| **Mnemonic** | `TwistedEd25519PrivateKey.fromDerivationPath("m/44'/637'/0'/1'/{accountIndex}'", mnemonic)` — change index `1'` avoids collision with signing paths. | motion-wallet `account.ts` |
| **Imported raw key** | Sign the fixed string `"Sign this message to derive decryption key from your private key"` with the Ed25519 account key → `TwistedEd25519PrivateKey.fromSignature(sig)`. | SDK `twistedEd25519.ts` |
| **Keyless (OIDC)** | `TwistedEd25519PrivateKey.generate()` — must be persisted encrypted under a stable identity root. | Spec §9 |

### Security invariants

- `dk` is derived on demand while the wallet is unlocked. When the wallet locks, the mnemonic/password are zeroed — `dk` ceases to exist in memory.
- `dk` bytes are never returned to any web origin, never logged, never serialized to extension storage as a standalone blob.
- If `dk` is derived via `fromSignature`, the wallet must use the **exact same** derivation string on every session. Changing it means a different `ek`, which breaks all existing registered balances.

---

## Operation-by-operation design

### Register

**What happens:** The wallet registers an encryption key (`ek`) for a `(user, token)` pair on-chain, along with a ZK proof-of-knowledge that it holds the corresponding `dk`.

**Who does what:**

| Step | Owner |
|---|---|
| User clicks "Enable confidential balance" for a token | App |
| App calls `ca_register({ token })` | App → Wallet |
| Derive `dk`, compute `ek = dk.publicKey()` | Wallet |
| Generate registration proof (Schnorr ZKPoK) | Wallet |
| Build and sign `register(sender, token, ek, commitment, response)` | Wallet |
| Submit transaction, return tx hash | Wallet → App |

**Key point:** Registration is **wallet-only**. The dApp must never call `registerBalance` itself — it doesn't have `dk`.

### Deposit

**What happens:** Public fungible asset balance is moved into the confidential pending balance. The deposited amount is **public** on-chain.

| Step | Owner |
|---|---|
| User enters amount to deposit | App |
| App calls `ca_deposit({ token, amount })` | App → Wallet |
| Check if user is registered; if not, register first | Wallet |
| Build and sign `deposit(sender, token, amount)` | Wallet |
| Submit transaction, return tx hash | Wallet → App |

**Key point:** No `dk` needed for deposit itself, but the wallet should auto-register if the user hasn't already.

### Withdraw

**What happens:** Confidential balance is moved back to public fungible asset balance. The withdrawn amount is **public** on-chain. Requires a ZK proof that the remaining balance is non-negative.

| Step | Owner |
|---|---|
| User enters amount to withdraw | App |
| App calls `ca_withdraw({ token, amount })` | App → Wallet |
| Fetch on-chain actual balance; decrypt with `dk` | Wallet |
| If actual < amount but actual + pending ≥ amount: rollover (and normalize if needed) first | Wallet |
| Build sigma proof + range proof for new balance | Wallet |
| Sign and submit `withdraw(sender, token, amount, new_balance, zkrp, sigma)` | Wallet |
| Return tx hash | Wallet → App |

**Key point:** The wallet transparently handles the rollover-before-withdraw case via `withdrawWithTotalBalance`.

### Confidential transfer

**What happens:** Encrypted value moves from sender to recipient. The transfer amount is **hidden** on-chain. Requires sigma proof + two range proofs (new balance, transfer amount).

| Step | Owner |
|---|---|
| User enters recipient, amount, (optionally auditor addresses) | App |
| App calls `ca_transfer({ token, recipient, amount, auditorAddresses? })` | App → Wallet |
| Fetch sender's actual balance, decrypt with `dk` | Wallet |
| If actual < amount: rollover/normalize first | Wallet |
| Fetch recipient's `ek` from chain | Wallet |
| Fetch global auditor `ek` for the token (if configured) | Wallet |
| Merge global auditor + any additional auditor keys from the request | Wallet |
| Build `ConfidentialTransfer` with proofs (sigma + 2× range) | Wallet |
| Sign and submit `confidential_transfer(...)` | Wallet |
| Return tx hash | Wallet → App |

**Key point:** The wallet manages all the complexity. The dApp just says "send X to Y."

### Rollover & normalization

**What happens:** Pending balance (from deposits and inbound transfers) is merged into the actual (spendable) balance. This is a **protocol-level bookkeeping** step — users should not have to think about it.

**Rollover requires normalization:** The chain enforces `normalized == true` before rollover. If it's `false`, the wallet must submit `normalize` first (which requires sigma + range proof using `dk`).

**Agreed approach: automatic rollover after every inbound transfer or deposit.**

While transaction fees remain low, the wallet should automatically rollover pending balances so the user never has to understand the pending/actual split. This also avoids normalization becoming a user-facing concept — if rollover happens promptly after each inbound operation, the balance stays in a clean state.

| Scenario | Wallet behavior |
|---|---|
| User sends a confidential transfer | After the transfer confirms, wallet auto-rollovers the **recipient's** pending balance (if the wallet controls the recipient account). |
| User receives an inbound transfer or deposit | Wallet detects pending > 0 and chains rollover (+ normalize if needed) automatically. |
| User wants to spend but actual < amount | Wallet chains rollover + normalize + spend in a single flow (via `transferWithTotalBalance` / `withdrawWithTotalBalance`). |
| Receive-only user (never sends) | Still needs rollover to make received funds spendable. The wallet should rollover on next balance fetch or on a background schedule. |

**Important edge case:** A user who only *receives* transfers and never sends will accumulate funds in pending that are not spendable until rolled over. The wallet must handle this — either by auto-rolling over when it detects pending > 0, or at minimum when the user attempts to spend or withdraw.

**The dApp should not need to know about normalization at all.** It is an internal protocol detail. The wallet should present a single combined balance to the user. If the wallet needs to show a brief "processing incoming funds" state while rollover transactions confirm, that is acceptable.

### Key rotation

**What happens:** The user's encryption key is replaced (e.g., after a suspected compromise of `dk`). Requires old + new keys, proofs, and a freeze/unfreeze dance to prevent inbound transfers during rotation.

This is a **wallet-only** operation (settings/advanced). The dApp does not need a `ca_rotateEncryptionKey` in v1, but the wallet UI should support it.

---

## Wallet UX decisions

### Balance visibility

Confidential balances should be **shown by default** as a separate line item beneath the regular asset — not hidden behind a toggle or special mode. "Confidential" refers to **on-chain privacy**, not visual hiding from the user. If a user has a shielded MOVE balance, it should appear as a distinct entry (e.g., "Shielded MOVE") below their regular MOVE balance. There is no need for the user to hide their own CA balance from themselves.

### Rollover is invisible to the user

The user should never see "pending balance" or "normalization" as concepts. The wallet auto-rollovers (see [above](#rollover--normalization)), so the displayed balance is always the combined spendable amount. During the brief window where rollover transactions are confirming, the wallet may show a subtle "processing incoming funds" indicator, but should not require user action.

### Spam token handling

For well-known assets (MOVE, USDC, WETH, WBTC, etc.), auto-rollover should happen unconditionally. For unknown or low-value tokens, the wallet may prompt the user before rolling over, to avoid accepting spammy assets automatically. This is an enhancement for later — v1 can auto-rollover everything.

---

## Auditor support

### Two kinds of auditors

The on-chain protocol supports **auditors** — third parties who receive encrypted copies of transfer amounts under their own encryption keys. There are two distinct sources:

1. **Global (per-token) auditor:** One auditor encryption key is recorded **on-chain** per asset, set by the token issuer via the module. The SDK fetches this automatically via `get_auditor(token)`. This auditor sees every confidential transfer for that asset.

2. **Per-transfer (voluntary) auditors:** The sender can include **additional** auditor encryption keys at transfer time. These are **not** stored on-chain — they only appear in the transaction data and the emitted `Transferred` event. They are useful for compliance, personal accounting, or regulated counterparties.

### What the wallet needs to do

- **Always include the global auditor** if one is configured for the token (the SDK handles this automatically when building `ConfidentialTransfer`).
- **Accept optional additional auditor keys** from the dApp or user via the transfer request.
- **Build encrypted copies** of the transfer amount for each auditor key (handled by the SDK — each auditor gets the transfer amount encrypted under their `ek`, plus `D` components bound into the sigma proof's Fiat-Shamir transcript).
- **Let users view** which global auditor is configured for a given token.

### What the dApp can do

- **Display** which global auditor is configured for an asset (fetch via `ca_getAuditor` or equivalent view function). This is informational — the auditor `ek` is public on-chain.
- **Let users enter or select additional auditor addresses** to include in a transfer. The dApp passes these to `ca_transfer`; the wallet builds the encrypted auditor copies.
- **Enterprise/compliance dApps** may show a dashboard of auditor addresses and names per asset, potentially with the ability to update the global auditor (token issuer only).

### Proposed `ca_transfer` request shape with auditor support

```ts
{
  token: string;           // FA metadata address
  recipient: string;       // recipient account address
  amount: string;          // transfer amount (decimal string or bigint-compatible)
  auditorAddresses?: string[];  // optional per-transfer auditor encryption keys (hex)
  senderAuditorHint?: string;   // optional opaque metadata (max 256 bytes, bound into proof)
}
```

### Auditor epoch (future consideration)

A security review of the upstream Aptos CA protocol recommends adding an `auditor_epoch` field to the confidential store to track auditor key rotations and prevent stale auditor keys from being used. This is a potential on-chain enhancement to track and integrate when available.

---

## Safety & loss-of-funds analysis

Every CA scenario must be validated to ensure it does not lead to loss of funds or irrecoverable states. The following table enumerates the known risk scenarios and their mitigations.

### Decryption key risks

| Scenario | Impact | Mitigation |
|---|---|---|
| **dk lost** (wallet uninstalled, mnemonic lost) | Funds remain on-chain but cannot be spent or withdrawn — effectively frozen forever. The Ed25519 signing key is not compromised. | Same mnemonic backup story as the signing key. Wallet should clearly communicate that mnemonic recovery restores both signing and CA decryption capability. |
| **dk derived differently after restore** (derivation policy changed, different wallet software) | Restored `dk` does not match the registered `ek` — same as key loss. | Wallets must use a stable, documented derivation path/policy. The `fromSignature` derivation string must never change. Wallet version notes must flag any derivation changes. |
| **dk compromised** (malware, leaked) | Attacker can decrypt all balances and construct valid proofs. Combined with a compromised Ed25519 key, attacker can transfer funds. `dk` alone cannot sign transactions. | Key rotation (`rotate_encryption_key`) re-encrypts the balance under a new key. Wallet should support this as an advanced operation. |
| **Wrong `ek` registered** (registered from a key not held by the user's wallet) | Wallet cannot decrypt or spend — same as key loss for that `(account, token)` pair. | Registration is wallet-only; the dApp cannot register an arbitrary `ek`. The wallet always derives and registers its own key. |

### Operational risks

| Scenario | Impact | Mitigation |
|---|---|---|
| **Rollover not performed** | Pending funds are not spendable. User sees a balance but cannot transfer or withdraw it. | Wallet auto-rollovers (see [rollover design](#rollover--normalization)). The SDK's `WithTotalBalance` methods also chain rollover before spends. |
| **Normalization skipped before rollover** | Rollover aborts with `ENORMALIZATION_REQUIRED`. Gas spent, no state change. | Wallet must check `is_normalized` before rollover and chain `normalize` first if needed. The SDK handles this internally. |
| **Wrong recipient address** | Confidential transfer is irreversible. Amount is hidden on-chain, but it is sent to the wrong party. | Standard address validation UX. No CA-specific mitigation beyond what exists for normal transfers. |
| **Wrong token metadata address** | Transaction fails, or wrong asset is moved. | Wallet should resolve token identifiers to FA metadata addresses and display the asset name for user confirmation. |
| **Transaction submitted with stale balance view** | Proof built against outdated ciphertext; chain rejects. Gas spent, no state change. | SDK fetches fresh views before proof construction. Wallet should not cache aggressively for proof-building paths. |
| **Multi-tx flow partially fails** (e.g., normalize succeeds but rollover fails) | State is partially updated — subsequent retries should work since the successful steps are idempotent in their end state. | Wallet should handle partial failure gracefully: detect current state and resume from where it left off rather than replaying the entire sequence. |

### Protocol constraints

| Scenario | Impact | Mitigation |
|---|---|---|
| **Frozen store** (pending balance frozen for key rotation) | Inbound transfers rejected until unfrozen. | Wallet UI should indicate frozen state. Key rotation flow should complete promptly (freeze → rotate → unfreeze). |
| **Allow list / token disabled** | Deposits and transfers may abort. Withdrawals may still work. | Wallet should check token status before building transactions and surface clear errors. |
| **Pending counter overflow** (too many inbound operations before rollover) | Further deposits and transfers to this account are rejected. | Auto-rollover after each inbound operation prevents this from accumulating. |

---

## Wallet ↔ application interface

### Read methods

| Method | Request | Response | Notes |
|---|---|---|---|
| `ca_getBalances` | `{ tokens: string[] }` | `{ balances: { token, registered, available, pending }[] }` | Wallet decrypts; dApp sees plaintext numbers only |
| `ca_isRegistered` | `{ token }` | `{ registered: boolean }` | No dk needed |
| `ca_getEncryptionKey` | `{ token }` | `{ encryptionKey: string }` | Public key — safe to return |

### Write methods

| Method | Request | Response | Notes |
|---|---|---|---|
| `ca_register` | `{ token }` | `{ txHash }` | Wallet derives dk, builds proof, submits |
| `ca_deposit` | `{ token, amount }` | `{ txHash }` | Auto-registers if needed |
| `ca_withdraw` | `{ token, amount }` | `{ txHash }` | Auto-rollover/normalize if needed |
| `ca_transfer` | `{ token, recipient, amount, auditorAddresses?, senderAuditorHint? }` | `{ txHash }` | Auto-rollover/normalize if needed |
| `ca_rolloverPending` | `{ token }` | `{ txHash }` | Explicit rollover; auto-normalizes if needed |

### What the dApp gets back

- **Transaction hashes** (and optionally structured event data after confirmation).
- **Decrypted balances** via `ca_getBalances`.
- **Never:** `dk`, proof data, raw ciphertext, or anything that would let the dApp reconstruct the key.

### Wallet adapter integration

The wallet adapter (`@moveindustries/wallet-adapter-react`) provides `useWallet()` with generic methods (`signAndSubmitTransaction`, etc.). For CA, the adapter should expose **thin wrapper functions** that:

1. **Feature-detect** whether the connected wallet supports `ca_*` methods.
2. **Forward** requests/responses without bundling any CA SDK or proof logic.
3. **Report unsupported** if the wallet doesn't implement the CA surface, so the dApp can degrade gracefully.

Example (conceptual):

```ts
const { caTransfer, caGetBalances, caSupported } = useConfidentialAssets();

if (!caSupported) {
  // show "wallet does not support confidential assets"
}

const balances = await caGetBalances({ tokens: [tokenAddress] });
const { txHash } = await caTransfer({ token, recipient, amount: "100" });
```

This is **not** the same as running the `ConfidentialAsset` SDK in the browser — these are RPC calls to the wallet.

---

## Resolved decisions

Captured from team discussion:

| # | Decision | Resolution |
|---|---|---|
| 1 | **Rollover strategy** | **Automatic after each inbound transfer/deposit** while fees are low. This avoids exposing "pending balance" as a user concept and avoids normalization being user-visible. |
| 2 | **Balance visibility** | **Show confidential balances by default** as a separate asset row (e.g., "Shielded MOVE" below "MOVE"). Confidential means on-chain privacy, not hiding from the user's own display. |
| 3 | **Normalization** | **Never user-facing.** If auto-rollover happens after each inbound operation, normalization is handled transparently. Even if it is needed, the wallet chains it internally before rollover. |
| 4 | **Auditor model** | One **global auditor per asset** stored on-chain. Sender can add **additional per-transfer auditors** that appear only in the transaction and emitted events. Both must be supported by the wallet. |

---

## Open questions

These should be resolved before implementation:

| # | Question | Options | Notes |
|---|---|---|---|
| 1 | **Should `ca_deposit` auto-register?** | (a) Yes — seamless. (b) No — require explicit `ca_register` first. | Auto-register is better UX; two transactions (register + deposit) can be sequenced by the wallet. |
| 2 | **Auditor address UX** | (a) Per-transfer entry only. (b) Wallet-managed address book. (c) dApp provides a list, wallet confirms. | For v1, (a) or (c) is likely sufficient. An enterprise dashboard for managing auditors per asset is a separate concern. |
| 3 | **Auditor epoch** | Should the on-chain module track an auditor epoch to prevent stale auditor keys? | Flagged in the upstream security review. Needs on-chain changes. |
| 4 | **Error reporting granularity** | What does the dApp see when rollover fails, normalization fails, proof generation fails, or the chain rejects? | Wallet should map internal failures to meaningful dApp-facing errors without leaking protocol internals. |
| 5 | **Multi-transaction flows** | When withdraw requires rollover + normalize + withdraw (3 txs), does the wallet handle all three silently, or notify the dApp of intermediate steps? | Recommend silent chaining with a single response for the final operation. |
| 6 | **Concurrent operations** | Can a dApp fire `ca_transfer` while a `ca_rolloverPending` is in flight? | Wallet should serialize CA operations per account/token to avoid on-chain race conditions. |
| 7 | **Spam token rollover** | Should the wallet auto-rollover unknown/low-value tokens, or prompt the user first? | For v1, auto-rollover everything. Spam filtering is an enhancement for later. |

---

*This document is a starting point for discussion. Once we agree on the remaining open questions, the implementation plan follows from the operation tables above.*
