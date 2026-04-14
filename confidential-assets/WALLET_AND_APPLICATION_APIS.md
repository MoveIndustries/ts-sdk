<a id="spec-top"></a>

# Confidential Assets: Wallet and Application API Specification





<a id="sec-conformance"></a>

## Conformance

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

**Section anchors:** Numbered clauses (e.g. [§1.3](#sec-1-3)) link to HTML `id` attributes placed immediately before each heading. IDs follow `sec-{n}` for top-level sections, `sec-{n}-{m}` for subsections, and `sec-scope-…` for subsections under [Scope](#sec-scope).



<a id="sec-scope"></a>

## Scope

This specification defines the interface between **wallets**, **applications (dApps)**, and the Aptos **Confidential Assets (CA)** protocol.

- **On-chain normative behavior** is defined by the Move module `**aptos_experimental::confidential_asset`** and its dependencies (`confidential_balance`, `confidential_proof`, etc.).
- **Off-chain normative behavior** for proof generation and transaction serialization is defined by a Confidential Assets **client SDK** that matches that on-chain ABI. Implementations MAY ship as the npm packages `**@moveindustries/confidential-assets`** and `**@moveindustries/ts-sdk**` or as other libraries producing byte-identical arguments for the same entry and view functions.



<a id="sec-scope-terminology-wallet-adapter"></a>

### Terminology: wallet adapter

**Wallet adapter** means the **standard dApp ↔ wallet connection layer** used to obtain an Aptos/Movement **account address**, **network**, and **signed transaction submission**—for example the packages and patterns around `**@aptos-labs/wallet-adapter-react`**, `**@moveindustries/wallet-adapter-react**`, or any implementation that exposes the same capabilities (`signAndSubmitTransaction`, `signMessage` where applicable, etc.). It is **not** a Confidential Assets–specific product name.

For **browser** dApps, Confidential Assets **MUST** be reached through **namespaced wallet methods** defined in [§5](#sec-5) (`ca_*`) or a wallet-documented equivalent, so the dApp never receives CA decryption key material. That CA layer is **not** part of the generic “wallet adapter” product name but **is** required for normative browser dApp CA support.

**Wallet adapter CA wrappers:** dApp packages (e.g. `@…/wallet-adapter-react`) **SHOULD** expose **thin** functions that **feature-detect** the connected wallet’s §5 surface and **forward** request/response only—e.g. `caTransfer`, `caGetBalances`, or a single entry like `signAndSubmitConfidential` if it maps to `ca_transfer` under the hood. **Naming is implementation-defined;** the requirement is **no CA SDK or proof logic in the dApp bundle** for browser flows. If the feature is missing, the adapter **SHOULD** report unsupported CA so the dApp can degrade gracefully.



<a id="sec-scope-security-properties"></a>

### Security properties (decryption vs signing keys)

- The **Ed25519 account signing key** MUST remain under wallet control for user-facing flows: browser dApps MUST submit CA transactions through the wallet (via [§5](#sec-5) `ca_*` write methods that internally sign and submit, and/or the adapter’s `**signAndSubmitTransaction**` only for payloads **built inside the wallet**) and MUST NOT embed the user’s **Ed25519** private key in application code.
- The `**TwistedEd25519PrivateKey`** (CA **decryption** key) **MUST NOT** be exposed to **browser dApp** origins: dApps MUST NOT receive it, derive it in-page, or run ZK proof construction in the dApp JavaScript runtime for user-facing flows. Wallets MUST derive and use it only inside a **privileged wallet process** ([§4.1](#sec-4-1)) and MUST expose [§5](#sec-5) so dApps can request balances and transfers **without** decryption key material crossing into the page. **Non-browser** clients (CLI, tests, custodial backends, native apps with no untrusted web origin) MAY use the [§3](#sec-3) SDK with a Twisted key in their own trust boundary; that path is **not** conforming for **browser** dApps ([§6](#sec-6)).
- **Registration is wallet-only** (see [§6](#sec-6) A1). If the **wallet** derived the Twisted key with **`fromSignature`** when it registered **`ek`**, any **wallet-side** reproduction of that key (e.g. after restart) MUST use the **same** derivation policy and, where applicable, the **same** Ed25519 signature bytes as that registration.

---



<a id="sec-1"></a>

## 1. On-chain model

For each pair **(account address, fungible asset metadata `Object<Metadata>`)** the chain stores a `**ConfidentialAssetStore`** with at least:


| Field (conceptual)  | Role                                                                                                                                 |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `**ek**`            | Twisted ElGamal encryption public key, registered via `**register**` with a zero-knowledge proof of knowledge of the decryption key. |
| **Pending balance** | Ciphertext bucket to which `**deposit_to_internal`** and inbound `**confidential_transfer**` credit value.                           |
| **Actual balance**  | Ciphertext bucket that `**confidential_transfer`** (sender) and `**withdraw**` consume; corresponds to “available” in client APIs.   |




<a id="sec-1-1"></a>

### 1.1 Move entry functions (signatures)

In all signatures below: `**sender**`: `&signer`; `**token**`: `Object<Metadata>`; vector arguments are BCS-encoded payloads produced off-chain unless otherwise specified.


| Operation                        | Move entry function (argument list)                                                                                                                                                                               | Notes                                                                                      |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Register                         | `register(sender, token, ek, registration_proof_commitment, registration_proof_response)`                                                                                                                         | One store per `(user, token)`; ZKPoK of decryption key.                                    |
| Deposit (public → confidential)  | `deposit(sender, token, amount)`; `deposit_to(sender, token, to, amount)`; `deposit_coins<CoinType>(sender, amount)`; `deposit_coins_to<CoinType>(sender, to, amount)`                                            | `deposit_coins*` perform legacy coin handling when applicable; deposited amount is public. |
| Withdraw (confidential → public) | `withdraw(sender, token, amount, new_balance, zkrp_new_balance, sigma_proof)`; `withdraw_to(sender, token, to, amount, new_balance, zkrp_new_balance, sigma_proof)`                                               | Withdrawn amount is public.                                                                |
| Confidential transfer            | `confidential_transfer(sender, token, to, new_balance, sender_amount, recipient_amount, auditor_eks, auditor_amounts, zkrp_new_balance, zkrp_transfer_amount, sigma_proof, sender_auditor_hint)`                 | Same `sender_auditor_hint` bytes must be used when proving and when submitting; emitted on `Transferred` with ciphertexts and `ek_volun_auds`. |
| Normalize                        | `normalize(sender, token, new_balance, zkrp_new_balance, sigma_proof)`                                                                                                                                            | Required when actual balance chunks are denormalized before certain operations.            |
| Rollover pending                 | `rollover_pending_balance(sender, token)`; `rollover_pending_balance_and_freeze(sender, token)`                                                                                                                   | Merges pending into actual; freeze variant supports key-rotation sequencing.               |
| Rotate encryption key            | `rotate_encryption_key(sender, token, new_ek, new_balance, zkrp_new_balance, sigma_proof)`; `rotate_encryption_key_and_unfreeze(sender, token, new_ek, new_confidential_balance, zkrp_new_balance, rotate_proof)` | Pending MUST be empty per module logic; batched entry rotates then unfreezes.              |
| Freeze / unfreeze                | `freeze_token(sender, token)`; `unfreeze_token(sender, token)`                                                                                                                                                    | Controls whether inbound CA transfers are accepted for that store.                         |


**View functions** used by conforming clients include: `has_confidential_asset_store`, `encryption_key`, `pending_balance`, `actual_balance`, `is_normalized`, `is_frozen`, `get_auditor`, and allow-list / token-enabled predicates as exposed by the deployed framework.



<a id="sec-1-2"></a>

### 1.2 Pending vs actual balance (rollover)

The following follows from `**aptos_experimental::confidential_asset`** implementation logic:

1. `**deposit_to_internal**` adds value only to the recipient’s `**pending_balance**`; `**actual_balance**` is unchanged.
2. `**confidential_transfer_internal**` proves against the sender’s `**actual_balance**` and updates it; it adds to the recipient’s `**pending_balance**` only.
3. `**withdraw_to_internal**` proves against and updates `**actual_balance**` only.

Therefore value that exists only in `**pending_balance**` is not available as sender `**actual_balance**` for `**confidential_transfer**` or `**withdraw**` until merged into `**actual_balance**`.

`**rollover_pending_balance_internal**` performs that merge: it aborts unless `**ca_store.normalized**` is true (`**ENORMALIZATION_REQUIRED**` otherwise); it homomorphically adds pending into actual, resets pending to zero, resets `**pending_counter**`, and sets `**normalized**` to false.


| Condition                                                                            | Rollover required before spend/withdraw from “available”?                                                                                                                                                                                                                                          |
| ------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Decrypted **actual** alone ≥ amount                                                  | **No** — sender paths only debit `**actual_balance`**.                                                                                                                                                                                                                                             |
| Decrypted **actual** amount but **actual + pending** ≥ amount                        | **Yes** — pending MUST be merged into actual first. Reference SDK: `**checkSufficientBalanceAndRolloverIfNeeded`** (invoked by `**transferWithTotalBalance**` / `**withdrawWithTotalBalance**`) submits `**rolloverPendingBalance**` when `available < amount` and `available + pending ≥ amount`. |
| Funds only increased **pending** (deposit or inbound transfer) and no later rollover | **Yes** for that value to count as **actual**, unless another transaction already rolled over.                                                                                                                                                                                                     |


**Normalization:** `**rollover_pending_balance`** requires `**ca_store.normalized == true**`. On `**ENORMALIZATION_REQUIRED**`, the client MUST submit `**normalize**` first; `**normalize_internal**` sets `**normalized**` to true after a valid proof.



<a id="sec-1-3"></a>

### 1.3 Token addressing

Clients MUST pass the **fungible asset metadata object address** (32-byte FA metadata) wherever the protocol expects `**Object<Metadata>`**. Legacy coin type strings (e.g. `0x1::aptos_coin::AptosCoin`) MUST NOT be used where the client API expects a metadata address.

---



<a id="sec-2"></a>

## 2. Cryptographic types (client SDK)


| Type                           | Definition                                                                                                                       |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| `**TwistedEd25519PrivateKey**` | 32-byte decryption key; decrypts balances and participates in ZK proof generation for transfer, withdraw, normalize, and rotate. |
| `**TwistedEd25519PublicKey**`  | Registered on-chain as `**ek**` per `(user, token)` store.                                                                       |


**Derivation APIs (reference SDK):**


| API                                                           | Semantics                                                                                                                                                                                                                                                                                                                              |
| ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TwistedEd25519PrivateKey.fromDerivationPath(path, mnemonic)` | SLIP-0010–style hardened derivation; path MUST satisfy SDK hardened rules (e.g. coin type **637**).                                                                                                                                                                                                                                    |
| `TwistedEd25519PrivateKey.fromSignature(ed25519Signature)` | Derives a **`TwistedEd25519PrivateKey`** from **Ed25519 signature bytes** (not from arbitrary message text). **Registration** ([`register`](#sec-1-1)) is **wallet-only**; the wallet submits **`ek` = `derivedKey.publicKey()`** with the ZK proof. **Browser dApps MUST NOT** use this API in the page to obtain a Twisted key. Wallet **`signMessage`** wrappers (nonce, domain, etc.) used for registration MUST not change the signed payload relative to the agreed derivation string ([§2](#sec-2) constant). |
| `TwistedEd25519PrivateKey.generate()`                         | Uniform random key; used when no stable seed-based derivation exists (see [§9](#sec-9)).                                                                                                                                                                                                                                               |


**Constant UTF-8 string (reference SDK) used with `fromSignature` when signing that string directly:**

`Sign this message to derive decryption key from your private key`

**Wallets** that derive the CA key with **`fromSignature`** MUST use this exact UTF-8 string as the signed payload (unless they publish a **versioned** replacement). Otherwise the derived **`TwistedEd25519PrivateKey`** and registered **`ek`** will not match other conforming wallets on restore or when switching products—**dApps MUST NOT** perform **`register`** or define alternate registration strings; interoperability is between **wallets** only.

---



<a id="sec-3"></a>

## 3. Client SDK operations (`ConfidentialAsset`)

Wallets **MUST** run `**ConfidentialAsset**` (or equivalent) **inside the wallet process** for browser-facing CA flows. **Browser dApps MUST NOT** instantiate it with a `**TwistedEd25519PrivateKey**` in the dApp runtime. **Non-browser** tooling MAY instantiate it wherever proof construction is intended (subject to that environment’s own security review).



<a id="sec-3-1"></a>

### 3.1 Read operations


| Method                         | Inputs                                                               | Output                                      |
| ------------------------------ | -------------------------------------------------------------------- | ------------------------------------------- |
| `hasUserRegistered`            | `accountAddress`, `tokenAddress`                                     | `boolean`                                   |
| `getEncryptionKey`             | `accountAddress`, `tokenAddress`                                     | `TwistedEd25519PublicKey`                   |
| `getBalance`                   | `accountAddress`, `tokenAddress`, `decryptionKey`, `useCachedValue?` | `ConfidentialBalance` (available / pending) |
| `isBalanceNormalized`          | `accountAddress`, `tokenAddress`                                     | `boolean`                                   |
| `isPendingBalanceFrozen`       | `accountAddress`, `tokenAddress`                                     | `boolean`                                   |
| `getAssetAuditorEncryptionKey` | `tokenAddress`                                                       | Optional auditor `TwistedEd25519PublicKey`  |




<a id="sec-3-2"></a>

### 3.2 Write operations (submit signed transactions)


| Method                                  | `TwistedEd25519PrivateKey` required              | Notes                                                   |
| --------------------------------------- | ------------------------------------------------ | ------------------------------------------------------- |
| `registerBalance`                       | Yes                                              | **Wallet-only** in production ([§6](#sec-6) A1): registration + ZK registration proof.                   |
| `deposit`                               | No                                               | Moves FA from public store to confidential **pending**. |
| `withdraw` / `withdrawWithTotalBalance` | Yes (`senderDecryptionKey`)                      | MAY chain rollover/normalize internally.                |
| `transfer` / `transferWithTotalBalance` | Yes; optional `additionalAuditorEncryptionKeys`  | Fetches recipient `**ek`** on-chain.                    |
| `rolloverPendingBalance`                | Optional; required if normalization needed first | MAY chain `normalizeBalance`.                           |
| `normalizeBalance`                      | Yes                                              |                                                         |
| `rotateEncryptionKey`                   | Old and new keys                                 | MAY require prior rollover/freeze per [§1.1](#sec-1-1). |


All write operations require an `**Account**` (Ed25519 transaction signer) plus off-chain proof generation with the decryption key **in the party that holds that key** (the wallet for browser dApps—see [§5](#sec-5)).

**Browser dApp pattern (conforming):** The dApp calls **`ca_transfer`**, **`ca_withdraw`**, etc. ([§5](#sec-5)). The wallet runs the §3 builders internally, signs, and submits; the dApp receives transaction hashes (and optional structured results) **only**—never `**TwistedEd25519PrivateKey**`.

---



<a id="sec-4"></a>

## 4. Wallet internal messaging API



<a id="sec-4-1"></a>

### 4.1 Trust boundary (wallet-native implementations)

For **browser extension** and **mobile** wallets that implement CA **inside** a privileged host process: **decryption keys** and **ZK proof construction** MUST execute there for user-facing CA. The host **MUST NOT** forward `**TwistedEd25519PrivateKey`** bytes (or seeds or serialized secrets equivalent to the decryption key) to arbitrary web origins. Returning **decrypted numeric balances** to first-party wallet UI over an authenticated local channel is permitted; returning them to **connected dApp origins** is permitted only via [§5](#sec-5) with explicit consent where required.

**Non-browser** SDK use ([§3](#sec-3)) in other trust boundaries does not change the browser dApp rules in [§6](#sec-6).



<a id="sec-4-2"></a>

### 4.2 Message identifiers and payloads

Implementations that use a **host ↔ UI** message bridge SHOULD use the identifiers below for interoperability. Implementations MAY use different names if they publish a mapping table; **payload and response schemas MUST be equivalent**.


| Message                         | Payload                                        | Response                                   |
| ------------------------------- | ---------------------------------------------- | ------------------------------------------ |
| `GET_CONFIDENTIAL_BALANCES`     | `{ network, accountIndex, tokens: string[] }`  | `{ balances: ConfidentialTokenBalance[] }` |
| `REGISTER_CONFIDENTIAL_BALANCE` | `{ network, accountIndex, token }`             | `{ result: TransactionResult }`            |
| `SEND_CONFIDENTIAL_TRANSACTION` | `{ network, accountIndex, to, amount, token }` | `{ result: TransactionResult }`            |
| `ESTIMATE_CONFIDENTIAL_FEE`     | Same as send                                   | `{ fee: string }`                          |
| `DEPOSIT_CONFIDENTIAL_ASSET`    | `{ network, accountIndex, token, amount }`     | `{ result: TransactionResult }`            |
| `WITHDRAW_CONFIDENTIAL_ASSET`   | `{ network, accountIndex, token, amount }`     | `{ result: TransactionResult }`            |
| `ROLLOVER_CONFIDENTIAL_PENDING` | `{ network, accountIndex, token }`             | `{ result: TransactionResult }`            |


`**ConfidentialTokenBalance` object:**

```ts
{
  token: string;
  available: string;
  pending: string;
  registered: boolean;
  error?: string;
}
```



<a id="sec-4-3"></a>

### 4.3 Key derivation

Wallets SHOULD assign a **derivation policy version** string to releases that affect `**ek`** reproduction.


| Account material                       | Requirement                                                                                                                                                                                           |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| BIP-39 mnemonic                        | SHOULD derive CA key with `TwistedEd25519PrivateKey.fromDerivationPath("m/44'/637'/0'/1'/{accountIndex}'", mnemonic)` so change index `**1'**` is disjoint from common signing paths under `0'/0'/…`. |
| Raw imported Ed25519 key (no mnemonic) | SHOULD derive CA key by signing `**TwistedEd25519PrivateKey.decryptionKeyDerivationMessage**` with the account signer and passing the signature to `**fromSignature**`, entirely inside the wallet.   |


The chain stores one `**ek**` per `(user, token)`. A wallet MAY register the **same** ElGamal public key for all tokens for one account, or MAY derive **distinct** keys per token for unlinkability. A change of policy MUST be documented; affected users MAY require re-registration or key rotation.



<a id="sec-4-4"></a>

### 4.4 Network parameters

Wallets MUST configure:

- Fullnode and indexer endpoints (`**MovementConfig`**).
- `**confidentialAssetModuleAddress**` when the deployed module address differs from the SDK default.

---



<a id="sec-5"></a>

## 5. dApp-facing `ca_*` API (browser requirement)

Wallets that support **browser** dApp integration for Confidential Assets **MUST** expose the methods in this section—or **functionally equivalent** namespaced features documented by the wallet (same request/response semantics)—under the wallet’s injected provider / adapter so **dApp JavaScript never materializes or receives `TwistedEd25519PrivateKey` bytes** (or any equivalent serialization of the CA decryption secret). All decryption and ZK proof work for those calls **MUST** run in the wallet’s privileged process.

Wallets that do **not** expose browser dApp CA at all **MUST NOT** invite dApps to use the §3 SDK in-page as a substitute; such wallets should document that CA is **wallet-UI-only** until `ca_*` (or equivalent) is implemented.

Concrete transport (JSON-RPC, `window.aptos`, wallet-standard feature objects, etc.) SHOULD follow the same conventions as the wallet’s existing Aptos adapter.



<a id="sec-5-1"></a>

### 5.1 Read methods (wallet decrypts; no decryption key to the dApp)


| Method                | Request                        | Response                                                    |
| --------------------- | ------------------------------ | ----------------------------------------------------------- |
| `ca_getBalances`      | `{ tokens: AccountAddress[] }` | `{ balances: { token, registered, available, pending }[] }` |
| `ca_isRegistered`     | `{ token }`                    | `{ registered: boolean }`                                   |
| `ca_getEncryptionKey` | `{ token }`                    | `{ encryptionKey: hex }` — OPTIONAL                         |


If `**ca_getBalances`** returns decrypted amounts, the wallet MUST obtain explicit user consent per origin.


<a id="sec-5-2"></a>

### 5.2 Write methods (wallet holds decryption key)


| Method                   | Request                               | Wallet obligation                                                           |
| ------------------------ | ------------------------------------- | --------------------------------------------------------------------------- |
| `ca_register`            | `{ token }`                           | Submit `**registerBalance**` with wallet-derived `**ek**`.                  |
| `ca_deposit`             | `{ token, amount }`                   | Submit `**deposit**`.                                                       |
| `ca_withdraw`            | `{ token, amount, recipient? }`       | Submit `**withdraw**` or `**withdrawWithTotalBalance**`.                    |
| `ca_transfer`            | `{ token, recipient, amount, memo? }` | Submit `**transfer**` or `**transferWithTotalBalance**`.                    |
| `ca_rolloverPending`     | `{ token }`                           | Submit `**rolloverPendingBalance**`.                                        |
| `ca_normalize`           | `{ token }`                           | Submit `**normalizeBalance**` if exposed.                                   |
| `ca_rotateEncryptionKey` | `{ token, policy }`                   | Submit `**rotateEncryptionKey**` per `**policy**`; OPTIONAL in v1 adapters. |


Each method MUST return committed **transaction hashes** and MAY return structured events.



<a id="sec-5-3"></a>

### 5.3 Prohibited adapter behavior

A wallet adapter **MUST NOT** offer a **generic** “sign arbitrary bytes for CA” hook whose output is passed to `**fromSignature`** when those bytes are **fully controlled by the dApp** and differ from the registered derivation policy (phishing / wrong-`**ek`** registration).

---



<a id="sec-6"></a>

## 6. Application (dApp) conformance


| ID  | Requirement                                                                                                                                                                                                                                                                                                                                               |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A1  | In a **browser**, dApps MUST NOT hold the user’s **Ed25519** signing private key. dApps **MUST NOT** submit **`register`** / **`registerBalance`** (CA **`ek`** registration is **wallet-only** via [§4](#sec-4) or [§5](#sec-5) `ca_register`).                                                                                                                                                     |
| A2  | **Browser** dApps MUST NOT obtain, derive, or hold `**TwistedEd25519PrivateKey**` (or equivalent CA decryption material) in the dApp process. They MUST NOT run the Confidential Assets SDK for **proof construction** or **balance decryption** in page JavaScript. They **MUST** use [§5](#sec-5) `**ca_*`** (or the wallet’s documented equivalent) for all CA operations that require the decryption key or ZK proofs. |
| A3  | **Browser** dApps MUST NOT **persist**, log, or forward CA decryption key material. They MUST NOT ask the wallet to **export** `**TwistedEd25519PrivateKey**` (or seeds) to the page.                                                                                                                                                                       |
| A4  | **Browser** dApps MUST NOT use **`fromSignature`** (or any API) in the page to construct a Twisted key. **`fromSignature`** is a **wallet-internal** (or non-browser tooling) concern for agreed derivation policies ([§2](#sec-2), [§4.3](#sec-4-3)).                                                                                                      |
| A5  | dApps MUST pass FA **metadata addresses** for `**token`** ([§1.3](#sec-1-3)).                                                                                                                                                                                                                                                                             |
| A6  | Deposit and withdraw amounts are public on-chain; dApps MUST NOT infer that confidential **transfer** amounts are visible.                                                                                                                                                                                                                                |


---



<a id="sec-7"></a>

## 7. End-to-end flows (informative)

The diagrams below are **non-normative** illustrations. They describe **browser** dApp ↔ wallet flows where the Twisted key stays in the wallet. **Non-browser** clients MAY still use the §3 SDK with a Twisted key in their own process (outside this document’s browser dApp conformance rules).



<a id="sec-7-1"></a>

### 7.1 Register and optional deposit

```mermaid
sequenceDiagram
  participant User
  participant App
  participant Wallet
  participant Chain
  User->>App: Opt in / deposit
  App->>Wallet: ca_register (wallet-only) and/or ca_deposit
  Wallet->>Wallet: Derive Twisted key; build txs
  Wallet->>Chain: register / deposit
  User->>Wallet: Approve transaction(s)
  Wallet->>App: Transaction hash(es)
```





<a id="sec-7-2"></a>

### 7.2 Confidential transfer (browser dApp + `ca_transfer`)

```mermaid
sequenceDiagram
  participant App
  participant Wallet
  participant Chain
  App->>Wallet: ca_transfer (intent: token, recipient, amount)
  Wallet->>Wallet: SDK build transfer (proofs); Twisted key stays in wallet
  Wallet->>Chain: confidential_transfer (signed)
  Wallet->>App: Transaction hash
```





<a id="sec-7-3"></a>

### 7.3 Pending → spendable

1. Inbound `**confidential_transfer**` and `**deposit**` increase **pending** ([§1.2](#sec-1-2)).
2. Before spend, clients MUST satisfy [§1.2](#sec-1-2) (rollover; `**normalize`** when `**ENORMALIZATION_REQUIRED**`).
3. Wallets SHOULD expose `**ROLLOVER_CONFIDENTIAL_PENDING**` ([§4.2](#sec-4-2)) or equivalent and SHOULD chain rollover (and normalize) inside `**ca_transfer**` / `**ca_withdraw**` when possible.



<a id="sec-7-4"></a>

### 7.4 Withdraw to public balance

```mermaid
sequenceDiagram
  participant Wallet
  participant Chain
  Wallet->>Wallet: Satisfy §1.2; build withdrawal proof
  Wallet->>Chain: withdraw(amount, ...)
```



---



<a id="sec-8"></a>

## 8. Failure and security analysis

Losing the **decryption key** does **not** compromise the **Ed25519 signing key**. Assets remain attributed to the account on-chain, but without the decryption key, clients **cannot** construct valid proofs for `**confidential_transfer`** / `**withdraw**` in the usual path: funds remain **inaccessible** in the confidential layer (loss of **availability**, not unauthorized transfer).



<a id="sec-8-1"></a>

### 8.1 Wallet / key-management


| Scenario                                                     | Consequence                                                                    |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------ |
| Decryption key unrecoverable                                 | Cannot spend or withdraw CA balance via conforming clients.                    |
| `**ek`** registered from a key not held by the user’s wallet | Wallet cannot decrypt or spend; possible coercion / lock-in.                   |
| Derivation policy change without migration                   | Restored wallet derives different key; same as key loss for existing `**ek**`. |
| Stale backup after `**rotate_encryption_key**`               | Old key cannot update state until recovery procedure is defined.               |




<a id="sec-8-2"></a>

### 8.2 Application errors


| Scenario                                             | Consequence                                                                               |
| ---------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| dApp stores or receives decryption key               | Privacy compromise; violates [§6](#sec-6) for browser dApps.                              |
| Wrong `**token**` identifier (coin type vs metadata) | Transaction failure or wrong asset.                                                       |
| Omitted rollover / normalize                         | Abort or revert; fee spent without state change.                                          |
| XSS on dApp origin                                  | Cannot steal CA decryption key if the wallet never injects it ([§5](#sec-5), [§6](#sec-6)); other dApp secrets may still be at risk. |




<a id="sec-8-3"></a>

### 8.3 Protocol constraints (on-chain)


| Constraint                           | Effect                                                                                                                                                                                                                 |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Allow list / token disabled          | `**deposit**` / `**confidential_transfer**` MAY abort per deployed rules; `**withdraw**` MAY remain allowed.                                                                                                           |
| Auditor configured for token         | `**confidential_transfer**` arguments MUST satisfy auditor vector ordering required by the module.                                                                                                                     |
| `**frozen**` store                   | Inbound transfers disallowed until `**unfreeze_token**`.                                                                                                                                                               |
| `**pending_counter**` / inbound caps | If limits enforced by the module are hit (e.g. too many pending operations before rollover), `**deposit**` / inbound `**confidential_transfer**` MAY abort until the user completes rollover / normalization workflow. |




<a id="sec-8-4"></a>

### 8.4 Operational, user-error, and out-of-scope losses

No specification can list every way value can be lost. The following are **not** fully enumerated above but commonly matter in production:


| Category     | Scenario                                                                                                              | Effect                                                                                                                                    |
| ------------ | --------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Signing key  | Loss or theft of the **Ed25519** account key                                                                          | Loss or theft of **all** assets on that account (public FA, CA, NFTs), not only CA. This spec does not restate general Aptos key hygiene. |
| User error   | **Wrong recipient** on `**confidential_transfer`** (address typo, clipboard malware)                                  | Transfer is **irreversible** on-chain; amount is hidden in CA but destination is not.                                                     |
| User error   | **Wrong public `withdraw` / `deposit` amount**                                                                        | Legible on-chain; user confirms incorrect value.                                                                                          |
| Economic     | **Insufficient gas** (or aborted multi-tx flow)                                                                       | Transaction fails; **fees still spent** on submitted steps; balance unchanged except gas.                                                 |
| Deployment   | **Wrong network**, wrong `**confidentialAssetModuleAddress`**, or **FA metadata** for a different token than intended | Failed transactions, or movement of the **wrong** asset type.                                                                             |
| Software     | **Bugs** in wallet, dApp, SDK, or on-chain module                                                                     | Potential mis-accounting, failed proofs, or (in extreme cases) protocol-level loss; outside the normative API contract of this document.  |
| Availability | **Frozen** account, **disabled token**, or **normalization** not completed                                            | Funds may be **temporarily unusable** until protocol preconditions are met (distinct from permanent key loss).                            |


**Privacy vs custody:** Theft of `**TwistedEd25519PrivateKey`** enables proof construction and balance decryption for that `**ek**`; it does **not** by itself authorize **Ed25519** signatures. A combined attack (malware holding both keys, or a custodian) can move funds.

---



<a id="sec-9"></a>

## 9. Keyless accounts (OIDC / ephemeral signing keys)

Wallets whose **signing** key is not stably derivable from a user-held mnemonic MUST NOT rely on `**fromDerivationPath(mnemonic)`** for the CA decryption key. They MUST NOT rely on `**fromSignature**` tied to **rotating** ephemeral Ed25519 signing keys across sessions without a stable link to a prior CA key.



<a id="sec-9-1"></a>

### 9.1 Keyless wallet requirements


| ID  | Requirement                                                                                                                                                                                     |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| K1  | On first CA use for a logical account, the wallet MUST generate `**TwistedEd25519PrivateKey.generate()`** (or equivalent CSPRNG) inside the trust boundary.                                     |
| K2  | The wallet MUST persist the resulting secret encrypted under a **stable identity root** (e.g. OS keystore, secure enclave, user password KDF, provider encrypted backup bound to OIDC subject). |
| K3  | On subsequent sessions or devices, the wallet MUST load and decrypt that blob before submitting CA transactions or returning decrypted balances.                                                |
| K4  | **Browser** dApps MUST use [§5](#sec-5) `**ca_*`** (or equivalent). Wallets MUST NOT satisfy CA requests by exporting `**TwistedEd25519PrivateKey**` to the page. If a wallet does not yet implement `ca_*`, it MUST treat CA as **wallet-UI-only** for browser origins rather than enabling an SDK-in-page workaround. |


---



<a id="sec-10"></a>

## 10. Versioning


| Item                        | Rule                                                                                                                   |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Mnemonic derivation path    | Wallets MUST document the path template (e.g. `m/44'/637'/0'/1'/{index}'`) and any per-token variant in release notes. |
| `**fromSignature**` message | Any change from the constant in [§2](#sec-2) MUST bump a **policy version** and be documented.                         |
| Module address              | Clients MUST support per-network `**confidentialAssetModuleAddress`** when the framework is not at the default.        |


---



<a id="sec-11"></a>

## 11. Normative references


| Artifact                 | Identification                                                                                                                                                                                        |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| On-chain CA              | Move package `**aptos_experimental**`, modules `**confidential_asset**`, `**confidential_balance**`, `**confidential_proof**`, consistent with the framework revision deployed to the target network. |
| Examples                 | Aptos core source tree: `**aptos-move/move-examples/confidential_asset**`.                                                                                                                            |
| Reference TypeScript SDK | npm `**@moveindustries/confidential-assets**`, `**@moveindustries/ts-sdk**`; any substitute MUST be wire-compatible with [§1](#sec-1) and [§3](#sec-3) for the same chain revision.                   |


---

*End of specification.*