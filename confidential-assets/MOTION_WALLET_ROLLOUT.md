# Motion Wallet rollout — confidential assets

This file tracks the engineering rollout plan for landing confidential-assets support in Motion Wallet. It is **not** part of the design specification — for the design see [`WALLET_INTEGRATION.md`](./WALLET_INTEGRATION.md). When the rollout is complete this file should be deleted.

## Branch integration plan

This section captures the concrete plan for combining Motion Wallet's existing keyless branch (`feat/keyless-wallet`) with the existing CA work (`confidential-assets-local`) into a single shippable branch. It is grounded in the actual state of both branches as of this writing, not in inference.

### State of the two branches

- **`feat/keyless-wallet`** — head `6bb7a61`. Implements full keyless authentication via `@eigerco/movement-keyless`: OAuth via `chrome.identity.launchWebAuthFlow`, ZK-proof generation via the prover, ephemeral-key refresh on a Chrome alarm. Files: `src/services/wallet/keyless-{auth,session,signer,config}.ts`, plus a `keyless` variant in `WalletEntry`. **The pepper is fetched on every unlock and currently discarded** (`src/services/wallet/account.ts` `initializeFromKeyless` destructures only `{ account }` from `MovementKeyless.completeLoginWithJwt`).
- **`confidential-assets-local`** — head `3019c40`. Implements CA registration / send / balances against the SDK; uses `accountIndex`-keyed software-backed `dk` derivation; assumes mnemonic or private-key vault types and explicitly throws `"Unsupported account type for confidential assets"` for anything else. Includes localnet-specific config and a `docs/CONFIDENTIAL_ASSETS_INTEGRATION_PLAN.md` whose "keyless" row predates pepper exposure and is now stale.
- **Divergence:** `feat/keyless-wallet` is 22 ahead of, 17 behind, the merge-base with `confidential-assets-local`.

### Recommended strategy

Cut a new branch from `feat/keyless-wallet`, port CA changes onto it, and drop the localnet-only bits.

Reasons:

- The keyless branch is closer to product trunk (it's the active product surface, not an experiment).
- The CA branch's localnet bits are obsolete now that CA is on Movement testnet — porting *forward* lets you delete them rather than carry them.
- Pepper lifecycle is the most invasive piece and already lives on the keyless branch; porting CA *to* keyless is one-directional, while the reverse would re-do this work.

### Proposed branch name

`feat/confidential-assets` (cut from `feat/keyless-wallet`).

### Step-by-step plan

#### Step 1 — Cut the branch

```
git switch feat/keyless-wallet
git pull
git switch -c feat/confidential-assets
```

#### Step 2 — Retain the pepper in the unlocked session

The keyless branch currently discards the pepper immediately after address verification: `MovementKeyless.completeLoginWithJwt` uses `pepper` to recompute the expected address, then the wallet destructures only `{ account }` and lets `pepper` fall out of scope. CA needs the pepper available *for the duration of the unlocked session* (same lifecycle as `cachedSigners` — in memory only, zeroed on wallet lock, never written to disk). The change is to widen the destructure and add `pepper` to the in-memory session struct.

In `src/services/wallet/account.ts`, change `initializeFromKeyless` to capture `pepper` and stash it in `keylessActiveSession`:

```ts
// before
const { account } = await keyless.completeLoginWithJwt(jwt, ephemeralKey)
// after
const { account, pepper } = await keyless.completeLoginWithJwt(jwt, ephemeralKey)
// ...
keylessActiveSession = { signer, aud: vaultData.aud, pepper }
```

Update the `keylessActiveSession` type:

```ts
let keylessActiveSession: {
  signer: KeylessSigner
  aud: string
  pepper: Uint8Array  // 31 raw bytes; hex-decoded from MovementKeyless result
} | null = null
```

The same `pepper` field is also captured by `refreshKeylessSession` (in `src/services/wallet/keyless-session.ts`) when the ephemeral key is refreshed mid-session — the prover round-trip there returns the same pepper, but the session struct should be updated atomically with the new signer to avoid windowed inconsistency. Keep pepper handling colocated with signer handling.

Zero the pepper on lock alongside `cachedSigners` (the existing lock path already calls `signer.dispose()`; add an explicit `keylessActiveSession.pepper.fill(0)` and set the field to `null`).

#### Step 3 — Generalize `dk` derivation

In `src/services/wallet/account.ts`, the existing `getTwistedDecryptionKey(accountIndex, tokenMetadataAddress)` branches on `vaultType`. Add a third branch:

```ts
if (vaultType === 'keyless') {
  if (!keylessActiveSession) throw new Error('Wallet locked')
  return keylessDecryptionKey(
    keylessActiveSession.pepper,
    keylessActiveSession.signer.getAddress(),
    tokenMetadataAddress,
  )
}
```

`keylessDecryptionKey` is the new SDK helper specified in the design doc (SDK helpers); it runs the canonical HKDF-SHA512 derivation and returns a `TwistedEd25519PrivateKey`. The SDK addition (`TwistedEd25519PrivateKey.fromUniformBytes`, the helper itself) lands in `@moveindustries/confidential-assets` as a prerequisite — a small PR there before any wallet code lands.

The existing `getEd25519SigningAccount` is a misnomer for the keyless case (a keyless signer is not an `Ed25519Account`). Rename to `getCaSenderAddress(accountIndex)` and return just the `AccountAddress` — the only thing the CA SDK call paths actually need from this function once `dk` is sourced separately. Mnemonic and private-key paths return `signer.accountAddress`; keyless returns `keylessActiveSession.signer.getAddress()`.

If any CA SDK call still requires a full `Account`-shaped signer (e.g. `ca.registerBalance({ signer, ... })`), use the keyless branch's `KeylessSigner` directly — it already implements the same `Signer` interface that the rest of the wallet uses. The CA SDK's `signer` parameter is structurally typed; verify the keyless `account` from `@eigerco/movement-keyless` is shape-compatible (it is in `KeylessSigner.buildSignSubmit` already, via `signer: this.account! as never`).

#### Step 4 — Port the CA service module

Bring over `src/services/wallet/confidential-asset.ts` from `confidential-assets-local`. Adjust:

- Replace `getEd25519SigningAccount(accountIndex)` calls with `getCaSenderAddress(accountIndex)` for address-only uses (most uses).
- For `ca.registerBalance({ signer, ... })` and similar, source `signer` from the wallet's existing signer factory (the same one keyless and mnemonic both feed into).
- Remove the explicit `'Unsupported account type for confidential assets'` throw in the keyless path — replaced by Step 3's keyless branch.

#### Step 5 — Port UI hooks and pages

Bring over `src/popup/hooks/useConfidentialBalances.ts` and any CA UI pages from `confidential-assets-local`. These should be backing-agnostic since they go through the wallet service layer — no keyless-specific changes expected, but smoke-test against a keyless account on testnet.

#### Step 6 — Drop localnet-only bits

Audit `confidential-assets-local` for localnet-only changes (network config additions, hardcoded addresses, dev-loop helpers). Drop them; testnet is the new baseline. Likely sites:

- `src/core/network/config.ts` — drop any localnet `confidentialAssetModuleAddress` overrides if testnet's default is canonical.
- `package.json` — drop any `file:..` overrides that pointed at a localnet-built SDK.

The existing `docs/CONFIDENTIAL_ASSETS_INTEGRATION_PLAN.md` on the CA branch is stale (its keyless row predates pepper exposure). Either delete it or replace its keyless row with a one-line pointer to `wallet_integration.md` § Keyless accounts — don't carry both forward.

#### Step 7 — Tests

- Unit-test `keylessDecryptionKey` against fixed pepper / address / token vectors (so a regression in the SDK is caught upstream of the wallet).
- Unit-test the `account.ts` keyless branch of `getTwistedDecryptionKey`: same pepper + same address + same token = same `dk`; same pepper + different addresses (owner vs multisig) = different `dk`; same pepper + same address + different tokens = different `dk`.
- Integration-test against testnet: register a token on a keyless account, deposit, verify balance decryption, send a confidential transfer, verify the recipient (also keyless) decrypts the right amount.
- Regression-test the existing keyless and mnemonic paths to confirm the `dk`-derivation rename / branch addition didn't break anything.

#### Step 8 — Wire up the SDK additions

Concurrent with the wallet work (or just before): land the SDK additions in `@moveindustries/confidential-assets`:

- `TwistedEd25519PrivateKey.fromUniformBytes(bytes: Uint8Array): TwistedEd25519PrivateKey` — accepts ≥ 32 bytes, reduces mod ℓ.
- `keylessDecryptionKey(pepper: Uint8Array, accountAddress: AccountAddressInput, tokenMetaAddr: AccountAddressInput): TwistedEd25519PrivateKey` — runs the canonical HKDF expansion specified in the design doc.
- Tests asserting fixed input vectors → fixed output `dk` bytes (regression guard for the wallet ↔ chain compatibility contract).

### Risks and order-of-operations notes

- **SDK PR must land first.** The wallet branch depends on `keylessDecryptionKey` and `fromUniformBytes`; landing the wallet PR before the SDK PR strands the wallet branch on a broken import.
- **First-time keyless registration is irreversible at the policy level.** Once a keyless account registers `ek[token]` on chain, that key is bound to *this* HKDF policy version (`v1`). A late change to salt, info layout, or hash function before public testnet release is free; after public release it requires `rotate_encryption_key`. So: lock the policy strings (`"movement-ca/v1"`, `"dk:"`, SHA-512, L=64) in code review, not after.
- **Multisig is a separate question.** Motion Wallet's multisig support and CA-on-multisig are independent of this branch merge. Do not block the keyless+CA combination on multisig; treat multisig as a follow-up.
- **`accountIndex` mismatch.** The `confidential-assets-local` branch threads `accountIndex` everywhere. Keyless wallets currently use `accountIndex = 0` only (one keyless account per vault). This works as-is, but if Motion Wallet later supports multiple keyless accounts per identity, the `getCaSenderAddress(accountIndex)` signature is already the right shape.

### Not implemented by this merge

The items below are part of the design (see the design doc) but do not ship in this particular PR. They are deferred implementation work, not unresolved design.

- Multisig CA flows.
- Hardware-backed CA.
- Per-asset auditor UI (separate work stream).
