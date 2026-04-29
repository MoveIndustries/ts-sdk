# Confidential Assets TS SDK — Security Audit

Scope: full read of `confidential-assets/src` (~5k LOC). Findings are ordered by severity and address both (a) the Rust-review concerns raised by a colleague (carried over to TS where applicable) and (b) issues I found in the TS code itself.

---

## Address of Rust review concerns (TS-specific)

### 1. Transfer "old balance with zero randomness" bug — does NOT exist in TS
`EncryptedAmount.fromCipherTextAndPrivateKey` (`src/crypto/encryptedAmount.ts:106`) keeps the **original on-chain ciphertext** and only fills in the decrypted plaintext chunks; randomness is left `undefined`. The transfer prover (`src/crypto/confidentialTransfer.ts:381–397`, `:436`) uses `senderEncryptedAvailableBalance.getCipherText()` — i.e., the actual on-chain D points, not a re-encryption. So the TS sigma proof correctly binds to stored ciphertext.

### 2. README/API drift
The TS API (`fromSignature`, etc.) matches the code; no obvious mismatch like the Rust README has.

### 3. Verifier panicking on malformed points — same class of issue exists in TS
`RistrettoPoint.fromHex(opts.sigmaProof.X1)` etc. throw inside the verifier (e.g. `src/crypto/confidentialTransfer.ts:647–654`, `src/crypto/confidentialWithdraw.ts:359–364`). For self-verification this is fine, but if any of these `verifySigmaProof` paths are exposed to untrusted inputs (e.g., a relay verifying client-supplied proofs), they can crash the process. Wrap in `try/catch` and return `false`.

### 4. Private-key `Debug`/leakage analog in TS
`TwistedEd25519PrivateKey.toString()` returns the raw hex (`src/crypto/twistedEd25519.ts:237`), and there is no `toJSON` / `util.inspect.custom` redaction. `console.log(key)` doesn't directly print the bytes (Hex wraps them), but `JSON.stringify(key)` will include the `key` field bytes, and `key.toString()` is fully readable. Add a redacted `toJSON` and `[util.inspect.custom]`. Worth aligning with the main TS SDK Ed25519PrivateKey conventions, exactly as your colleague suggested for the Rust side.

### 5. `with_fee_payer` analog
`withFeePayer` is wired through here (`src/api/confidentialAsset.ts:557`, `src/internal/confidentialAssetTxnBuilder.ts:551`). Functional, but `submitTxn` (`src/api/confidentialAsset.ts:555`) refuses to submit when `withFeePayer` is set unless `transaction.feePayerAddress` is populated, and nothing in the SDK populates it — callers must pre-set it. Either document this clearly or add a sponsorship hook.

---

## Critical / High

### [H1] WASM crypto loaded from public unpkg CDN with no integrity check
Both range proofs and Pollard kangaroo decryption pull `@moveindustries/confidential-asset-wasm-bindings@0.0.3` from `https://unpkg.com/...` at runtime (`src/crypto/twistedElGamal.ts:14–15`, `src/crypto/rangeProof.ts:11–12`). No SRI, no fallback to a bundled artifact. If unpkg is compromised, the npm package is hijacked, or DNS is poisoned, an attacker can serve malicious WASM that:

- generates fake range/sigma proofs (loss of soundness / value theft via crafted balances), or
- exfiltrates decryption keys via `decryptionFn`, since the kangaroo WASM operates on points derived using the sender's private key (`src/crypto/twistedElGamal.ts:212–219`).

**This is the single biggest production-readiness blocker in this SDK.** Fix: bundle the WASM into the package as a base64/asset import or ship it in `dist/`, and resolve from there. If you must fetch remotely, pin to a content hash and verify with SubresourceIntegrity (or hash-check the bytes before `initWasm`). Loading mutable third-party WASM into a wallet flow is unacceptable.

### [H2] ✅ RESOLVED — Transfer/withdraw/rotation/normalization proofs do not include `tokenAddress` in the Fiat–Shamir transcript

**Status: fixed.** `tokenAddress` is now appended to the FS domain context for all four protocols across Movement Move (`aptos-experimental/sources/confidential_asset/confidential_proof.move`), the Rust SDK (`aptos-rust-sdk/crates/confidential-assets`), and the TS SDK. 58/58 Move unit tests, 4/4 cargo `confidential_asset_e2e` tests, 14 Rust lib+integration tests, and 24 TS unit tests pass after the change. The TS-generated `transfer_sigma.fixture.json` parity fixture in the Rust SDK is temporarily `skip: true` and must be regenerated against the updated TS SDK (see `aptos-rust-sdk/crates/confidential-assets/tests/fixtures/ts/README.md`) before flipping back to `skip: false`. **This is a wire-format-breaking change**: any deployed `confidential_asset` instance and any client (TS or Rust) running against it must be upgraded together. Pre-upgrade proofs already on-chain remain valid (verified at submission); mixed old/new deployments will fail with `ESIGMA_PROTOCOL_VERIFY_FAILED`.

---

### [H2 — original finding]

The protocols all accept `tokenAddress` as input (e.g., `src/crypto/confidentialTransfer.ts:58`, `:115`, `:180`) and pass it through, but the FS challenge call lists for transfer (`:426–450`), withdraw (`src/crypto/confidentialWithdraw.ts:231–250`), rotation (`src/crypto/confidentialKeyRotation.ts:202–218`), and normalization (`src/crypto/confidentialNormalization.ts:196–…`) do not include `tokenAddress`. Only `confidentialRegistration` does (`src/crypto/confidentialRegistration.ts:73`).

**TS ↔ Move parity is intentional.** The Movement fork at `aptos-core/aptos-move/framework/aptos-experimental/sources/confidential_asset/confidential_proof.move` defines the FS transcript via `prepend_domain_context` (lines 1284–1296), which prepends only `chain_id` (single byte), `sender`, and `contract_address` — no `token_address`. Registration is the only protocol that appends `token_address` (line 227). The TS prover matches the Move verifier exactly, which is why e2e passes. The TS code carrying an unused `tokenAddress` is a vestigial parameter, not a TS-side bug.

So the live concern is **protocol-level domain separation**, on both sides:

- The proof is not bound by token. Cross-token replay is theoretically possible whenever the same `(sender, contract, ciphertext)` tuple arises for two different tokens. In practice on-chain state is keyed by token so the stored ciphertexts will differ, blocking replay — but soundness should not rest on storage-layout coincidences.
- The proof is not bound by recipient address either (the recipient's encryption *key* is in the transcript, but not their account address).

**Comparison with Aptos Labs upstream (`aptos-labs/aptos-core@main`).** Upstream replaced the hand-rolled per-protocol FS hashing with a generic Sigma framework (`aptos-framework/sources/confidential_asset/sigma_protocols/sigma_protocol_fiat_shamir.move`). Their `DomainSeparator::V1` carries:

- `contract_address` — same as Movement.
- `chain_id` — same.
- `protocol_id` — protocol-specific bytes (e.g. `"Transfer"`).
- `session_id` — **chosen per protocol; for transfer this is `bcs::to_bytes(TransferSession)`** where `TransferSession { sender, recipient, asset_type: Object<Metadata>, num_avail_chunks, num_transfer_chunks, has_effective_auditor, num_volun_auditors }` (`sigma_protocol_transfer.move:181-184`, `:551-552`).

Upstream therefore binds, in addition to what Movement binds, the **recipient address**, the **asset type / token metadata object**, the **chunk counts**, and the **auditor configuration**, as well as the **fully-qualified Move type name** of the protocol marker via `type_info::type_name<P>()` (defense-in-depth against cross-protocol confusion). This is a strict superset of what Movement binds — Movement is a weaker variant of essentially the same construction.

Net: there is no TS-vs-Move correctness problem here, but the Movement protocol is **measurably weaker on domain separation than the Aptos Labs upstream**. Aptos Labs is independent (we can't copy directly), but it's a clear roadmap for what to harden:

1. Bind `tokenAddress` into all four non-registration transcripts.
2. Bind the recipient address into transfer.
3. Consider binding chunk counts and auditor count to prevent any future "shape" confusion attacks.

Severity reclassified to Medium-High protocol-hardening item; not a TS implementation bug.

### [H3] `chainId` truncated to a single byte
`src/crypto/fiatShamir.ts:55`. Comment says this matches Move's `(chain_id::get() as u8)`. If two chains share `chain_id mod 256`, FS challenges collide and proofs replay across them. This is on the Move side too, but should be documented as a protocol-level constraint (and audited at the chain registry level).

---

## Medium

### [M1] `ed25519GenRandom` boundary bug
`src/utils.ts:23–30`. `do { ... } while (rand > n)` admits `rand == n` (≡ 0 mod n) and `rand == 0`. Probability is negligible but a zero scalar leaks the witness in many sigma constructions. Use `do { ... } while (rand >= n || rand === 0n)`.

### [M2] Broken input-range checks in `TwistedElGamal.encryptWithPK` and `encryptWithNoRandomness`
`src/crypto/twistedElGamal.ts:99`, `:102`, `:122`. The condition is `amount < 0n && amount > n` — `&&` instead of `||`. Always false, so the validation is dead code. The math doesn't blow up because of `multiply` semantics, but every "guard" in this file is currently a no-op. Same pattern at `:102` for `random`.

### [M3] Decryption-key derivation message has weak domain separation
`src/crypto/twistedEd25519.ts:170–178`. `fromSignature` derives a confidential-asset *decryption key* from any Ed25519 signature over the literal string `"Sign this message to derive decryption key from your private key"`. There's no contract address, chain id, or token address mixed in. Any wallet/dApp that ever signs that exact message — including one that "echoes back" arbitrary text — leaks the user's confidential-asset decryption key. Recommend: bind to chain id + contract address + token (or use a structured message type with a clear DST).

### [M4] `Buffer` used in browser-targeted module
`src/crypto/confidentialRegistration.ts:81`, `:127`. Will throw `ReferenceError` in the browser unless polyfilled. Replace with `bytesToNumberLE`, which is already imported elsewhere.

### [M5] Verifier paths can throw on adversarial input
(See Rust review #3 carryover.) `verifySigmaProof`, `verifyRangeProof`, and constructors of `TwistedElGamalCiphertext` / `TwistedEd25519PublicKey` throw on malformed bytes. If any production caller validates third-party proofs (audit tooling, indexers, relayers), a single bad input can DoS them. Wrap in `try/catch` and return `false`.

### [M6] No private-key zeroization
`TwistedEd25519PrivateKey` holds bytes in a `Hex` instance; nothing ever overwrites them. JS limits what you can do here, but at minimum:

- Don't leave intermediate scalar `BigInt`s lying around (you can't zero them in JS — bigints are immutable — but at least overwrite the `Uint8Array`s you do control via `bytes.fill(0)` after use).
- Avoid round-tripping the private key through `bytesToNumberLE` repeatedly inside hot paths if you can help it.
- Add a redacted `toString` / `toJSON` / `[Symbol.for("nodejs.util.inspect.custom")]`.

### [M7] Cache lifetime / invalidation issues
`src/utils/memoize.ts`.

- Encryption keys cached for **1 hour** keyed by `${address}-${tokenAddress}-${network}` (`src/internal/viewFunctions.ts:357`). If a counterparty rotates their key during that window, transfers will be encrypted to the *old* recipient pubkey and the recipient cannot decrypt. The cache key is also vulnerable to address-format inconsistency (string vs `AccountAddress`) producing duplicate entries.
- No cache size cap — long-running daemons grow unbounded.
- `setCache` after a transfer (`src/api/confidentialAsset.ts:421–423`) sets the *encryption* key cache to a *decryption* key — almost certainly a bug or a type abuse.

### [M8] `ChunkedAmount` constructor truthiness bug
`src/crypto/chunkedAmount.ts:37`. `args.amount ? BigInt(args.amount) : ChunkedAmount.chunksToAmount(args.amountChunks)` — when `amount` is `0n` or `0`, this falls into the `chunksToAmount` branch. Likely fine because the chunks should sum to 0 too, but it's a footgun if anyone passes amount=0 with non-matching chunks.

---

## Low / hygiene

- `fromSignature` variable name `invertModScalarLE` (`src/crypto/twistedEd25519.ts:174`) — code only does `mod n`, never inverts. Misleading.
- `src/helpers.ts` exports a deprecated FS function `genFiatShamirChallenge` with no DST; nothing seems to use it but it's still public surface. Remove or mark `@internal`.
- `submitTxn` swallows the auth error case poorly: it requires `withFeePayer` *and* a pre-set `feePayerAddress`, but nothing in the SDK helps the caller set one.
- Error messages contain plaintext balances ("Available balance: 1234") in the constructor of `ConfidentialTransfer` (`src/crypto/confidentialTransfer.ts:158`) — fine for client-side, but be aware these can end up in logs.
- `src/internal/viewFunctions.ts:139` has a useless `try { … } catch (error) { throw error; }` (also in `getEncryptionKey:362` and `getBalance`) — drop.
- `getChainIdByteForProofs` silently falls back to `0` if `chain_id::get` fails and `getLedgerInfo` returns non-numeric (`src/internal/viewFunctions.ts:391–395`). A chain-id mismatch produces opaque on-chain failures; better to throw.
- `scripts/`, `tests/`, `app-ideas/` not audited here — recommend a separate look at any CLI utilities that take seed phrases on the command line.
- Duplicate documentation: `WALLET_INTEGRATION.md` vs `WALLET_AND_APPLICATION_APIS.md` — not a security issue, but pick one.

---

## Production-readiness checklist

Before public promotion, block on these:

1. **Bundle WASM locally / add SRI** (H1).
2. **Confirm `tokenAddress` transcript inclusion against Move** (H2). If Move has it, add it; if Move doesn't, decide whether you want to fix protocol-side and move both ends together.
3. **Make verifiers fail-closed**, not throw, on malformed proof bytes (M5).
4. **Redact private-key Debug/JSON output and add zero-overwrite** for byte buffers you control (M6, plus colleague's note).
5. **Strengthen `fromSignature` DST** to bind chain/contract/token (M3).
6. **Fix the always-false range checks** (M2) and **`ed25519GenRandom` boundary** (M1).
7. **Replace `Buffer` calls** with portable utils (M4).
8. **Cache invalidation policy** for encryption keys, plus fix the wrong-type `setCache` in `rotateEncryptionKey` (M7).
9. **Document the `chainId & 0xff` constraint** as a chain-registry invariant (H3 / `src/crypto/fiatShamir.ts:55`).
10. **CI on PRs**, not just on release: typecheck + tests + a TS↔Move e2e on a pinned Move commit, with proofs round-tripped through the on-chain verifier (the same key question raised against the Rust crate).

---

## Bottom line

The cryptographic core looks correct, and the transfer prover correctly uses on-chain ciphertext — so the headline Rust concern is absent here. The biggest production risks are **non-cryptographic plumbing**: remote-loaded WASM, unredacted private keys, missing token transcript binding, plus the boundary/validation bugs listed above. None of them is blocking for a localnet beta, but they should all be fixed before this is something you ask wallets to integrate.
