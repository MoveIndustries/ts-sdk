# @moveindustries/shielded-assets

This directory contains **both**:

- **`npm` package** `@moveindustries/shielded-assets` — TypeScript helpers and transaction builders (`src/`, published to the registry).
- **Move package** (`move/`) — on-chain **shielded pool** modules to compile and publish on **Movement** (testnet / mainnet).

Together they implement **shielded fungible-asset** flows using [`fungible_asset`](https://github.com/movementlabsxyz/aptos-core): **shield** (deposit into pool custody), **shielded transfer** (move value **inside** the pool without an account-to-account FA transfer), and **unshield** (withdraw to a normal account).

### Shielded Assets end goal

The **goal** is **Zcash-style shielded activity on Movement**: fungible value can live in a **shared pool** instead of hopping wallet-to-wallet on the ledger for every payment. For **shielded** steps, observers should **not** be able to read **amounts** or reconstruct **who paid whom** from public data the way they can on a normal transfer. **Shield** and **unshield** are the **edges** where tokens enter and leave the pool—there, **which accounts** move FA is **visible**, like any other transfer. **Inside the pool**, the **target** is: **amounts hidden**, **no on-chain recipient address** for the shielded payment itself, and **auditability** (issuers, compliance, recovery) via **optional viewing-key ciphertext on events**—the chain never needs to decrypt those blobs for consensus.

**Compared to [`confidential-assets`](../confidential-assets/)** (same chain, different privacy shape):

- **Confidential-assets:** **Amounts** are hidden on each transfer. **Sender and recipient** addresses are **visible** on every transfer (normal account-to-account FA move).
- **Shielded-assets (target):** **Amounts** should be hidden on **shielded** hops once zero-knowledge verification replaces witness data in arguments. **Who is visible** depends on the step: **inside the pool**, there is **no on-chain recipient address** for the shielded payment; the **account that signs** the transaction (e.g. gas payer) may still be visible. **At shield and unshield**, **depositor** and **withdrawal recipient** are **visible** wherever FA moves in or out of the pool.

### Where the implementation is today

The **Move modules and TS client** implement the **real** pool, Merkle tree, nullifiers, FA custody, and **shielded transfer** without moving FA between user accounts for that hop. **Until ZK spends land**, **amounts and sensitive proof material still appear in transaction arguments**—so this is **not** yet the privacy level described above; it is the **scaffolding** that work is building on. See **Privacy: today vs target** and **Plan: Zcash-like shielded transactions + auditability**.

On-chain, pool value is **not** stored as per-user FA balances. It is tracked as **commitments** (tree leaves) in a **Merkle tree** (depth **20**), with **nullifiers** to prevent double-spends and a **history of past roots** (up to **128** per token) so inclusion can be checked against an older root. Optional **event ciphertext** supports viewing keys for audit and wallet sync; validators do **not** decrypt it.

## Protocol (what happens on-chain)

1. **Shield** — User withdraws FA from their primary store and deposits into the pool’s primary store. A **commitment** `cm = keccak256("SA_NOTE_v1" || bcs(amount) || blinding)` is appended to the **incremental Merkle tree** for that token. A **new root** is stored and appended to **root history** (up to 128 roots). Optional **`incoming_view_ciphertext`** is accepted and emitted in **`ShieldedInsertEvent`** (the chain does **not** decrypt or verify it against `cm`).

2. **Shielded → shielded (`shielded_transfer`)** — **Spend** one existing commitment (same Merkle/nullifier checks as unshield, against a **`historic_root`**) and append **one new commitment** with the same **`amount`** and a fresh **`blinding_out`**. **Pool FA balance does not change** (no transparent payout). The payee learns **`blinding_out`** off-chain; optional **`outgoing_view_ciphertext`** is emitted on **`ShieldedTransferEvent`**.

3. **Unshield** — Submitter provides **amount**, **blinding**, **leaf index**, **Merkle siblings** (exactly **20** × 32-byte hashes), a **`historic_root`** that must appear in **`roots_ring`**, and **recipient**. The contract checks the nullifier is fresh, verifies the Merkle proof against that historic root, transfers FA to the recipient’s primary store, and emits **`UnshieldEvent`**. Optional **`outgoing_view_ciphertext`** is emitted but not verified on-chain.

4. **Per-token isolation** — State is keyed by **FA metadata object address**: each fungible asset has its own `TokenPool` (tree, nullifiers, roots).

## Moving parts

| Piece | Role |
|--------|------|
| **`ShieldedPoolRegistry`** | Holds `ExtendRef` for the object that custodies FA; `pools: Table<address, TokenPool>` keyed by metadata address. |
| **`TokenPool`** | `filled_subtrees`, `next_leaf_index`, `current_root`, `roots_ring` + `roots_write_seq`, `nullifiers` table. |
| **`merkle.move`** | Keccak pairing, `incremental_append`, `verify_proof` (fixed depth), `precompute_zero_levels`. |
| **Events** | `ShieldedInsertEvent` / `ShieldedTransferEvent` / `UnshieldEvent` — indexers and auditors consume these; decrypt ciphertext off-chain with IVK/OVK. |
| **TS SDK** | `noteCommitment`, `deriveNullifier`, `MerkleTreeSimulator`, `viewKey` (XChaCha), `ShieldedPoolClient` (`buildShield`, `buildShieldedTransfer`, `buildUnshield`). |

## On-chain `#[view]` helpers

| Function | Purpose |
|----------|---------|
| `tree_depth()` | Always `20` (must match proof sibling count). |
| `leaf_count(metadata)` | Number of leaves (`next_leaf_index`) for that FA. |
| `current_merkle_root(metadata)` | Latest root after the last shield. |
| `is_known_root(metadata, root)` | Whether `root` is in `roots_ring` (use before trusting an unshield). |
| `root_history_len(metadata)` | How many roots are stored (≤ 128 once full). |
| `pool_balance(metadata)` | FA balance held by the pool (via primary store). |

## Limits (match Move constants)

- **Tree capacity:** `2^20` leaves per FA metadata.
- **Viewer ciphertext:** incoming max **512** bytes, outgoing max **256** bytes (Move aborts if larger).

## Performance (on-chain)

- **Shield:** `O(TREE_DEPTH)` hashes per deposit (20), not `O(n)` over all leaves.
- **`current_merkle_root`:** reads `TokenPool.current_root` (single field).

## Viewer keys (auditability)

The **ledger never decrypts** viewer blobs and does **not** prove they match a note commitment. Anyone with the right **IVK/OVK** can decrypt **off-chain** from events (or trial-decrypt incoming ciphertexts like Zcash-style incoming viewing).

- **Incoming (IVK):**  
  `encryptIncomingViewPayload(ivk32, encodeIncomingPlaintext(amount, blinding32, metadataAddress32))` → `shield` arg `incoming_view_ciphertext`.  
  Plaintext layout: **8-byte BCS `u64` LE** + **32** blinding + **32** metadata address (raw).

- **Outgoing (OVK):**  
  `encryptOutgoingViewPayload(ovk32, encodeOutgoingPlaintext(recipientAddress32, memoUtf8?))` → `unshield` arg `outgoing_view_ciphertext`.  
  `recipientAddress32` is the **32-byte raw account address** (same encoding as Move `address`).

Ciphertext wire format: **XChaCha20-Poly1305**, `nonce(24) || ciphertext+tag`. Keys: domain-separated **SHA-256** in `viewKey.ts`.

## Build

```bash
pnpm install
pnpm build
pnpm test
```

## Move

```bash
cd move
aptos move compile --dev
aptos move test --dev
```

## Usage (TypeScript)

```typescript
import {
  ShieldedPoolClient,
  noteCommitment,
  MerkleTreeSimulator,
  encryptIncomingViewPayload,
  encodeIncomingPlaintext,
  randomViewingKey32,
} from "@moveindustries/shielded-assets";

const ivk = randomViewingKey32();
const blinding = randomViewingKey32();
const amount = 1_000_000n;
const cm = noteCommitment(amount, blinding);
const incomingCt = encryptIncomingViewPayload(
  ivk,
  encodeIncomingPlaintext(amount, blinding, metadataAddress32),
);

const client = new ShieldedPoolClient(config, "0x…published…");
await client.buildShield({
  sender,
  metadata: tokenMetadataAddress,
  amount,
  blinding,
  incomingViewCiphertext: incomingCt,
});
```

**Shielded transfer:** Same **`historic_root`** / **`merkleSiblings`** pattern as unshield for the **input** note; then append a new commitment with `buildShieldedTransfer({ … blindingIn, blindingOut, … })` (pool balance unchanged).

**Unshield:** Use the **`merkle_root` from the relevant `ShieldedInsertEvent`** (or any root still in `roots_ring`) as **`historic_root`**. Preflight with **`is_known_root`**. Build **`merkleSiblings`** with **`MerkleTreeSimulator`** by replaying **all** note commitments for that FA **in chain order** (length **20**).

## Privacy notes

- **`shield`, `shielded_transfer`, and `unshield`** in this package still use a **witness in transaction arguments** (`amount`, blindings, Merkle siblings where applicable). Indexers see those fields. Viewer ciphertexts are for **audit / wallet sync**, not on-chain zero-knowledge. Replacing witness revelation with **ZK proofs for note spends** (transfers and unshield, and optionally shield) is the path to global observer privacy for shielded activity.

## Plan: Zcash-like shielded transactions + auditability

**Goal:** Inside the pool, observers should not learn **amounts** or **who paid whom** from calldata; **nullifiers** and **commitments** remain public as in Zcash-style models. **Auditability** (issuers, compliance, wallet recovery) is handled by **viewing keys** and **optional ciphertext on events** (see **Viewer keys (auditability)** earlier in this README)—without requiring the chain to decrypt or trust those blobs for consensus.

This section lists what is still required to close the gap between **today’s witness-based protocol**—**shield**, **`shielded_transfer`**, and **unshield`** are already implemented on-chain—and **that goal** (hiding amounts and spend linkage from calldata via ZK).

### What Movement provides

**Movement** runs **Move** with the standard framework modules (`aptos_std`, `aptos_framework`). This package pins [`movementlabsxyz/aptos-core`](https://github.com/movementlabsxyz/aptos-core) in [`Move.toml`](./move/Move.toml).

Relevant primitives for a future ZK spend path include:

- **Pairing-friendly curve arithmetic** via [`aptos_std::crypto_algebra`](https://github.com/movementlabsxyz/aptos-core/blob/main/aptos-move/framework/aptos-stdlib/sources/cryptography/crypto_algebra.move) and curve markers such as **BN254** ([`aptos_std::bn254_algebra`](https://github.com/movementlabsxyz/aptos-core/blob/main/aptos-move/framework/aptos-stdlib/sources/cryptography/bn254_algebra.move))—the usual setting for **circom / snarkjs** Groth16 artifacts on **bn128**.
- A reference **Groth16 verifier pattern** in [**`groth16_example`**](https://github.com/movementlabsxyz/aptos-core/blob/main/aptos-move/move-examples/groth16_example/sources/groth16.move) (generic pairing check).
- **Hashing** including **Keccak256** ([`aptos_std::aptos_hash`](https://github.com/movementlabsxyz/aptos-core/blob/main/aptos-move/framework/aptos-stdlib/sources/hash.move)) for Merkle interoperability with this repo’s current tree.

The [`aptos-stdlib/sources/cryptography`](https://github.com/movementlabsxyz/aptos-core/tree/main/aptos-move/framework/aptos-stdlib/sources/cryptography) tree in that fork lists further modules (signatures, Ristretto255, etc.) for other protocols.

**Network requirement:** On-chain use of `crypto_algebra` requires the **cryptography algebra natives** feature to be enabled on the **Movement** deployment. Confirm with the target network’s documentation or operators before relying on pairing verification in production.

### Remaining work (zero-knowledge note spends)

In Zcash-style wording, a **spend** is any transaction that **consumes** a shielded note. That includes **`shielded_transfer`** (outputs stay in the pool) and **`unshield`** (output goes to transparent FA)—not only “transfers” between users. Zero-knowledge proofs are what remove witness data from calldata for those flows (and similarly for **`shield`** if deposits are also proved in ZK).

| Area | Target outcome |
|------|----------------|
| **Spend circuit** | A circuit (e.g. **circom**) proving, in zero knowledge, validity of such a spend: knowledge of note opening(s), **Merkle inclusion** against an allowed historic root, correct **nullifier(s)**, **value conservation**, and well-formed **output note commitment(s)**. Public inputs are typically **roots, nullifiers, output commitments**—not raw amounts or blinding factors. |
| **Hash / tree alignment** | The **on-chain** Merkle leaf hash and commitment scheme must match what the circuit proves. **Keccak** Merkle paths inside a SNARK are constraint-heavy; many designs use **Poseidon** (or similar) in-circuit and either implement the same hash on-chain or rely on proofs-only checks—both imply a **protocol decision** and possibly a **v2 tree** or migration. |
| **Move verifier + VK** | Integrate a Groth16 verifier (pattern from `groth16_example`): **deserialize** proof + **verification key**, run **`verify_proof`** (or the prepared variant), then apply **state transitions** (insert nullifiers, append output commitments, FA unshield only as the public inputs allow). The VK is **per-circuit**, not a single global Move native bundled with the framework; each deployment supplies a **circuit-specific** VK (constants or on-chain config). |
| **Trusted setup / SRS** | Groth16 needs a **circuit-specific** proving key. Production expects an appropriate **ceremony** or reuse of a trusted SRS—not ad-hoc local keys. |
| **Client prover** | A wallet or service performs witness generation, proof creation (e.g. **snarkjs**, **wasm** prover), and encoding public inputs as **`Fr`** for BN254. |
| **Tooling** | Community helper [**snarkjs-to-aptos**](https://github.com/zjma/snarkjs-to-aptos) converts **snarkjs** verification keys, proofs, and public inputs into **`aptos_std`-compatible** Move formats (name reflects the module lineage). The `circuits/` folder can hold **circom** sources and build scripts for CI and reproducible keys. |

### Auditability (Zcash-style viewing, policy-friendly)

ZK shielding hides details from **the world**; **auditability** is a separate axis:

- **Incoming viewing (IVK):** Recipients (or holders of IVK) can decrypt **incoming** note metadata from **`ShieldedInsertEvent`** ciphertexts (off-chain).
- **Outgoing viewing (OVK):** Holders of OVK can decrypt **spend** metadata from **`UnshieldEvent` / `ShieldedTransferEvent`** ciphertexts (off-chain).
- The **ledger never verifies** that ciphertext matches commitments; auditors and wallets use **keys + events**. Product policy (who must hold which keys, retention, reporting) sits **above** the protocol.

When **ZK spends** land, the same event + IVK/OVK model still applies: encrypt **what auditors need** (within size limits), keep **proofs** for consensus, and document **who can decrypt what** per deployment.

### Staged delivery (suggested)

1. **Current (witness-based):** **Shield**, **`shielded_transfer`**, and **unshield** with Merkle proofs, nullifiers, FA custody, and optional viewer ciphertext on events. Transaction arguments still expose witnesses—good for **correctness** and **wallet sync**, not for **strong privacy** against observers.
2. **ZK spend (testnet):** One **Groth16** spend path + minimal circuit + Move verifier + dev SRS; optional parallel **test-only** tree depth or separate module address.
3. **Hardening:** Audits, gas limits, DoS bounds on proof size, upgrade story, and **production SRS**.
4. **Product fit:** Indexer requirements, issuer policy, and clear **privacy / audit** labeling per release.

## Production / roadmap considerations

The design supports **staged releases** (testnet → hardened mainnet). Beyond the **Plan: Zcash-like shielded transactions + auditability** section above:

- **Security:** third-party review of Move + TS, fuzzing, and explicit invariants (no double-spend, no silent inflation, nullifier uniqueness, proof verification soundness).
- **Operations:** published module address, indexers subscribed to pool events, monitoring, upgrade policy.
- **Scope honesty:** each release should state what is guaranteed (witness-based vs ZK spends, what viewing keys can and cannot prove on-chain).

The **Merkle + nullifier + FA + event ciphertext** layout is intended to **increment** toward stricter privacy and policy without throwing away the whole design.
