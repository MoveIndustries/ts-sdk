import {
  AccountAddressInput,
  AnyNumber,
  InputGenerateTransactionOptions,
  Movement,
  MovementConfig,
  SimpleTransaction,
} from "@moveindustries/ts-sdk";
import { MODULE_NAME, TREE_DEPTH } from "./consts";

const DEFAULT_MODULE = "0x000000000000000000000000000000000000000000000000000000000000cafe";

/**
 * Build shielded pool transactions against a published `@shielded_assets` package.
 *
 * Viewer keys: use `encryptIncomingViewPayload` / `encryptOutgoingViewPayload` so auditors
 * can decrypt event blobs with IVK/OVK (see `viewKey.ts`).
 */
export class ShieldedPoolClient {
  readonly client: Movement;

  readonly moduleAddress: string;

  constructor(config: MovementConfig, moduleAddress: string = DEFAULT_MODULE) {
    this.client = new Movement(config);
    this.moduleAddress = moduleAddress;
  }

  private fn(name: "shield" | "unshield" | "shielded_transfer"): `${string}::${string}::${string}` {
    return `${this.moduleAddress}::${MODULE_NAME}::${name}`;
  }

  /**
   * Shield: move FA into pool and append a note commitment.
   * `incomingViewCiphertext` may be empty; otherwise use `encryptIncomingViewPayload(ivk, plaintext)`.
   */
  async buildShield(args: {
    sender: AccountAddressInput;
    metadata: AccountAddressInput;
    amount: AnyNumber;
    blinding: Uint8Array;
    incomingViewCiphertext?: Uint8Array;
    options?: InputGenerateTransactionOptions;
  }): Promise<SimpleTransaction> {
    const ct = args.incomingViewCiphertext ?? new Uint8Array(0);
    return this.client.transaction.build.simple({
      sender: args.sender,
      data: {
        function: this.fn("shield"),
        functionArguments: [args.metadata, args.amount, args.blinding, ct],
      },
      options: args.options,
    });
  }

  /**
   * Shielded → shielded: spend an input note and append a new note with the same amount (pool FA unchanged).
   * `merkleSiblings` must have length `TREE_DEPTH` (20); use `MerkleTreeSimulator.getPath(leafIndex)`.
   */
  async buildShieldedTransfer(args: {
    sender: AccountAddressInput;
    metadata: AccountAddressInput;
    amount: AnyNumber;
    blindingIn: Uint8Array;
    leafIndex: AnyNumber;
    merkleSiblings: Uint8Array[];
    historicRoot: Uint8Array;
    blindingOut: Uint8Array;
    outgoingViewCiphertext?: Uint8Array;
    options?: InputGenerateTransactionOptions;
  }): Promise<SimpleTransaction> {
    if (args.merkleSiblings.length !== TREE_DEPTH) {
      throw new Error(`merkleSiblings must have length ${TREE_DEPTH}`);
    }
    const ov = args.outgoingViewCiphertext ?? new Uint8Array(0);
    return this.client.transaction.build.simple({
      sender: args.sender,
      data: {
        function: this.fn("shielded_transfer"),
        functionArguments: [
          args.metadata,
          args.amount,
          args.blindingIn,
          args.leafIndex,
          args.merkleSiblings,
          args.historicRoot,
          args.blindingOut,
          ov,
        ],
      },
      options: args.options,
    });
  }

  /**
   * Unshield: prove Merkle inclusion against a **historic** root from `ShieldedInsertEvent` / `roots_ring`.
   * `merkleSiblings` must have length `TREE_DEPTH` (20); use `MerkleTreeSimulator.getPath(leafIndex)`.
   */
  async buildUnshield(args: {
    sender: AccountAddressInput;
    metadata: AccountAddressInput;
    amount: AnyNumber;
    blinding: Uint8Array;
    leafIndex: AnyNumber;
    merkleSiblings: Uint8Array[];
    historicRoot: Uint8Array;
    recipient: AccountAddressInput;
    outgoingViewCiphertext?: Uint8Array;
    options?: InputGenerateTransactionOptions;
  }): Promise<SimpleTransaction> {
    if (args.merkleSiblings.length !== TREE_DEPTH) {
      throw new Error(`merkleSiblings must have length ${TREE_DEPTH}`);
    }
    const ov = args.outgoingViewCiphertext ?? new Uint8Array(0);
    return this.client.transaction.build.simple({
      sender: args.sender,
      data: {
        function: this.fn("unshield"),
        functionArguments: [
          args.metadata,
          args.amount,
          args.blinding,
          args.leafIndex,
          args.merkleSiblings,
          args.historicRoot,
          args.recipient,
          ov,
        ],
      },
      options: args.options,
    });
  }
}

export { TREE_DEPTH };
