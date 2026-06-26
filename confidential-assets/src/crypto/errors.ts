// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

/**
 * Thrown when a confidential `withdraw` / `transfer` would spend more than the
 * sender's **available (actual)** balance. Raised during proof construction —
 * before any transaction is submitted — because the proof builder already
 * decrypts the available balance to range-prove the remainder, so the check is
 * free and fails fast.
 *
 * Named per MIP-001 §"Required SDK Changes": carries a stable
 * `code = "INSUFFICIENT_BALANCE"` so callers can branch programmatically
 * (`if (e instanceof InsufficientBalanceError)` or `e.code === "INSUFFICIENT_BALANCE"`)
 * instead of string-matching a message. Pending balance is intentionally not
 * counted — accepting incoming funds is a separate, explicit
 * `rolloverPendingBalance` step.
 */
export class InsufficientBalanceError extends Error {
  /** Stable machine-readable code (MIP-001: `INSUFFICIENT_BALANCE`). */
  readonly code = "INSUFFICIENT_BALANCE" as const;

  /** Sender's available (actual, spendable) balance at proof-build time. */
  readonly available: bigint;

  /** Amount the caller attempted to spend. */
  readonly requested: bigint;

  constructor(args: { available: bigint; requested: bigint; operation: "withdraw" | "transfer" }) {
    super(
      `INSUFFICIENT_BALANCE: available (actual) balance ${args.available.toString()} is less than the ` +
        `requested ${args.operation} amount ${args.requested.toString()}. Pending balance is not included; ` +
        `roll over pending funds (rolloverPendingBalance) to accept incoming funds before spending them.`,
    );
    this.name = "InsufficientBalanceError";
    this.available = args.available;
    this.requested = args.requested;
  }
}
