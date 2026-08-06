// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import { hasTransactionExpired } from "../../src/internal/transaction";

/**
 * A transaction whose expiry has passed is dropped from the mempool, and its
 * hash then 404s. waitForTransaction retries a 404, so it cannot tell that case
 * apart from a transaction that is simply slow, and reports a poll timeout for
 * both. This is the comparison that separates them.
 *
 * The two fields are in different units: expiration_timestamp_secs is seconds,
 * ledger_timestamp is microseconds.
 */
describe("hasTransactionExpired", () => {
  const expirySecs = "1786000000";
  const asMicros = (secs: number) => String(secs * 1_000_000);

  it("reports expired when chain time has passed the expiry", () => {
    expect(
      hasTransactionExpired({
        expirationTimestampSecs: expirySecs,
        ledgerTimestampMicros: asMicros(1786000001),
      }),
    ).toBe(true);
  });

  it("reports not expired when chain time is before the expiry", () => {
    expect(
      hasTransactionExpired({
        expirationTimestampSecs: expirySecs,
        ledgerTimestampMicros: asMicros(1785999999),
      }),
    ).toBe(false);
  });

  it("treats the exact expiry second as not yet expired", () => {
    expect(
      hasTransactionExpired({
        expirationTimestampSecs: expirySecs,
        ledgerTimestampMicros: asMicros(1786000000),
      }),
    ).toBe(false);
  });

  it("converts units rather than comparing the numbers directly", () => {
    // Compared raw, a microsecond ledger timestamp dwarfs any second-based
    // expiry and every transaction looks expired.
    expect(
      hasTransactionExpired({
        expirationTimestampSecs: expirySecs,
        ledgerTimestampMicros: asMicros(1000),
      }),
    ).toBe(false);
  });

  it("accepts numbers and bigints as well as the strings the API returns", () => {
    expect(hasTransactionExpired({ expirationTimestampSecs: 100, ledgerTimestampMicros: 200_000_000 })).toBe(true);
    expect(hasTransactionExpired({ expirationTimestampSecs: 100n, ledgerTimestampMicros: 50_000_000n })).toBe(false);
  });

  it("reports not expired on unparseable input, so a bad value cannot invent an expiry", () => {
    expect(hasTransactionExpired({ expirationTimestampSecs: "not-a-number", ledgerTimestampMicros: "1" })).toBe(false);
    expect(hasTransactionExpired({ expirationTimestampSecs: "1", ledgerTimestampMicros: "not-a-number" })).toBe(false);
  });
});
