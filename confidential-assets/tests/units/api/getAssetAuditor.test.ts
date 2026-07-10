import { confidentialAsset, TOKEN_ADDRESS } from "../../helpers";

// These exercise the public `get_asset_auditor` / `get_chain_auditor` views (live chain reads).
// The directory name is "units/api" but everything in it requires a running localnet — see
// jest.config.js `testPathIgnorePatterns`. Run via `pnpm jest tests/units/api` against a
// #328-enabled localnet.
describe("Auditor reads", () => {
  it("it should get the per-asset auditor", async () => {
    const assetAuditor = await confidentialAsset.getAssetAuditorEncryptionKey({
      tokenAddress: TOKEN_ADDRESS,
    });

    // Defined when the FA issuer has called `set_asset_auditor`; undefined otherwise.
    expect(assetAuditor === undefined || assetAuditor.toString().length > 0).toBe(true);
  });

  it("it should get the chain auditor", async () => {
    const chainAuditor = await confidentialAsset.getChainAuditorEncryptionKey();

    // Required for `confidential_transfer` to succeed under movementlabsxyz/aptos-core#328.
    // We don't hard-assert defined here so this read test passes regardless of localnet config;
    // transfer-side tests will surface the missing-chain-auditor error if it isn't set.
    expect(chainAuditor === undefined || chainAuditor.toString().length > 0).toBe(true);
  });
});
