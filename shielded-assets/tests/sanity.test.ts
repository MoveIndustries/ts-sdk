import { SHIELDED_ASSETS_SDK_VERSION } from "../src/index";

describe("shielded-assets", () => {
  it("exposes version", () => {
    expect(SHIELDED_ASSETS_SDK_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
