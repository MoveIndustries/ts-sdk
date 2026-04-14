const path = require("path");
const parent = require("../jest.config.js");

module.exports = {
  ...parent,
  // Parent maps `../../src` → dist to avoid circular deps in the main ts-sdk workspace. For this package,
  // that forces a manual `pnpm build` before e2e/unit tests pick up crypto changes. Resolve the package
  // entry from source so tests always match the working tree.
  moduleNameMapper: {
    ...(parent.moduleNameMapper || {}),
    "^../../src$": path.join(__dirname, "src/index.ts"),
  },
  setupFilesAfterEnv: ["../tests/setupPerFile.cjs"],
  testPathIgnorePatterns: ["./tests/units/api"],
  coveragePathIgnorePatterns: ["./tests/units/api"],
  coverageThreshold: {
    global: {
      branches: 30, // 90,
      functions: 50, // 95,
      lines: 50, // 95,
      statements: 50, // 95,
    },
  },
  globalSetup: "../tests/preTest.cjs",
  globalTeardown: "../tests/postTest.cjs",
};
