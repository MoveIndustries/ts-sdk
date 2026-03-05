const path = require("path");
const envPath = path.resolve(__dirname, ".env.development");

require("dotenv").config({
  path: [envPath],
});

/** @type {import("ts-jest/dist/types").InitialOptionsTsJest} */
module.exports = {
  preset: "ts-jest",
  moduleNameMapper: {
    "^(\\.{1,2}/.*)\\.js$": "$1",
    // Use built output to avoid circular dependency issues with ts-jest
    "^../../src$": "<rootDir>/dist/common/index.js",
    "^../../src/(.*)$": "<rootDir>/src/$1",
    "^../../../src$": "<rootDir>/dist/common/index.js",
    "^../../../src/(.*)$": "<rootDir>/src/$1",
  },
  testEnvironment: "node",
  coveragePathIgnorePatterns: [
    "./src/internal/queries/",
    "./src/types/generated",
    "./tests/e2e/ans/publishANSContracts.ts",
    "./confidential-assets/*",
  ],
  testPathIgnorePatterns: [
    "dist/*",
    "examples/*",
    "confidential-assets/*",
    // Skip tests for features not supported on Movement localnet
    "tests/e2e/api/keyless.test.ts",
    "tests/e2e/api/abstraction.test.ts",
  ],
  collectCoverage: true,
  setupFiles: ["dotenv/config"],
  coverageThreshold: {
    global: {
      branches: 40, // 90,
      functions: 50, // 95,
      lines: 50, // 95,
      statements: 50, // 95,
    },
  },
  // To help avoid exhausting all the available fds and stabilize localnet in CI.
  maxWorkers: 1,
  // Start/stop localnet per test file instead of once for the whole run
  setupFilesAfterEnv: ["./tests/setupPerFile.cjs"],
};
