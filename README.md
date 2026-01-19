# TypeScript SDK for Movement and Aptos

> [!NOTE]
> This Movement TS SDK repo is forked from github.com/aptos-labs prior to the date on which the Aptos Foundation implemented its Innovation-Enabling Source Code License in substitution for the prior Apache License, Version 2.0  governing this repository. 
>
> Move Industries continues to maintain, develop, modify, and distribute this repository solely under the Apache License, Version 2.0, as existed at the time of the fork and without application of the license instituted by the Aptos Foundation.

## Test results:

All unit tests pass.

All e2e pasts when run one suite at a time with `--runInBand` pass except keyless, abstraction and ANS tests:

  ---
  FAILING TESTS

  Suite: tests/e2e/api/keyless.test.ts (16 failures)

  Keyless Account:
  - derives the keyless account and submits a transaction
  - creates the keyless account via the static constructor and submits a transaction
  - derives the keyless account with email uidKey and submits a transaction
  - derives the keyless account with custom pepper and submits a transaction
  - deriving keyless account with async proof fetch executes callback
  - derives the keyless account with async proof fetch and submits a transaction
  - deriving keyless account using all parameters
  - keyless account verifies signature for arbitrary message correctly

  Federated Keyless Account:
  - derives the keyless account and submits a transaction
  - creates the keyless account via the static constructor and submits a transaction
  - derives the keyless account with email uidKey and submits a transaction
  - derives the keyless account with custom pepper and submits a transaction
  - deriving keyless account with async proof fetch executes callback
  - derives the keyless account with async proof fetch and submits a transaction
  - deriving keyless account using all parameters
  - keyless account verifies signature for arbitrary message correctly

  Suite: tests/e2e/api/paginateQuery.test.ts (1 failure)

  - it should paginate correctly on fullnode queries

  Suite: tests/e2e/api/abstraction.test.ts (4 failures)

  - should be able to send a transaction using acount abstraction
  - should be able to send a transaction using custom signer
  - should be able to send a transaction with permissioned signer
  - should be able to send a transaction with derivable account abstraction

  Suite: tests/e2e/client/customClient.test.ts (1 failure)

  - it uses custom client for transaction submission

  Suite: tests/e2e/client/aptosRequest.test.ts (2 failures)

  - call should include all expected headers
  - when server returns transaction submission error

  ---
  SKIPPED TESTS

  Suite: tests/e2e/api/verifySignatureAsync.test.ts (1 skipped)

  - signs a message with a 2 of 4 multikey scheme with keyless account and verifies successfully

  Suite: tests/e2e/ans/ans.test.ts (23 skipped - entire suite)