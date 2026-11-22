# Slither detector → DASP mapping

Used by the eval harness to compare auditor/Slither findings against
SmartBugs / SolidiFI gold labels (DASP taxonomy).

Rules:

- Mapping is **slug-first** (`config/slither_dasp_map.yaml`), then a
  playbook-class fallback, then `other`.
- `timestamp` is `time_manipulation`; `weak-prng` is `bad_randomness`.
- The Slither baseline run uses Slither High/Medium/Low detectors only
  (the same set the auditor surfaces), not custom honeypot/ERC-4626 analyzers.
- Unmapped or non-DASP detectors (`other`) are still scored: they are
  false positives unless the gold label is also `other` (3 Curated rows).
- Slither does not reliably detect `front_running` or `short_addresses`;
  expect low recall on those classes.

## `access_control`

- `arbitrary-send-erc20`
- `arbitrary-send-erc20-permit`
- `arbitrary-send-eth`
- `backdoor`
- `controlled-delegatecall`
- `delegatecall-loop`
- `external-log-gate`
- `hidden-owner-drain`
- `incorrect-modifier`
- `missing-msg-sender-check`
- `missing-zero-check`
- `msg-value-loop`
- `payout-lure`
- `privileged-auth-protected`
- `privileged-auth-unprotected`
- `privileged-auth-weak`
- `protected-vars`
- `quiz-honeypot`
- `rtlo`
- `suicidal`
- `transfer-blocking-token`
- `tx-origin`
- `unlimited-owner-mint`
- `unprotected-upgrade`

## `arithmetic`

- `divide-before-multiply`
- `erc4626-inflation`
- `incorrect-exp`
- `incorrect-shift`
- `pool-accounting`

## `bad_randomness`

- `gelato-unprotected-randomness`
- `weak-prng`

## `denial_of_service`

- `calls-loop`
- `locked-ether`
- `return-bomb`

## `other`

- `abiencoderv2-array`
- `array-by-reference`
- `boolean-cst`
- `bridge-message-validation`
- `chainlink-feed-registry`
- `chronicle-unchecked-price`
- `compound-empty-market`
- `constant-function-asm`
- `constant-function-state`
- `controlled-array-length`
- `domain-separator-collision`
- `encode-packed-collision`
- `enum-conversion`
- `erc20-interface`
- `erc721-interface`
- `events-access`
- `events-maths`
- `incorrect-equality`
- `incorrect-return`
- `incorrect-unary`
- `mapping-deletion`
- `msg-value-in-nonpayable`
- `multiple-constructors`
- `name-reused`
- `optimism-deprecation`
- `out-of-order-retryable`
- `public-mappings-nested`
- `pyth-deprecated-functions`
- `pyth-unchecked-confidence`
- `pyth-unchecked-publishtime`
- `return-leave`
- `reused-constructor`
- `reward-acc-per-share`
- `shadowing-abstract`
- `shadowing-builtin`
- `shadowing-local`
- `shadowing-state`
- `stale-oracle-risk`
- `storage-array`
- `tautological-compare`
- `tautology`
- `uninitialized-fptr-cst`
- `uninitialized-local`
- `uninitialized-state`
- `uninitialized-storage`
- `variable-scope`
- `void-cst`
- `write-after-write`

## `reentrancy`

- `reentrancy-balance`
- `reentrancy-benign`
- `reentrancy-eth`
- `reentrancy-events`
- `reentrancy-no-eth`
- `reentrancy-unlimited-gas`

## `time_manipulation`

- `timestamp`

## `unchecked_low_level_calls`

- `unchecked-lowlevel`
- `unchecked-send`
- `unchecked-transfer`
- `unused-return`

