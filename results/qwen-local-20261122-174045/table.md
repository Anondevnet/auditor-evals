# Eval results

Run `qwen-local-20261122-174045` — Slither + qwen-local — 2026-11-22T21:47:56-05:00 (America/Detroit)

| System | Precision | Recall | F1 | FP rate (clean) | $/contract | p50 s | p95 s |
|---|---|---|---|---|---|---|---|
| Slither + qwen-local | 0.233 | 0.496 | 0.317 | 0.680 | $0 | 58.01 | 106.05 |

Line-level micro/macro (matching rule: same DASP class and ±3 lines or same function):

- micro P/R/F1 = 0.233 / 0.496 / 0.317
- macro P/R/F1 = 0.256 / 0.450 / 0.270

Contract-level micro/macro:

- micro P/R/F1 = 0.252 / 0.658 / 0.365
- macro P/R/F1 = 0.231 / 0.514 / 0.296

Findings/contract: 13.91. Compile failures: 12 / 243. Slither tool failures: 3 / 243 (timeouts: 0). Failures are tracked in raw.jsonl and scored as zero findings, not dropped.

## Per-class F1 (line-level)

| Class | Precision | Recall | F1 | TP | FP | FN |
|---|---|---|---|---|---|---|
| reentrancy | 0.292 | 0.990 | 0.451 | 205 | 498 | 2 |
| access_control | 0.176 | 0.941 | 0.297 | 175 | 817 | 11 |
| arithmetic | 0.136 | 0.034 | 0.054 | 8 | 51 | 227 |
| unchecked_low_level_calls | 0.799 | 0.417 | 0.548 | 191 | 48 | 267 |
| denial_of_service | 0.040 | 0.143 | 0.062 | 1 | 24 | 6 |
| bad_randomness | 0.063 | 0.129 | 0.085 | 4 | 59 | 27 |
| front_running | — | 0.000 | — | 0 | 0 | 224 |
| time_manipulation | 0.537 | 0.845 | 0.657 | 202 | 174 | 37 |
| short_addresses | — | 0.000 | — | 0 | 0 | 1 |
| other | 0.004 | 1.000 | 0.007 | 3 | 814 | 0 |

## Per-class F1 (contract-level)

| Class | Precision | Recall | F1 | TP | FP | FN |
|---|---|---|---|---|---|---|
| reentrancy | 0.353 | 0.947 | 0.514 | 36 | 66 | 2 |
| access_control | 0.145 | 0.680 | 0.239 | 17 | 100 | 8 |
| arithmetic | 0.071 | 0.043 | 0.054 | 1 | 13 | 22 |
| unchecked_low_level_calls | 0.791 | 0.803 | 0.797 | 53 | 14 | 13 |
| denial_of_service | 0.045 | 0.167 | 0.071 | 1 | 21 | 5 |
| bad_randomness | 0.200 | 0.500 | 0.286 | 4 | 16 | 4 |
| front_running | — | 0.000 | — | 0 | 0 | 11 |
| time_manipulation | 0.211 | 1.000 | 0.348 | 12 | 45 | 0 |
| short_addresses | — | 0.000 | — | 0 | 0 | 1 |
| other | 0.029 | 1.000 | 0.056 | 3 | 101 | 0 |

## Failures

These files compiled with the selected solc (confirmed separately) but Slither 0.11.2 crashed. They are scored as zero findings, not dropped:

- `curated/reentrancy/reentrancy_bonus.sol`
- `curated/reentrancy/reentrancy_cross_function.sol`
- `curated/unchecked_low_level_calls/0x89c1b3807d4c67df034fffb62f3509561218d30b.sol`

Dataset: SmartBugs Curated @`230e64912347`, SolidiFI @`4b0573e1b3f7`, Wild @`91ec17573d3e`, n=243 (curated=143, solidifi=50, wild=50). Seed=20261114.
