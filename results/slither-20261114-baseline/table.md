# Eval results

Run `slither-20261114-baseline` — Slither only — 2026-11-14T12:25:13-05:00 (America/Detroit)

| System | Precision | Recall | F1 | FP rate (clean) | $/contract | p50 s | p95 s |
|---|---|---|---|---|---|---|---|
| Slither only | 0.228 | 0.493 | 0.312 | 0.780 | $0 | 0.26 | 1.09 |

Line-level micro/macro (matching rule: same DASP class and ±3 lines or same function):

- micro P/R/F1 = 0.228 / 0.493 / 0.312
- macro P/R/F1 = 0.226 / 0.444 / 0.253

Contract-level micro/macro:

- micro P/R/F1 = 0.233 / 0.684 / 0.348
- macro P/R/F1 = 0.206 / 0.513 / 0.275

Findings/contract: 14.16. Compile failures: 0 / 243. Slither tool failures: 3 / 243 (timeouts: 0). Failures are tracked in raw.jsonl and scored as zero findings, not dropped.

## Per-class F1 (line-level)

| Class | Precision | Recall | F1 | TP | FP | FN |
|---|---|---|---|---|---|---|
| reentrancy | 0.252 | 0.990 | 0.402 | 205 | 607 | 2 |
| access_control | 0.177 | 0.935 | 0.297 | 174 | 811 | 12 |
| arithmetic | 0.000 | 0.000 | 0.000 | 0 | 55 | 235 |
| unchecked_low_level_calls | 0.775 | 0.428 | 0.551 | 196 | 57 | 262 |
| denial_of_service | 0.038 | 0.143 | 0.061 | 1 | 25 | 6 |
| bad_randomness | 0.048 | 0.097 | 0.064 | 3 | 60 | 28 |
| front_running | — | 0.000 | — | 0 | 0 | 224 |
| time_manipulation | 0.515 | 0.845 | 0.640 | 202 | 190 | 37 |
| short_addresses | — | 0.000 | — | 0 | 0 | 1 |
| other | 0.004 | 1.000 | 0.007 | 3 | 851 | 0 |

## Per-class F1 (contract-level)

| Class | Precision | Recall | F1 | TP | FP | FN |
|---|---|---|---|---|---|---|
| reentrancy | 0.333 | 0.947 | 0.493 | 36 | 72 | 2 |
| access_control | 0.146 | 0.760 | 0.245 | 19 | 111 | 6 |
| arithmetic | 0.000 | 0.000 | 0.000 | 0 | 16 | 23 |
| unchecked_low_level_calls | 0.763 | 0.879 | 0.817 | 58 | 18 | 8 |
| denial_of_service | 0.042 | 0.167 | 0.067 | 1 | 23 | 5 |
| bad_randomness | 0.150 | 0.375 | 0.214 | 3 | 17 | 5 |
| front_running | — | 0.000 | — | 0 | 0 | 11 |
| time_manipulation | 0.188 | 1.000 | 0.316 | 12 | 52 | 0 |
| short_addresses | — | 0.000 | — | 0 | 0 | 1 |
| other | 0.023 | 1.000 | 0.046 | 3 | 125 | 0 |

## Failures

These files compiled with the selected solc (confirmed separately) but Slither 0.11.2 crashed. They are scored as zero findings, not dropped:

- `curated/reentrancy/reentrancy_bonus.sol`
- `curated/reentrancy/reentrancy_cross_function.sol`
- `curated/unchecked_low_level_calls/0x89c1b3807d4c67df034fffb62f3509561218d30b.sol`

Dataset: SmartBugs Curated @`230e64912347`, SolidiFI @`4b0573e1b3f7`, Wild @`91ec17573d3e`, n=243 (curated=143, solidifi=50, wild=50). Seed=20261114.
