# auditor-evals

Reproducible evaluation harness for [Solana's contract auditor](../auditor-src): how much does an LLM add on top of Slither for labeled Solidity bugs?

This repository is a **local** worktree (no GitHub remote). Datasets are public; pins and file SHA-256s live in `datasets/pins.json` and `datasets/manifest.jsonl`.

## Dataset (v1, frozen)

| Source | Pin | n | Role |
|---|---|---|---|
| SmartBugs Curated | see `datasets/pins.json` | 143 | labeled vulnerable (DASP) |
| SolidiFI-benchmark | see `datasets/pins.json` | 50 | injected bugs, stratified by type |
| SmartBugs Wild | see `datasets/pins.json` | 50 | `unverified-clean` negatives (fixed seed, prefer compile-success) |

Sampling seed: `20261114`. Gold labels: `labels/*.jsonl` (schema in `labels/schema.json`). Matching rule: same DASP class and (±3 lines **or** same function). Line-level and contract-level scores are both reported.

## Quick start

```bash
# Uses the auditor checkout at $AUDITOR_SRC (default /workspace/auditor-src)
make fetch                 # clone pinned commits, verify sha256, write manifest + labels
make test
make run MODEL=slither     # Slither-only baseline, $0, no API calls
make table RUN_DIR=results/<run_id>
```

Paid models (`MODEL=gpt-6.1-sol`, `claude-sonnet-5.5`, `claude-haiku-5.5`, `gpt-6.1-terra`) are **stubbed**. They read `config/models.yaml` + `config/prices.yaml`, require env-var keys (`OPENAI_API_KEY` / `ANTHROPIC_API_KEY`, never hardcoded), and abort if a hard per-run spend cap would be exceeded. This workstream does not call paid APIs (`AUDITOR_EVALS_ALLOW_PAID` is unset).

### Qwen local run (not executed here)

Needs Solana's Mac, not this box:

1. Ollama running on `127.0.0.1:11434`.
2. The exact tag from `config/models.yaml` (`huihui_ai/qwen3.5-abliterated:9b`, or record whatever `ollama list` shows — the auditor historically used `qwen3-8b-uncensored-16k:latest`).
3. `AUDITOR_SRC` pointing at the auditor checkout, with the same Python 3.11 venv / slither / solc-select as the baseline.
4. `make run MODEL=qwen-local`

## Results

Slither-only baseline `results/slither-20261114-baseline`, run 2026-11-14 12:23 America/Detroit. n=243. $0. Line-level matching (same DASP class and ±3 lines or same function):

| System | Precision | Recall | F1 | FP rate (clean) | $/contract | p50 s | p95 s |
|---|---|---|---|---|---|---|---|
| Slither only | 0.228 | 0.493 | 0.312 | 0.780 | $0 | 0.26 | 1.09 |
| + Qwen (local) | | | | | $0 | | |
| + gpt-6.1-sol | | | | | | | |
| + Claude Sonnet 5.5 | | | | | | | |
| + Claude Haiku 5.5 | | | | | | | |

Contract-level micro P/R/F1 = 0.233 / 0.684 / 0.348. Findings/contract: 14.16.

Compile failures: **0 / 243**. Slither tool failures: **3 / 243** (not dropped; scored as zero findings). All three compiled with solc 0.4.26; Slither 0.11.2 crashed (`AssertionError` in slithIR tuple assignment on `reentrancy_bonus.sol` and `reentrancy_cross_function.sol`; `NotConstant` on `0x89c1b3807d4c67df034fffb62f3509561218d30b.sol`).

Full per-class tables are in `results/slither-20261114-baseline/table.md`. Headline line-level F1: time_manipulation 0.640, unchecked_low_level_calls 0.551, reentrancy 0.402, access_control 0.297; arithmetic 0.000 (no TPs — modern Slither has essentially retired overflow detectors); front_running and short_addresses have no Slither slugs (0 predictions). 39/50 Wild "unverified-clean" contracts had at least one finding (FP rate 0.780); many are `other` (informational-mapped High/Medium/Low detectors).

### Token estimate and paid-run projection (no API calls)

Measured with tiktoken `o200k_base` on the actual Slither+LLM triage prompt (source + findings). Average **2,644 input** / **1,204 estimated output** tokens per contract (p50 in 1,041; p95 in 8,205; max 27,486). Spec assumption was 6k / 1.5k. Claude token counts use a 1.30 multiplier. Prices as of 2026-11-14 in `config/prices.yaml`. Budget $40.

Projected cost for the full 243-contract set × 3 runs, measured tokens (list / 50% batch):

| Config | ×3 list | ×3 batch 50% | vs $40 |
|---|---|---|---|
| gpt-6.1-sol ($2/$10 per 1M) | $12.63 | $6.32 | under |
| gpt-6.1-terra ($1/$5) | $6.32 | $3.16 | under |
| Claude Sonnet 5.5 ($2/$10, ×1.30 tokens) | $16.42 | $8.21 | under |
| Claude Haiku 5.5 ($0.10/$0.50, ×1.30) | $0.82 | $0.41 | under |

Using the spec's 6k/1.5k assumption, the most expensive cell is Claude Sonnet 5.5 ×3 list at $25.59, still under $40. All paid configs fit the budget for three runs. Paid providers remain stubbed; this workstream did not call any paid API.

## Layout

```
datasets/manifest.jsonl  datasets/fetch.py  datasets/pins.json
labels/schema.json  labels/*.jsonl
runners/run_eval.py  runners/providers/{ollama,openai,anthropic}.py
scoring/match.py  scoring/metrics.py
config/models.yaml  config/prices.yaml  config/slither_dasp_map.yaml
docs/slither_dasp_map.md
results/<run_id>/{raw.jsonl,metrics.json,table.md}
```

## License / citation

SmartBugs Curated and Wild are Apache-2.0 (contracts keep original licenses). SolidiFI has no SPDX license; research use, cite Ghaleb & Pattabiraman, ISSTA 2020. The injected SolidiFI contracts are **not** stored in this repository; run `make fetch` to clone the pinned commit locally. Do not republish Code4rena reports from this repo.
