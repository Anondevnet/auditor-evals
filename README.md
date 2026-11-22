# auditor-evals

Reproducible evaluation harness for [Solana's contract auditor](../auditor-src): how much does an LLM add on top of Slither for labeled Solidity bugs?

Private companion repo to [Anondevnet/contract-auditor](https://github.com/Anondevnet/contract-auditor). Datasets are public; pins and file SHA-256s live in `datasets/pins.json` and `datasets/manifest.jsonl`. SolidiFI sources are not committed (no SPDX license); fetch them locally with `make fetch`.

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

### Qwen local run (Mac mini)

The Ollama provider is implemented (loopback only, $0). It is meant to run on Solana's Apple Silicon Mac mini (16 GB, Ollama already in use, Python 3.11 via pyenv). Do not run it against a paid API.

Copy-paste on the Mac, from a clone of this repo:

```bash
cd /path/to/auditor-evals
chmod +x scripts/mac_qwen_run.sh

# Optional, if the auditor checkout is not a sibling named contract-auditor / auditor-src:
export AUDITOR_SRC=/path/to/contract-auditor

# Check what is missing (never uses sudo; prints install hints and a runtime estimate):
./scripts/mac_qwen_run.sh --check

# Smoke test one contract, then the full 243-contract sweep (use tmux):
./scripts/mac_qwen_run.sh --limit 1
./scripts/mac_qwen_run.sh
# equivalent: make run MODEL=qwen-local TIMEOUT=300
```

Prerequisites the script checks:

| Check | Expected |
|---|---|
| Python | 3.11 on `PATH` as `python3.11` or `python3` (pyenv is fine) |
| `AUDITOR_SRC` | checkout of `contract-auditor` (or the older `auditor-src` tree) containing `audit.py` |
| Ollama | daemon answering on `127.0.0.1:11434` |
| Model tag | `huihui_ai/qwen3.5-abliterated:9b` from `config/models.yaml`, or the historical alt `qwen3-8b-uncensored-16k:latest`. Record the exact `ollama list` tag. Missing tag: `ollama pull <tag>` (or pass `--pull`) |
| slither / solc-select | used if already on `PATH`; otherwise the script pip-installs them into `./.venv` and installs solc `0.4.26 0.5.17 0.6.12 0.7.6 0.8.20 0.8.26` with `solc-select` (user prefix, no sudo) |

The script creates `./.venv` inside the repo, never uses sudo, and refuses to talk to a non-loopback Ollama host.

**Runtime estimate:** 243 contracts, ~2,644 input / ~1,204 output tokens each on average. A 9B Q4/Q5 model on a 16 GB M-series Mac is typically ~20–40 tok/s, or about 45–90 seconds per contract, so the full sweep is **about 3–6 hours** wall clock (budget 8 hours, run in tmux). Cost is $0. The script uses a 300s per-contract timeout because the slither-only default of 90s is too tight for a 9B generation.

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
