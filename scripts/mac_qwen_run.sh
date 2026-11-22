#!/usr/bin/env bash
# Run the local Qwen eval on an Apple Silicon Mac (16 GB Mac mini).
# Never uses sudo. Never calls a paid API. Ollama is loopback-only.
#
# Usage:
#   ./scripts/mac_qwen_run.sh --check          # print prerequisites, do not run
#   ./scripts/mac_qwen_run.sh                  # venv + make run MODEL=qwen-local
#   ./scripts/mac_qwen_run.sh --limit 1        # smoke test one contract
#   ./scripts/mac_qwen_run.sh --pull           # ollama pull a missing model tag, then run
#
# Optional env:
#   AUDITOR_SRC   path to the contract-auditor (or auditor-src) checkout
#   TIMEOUT       seconds per contract (default 300; the slither-only default of 90 is tight for a 9B model)
#   PYTHON        python 3.11 executable (otherwise python3.11 or python3 is detected)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CHECK_ONLY=0
PULL=0
LIMIT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) CHECK_ONLY=1; shift ;;
    --pull)  PULL=1; shift ;;
    --limit) LIMIT="${2:-}"; shift 2 ;;
    -h|--help)
      sed -n '2,16p' "$0"
      exit 0
      ;;
    *)
      echo "unknown argument: $1 (try --help)" >&2
      exit 2
      ;;
  esac
done

PREFERRED_MODEL="huihui_ai/qwen3.5-abliterated:9b"
ALT_MODEL="qwen3-8b-uncensored-16k:latest"
SOLC_VERSIONS=(0.4.26 0.5.17 0.6.12 0.7.6 0.8.20 0.8.26)
TIMEOUT="${TIMEOUT:-300}"
N_CONTRACTS=243

# --- helpers ----------------------------------------------------------------
ok()   { printf '  [ok]  %s\n' "$*"; }
miss() { printf '  [MISS] %s\n' "$*"; MISSING+=("$*"); }
note() { printf '  [..]  %s\n' "$*"; }

# Locate AUDITOR_SRC if the caller did not set it.
if [[ -z "${AUDITOR_SRC:-}" ]]; then
  for cand in \
      "$ROOT/../contract-auditor" \
      "$ROOT/../auditor-src" \
      "$HOME/contract-auditor" \
      "$HOME/src/contract-auditor"
  do
    if [[ -f "$cand/audit.py" && -d "$cand/auditor" ]]; then
      AUDITOR_SRC="$(cd "$cand" && pwd)"
      break
    fi
  done
fi

echo "== auditor-evals Mac Qwen runbook =="
echo "repo: $ROOT"
echo

MISSING=()

# Python 3.11 (pyenv is fine; never install with sudo from this script)
PY="${PYTHON:-}"
if [[ -z "$PY" ]]; then
  if command -v python3.11 >/dev/null 2>&1; then
    PY="$(command -v python3.11)"
  elif command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 11) else 1)' 2>/dev/null; then
    PY="$(command -v python3)"
  fi
fi
if [[ -n "$PY" ]]; then
  ok "python: $PY ($("$PY" -c 'import sys; print(".".join(map(str, sys.version_info[:3])))'))"
else
  miss "python3.11 not found. Install with pyenv (no sudo):  pyenv install 3.11.11 && pyenv local 3.11.11"
fi

# AUDITOR_SRC
if [[ -n "${AUDITOR_SRC:-}" && -f "$AUDITOR_SRC/audit.py" ]]; then
  ok "AUDITOR_SRC=$AUDITOR_SRC"
else
  miss "AUDITOR_SRC not set / no audit.py there. Clone https://github.com/Anondevnet/contract-auditor and export AUDITOR_SRC=/path/to/contract-auditor"
fi

# Ollama daemon on loopback
if command -v ollama >/dev/null 2>&1; then
  ok "ollama binary: $(command -v ollama)"
else
  miss "ollama binary not on PATH. Install the official Mac app from https://ollama.com (no sudo from this script) and reopen the terminal."
fi

OLLAMA_OK=0
if curl -fsS --max-time 2 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
  ok "ollama daemon is answering on 127.0.0.1:11434"
  OLLAMA_OK=1
else
  miss "ollama daemon is not answering on 127.0.0.1:11434. Start the Ollama app (or: ollama serve) and retry."
fi

FOUND_TAG=""
if [[ "$OLLAMA_OK" -eq 1 ]]; then
  TAGS="$(curl -fsS --max-time 5 http://127.0.0.1:11434/api/tags 2>/dev/null || true)"
  # Prefer the models.yaml tag, then the historical alt, then any qwen 8/9B-ish name.
  for tag in "$PREFERRED_MODEL" "$ALT_MODEL"; do
    if printf '%s' "$TAGS" | grep -F -q "\"$tag\""; then
      FOUND_TAG="$tag"
      break
    fi
    # ollama sometimes lists the name without a tag suffix or with a digest-only match
    short="${tag%%:*}"
    if printf '%s' "$TAGS" | grep -F -q "\"name\":\"$tag\"" || printf '%s' "$TAGS" | grep -F -q "$short"; then
      # confirm a closer match
      if printf '%s' "$TAGS" | grep -F -q "$tag" || printf '%s' "$TAGS" | grep -F -q "$short"; then
        FOUND_TAG="$tag"
        break
      fi
    fi
  done
  if [[ -n "$FOUND_TAG" ]]; then
    ok "model tag present: $FOUND_TAG"
  else
    miss "neither preferred tag ($PREFERRED_MODEL) nor alt ($ALT_MODEL) is in \`ollama list\`."
    note "Pull one locally (no sudo, ~5–8 GB):  ollama pull $PREFERRED_MODEL"
    note "or:  ollama pull $ALT_MODEL"
    note "Record the exact \`ollama list\` tag in the run notes."
    if [[ "$PULL" -eq 1 ]]; then
      note " --pull set; running: ollama pull $PREFERRED_MODEL"
      ollama pull "$PREFERRED_MODEL"
      FOUND_TAG="$PREFERRED_MODEL"
    fi
  fi
  echo "  ollama list:"
  if command -v ollama >/dev/null 2>&1; then
    ollama list 2>/dev/null | sed 's/^/    /' || true
  fi
fi

# slither / solc-select: may already be on PATH, or we will install into the venv later.
SLITHER_BIN="$(command -v slither || true)"
SOLC_SELECT_BIN="$(command -v solc-select || true)"
if [[ -n "$SLITHER_BIN" ]]; then
  ok "slither: $SLITHER_BIN ($("$SLITHER_BIN" --version 2>/dev/null | head -1 || echo present))"
else
  note "slither not on PATH yet; the repo venv will pip-install slither-analyzer (no sudo)."
fi
if [[ -n "$SOLC_SELECT_BIN" ]]; then
  ok "solc-select: $SOLC_SELECT_BIN"
  installed="$("$SOLC_SELECT_BIN" versions 2>/dev/null || true)"
  missing_solc=()
  for v in "${SOLC_VERSIONS[@]}"; do
    if printf '%s' "$installed" | grep -F -q "$v"; then
      ok "solc $v"
    else
      missing_solc+=("$v")
    fi
  done
  if [[ ${#missing_solc[@]} -gt 0 ]]; then
    note "solc versions not installed: ${missing_solc[*]}"
    note "Install into your user dir (no sudo):  solc-select install ${missing_solc[*]}"
  fi
else
  note "solc-select not on PATH yet; the repo venv will pip-install it (no sudo)."
fi

# Runtime estimate (printed even on --check).
echo
echo "== runtime estimate =="
echo "  243 contracts, Slither + a local 9B Qwen tag, 16 GB Apple Silicon."
echo "  Token estimate from the Slither baseline triage prompt: ~2,644 input / ~1,204 output tokens per contract"
echo "  (p95 input ~8,205; a few contracts are much longer)."
echo "  A 9B Q4/Q5 model on a 16 GB M-series Mac is typically ~20–40 tok/s generate."
echo "  That is roughly 45–90 seconds per contract (prefill + generation + Slither),"
echo "  so the full 243-contract sweep is about 3–6 hours wall clock."
echo "  Budget 8 hours of headroom, and run it in tmux or screen so an SSH/GUI sleep does not kill it."
echo "  Per-contract timeout default in this script: ${TIMEOUT}s (the slither-only default of 90s is too tight)."
echo "  Cost: \$0. No paid API is called."
echo

if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo "== missing prerequisites =="
  for m in "${MISSING[@]}"; do
    echo "  - $m"
  done
  echo
  echo "Fix the items marked [MISS], then re-run. This script never uses sudo."
  exit 1
fi

if [[ "$CHECK_ONLY" -eq 1 ]]; then
  echo "Prerequisites look good. To run the full sweep:"
  echo "  cd $ROOT"
  echo "  ./scripts/mac_qwen_run.sh"
  echo "Smoke test one contract first:"
  echo "  ./scripts/mac_qwen_run.sh --limit 1"
  exit 0
fi

# --- venv inside the repo ---------------------------------------------------
VENV="$ROOT/.venv"
if [[ ! -x "$VENV/bin/python" ]]; then
  echo "creating venv at $VENV with $PY"
  "$PY" -m venv "$VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"
python -m pip install -q --upgrade pip
python -m pip install -q -r "$ROOT/requirements.txt"
if [[ -n "${AUDITOR_SRC:-}" && -f "$AUDITOR_SRC/requirements.txt" ]]; then
  python -m pip install -q -r "$AUDITOR_SRC/requirements.txt"
fi
python -m pip install -q slither-analyzer solc-select

# Install missing solc versions into the user/solc-select prefix (no sudo).
if command -v solc-select >/dev/null 2>&1; then
  installed="$(solc-select versions 2>/dev/null || true)"
  for v in "${SOLC_VERSIONS[@]}"; do
    if ! printf '%s' "$installed" | grep -F -q "$v"; then
      echo "solc-select install $v"
      solc-select install "$v"
    fi
  done
  # Prefer a modern default; plan_compile still picks per-pragma.
  solc-select use 0.8.26 >/dev/null 2>&1 || true
fi

export AUDITOR_SRC
export PYTHON="$VENV/bin/python"
export TIMEOUT
EXTRA_ARGS=()
if [[ -n "$LIMIT" ]]; then
  EXTRA_ARGS+=(--limit "$LIMIT")
fi
echo
echo "starting: make run MODEL=qwen-local TIMEOUT=$TIMEOUT PYTHON=$PYTHON AUDITOR_SRC=$AUDITOR_SRC ${EXTRA_ARGS[*]:-}"
echo
make run MODEL=qwen-local TIMEOUT="$TIMEOUT" PYTHON="$PYTHON" EXTRA_ARGS="${EXTRA_ARGS[*]:-}"
