PYTHON ?= python3
# Default to the box checkout; on a Mac export AUDITOR_SRC to the contract-auditor clone.
AUDITOR_SRC ?= $(shell if [ -d /workspace/auditor-src ]; then echo /workspace/auditor-src; elif [ -d ../contract-auditor ]; then (cd ../contract-auditor && pwd); else echo /workspace/auditor-src; fi)
TIMEOUT ?= 90
EXTRA_ARGS ?=
export AUDITOR_SRC
export PYTHONPATH := $(CURDIR):$(AUDITOR_SRC):$(PYTHONPATH)

.PHONY: fetch run table test

fetch:
	$(PYTHON) datasets/fetch.py

run:
	$(PYTHON) runners/run_eval.py --model $(or $(MODEL),slither) --timeout $(TIMEOUT) $(EXTRA_ARGS)

table:
	@if [ -z "$(RUN_DIR)" ]; then echo "usage: make table RUN_DIR=results/<run_id>"; exit 2; fi
	$(PYTHON) runners/run_eval.py --table-only --run-dir $(RUN_DIR)

test:
	$(PYTHON) -m pytest tests/
