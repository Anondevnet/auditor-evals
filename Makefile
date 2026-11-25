PYTHON ?= python3
# Default to a sibling contract-auditor clone; export AUDITOR_SRC to use another checkout.
AUDITOR_SRC ?= $(abspath $(CURDIR)/../contract-auditor)
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
