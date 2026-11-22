PYTHON ?= python3
AUDITOR_SRC ?= /workspace/auditor-src
export AUDITOR_SRC
export PYTHONPATH := $(CURDIR):$(AUDITOR_SRC):$(PYTHONPATH)

.PHONY: fetch run table test

fetch:
	$(PYTHON) datasets/fetch.py

run:
	$(PYTHON) runners/run_eval.py --model $(or $(MODEL),slither)

table:
	@if [ -z "$(RUN_DIR)" ]; then echo "usage: make table RUN_DIR=results/<run_id>"; exit 2; fi
	$(PYTHON) runners/run_eval.py --table-only --run-dir $(RUN_DIR)

test:
	$(PYTHON) -m pytest tests/
