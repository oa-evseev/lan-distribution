.PHONY: install install-client install-server uninstall test lint format check
PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

install: install-client
install-client:
	./scripts/install.sh client
install-server:
	./scripts/install.sh server
uninstall:
	./scripts/uninstall.sh
test:
	$(PYTHON) -m pytest
lint:
	$(PYTHON) -m ruff check .
format:
	$(PYTHON) -m ruff format .
check:
	$(PYTHON) -m pytest
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .
	$(PYTHON) -m mypy src
	bash -n scripts/install.sh scripts/uninstall.sh
	git diff --check
