# If you have `direnv` loaded in your shell, and allow it in the repository,
# the `make` command will point at the `scripts/make` shell script.
# This Makefile is just here to allow auto-completion in the terminal.

.PHONY: install test lint clean

install:
	uv pip install -e ".[dev]"

test:
	pytest

lint:
	ruff check . --config config/ruff.toml
	ruff format --check . --config config/ruff.toml

format:
	ruff check --fix . --config config/ruff.toml
	ruff format . --config config/ruff.toml

clean:
	rm -rf .pytest_cache
	rm -rf .ruff_cache
	rm -rf .coverage
	rm -rf htmlcov
	rm -rf dist
	rm -rf *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
