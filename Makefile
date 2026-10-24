# Supported Python versions
PYTHON_VERSIONS = 3.10 3.11 3.12 3.13 3.14 3.15
DEFAULT_PYTHON = 3.10

# Install dependencies
.PHONY: install
install:
	@uv sync
	@find . -type d \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".ruff_cache" -o -name ".mypy_cache" \) -exec rm -rf {} + 2>/dev/null; find . -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete 2>/dev/null; true

# Install dev dependencies
.PHONY: install-dev
install-dev:
	@uv sync --extra dev
	@find . -type d \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".ruff_cache" -o -name ".mypy_cache" \) -exec rm -rf {} + 2>/dev/null; find . -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete 2>/dev/null; true

# Update dependencies
.PHONY: lock
lock:
	@uv lock
	@find . -type d \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".ruff_cache" -o -name ".mypy_cache" \) -exec rm -rf {} + 2>/dev/null; find . -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete 2>/dev/null; true


# Upgrade dependencies
.PHONY: upgrade
upgrade:
	@uv lock --upgrade
	@uv sync --all-extras
	@find . -type d \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".ruff_cache" -o -name ".mypy_cache" \) -exec rm -rf {} + 2>/dev/null; find . -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete 2>/dev/null; true

# Start example-app
.PHONY: start-example
start-example:
	@COMPOSE_BAKE=true PYTHON_VERSION=$(DEFAULT_PYTHON) docker compose up --build tornadoapi-guard-example
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

.PHONY: run-example
run-example:
	@COMPOSE_BAKE=true docker compose build tornadoapi-guard-example
	@docker compose up tornadoapi-guard-example
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Stop
.PHONY: stop
stop:
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Restart
.PHONY: restart
restart: stop start-example

# Lint code
.PHONY: lint
lint:
	@COMPOSE_BAKE=true docker compose run --rm --no-deps tornadoapi-guard sh -c "echo 'Checking formatting w/ Ruff...' ; echo '' ; ruff format --check . ; echo '' ; echo '' ; echo 'Linting w/ Ruff...' ; echo '' ; ruff check . ; echo '' ; echo '' ; echo 'Type checking w/ Mypy...' ; echo '' ; mypy . ; echo '' ; echo '' ; echo 'Finding dead code w/ Vulture...' ; echo '' ; vulture"
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Fix code
.PHONY: fix
fix:
	@echo "Fixing formatting w/ Ruff..."
	@echo ''
	@uv run ruff check --fix .
	@find . -type d \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".ruff_cache" -o -name ".mypy_cache" \) -exec rm -rf {} + 2>/dev/null; find . -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete 2>/dev/null; true

# Find dead code with Vulture
.PHONY: vulture
vulture:
	@echo "Finding dead code with Vulture..."
	@echo ''
#	@uv run vulture
#	@uv run vulture --verbose
	@uv run vulture vulture_whitelist.py
	@find . -type d \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".ruff_cache" -o -name ".mypy_cache" \) -exec rm -rf {} + 2>/dev/null; find . -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete 2>/dev/null; true

# Security scan with Bandit
.PHONY: bandit
bandit:
	@echo "Running Bandit security scan..."
	@echo ''
	@uv run bandit -r tornadoapi_guard -ll
	@find . -type d \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".ruff_cache" -o -name ".mypy_cache" \) -exec rm -rf {} + 2>/dev/null; find . -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete 2>/dev/null; true

# Check dependencies with Safety
.PHONY: safety
safety:
	@echo "Checking dependencies with Safety..."
	@echo ''
	@uv run safety scan
	@find . -type d \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".ruff_cache" -o -name ".mypy_cache" \) -exec rm -rf {} + 2>/dev/null; find . -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete 2>/dev/null; true

# Audit dependencies with pip-audit
.PHONY: pip-audit
pip-audit:
	@echo "Auditing dependencies with pip-audit..."
	@echo ''
	@uv run pip-audit
	@find . -type d \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".ruff_cache" -o -name ".mypy_cache" \) -exec rm -rf {} + 2>/dev/null; find . -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete 2>/dev/null; true

# Analyze code complexity with Radon
.PHONY: radon
radon:
	@echo "Analyzing code complexity with Radon..."
	@echo ''
	@echo "Cyclomatic Complexity:"
	@uv run radon cc tornadoapi_guard -nc
	@echo ''
	@echo "Maintainability Index:"
	@uv run radon mi tornadoapi_guard -nc
	@echo ''
	@echo "Raw Metrics:"
	@uv run radon raw tornadoapi_guard
	@find . -type d \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".ruff_cache" -o -name ".mypy_cache" \) -exec rm -rf {} + 2>/dev/null; find . -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete 2>/dev/null; true

# Check complexity thresholds with Xenon
.PHONY: xenon
xenon:
	@echo "Checking complexity thresholds with Xenon..."
	@echo ''
	@uv run xenon tornadoapi_guard --max-absolute B --max-modules A --max-average A
	@find . -type d \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".ruff_cache" -o -name ".mypy_cache" \) -exec rm -rf {} + 2>/dev/null; find . -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete 2>/dev/null; true

# Analyze dependencies with Deptry
.PHONY: deptry
deptry:
	@echo "Analyzing dependencies with Deptry..."
	@echo ''
	@uv run deptry .
	@find . -type d \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".ruff_cache" -o -name ".mypy_cache" \) -exec rm -rf {} + 2>/dev/null; find . -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete 2>/dev/null; true

# Lint local (without Docker)
.PHONY: local-test
local-test:
	@REDIS_URL=$${REDIS_URL:-redis://localhost:6379} \
	uv run pytest -v --cov=tornadoapi_guard --cov-report=term-missing
	@find . -type d \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".ruff_cache" -o -name ".mypy_cache" \) -exec rm -rf {} + 2>/dev/null; find . -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete 2>/dev/null; true

# Run all security checks
.PHONY: security
security: bandit safety pip-audit
	@echo "All security checks completed."

# Run all code quality checks
.PHONY: quality
quality: lint vulture radon xenon
	@echo "All code quality checks completed."

# Run all analysis tools
.PHONY: analysis
analysis: deptry
	@echo "All analysis tools completed."

# Run all checks (linting, security, quality, and analysis)
.PHONY: check-all
check-all: lint security quality analysis
	@echo "All checks completed."

# Run tests (default Python version)
.PHONY: test
test:
	@COMPOSE_BAKE=true PYTHON_VERSION=$(DEFAULT_PYTHON) docker compose run --rm --build tornadoapi-guard pytest -v --cov=.
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Run All Python versions
.PHONY: test-all
test-all: test-3.10 test-3.11 test-3.12 test-3.13 test-3.14 test-3.15

# Python 3.10
.PHONY: test-3.10
test-3.10:
	@docker compose down -v tornadoapi-guard
	@COMPOSE_BAKE=true PYTHON_VERSION=3.10 docker compose build tornadoapi-guard
	@PYTHON_VERSION=3.10 docker compose run --rm tornadoapi-guard pytest -v --cov=.
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Python 3.11
.PHONY: test-3.11
test-3.11:
	@docker compose down -v tornadoapi-guard
	@COMPOSE_BAKE=true PYTHON_VERSION=3.11 docker compose build tornadoapi-guard
	@PYTHON_VERSION=3.11 docker compose run --rm tornadoapi-guard pytest -v --cov=.
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Python 3.12
.PHONY: test-3.12
test-3.12:
	@docker compose down -v tornadoapi-guard
	@COMPOSE_BAKE=true PYTHON_VERSION=3.12 docker compose build tornadoapi-guard
	@PYTHON_VERSION=3.12 docker compose run --rm tornadoapi-guard pytest -v --cov=.
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Python 3.13
.PHONY: test-3.13
test-3.13:
	@docker compose down -v tornadoapi-guard
	@COMPOSE_BAKE=true PYTHON_VERSION=3.13 docker compose build tornadoapi-guard
	@PYTHON_VERSION=3.13 docker compose run --rm tornadoapi-guard pytest -v --cov=.
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Python 3.14
.PHONY: test-3.14
test-3.14:
	@docker compose down -v tornadoapi-guard
	@COMPOSE_BAKE=true PYTHON_VERSION=3.14 docker compose build tornadoapi-guard
	@PYTHON_VERSION=3.14 docker compose run --rm tornadoapi-guard pytest -v --cov=.
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Python 3.15
.PHONY: test-3.15
test-3.15:
	@docker compose down -v tornadoapi-guard
	@COMPOSE_BAKE=true PYTHON_VERSION=3.15 docker compose build tornadoapi-guard
	@PYTHON_VERSION=3.15 docker compose run --rm tornadoapi-guard pytest -v --cov=.
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Serve docs
.PHONY: serve-docs
serve-docs:
	@UV_PROJECT_ENVIRONMENT=.venv/docs uv run --python 3.14 --extra dev --group docs mkdocs serve
	@find . -type d \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".ruff_cache" -o -name ".mypy_cache" \) -exec rm -rf {} + 2>/dev/null; find . -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete 2>/dev/null; true

# Lint documentation
.PHONY: lint-docs
lint-docs:
	@uv run --group docs pymarkdownlnt scan -r -e ./.venv -e ./.git -e ./.github -e ./data -e ./tornadoapi_guard -e ./tests -e ./.claude -e ./CLAUDE.md -e ./.cursor -e ./.kiro -e ./ZZZ .
	@find . -type d \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".ruff_cache" -o -name ".mypy_cache" \) -exec rm -rf {} + 2>/dev/null; find . -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete 2>/dev/null; true

# Fix documentation
.PHONY: fix-docs
fix-docs:
	@uv run --group docs pymarkdownlnt fix -r -e ./.venv -e ./.git -e ./.github -e ./data -e ./tornadoapi_guard -e ./tests -e ./.claude -e ./CLAUDE.md -e ./.cursor -e ./.kiro -e ./ZZZ .
	@find . -type d \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".ruff_cache" -o -name ".mypy_cache" \) -exec rm -rf {} + 2>/dev/null; find . -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete 2>/dev/null; true

# Prune
.PHONY: prune
prune:
	@docker system prune -f

# Clean Cache Files
.PHONY: clean
clean:
	@find . -type d \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".ruff_cache" -o -name ".mypy_cache" \) -exec rm -rf {} + 2>/dev/null; find . -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete 2>/dev/null; true

# Version Management
.PHONY: bump-version
bump-version:
	@if [ -z "$(VERSION)" ]; then echo "Usage: make bump-version VERSION=x.y.z"; exit 1; fi
	@uv run python .github/scripts/bump_version.py $(VERSION)

# Help
.PHONY: help
help: ## Show available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help

# Python versions list
.PHONY: show-python-versions
show-python-versions:
	@echo "Supported Python versions: $(PYTHON_VERSIONS)"
	@echo "Default Python version: $(DEFAULT_PYTHON)"
