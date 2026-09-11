.PHONY: test test-signatures lint format install dev audit audit-python audit-frontend

install:
	pip install -e .

dev:
	pip install -e ".[dev,api,ml]"

test:
	pytest tests/ -v

test-signatures:
	pytest tests/signatures/ -v

lint:
	ruff check .

# CloudFormation templates are not covered by ruff or pytest, and a template
# error is only reported by AWS at stack-creation time — after the operator has
# already waited through packaging and upload.
lint-infra:
	cfn-lint infra/self-hosted.yaml infra/managed-agent.yaml

format:
	ruff format .

# --- Dependency vulnerability audits (coverage gaps C and D) ---
# Run both dependency audits. Fails if either tool reports vulnerabilities.
audit: audit-python audit-frontend

# Audit the pinned Lambda runtime dependencies with pip-audit.
audit-python:
	pip install --quiet pip-audit
	pip-audit -r scripts/requirements-lambda.txt

# Audit the frontend dependencies with npm audit (needs a lockfile).
audit-frontend:
	cd frontend && npm install --package-lock-only && npm audit --audit-level=high
