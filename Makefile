.PHONY: help simulate test lint fmt validate scan tflint all clean

help: ## List available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

simulate: ## Replay every recorded incident through the pipeline (offline)
	python3 simulator/simulate.py --all

test: ## Run the unit test suite
	pytest tests/ -q

lint: ## Lint the Python sources with ruff
	ruff check src simulator tests

fmt: ## Check Terraform formatting
	cd infra && terraform fmt -check -recursive

validate: ## terraform validate (after terraform init -backend=false)
	cd infra && terraform init -backend=false && terraform validate

tflint: ## Run tflint over infra/
	cd infra && tflint --init && tflint --recursive

scan: ## Run checkov + tfsec over infra/
	cd infra && checkov -d . --framework terraform --compact
	cd infra && tfsec .

all: lint test fmt validate tflint scan simulate ## Every local gate, in order

deploy: ## plan then apply - read the plan output before typing yes
	cd infra && terraform init && terraform plan -out=tfplan
	@echo "Review infra/tfplan, then run: cd infra && terraform apply tfplan"
