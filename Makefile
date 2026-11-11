# SentinelX developer convenience targets.
#
# This Makefile is intentionally thin — most workflows live in cargo, the CI
# pipelines, or `scripts/`. The targets here are ones a developer reaches for
# at the terminal often enough that an alias pays off.

# ---------------------------------------------------------------------------
# Knobs
# ---------------------------------------------------------------------------

SBOM_OUT          ?= sbom.cyclonedx.json
SBOM_FORMAT       ?= json
CARGO             ?= cargo
CARGO_CYCLONEDX   ?= cargo-cyclonedx

.DEFAULT_GOAL := help

# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

.PHONY: help
help: ## Show this help.
	@awk 'BEGIN {FS = ":.*##"; printf "Targets:\n"} \
		/^[a-zA-Z0-9_.-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 }' \
		$(MAKEFILE_LIST)

.PHONY: audit
audit: ## Run cargo audit using the workspace ignore policy (.cargo/audit.toml).
	$(CARGO) audit \
		--deny warnings \
		--deny unmaintained \
		--deny unsound \
		--deny yanked

.PHONY: audit-install
audit-install: ## Install cargo-audit (one-time, pinned via --locked).
	$(CARGO) install --locked cargo-audit

.PHONY: sbom
sbom: sbom-install ## Generate a CycloneDX SBOM for the workspace (LOW-001).
	# cargo-cyclonedx writes one SBOM per workspace package by default; we
	# request a single aggregated SBOM and rename to the canonical artifact
	# name the release pipeline publishes.
	$(CARGO_CYCLONEDX) \
		--format $(SBOM_FORMAT) \
		--all \
		--override-filename $(basename $(SBOM_OUT))
	@if [ -f "$(basename $(SBOM_OUT)).cdx.$(SBOM_FORMAT)" ]; then \
		mv "$(basename $(SBOM_OUT)).cdx.$(SBOM_FORMAT)" "$(SBOM_OUT)"; \
	fi
	@echo "SBOM written to $(SBOM_OUT)"

.PHONY: sbom-install
sbom-install: ## Install cargo-cyclonedx (one-time, pinned via --locked).
	@if ! command -v $(CARGO_CYCLONEDX) >/dev/null 2>&1; then \
		$(CARGO) install --locked cargo-cyclonedx; \
	fi

.PHONY: sbom-verify
sbom-verify: ## Verify a sigstore-signed SBOM (see docs/runbooks/supply-chain.md).
	@if [ ! -f "$(SBOM_OUT)" ] || [ ! -f "$(SBOM_OUT).sig" ] || [ ! -f "$(SBOM_OUT).pem" ]; then \
		echo "Missing $(SBOM_OUT), $(SBOM_OUT).sig, or $(SBOM_OUT).pem. Download all three from the GitHub release."; \
		exit 1; \
	fi
	cosign verify-blob \
		--certificate $(SBOM_OUT).pem \
		--signature $(SBOM_OUT).sig \
		--certificate-identity-regexp 'https://github\.com/.*/\.github/workflows/release\.yml@.*' \
		--certificate-oidc-issuer https://token.actions.githubusercontent.com \
		$(SBOM_OUT)

.PHONY: check
check: ## cargo check the workspace.
	$(CARGO) check --workspace --all-targets

.PHONY: fmt
fmt: ## cargo fmt the workspace.
	$(CARGO) fmt --all

.PHONY: lint
lint: ## cargo clippy the workspace (matches CI).
	$(CARGO) clippy --workspace --all-targets -- -D warnings
