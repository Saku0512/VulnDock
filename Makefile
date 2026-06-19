SHELL := /bin/bash

WAILS ?= wails
NPM ?= npm
GO ?= go

FRONTEND_DIR := frontend
WAILS_TAGS ?= webkit2_41
WAILS_FLAGS := -tags $(WAILS_TAGS)

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show available targets.
	@awk 'BEGIN {FS = ":.*## "; printf "Usage: make <target>\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: dev
dev: ## Run the Wails app in live development mode.
	$(WAILS) dev $(WAILS_FLAGS)

.PHONY: build
build: ## Build a redistributable Wails package.
	$(WAILS) build $(WAILS_FLAGS)

.PHONY: install
install: frontend-install ## Install project dependencies.

.PHONY: frontend-install
frontend-install: ## Install frontend dependencies from package-lock.json.
	$(NPM) ci --prefix $(FRONTEND_DIR)

.PHONY: frontend-dev
frontend-dev: ## Run only the Vite frontend dev server.
	$(NPM) run dev --prefix $(FRONTEND_DIR)

.PHONY: frontend-build
frontend-build: ## Build only the Vite frontend.
	$(NPM) run build --prefix $(FRONTEND_DIR)

.PHONY: check
check: go-test frontend-check ## Run backend tests and frontend type checks.

.PHONY: frontend-check
frontend-check: ## Run Svelte/TypeScript checks.
	$(NPM) run check --prefix $(FRONTEND_DIR)

.PHONY: go-test
go-test: ## Run Go tests.
	$(GO) test ./...

.PHONY: fmt
fmt: ## Format Go source files.
	$(GO) fmt ./...

.PHONY: tidy
tidy: ## Tidy Go module files.
	$(GO) mod tidy

.PHONY: doctor
doctor: ## Run Wails environment diagnostics.
	$(WAILS) doctor

.PHONY: clean
clean: ## Remove generated build artifacts.
	$(RM) -r build/bin $(FRONTEND_DIR)/dist
