SHELL := /bin/bash

WAILS ?= wails
NPM ?= npm
GO ?= go

FRONTEND_DIR := frontend
WAILS_TAGS ?= webkit2_41
WAILS_FLAGS := -tags $(WAILS_TAGS)
DIST_DIR := dist
APP_NAME := VulnDock

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

.PHONY: package-linux
package-linux: build ## Package the Linux desktop app for GitHub Releases.
	$(RM) -r $(DIST_DIR)/package
	mkdir -p $(DIST_DIR)/package
	cp build/bin/$(APP_NAME) $(DIST_DIR)/package/$(APP_NAME)
	cp build/linux/vulndock.desktop $(DIST_DIR)/package/vulndock.desktop
	cp build/appicon.png $(DIST_DIR)/package/vulndock.png
	tar -C $(DIST_DIR)/package -czf $(DIST_DIR)/$(APP_NAME)_linux_$(shell $(GO) env GOARCH).tar.gz .

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
check: test frontend-check ## Run tests and frontend type checks.

.PHONY: test
test: go-test frontend-test ## Run backend and frontend tests.

.PHONY: frontend-check
frontend-check: ## Run Svelte/TypeScript checks.
	$(NPM) run check --prefix $(FRONTEND_DIR)

.PHONY: frontend-test
frontend-test: ## Run frontend unit tests.
	$(NPM) test --prefix $(FRONTEND_DIR)

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
	$(RM) -r build/bin $(FRONTEND_DIR)/dist $(DIST_DIR)
