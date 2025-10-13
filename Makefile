# Vulners Lookup Extension Makefile

# Variables
VERSION := 1.0.3
EXTENSION_NAME := vulners-lookup
BUILD_DIR := build
DIST_DIR := dist
ZIP_NAME := $(EXTENSION_NAME)-v$(VERSION).zip

# Default target
.PHONY: all
all: build

# Development build
.PHONY: build
build:
	npm run build

# Production build
.PHONY: build-prod
build-prod:
	npm run build:prod

# Create distributable zip file
.PHONY: package
package: build-prod
	cd $(BUILD_DIR) && zip -r ../$(ZIP_NAME) ./*
	@echo "✅ Extension packaged: $(ZIP_NAME)"
	@echo "📦 Size: $$(du -h $(ZIP_NAME) | cut -f1)"

# Install dependencies
.PHONY: install
install:
	npm install

# Clean build artifacts
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR) $(DIST_DIR)
	rm -f $(EXTENSION_NAME)-v*.zip

# Development mode with watch
.PHONY: dev
dev:
	npm run dev

# Run type checking
.PHONY: typecheck
typecheck:
	npx tsc --noEmit

# Run unit tests
.PHONY: test
test:
	npm test

# Run tests in watch mode
.PHONY: test-watch
test-watch:
	npm run test:watch

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	npm run test:coverage

# Run tests and generate coverage report
.PHONY: coverage
coverage: test-coverage
	@echo "📊 Coverage report generated in coverage/ directory"
	@echo "🌐 Open coverage/lcov-report/index.html in browser to view"

# Lint code with ESLint
.PHONY: lint
lint:
	npm run lint

# Lint and fix code with ESLint
.PHONY: lint-fix
lint-fix:
	npm run lint:fix

# Format code with Prettier
.PHONY: format
format:
	npm run format

# Check code formatting with Prettier
.PHONY: format-check
format-check:
	npm run format:check

# Run all quality checks
.PHONY: check
check: lint format-check test typecheck
	@echo "✅ All quality checks passed!"

# Pre-commit hook - format and lint before committing
.PHONY: pre-commit
pre-commit: format lint-fix test
	@echo "🚀 Pre-commit checks completed successfully!"

# Show help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  make build         - Build extension for development"
	@echo "  make build-prod    - Build optimized extension for production"
	@echo "  make package       - Build and create distributable zip file"
	@echo "  make install       - Install npm dependencies"
	@echo "  make clean         - Remove all build artifacts"
	@echo "  make dev           - Start development mode with file watching"
	@echo "  make typecheck     - Run TypeScript type checking"
	@echo "  make test          - Run unit tests"
	@echo "  make test-watch    - Run tests in watch mode"
	@echo "  make test-coverage - Run tests with coverage report"
	@echo "  make coverage      - Generate and report test coverage"
	@echo "  make lint          - Run ESLint to check code quality"
	@echo "  make lint-fix      - Run ESLint with automatic fixes"
	@echo "  make format        - Format TypeScript and CSS code with Prettier"
	@echo "  make format-check  - Check TypeScript and CSS formatting with Prettier"
	@echo "  make check         - Run all quality checks (lint, format, test, typecheck)"
	@echo "  make pre-commit    - Run pre-commit checks (format, lint-fix, test)"
	@echo "  make help          - Show this help message"

# Phony catch-all
.PHONY: all build build-prod package install clean dev typecheck test test-watch test-coverage coverage lint lint-fix format format-check check pre-commit help
