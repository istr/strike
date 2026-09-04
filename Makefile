.PHONY: build generate golden lint test integration vuln check

build: generate
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o strike ./cmd/strike

# --- Schema pipeline: CUE -> JSON Schema -> Go/Rust types ---

# Generate JSON Schema exports and Go types from the CUE contracts.
generate:
	go generate ./contract

# Update golden test fixtures (run after intentional changes to sign/pack/digest).
golden:
	go test ./internal/executor/ -run Golden -update -count=1
	@echo "golden fixtures updated -- commit if changes are intentional"

# --- Quality gates ---

# Go-side type-discipline gate: conversion ownership, the three flow classes,
# and stuttering accessors, all over one extractor traversal.
.PHONY: lint-type
lint-type:
	cd tools/linttype && go build -o $(CURDIR)/.build/linttype .
	$(CURDIR)/.build/linttype ./...

# Standalone gate, intentionally not in the aggregate `lint` target: it reports
# hand-written types that a CUE-first tree would generate instead, and is run on
# demand rather than gating.
.PHONY: cuelint
cuelint:
	cd tools/cuelint && go build -o $(CURDIR)/.build/cuelint .
	$(CURDIR)/.build/cuelint ./...

# Gate for the two tree-wide source checks that need no Go type information:
# printable-ASCII source and ADR-index coverage. Both walk the module tree from
# the directory holding go.mod, so the command takes no package pattern; it is
# run from the repository root.
.PHONY: lint-docs
lint-docs:
	cd tools/lintdocs && go build -o $(CURDIR)/.build/lintdocs .
	$(CURDIR)/.build/lintdocs

.PHONY: lint-arch
lint-arch:
	go run github.com/fe3dback/go-arch-lint@v1.14.0 check --project-path .

lint-ci:
	golangci-lint run ./...

lint-cue-fmt:
	go tool cue fmt --check --files contract

lint: lint-ci lint-type lint-arch lint-docs lint-cue-fmt

test:
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
	@go tool cover -func=coverage.out | tail -1

# Integration tests (auto-detects podman socket; set STRIKE_INTEGRATION=0 to skip).
integration:
	go test -race -v -count=1 ./...

vuln:
	govulncheck ./...

# Run all quality gates (CI entry point).
check: lint vuln test build
