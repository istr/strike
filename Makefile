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

.PHONY: lint-typeconv
lint-typeconv:
	cd tools/linttypeconv && go build -o $(CURDIR)/.build/linttypeconv .
	$(CURDIR)/.build/linttypeconv ./...

# Standalone gate, intentionally not in the aggregate `lint` target: it reports
# hand-written types that a CUE-first tree would generate instead, and is run on
# demand rather than gating.
.PHONY: cuelint
cuelint:
	cd tools/cuelint && go build -o $(CURDIR)/.build/cuelint .
	$(CURDIR)/.build/cuelint ./...

# Standalone gate, intentionally not in the aggregate `lint` target: it fails
# on the flow-typing classes it covers and stands up red (empty allowlist), so
# the covered tree is proven clean class by class. It graduates into aggregate
# lint at the first point where every covered class passes at once.
.PHONY: lint-typeflow
lint-typeflow:
	cd tools/linttypeflow && go build -o $(CURDIR)/.build/linttypeflow .
	$(CURDIR)/.build/linttypeflow ./...

lint-ascii:
	@! grep -rPn '[^\x00-\x7F]' --include='*.md' --include='*.go' --include='*.cue' \
		--exclude='*_test.go' . \
		&& echo "ascii-only: ok" \
		|| { echo "non-ASCII found in source files (see above)"; exit 1; }

lint-adr-index:
	@for f in docs/ADR-[0-9]*.md; do \
		b=$$(basename "$$f"); \
		grep -q "$$b" docs/ADR-INDEX.md \
			|| { echo "ADR on disk but missing from ADR-INDEX.md: $$b"; exit 1; }; \
	done; echo "adr-index: ok"

.PHONY: lint-arch
lint-arch:
	go run github.com/fe3dback/go-arch-lint@v1.14.0 check --project-path .

lint-ci:
	golangci-lint run ./...

lint-cue-fmt:
	go tool cue fmt --check --files contract

lint: lint-ci lint-typeconv lint-arch lint-ascii lint-adr-index lint-cue-fmt

test:
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
	@go tool cover -func=coverage.out | tail -1

# Integration tests (auto-detects podman socket; set STRIKE_INTEGRATION=0 to skip).
integration:
	go test -race -v -count=1 ./test/integration/

vuln:
	govulncheck ./...

# Run all quality gates (CI entry point).
check: lint test vuln build
