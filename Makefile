.PHONY: build specs generate golden lint test integration vuln check

build: generate
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o strike ./cmd/strike

# --- Schema pipeline: CUE -> JSON Schema -> Go/Rust types ---

# Step 1: Export CUE specs to JSON Schema.
# These JSON Schema files are the cross-implementation contract that
# both the Go and (future) Rust validators build from.
specs: contract/primitive/scalars.cue contract/lane/peer.cue contract/target/target.cue contract/lane/lane.cue contract/lane/trustroot.cue contract/provenance/provenance.cue contract/attest/attestation.cue contract/record/record.cue
	cue export ./contract/lane -e '#Lane' \
	    --out jsonschema --force -o contract/lane.schema.json
	cue export ./contract/attest -e '#Attestation' \
	    --out jsonschema --force -o contract/attestation.schema.json
	cue export ./contract/trustlayers \
	    --out json --force -o contract/trust-layers.json

# Step 2: Generate Go types from the CUE schemas via gengotypes.
generate: specs
	cue exp gengotypes ./contract/lane
	cue exp gengotypes ./contract/primitive
	cue exp gengotypes ./contract/endpoint
	cue exp gengotypes ./contract/output
	cue exp gengotypes ./contract/provenance
	cue exp gengotypes ./contract/target
	cue exp gengotypes ./contract/record
	cue exp gengotypes ./contract/attest
	sed -i 's#github.com/istr/strike/contract/#github.com/istr/strike/internal/#g' contract/lane/cue_types_gen.go contract/primitive/cue_types_gen.go contract/endpoint/cue_types_gen.go contract/output/cue_types_gen.go contract/provenance/cue_types_gen.go contract/target/cue_types_gen.go contract/record/cue_types_gen.go contract/attest/cue_types_gen.go
	# contract/attest's Go home is internal/deploy (package deploy), not internal/attest:
	# the CUE package name stays "attest" (matching its contract/ directory), but the
	# generated Go joins the hand-written deploy package that already imports it.
	sed -i '0,/^package attest$$/{s/^package attest$$/package deploy/}' contract/attest/cue_types_gen.go
	# gengotypes emits a bogus bare import (e.g. "lane") for every cross-package
	# qualifier used inside a @go(,type=map[pkg.K]V) override string. For endpoint
	# and primitive a real import already exists from an un-overridden field
	# elsewhere, so the bare line is a duplicate and is dropped; lane and record
	# are referenced only inside override strings, so their bare line is the only
	# source of that import and is corrected to the real path instead.
	sed -i -e '/^\t"endpoint"$$/d' -e '/^\t"primitive"$$/d' \
	    -e 's#^\t"lane"$$#\t"github.com/istr/strike/internal/lane"#' \
	    -e 's#^\t"record"$$#\t"github.com/istr/strike/internal/record"#' \
	    contract/attest/cue_types_gen.go
	gofmt -w contract/attest/cue_types_gen.go
	mkdir -p internal/primitive internal/endpoint internal/output internal/provenance internal/target internal/record
	mv contract/lane/cue_types_gen.go internal/lane/lane.gen.go
	mv contract/primitive/cue_types_gen.go internal/primitive/primitive.gen.go
	mv contract/endpoint/cue_types_gen.go internal/endpoint/endpoint.gen.go
	mv contract/output/cue_types_gen.go internal/output/output.gen.go
	mv contract/provenance/cue_types_gen.go internal/provenance/provenance.gen.go
	mv contract/target/cue_types_gen.go internal/target/target.gen.go
	mv contract/record/cue_types_gen.go internal/record/record.gen.go
	mv contract/attest/cue_types_gen.go internal/deploy/attest.gen.go
	cd tools/genenums && go build -o $(CURDIR)/.build/genenums .
	$(CURDIR)/.build/genenums ./contract/lane ./contract/primitive ./contract/endpoint ./contract/output ./contract/provenance ./contract/target ./contract/record ./contract/attest

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
	cue fmt --check --files contract

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
