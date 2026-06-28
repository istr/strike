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
	sed -i 's#github.com/istr/strike/contract/#github.com/istr/strike/internal/#g' contract/lane/cue_types_gen.go contract/primitive/cue_types_gen.go contract/endpoint/cue_types_gen.go contract/output/cue_types_gen.go contract/provenance/cue_types_gen.go contract/target/cue_types_gen.go contract/record/cue_types_gen.go
	mkdir -p internal/primitive internal/endpoint internal/output internal/provenance internal/target internal/record
	mv contract/lane/cue_types_gen.go internal/lane/lane.gen.go
	mv contract/primitive/cue_types_gen.go internal/primitive/primitive.gen.go
	mv contract/endpoint/cue_types_gen.go internal/endpoint/endpoint.gen.go
	mv contract/output/cue_types_gen.go internal/output/output.gen.go
	mv contract/provenance/cue_types_gen.go internal/provenance/provenance.gen.go
	mv contract/target/cue_types_gen.go internal/target/target.gen.go
	mv contract/record/cue_types_gen.go internal/record/record.gen.go

# Update golden test fixtures (run after intentional changes to sign/pack/digest).
golden:
	go test ./internal/executor/ -run Golden -update -count=1
	@echo "golden fixtures updated -- commit if changes are intentional"

# --- Quality gates ---

.PHONY: lint-from
lint-from:
	cd tools/lintfrom && go build -o $(CURDIR)/.build/lintfrom .
	$(CURDIR)/.build/lintfrom ./...

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

lint: lint-ci lint-from lint-arch lint-ascii lint-adr-index lint-cue-fmt

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
