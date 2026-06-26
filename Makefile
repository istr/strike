.PHONY: build specs generate golden lint test integration vuln check

build: generate
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o strike ./cmd/strike

# --- Schema pipeline: CUE -> JSON Schema -> Go/Rust types ---

# Step 1: Export CUE specs to JSON Schema.
# These JSON Schema files are the cross-implementation contract that
# both the Go and (future) Rust validators build from.
specs: specs/spec/scalars.cue specs/lane/peer.cue specs/lane/target.cue specs/lane/lane.cue specs/lane/trustroot.cue specs/lane/provenance.cue specs/attest/attestation.cue specs/attest/artifact-record.cue
	cue export ./specs/lane -e '#Lane' \
	    --out jsonschema --force -o specs/lane.schema.json
	cue export ./specs/attest -e '#Attestation' \
	    --out jsonschema --force -o specs/attestation.schema.json
	cue export ./specs/trustlayers \
	    --out json --force -o specs/trust-layers.json

# Step 2: Generate Go types from the CUE lane schema.
# Uses gengotypes for now; will move to JSON Schema input once
# a JSON-Schema-to-Go generator is selected.
generate: specs
	cue exp gengotypes ./specs/lane
	cue exp gengotypes ./specs/spec
	sed -i 's#github.com/istr/strike/specs/#github.com/istr/strike/internal/#g' specs/lane/cue_types*gen.go specs/spec/cue_types*gen.go
	mkdir -p internal/spec
	mv specs/lane/cue_types*gen.go internal/lane/cue_types_gen.go
	mv specs/spec/cue_types*gen.go internal/spec/cue_types_gen.go

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
	cue fmt --check --files specs

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
