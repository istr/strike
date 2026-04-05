.PHONY: build specs generate golden lint test integration vuln check

build: generate
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o strike ./cmd/strike

# --- Schema pipeline: CUE -> JSON Schema -> Go/Rust types ---

# Step 1: Export CUE specs to JSON Schema.
# These JSON Schema files are the cross-implementation contract that
# both the Go and (future) Rust validators build from.
specs: specs/lane.cue specs/attestation.cue
	cue export ./specs:lane -e '#Lane' \
	    --out jsonschema --force -o specs/lane.schema.json
	cue export ./specs:deploy -e '#Attestation' \
	    --out jsonschema --force -o specs/attestation.schema.json

# Step 2: Generate Go types from the CUE lane schema.
# Uses gengotypes for now; will move to JSON Schema input once
# a JSON-Schema-to-Go generator is selected.
generate: specs
	cue exp gengotypes ./specs:lane
	mv specs/cue_types_lane_gen.go internal/lane/cue_types_lane_gen.go

# Update golden test fixtures (run after intentional changes to sign/pack/digest).
golden:
	go test ./internal/executor/ -run Golden -update -count=1
	@echo "golden fixtures updated -- commit if changes are intentional"

# --- Quality gates ---

lint:
	golangci-lint run ./...

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
