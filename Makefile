.PHONY: build generate schema lint test vuln check

build: generate
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o strike ./cmd/strike

# Go-Structs aus CUE generieren
generate: internal/lane/schema.cue
	cue exp gengotypes ./internal/lane/

# Export JSON schema for IDE support
schema:
	cue export ./internal/lane/schema.cue \
	    --out openapi                      \
	    -o internal/lane/schema.json

# --- Quality gates ---

lint:
	golangci-lint run ./...

test:
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
	@go tool cover -func=coverage.out | tail -1

vuln:
	govulncheck ./...

# Run all quality gates (CI entry point)
check: lint test vuln build
