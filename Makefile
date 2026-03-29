.PHONY: generate schema

build: generate
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o strike ./main.go

# Go-Structs aus CUE generieren
generate: pipeline/schema.cue
	cue exp gengotypes ./pipeline/

# Export JSON schema for IDE support
schema:
	cue export ./pipeline/schema.cue \
	    --out openapi                 \
	    -o pipeline/schema.json
