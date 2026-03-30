.PHONY: generate schema

build: generate
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o strike ./main.go

# Go-Structs aus CUE generieren
generate: lane/schema.cue
	cue exp gengotypes ./lane/

# Export JSON schema for IDE support
schema:
	cue export ./lane/schema.cue \
	    --out openapi                 \
	    -o lane/schema.json
