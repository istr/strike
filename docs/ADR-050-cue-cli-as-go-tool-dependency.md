# ADR-050: Build-toolchain -- the cue CLI as a go.mod tool dependency

## Status

Accepted.

## Context

The CUE toolchain was installed twice: the `cue` CLI binary and the
`cuelang.org/go` Go API required by go.mod, kept in sync by hand. The CLI was
invoked only from the Makefile (schema export, `gengotypes`, `fmt --check`).
`gengotypes` lives under `cuelang.org/go/internal/` and is reachable only
through `cmd/cue`, so the CLI cannot be dropped outright.

## Decision

`cuelang.org/go/cmd/cue` is a go.mod `tool` dependency, MVS-unified with the
`cuelang.org/go` library so the CLI and API cannot drift. Codegen, the JSON
Schema exports, and `fmt --check` run through `go tool cue`, `go generate`
driven from `contract/generate.go`. Export and fmt-check are NOT reimplemented
on the public CUE API: `go tool cue export`/`fmt` reproduce the outputs exactly,
and calling the pinned tool is less code than a reimplementation. The
gengotypes post-processing (import rewrite, package rename, bare-import repair,
move) folds into the main-module `tools/genenums` command, whose separate
`go.mod` is removed.

## Consequences

The hand-installed `cue` binary is gone; `make generate`/`fmt` need only the
pinned module. `cmd/cue` pulls build-time-only indirect dependencies
(`tetratelabs/wazero`, `coder/websocket`) into the module graph; they are not
linked into the shipped controller. Spawning `cue` at build time is outside the
runtime-controller no-exec invariant, which binds only the attested runtime
path.

## Principles

Code is liability; Meaning is single-sourced; CUE first.
