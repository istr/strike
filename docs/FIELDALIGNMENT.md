# Field Alignment

The field-ordering reference for strike structs. It is extracted from
`docs/CODE-STYLE.md` so that the pattern catalog stays lean; `AGENTS.md` cites
this file as `docs/FIELDALIGNMENT.md`. The pattern anchor in the catalog
(`docs/CODE-STYLE.md#fieldalignment-default`) carries the one-line rule and
points here for the full procedure.

**Rule.** Structs are declared in fieldalignment-clean order: fields grouped
by descending alignment, within each group by descending total size. For JSON
unmarshaling, the JSON tag does the mapping; field order is irrelevant to
behaviour.

## Alignment groups on amd64/arm64

Strike runs only on 64-bit architectures (amd64, arm64). Go types fall into
six size/alignment groups:

| Group | Align | Total size | Types                                                        |
|-------|-------|-----------:|--------------------------------------------------------------|
| A     | 8     |   24 bytes | slices (`[]T`), `time.Time`                                  |
| B     | 8     |   16 bytes | `string`, interface types (`error`, `any`, named interfaces) |
| C     | 8     |    8 bytes | pointers (`*T`), maps, channels, funcs, `int64`/`uint64`/`float64`, `int`/`uint`/`uintptr` |
| D     | 4     |    4 bytes | `int32`, `uint32`, `float32`, `rune`                         |
| E     | 2     |    2 bytes | `int16`, `uint16`                                            |
| F     | 1     |    1 byte  | `bool`, `byte`, `int8`, `uint8`                              |

**Declaration order.** Group A first, then B, then C, then D, then E, then F.
Within a group, larger fields before smaller (relevant only inside group A for
`[]T` vs another `[]T`; all fields inside one of B/C/D/E/F are the same size).

Embedded structs inherit the alignment of their largest field; a struct
embedding a `time.Time` is group-A-aligned.

## Strike-specific cheat sheet

The types that appear most often in this codebase:

- `[]byte`, `[]string`, `[]Step`, `[]Peer` -> A (24 bytes)
- `time.Time` -> A (24 bytes)
- `string`, `Host` (named string), `AbsPath` -> B (16 bytes)
- `error`, `lane.Peer`, `transport.TLSTrust`, `DeployMethod`
  (interfaces) -> B (16 bytes)
- `*Lane`, `*Step`, `*AbsPath`, `*Duration` (any pointer) -> C (8 bytes)
- `map[string]string`, `map[string]SecretSource` -> C (8 bytes)
- `int64`, `Timestamp` -> C (8 bytes)
- `bool` (e.g. `ForceRun`, `Active`) -> F (1 byte)

## Example 1 -- mixed primitives

**Bad** (4 padding gaps, 32 bytes wasted of 40):

```go
type StepResult struct {
    Failed   bool    // 1 byte + 7 padding
    Duration int64   // 8 bytes
    Name     string  // 16 bytes
    Active   bool    // 1 byte + 7 trailing padding
}
```

**Good** (no padding gaps, 32 bytes):

```go
type StepResult struct {
    Name     string  // B: 16 bytes
    Duration int64   // C: 8 bytes
    Failed   bool    // F: 1 byte
    Active   bool    // F: 1 byte (+6 trailing pad to align next struct)
}
```

## Example 2 -- slices, interfaces, pointers

**Bad:**

```go
type StepRecord struct {
    Active   bool                    // F: 1 byte (+7 pad)
    Defaults *LaneDefaults           // C: 8 bytes
    Steps    []Step                  // A: 24 bytes
    Name     string                  // B: 16 bytes
    Trust    transport.TLSTrust      // B: 16 bytes (interface)
}
```

**Good:**

```go
type StepRecord struct {
    Steps    []Step                  // A: 24 bytes
    Name     string                  // B: 16 bytes
    Trust    transport.TLSTrust      // B: 16 bytes
    Defaults *LaneDefaults           // C: 8 bytes
    Active   bool                    // F: 1 byte
}
```

## Example 3 -- optional fields (pointers)

Optional fields use `*T` regardless of T's size. A pointer is always 8 bytes
(group C); it does not inherit the size of what it points to.

```go
type Step struct {
    Args     []string             // A: 24 bytes (slice)
    Name     string               // B: 16 bytes
    Env      map[string]string    // C: 8 bytes (map header)
    Image    *ImageRef            // C: 8 bytes (pointer to string-typed alias)
    Workdir  *AbsPath             // C: 8 bytes
    Timeout  *Duration            // C: 8 bytes
    ForceRun bool                 // F: 1 byte
}
```

Note: `*AbsPath` is 8 bytes even though `AbsPath` itself (a string) is 16
bytes. The pointer is the field, not the pointee.

## CUE-generated types

Files like `internal/lane/lane.gen.go` are produced by `cue exp gengotypes`.
If a generated struct triggers fieldalignment:

1. The fix is in the CUE schema (e.g., `contract/lane/lane.cue` or
   `contract/primitive/scalars.cue`), not in the generated `.go` file.
2. The generator emits Go fields in the declaration order of the CUE
   definition. Reorder fields in the `.cue` source.
3. Run `make generate`. Verify the regenerated Go matches the new order and
   that `golangci-lint run` is clean.
4. Never edit `*.gen.go` directly. The next `make generate` overwrites the
   change. See `docs/CUE-WORKFLOW.md`.

## Decision procedure when writing a new struct

1. List the fields with their Go type.
2. Assign each field a group letter from the table above.
3. Sort by group (A, B, C, D, E, F).
4. Within group A, larger total size first (rarely matters in strike; most
   A-fields are 24 bytes).
5. Within other groups, operator choice (typically: identifier-like fields
   first, flags last).

If the result still triggers `golangci-lint`, the linter's suggested
"optimal" order in the error message is authoritative. Apply it.

**Bad** (declared in JSON-field-order to mirror an API response):

```go
var raw struct { //nolint:govet // field order matches API response
    Body           string `json:"body"`
    IntegratedTime int64  `json:"integratedTime"`
    LogID          string `json:"logID"`
    LogIndex       int64  `json:"logIndex"`
}
```

**Good:**

```go
var raw struct {
    Body           string `json:"body"`           // B: 16 bytes
    LogID          string `json:"logID"`          // B: 16 bytes
    IntegratedTime int64  `json:"integratedTime"` // C: 8 bytes
    LogIndex       int64  `json:"logIndex"`       // C: 8 bytes
}
```

**Rationale.** `json.Unmarshal` is tag-driven; declaration order has no effect
on which JSON field maps to which Go field. The justification "matches the API
response" is factually wrong about `Unmarshal`. The cost of misaligned fields
is real (more memory per instance, worse cache density); the benefit of
mirrored declaration order is zero.

## Discovery

`golangci-lint run ./...` -- look for `fieldalignment:` findings. The
suggested "optimal" struct in the linter message is the target.

## Allowed permanent exceptions

See the allowed-permanent-annotations table at the top of
`docs/CODE-STYLE.md`. Only `internal/executor.SETPayload` has a sanctioned
`//nolint:govet` for fieldalignment: that struct's field order is part of the
signed payload, so reordering would break the cross-implementation contract.
A field order that is signed and must stay byte-stable is the
`marshal-order-contract` pattern -- pin it with a reflection test rather than
trusting the suppression's prose. Adding any other permanent fieldalignment
exception requires an ADR.

## See also

- `docs/CODE-STYLE.md#fieldalignment-default` -- the catalog anchor and
  one-line rule.
- `docs/CODE-STYLE.md#marshal-order-contract` -- signed, byte-stable field
  order pinned by a reflection test.
- `AGENTS.md` -- the operative rule that this layout is consulted before
  declaring a struct, not after the linter flags it.
- `docs/CUE-WORKFLOW.md` -- fixing alignment on CUE-generated types.
