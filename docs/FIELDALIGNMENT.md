# Field Alignment

The field-ordering reference for strike structs. It is extracted from
`docs/CODE-STYLE.md` so that the pattern catalog stays lean; `AGENTS.md` cites
this file as `docs/FIELDALIGNMENT.md`. The pattern anchor in the catalog
(`docs/CODE-STYLE.md#fieldalignment-default`) carries the one-line rule and
points here for the full procedure.

**Rule.** Structs are declared in a field order the `fieldalignment` analyzer
(govet, run by `golangci-lint`) accepts as optimal. It measures two things,
and one order satisfies both:

- **Size.** No padding that another order would remove. Finding: "T has size
  N ... but the optimal size is M".
- **Pointer bytes.** The prefix the garbage collector scans, up to the end of
  the last pointer word, is as short as possible. Finding: "T has N leading
  bytes of pointer data but optimal value is M".

For JSON unmarshaling, the JSON tag does the mapping; field order is
irrelevant to behavior.

## Field classes on amd64/arm64

Strike runs only on 64-bit architectures (amd64, arm64). Every type that
contains a pointer is 8-aligned there; what places it is its trailing
non-pointer bytes, the bytes after its last pointer word.

| Class | Align | Size     | Trailing non-pointer bytes | Types                                                                                                             |
|-------|-------|---------:|---------------------------:|-------------------------------------------------------------------------------------------------------------------|
| P0    | 8     | 8 and up |                          0 | pointers (`*T`), maps, channels, funcs (8); interfaces (16); `time.Time` (24); structs whose last word is a pointer |
| P8    | 8     |       16 |                          8 | `string` and named strings                                                                                        |
| P16   | 8     |       24 |                         16 | slices (`[]T`)                                                                                                    |
| N8    | 8     |        8 |                         -- | `int64`/`uint64`/`float64`, `int`/`uint`/`uintptr`                                                                |
| N4    | 4     |        4 |                         -- | `int32`, `uint32`, `float32`, `rune`                                                                              |
| N2    | 2     |        2 |                         -- | `int16`, `uint16`                                                                                                 |
| N1    | 1     |        1 |                         -- | `bool`, `byte`, `int8`, `uint8`                                                                                   |

Both words of an interface are pointers, and the last word of `time.Time` is
its `*Location`. A struct-typed field takes the largest alignment of its
fields; its trailing non-pointer bytes are the bytes after its own last
pointer word.

**Declaration order.**

1. Pointer-containing fields first, ending with the one that has the most
   trailing non-pointer bytes -- in practice a slice if there is one, else a
   string. The order of the others changes neither measure; the canonical
   order is P0, then P8, then P16.
2. Then pointer-free fields by descending alignment: N8, N4, N2, N1.

Within a class any order passes; the analyzer's own suggestion puts larger
fields first.

## Strike-specific cheat sheet

The types that appear most often in this codebase:

- `*Lane`, `*Step`, `*AbsPath`, `*Duration` (any pointer) -> P0 (8 bytes)
- `map[string]string`, `map[primitive.Identifier]SecretSource` -> P0 (8 bytes)
- `error`, `lane.Peer`, `lane.DeployMethod`, `container.Engine`
  (interfaces) -> P0 (16 bytes)
- `clock.Time` (an alias of `time.Time`) -> P0 (24 bytes)
- `endpoint.Address`, `lane.FulcioExtensions` (structs whose last word is a
  pointer) -> P0 (32 and 40 bytes)
- `string`, `Host`, `AbsPath`, `Identifier`, `Timestamp` (named strings) ->
  P8 (16 bytes)
- `[]byte`, `[]string`, `[]Step`, `[]Peer` -> P16 (24 bytes)
- `int64` -> N8 (8 bytes)
- `bool` (e.g. `ForceRun`, `Active`) -> N1 (1 byte)

## Example 1 -- mixed primitives

**Bad** (14 bytes of padding; size 40, optimal 32):

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
    Name     string  // P8: 16 bytes
    Duration int64   // N8: 8 bytes
    Failed   bool    // N1: 1 byte
    Active   bool    // N1: 1 byte (+6 trailing pad to align next struct)
}
```

## Example 2 -- slices, interfaces, pointers

**Bad** (72 leading pointer bytes, optimal 48):

```go
type StepRecord struct {
    Active   bool                    // N1: 1 byte (+7 pad)
    Defaults *LaneDefaults           // P0: 8 bytes
    Steps    []Step                  // P16: 24 bytes
    Name     string                  // P8: 16 bytes
    Peer     lane.Peer               // P0: 16 bytes (interface)
}
```

**Good** (48 leading pointer bytes):

```go
type StepRecord struct {
    Peer     lane.Peer               // P0: 16 bytes
    Defaults *LaneDefaults           // P0: 8 bytes
    Name     string                  // P8: 16 bytes
    Steps    []Step                  // P16: 24 bytes, last pointer-containing field
    Active   bool                    // N1: 1 byte
}
```

## Example 3 -- optional fields (pointers)

Optional fields use `*T` regardless of T's size. A pointer is always 8 bytes
(class P0); it does not inherit the size of what it points to.

```go
type Step struct {
    Env      map[string]string    // P0: 8 bytes (map pointer)
    Image    *ImageRef            // P0: 8 bytes (pointer to string-typed alias)
    Workdir  *AbsPath             // P0: 8 bytes
    Timeout  *Duration            // P0: 8 bytes
    Name     string               // P8: 16 bytes
    Args     []string             // P16: 24 bytes, last pointer-containing field
    ForceRun bool                 // N1: 1 byte
}
```

Note: `*AbsPath` is 8 bytes even though `AbsPath` itself (a string) is 16
bytes. The pointer is the field, not the pointee.

## Example 4 -- struct-typed fields

A struct field is classed by its own layout, not by its size. Ordering this
decode struct by size alone (`Extensions`, `Issuer`, the strings, `Trust`)
ends it in a pointer: 128 leading pointer bytes instead of 120.

```go
type alias struct {
    Trust      *endpoint.Certificate // P0: 8 bytes
    Issuer     endpoint.Address      // P0: 32 bytes (last word is a pointer)
    Extensions FulcioExtensions      // P0: 40 bytes (five pointers)
    Audience   string                // P8: 16 bytes
    Identity   primitive.StringOrURI // P8: 16 bytes
    Token      primitive.Identifier  // P8: 16 bytes, last pointer-containing field
}
```

## CUE-generated types

Files like `internal/lane/lane.gen.go` are produced by `cue exp gengotypes`.
`golangci-lint` skips generated files, so `make lint` never reports a
generated struct; the standalone analyzer (see Discovery) does. To fix one:

1. The fix is in the CUE schema (e.g., `contract/lane/lane.cue` or
   `contract/primitive/scalars.cue`), not in the generated `.go` file.
2. The generator emits Go fields in the declaration order of the CUE
   definition. Reorder fields in the `.cue` source.
3. Run `make generate`. Verify the regenerated Go matches the new order and
   that the standalone analyzer no longer reports the struct.
4. Never edit `*.gen.go` directly. The next `make generate` overwrites the
   change. See `docs/CUE-WORKFLOW.md`.

## Decision procedure when writing a new struct

1. List the fields with their Go type.
2. Assign each field a class from the table above.
3. Pointer-containing fields first: P0, then P8, then P16. The last of them
   must be one with the most trailing non-pointer bytes.
4. Then pointer-free fields: N8, N4, N2, N1.
5. Within a class, operator choice (typically: identifier-like fields first,
   flags last).

If the result still triggers `golangci-lint`, the order the analyzer suggests
is authoritative. Apply it. The finding itself carries only the measured and
the optimal byte counts; Discovery shows how to print the order.

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
    Body           string `json:"body"`           // P8: 16 bytes
    LogID          string `json:"logID"`          // P8: 16 bytes
    IntegratedTime int64  `json:"integratedTime"` // N8: 8 bytes
    LogIndex       int64  `json:"logIndex"`       // N8: 8 bytes
}
```

**Rationale.** `json.Unmarshal` is tag-driven; declaration order has no effect
on which JSON field maps to which Go field. The justification "matches the API
response" is factually wrong about `Unmarshal`. The cost of misaligned fields
is real (more memory per instance, worse cache density); the benefit of
mirrored declaration order is zero.

## Discovery

`golangci-lint run ./...` -- look for `fieldalignment:` findings. A finding
names the struct and the two byte counts but prints no order. To see the
order, run the standalone analyzer with a diff preview, which writes nothing:

```sh
go run golang.org/x/tools/go/analysis/passes/fieldalignment/cmd/fieldalignment -fix -diff ./internal/lane/
```

The preview drops field comments; carry them over by hand. It also lists the
generated structs `make lint` skips. Never run it with `-fix` alone: that
rewrites every flagged struct in the package, generated files included.

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
