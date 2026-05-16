# ADR-027: Subpath Selection on Inputs

## Status

Accepted. Resolves the "subpath selection on inputs" deferral
recorded in [ADR-026](ADR-026-containers-as-sole-inter-step-storage.md)
under "What is deferred". Refines but
does not supersede [ADR-011](ADR-011-sources-elimination.md). The
implementation path it relies on is the inter-step storage model
established in [ADR-026](ADR-026-containers-as-sole-inter-step-storage.md).

## Context

[ADR-011](ADR-011-sources-elimination.md) made every data flow into a
step enter through an `InputEdge` from a previous step's `OutputSpec`,
and `lane.Build` enforces mount disjointness so two input mounts
within the same step cannot nest. The motivation was structural:
every input is content-addressed, every input is visible in the DAG,
no host filesystem leaks past validation.

The disjointness rule has one well-known consequence. A step that
wants pieces of a single source artifact at non-overlapping container
paths has no way to express that directly. The current canonical
answer is an intermediate extract step that copies (or repackages)
the wanted pieces into new artifacts whose outputs the consumer
mounts separately. The shape is the `extract_npm_files` step in
`cmd/strike/testdata/hugo.yaml`:

```yaml
- name: extract_npm_files
  image: docker.io/library/busybox@sha256:...
  args: [cp, /src/package.json, /src/package-lock.json, /out/]
  inputs:
    - { name: tree, from: source.tree, mount: /src }
  outputs:
    - { name: package_json, type: file, path: /out/package.json }
    - { name: package_lock, type: file, path: /out/package-lock.json }

- name: npm_install
  image: docker.io/hugomods/hugo:debian-ci-non-root@sha256:...
  args: [npm, ci, --ignore-scripts, --no-bin-links]
  workdir: /out
  inputs:
    - { name: pkg,  from: extract_npm_files.package_json, mount: /out/package.json }
    - { name: lock, from: extract_npm_files.package_lock, mount: /out/package-lock.json }
  outputs:
    - { name: node_modules, type: directory, path: /out/node_modules }
```

This works, but the cost is concrete:

- An additional container start per source-tree access pattern.
- An additional output wrapped as an OCI image and loaded into the
  engine store, with its own manifest, config, and layer.
- An additional spec hash and provenance record for what is
  fundamentally a projection of an existing artifact.
- The extract step's content is structurally a subset of its input,
  but the type system cannot express that subset relationship: the
  extract output is, to downstream consumers, an independent
  artifact whose digest no longer ties back to the source. A
  verifier sees `extract_npm_files.package_json` as a separate
  content address, not as "byte-for-byte a slice of `source.tree`".

In-place builders (npm, pip, cargo, go mod, bundler, gem) make this
pattern recur. Each of them takes one or two declarative input files
(`package.json` + lockfile; `pyproject.toml` + lock; `Cargo.toml` +
`Cargo.lock`; `go.mod` + `go.sum`) from a working tree and writes
side-channel state alongside them (`node_modules`, `.venv`, `target`,
etc.). Under strike's read-only-inputs + writable-output discipline,
the declarative files must appear inside the writable output
directory, and the side-channel becomes the declared output. Today
each such builder needs a dedicated extract step.

The same review surfaced a second concern. The existing `#InputRef`
carries a `name` field whose role is "local identifier within the
consuming step". On inspection, this identifier is never read by
anything that needs it to be a name: the disjointness check uses the
mount path, the cache key already incorporates mount and `from`, the
executor identifies an input by its mount in container space, and
lane authors choose arbitrary strings (`tree`, `pkg`, `binary`) that
add no information the operator could not read from `mount`
directly. Carrying a mandatory field that no consumer needs is an
instance of "code is liability" inverted at the schema layer: the
field forces every lane author to choose a name, every test fixture
to spell one out, and every diagnostic that references "input X" to
disambiguate against a value the operator never thinks in terms of.

[ADR-026](ADR-026-containers-as-sole-inter-step-storage.md)
flagged the subpath gap under "What is deferred":

> Subpath selection on inputs so a step can mount one file from a
> multi-file producer image without an intermediate extract step.
> Own ADR.

Two real-world artifacts forced the question now:

- The hugo fixture in `cmd/strike/testdata/hugo.yaml` carries an
  `extract_npm_files` step purely to project two files out of the
  source tree, and three `name:` fields whose values are read by
  nothing.
- The website-deployment lane drafted alongside the strike work
  would benefit from the same projection without inflating the step
  count or the attestation chain.

## Decision

`#InputRef` is restructured in two parts:

- The `name` field is removed. An input is identified within its
  step by its `mount` path, which is unique per step by virtue of
  the existing disjointness rule.
- A new optional `subpath` field is added. When present, only the
  named path within the producing step's output is mounted at the
  input's container path. When absent, the existing behaviour is
  preserved: the entire output is mounted.

```cue
#InputRef: {
    @go(InputRef)
    from:     string @go(From)
    subpath?: #InputSubpath @go(Subpath)
    mount:    #ContainerPath @go(Mount)
    digest?:  #Digest @go(Digest,type=*Digest)
}

// A clean relative path within a producer output. No leading slash,
// no trailing slash, no "." or ".." segments, no empty segments.
// Used to select a single file or subdirectory of a directory or
// image output for mounting into a consumer step.
#InputSubpath: string &
    =~"^[^/]" &            // no leading slash
    !~"//" &               // no double slashes
    !~"^\\.\\.($|/)" &     // no leading ".."
    !~"/\\.\\.($|/)" &     // no embedded ".."
    !~"^\\.($|/)" &        // no leading "."
    !~"/\\.($|/)" &        // no embedded "."
    !~".+/$"               // no trailing slash
```

`subpath` is interpreted relative to the source artifact's content
root:

- For a `directory` output, the subpath is relative to the
  directory's root. A subpath that names a regular file selects
  that file; a subpath that names a subdirectory selects that
  subdirectory.
- For an `image` output, the subpath is relative to the image's
  root filesystem (`/` is the rootfs root). This is the only
  structural difference from the `directory` case, and it is the
  natural one: an image output's content root *is* the rootfs
  root, whereas a directory output's content root is the directory
  it produced.
- For a `file` output, declaring `subpath` is rejected at
  `lane.Build` time. A file output has no internal structure to
  select within; the operator should reference the producer output
  without a subpath.

If the named subpath does not exist in the producer output, the
consumer step fails at mount construction with a clear message
naming the producer step, output, and the missing subpath. This is
a runtime error, not a build-time error: the producer's content is
not knowable until the producer has run, and a static manifest of
producer contents would either drift from reality or constrain
producers unnecessarily.

`lane.Build` enforces mount disjointness with one explicit
clarification: disjointness is evaluated on container mount paths,
not on producer paths. Two inputs that both reference `source.tree`
are accepted iff their `mount:` paths are disjoint per the existing
rule in ADR-011. Two inputs from the same producer mounted at
`/out/package.json` and `/out/package-lock.json` are accepted
(sibling mount paths). Two inputs from the same producer mounted at
`/out/x` and `/out/x/y` are rejected for the same reason as before
(nested mount paths in the consumer container). The disjointness
check does not look at the producer side; whether two consumer
inputs draw from overlapping producer subpaths is the operator's
concern and structurally harmless, since both mounts are read-only
against independent target paths.

The cache key for a consuming step incorporates each input's
`(from, mount, subpath)` triple. The `name` term that was part of
the previous spec-hash is gone; `subpath` takes its place. Two
consumer steps that differ only by which subpath they select from
the same producer produce different cache keys and are
independently cacheable.

The lane's archetypal example becomes:

```yaml
- name: source
  image: alpine/git@sha256:...
  args: [git, clone, --depth, "1", "https://...", /out/tree]
  outputs:
    - { name: tree, type: directory, path: /out/tree }

- name: npm_install
  image: docker.io/hugomods/hugo:debian-ci-non-root@sha256:...
  args: [npm, ci, --ignore-scripts, --no-bin-links]
  workdir: /out
  peers:
    - { type: oci, registry: docker.io }
    - type: https
      host: registry.npmjs.org
      trust: { mode: cert_fingerprint, fingerprint: sha256:... }
  env:
    npm_config_cache: "/tmp/.npm"
  inputs:
    - from: source.tree
      subpath: package.json
      mount: /out/package.json
    - from: source.tree
      subpath: package-lock.json
      mount: /out/package-lock.json
    - from: source.tree
      subpath: packages
      mount: /out/packages
  outputs:
    - { name: node_modules, type: directory, path: /out/node_modules }
```

The `extract_npm_files` step is no longer required for this
pattern. The producing `source` step runs once; three
subpath-bearing input edges fan out from its single output.

## Consequences

- `#InputRef` becomes a three-or-four-field type instead of
  four-or-five. Removing `name` is a structural simplification
  that pre-existed the subpath motivation but became visible
  during it: a schema field whose value is read by nothing was
  carrying load it did not earn.
- The schema gains one optional field (`subpath`). Existing lanes
  that do not use `subpath` are unaffected at the semantic layer
  (parsing, DAG build, execution, cache, attestation behave
  identically modulo the `name` removal).
- Every existing lane YAML that declares inputs must have the
  `name:` key removed from each input entry. This includes
  `cmd/strike/testdata/hugo.yaml`,
  `cmd/strike/testdata/deploy_lane.yaml`,
  `cmd/strike/testdata/fan_out_lane.yaml`,
  `cmd/strike/testdata/hugo_like_lane.yaml`,
  `cmd/strike/testdata/image_from_lane.yaml`,
  `cmd/strike/testdata/pack_lane.yaml`, and any further fixture
  under `internal/lane/testdata` or similar locations. A grep over
  `inputs:` blocks under `cmd/strike/testdata` and `internal/lane`
  surfaces the candidates exhaustively at instruction time.
- The `extract_npm_files` step in `cmd/strike/testdata/hugo.yaml`
  becomes unnecessary for its current purpose. The fixture is
  updated to use subpath selection on `npm_install` directly and
  thereby exercises the new feature end-to-end through
  `TestProvenanceCapture_EndToEnd` and any integration tests that
  cover the npm-install pattern.
- `InputEdge.LocalName` is removed alongside `InputRef.Name`. The
  edge identifies its input by `Mount` in diagnostics; the
  existing mount-disjointness error message changes from
  `input mounts %q (input %q) and %q (input %q) overlap` to
  `input mounts %q and %q overlap`. Other error sites that
  previously printed `LocalName` (`buildInputMounts`, the input
  resolver in `lane.Build`) switch to printing `Mount` or the
  `(from, subpath)` pair, whichever is more diagnostic at the
  call site.
- Tests that asserted on `LocalName` are rewritten to assert on
  `Mount` or, where applicable, on `Subpath`. The expected count
  is small: `dag_edges_test.go` has a direct `LocalName` check,
  and the executor's mount-construction tests in `run_test.go`
  exercise input-edge values.
- The intermediate-extract pattern remains valid for cases that
  need transformation rather than projection. Subpath selection
  only handles "give me a named subset of an existing artifact";
  if the consumer needs different content (rewritten, recompressed,
  re-permissioned, filtered), it still wants a containerized step
  that performs the transformation and produces a new artifact.
- The implementation does not introduce a new transport mechanism.
  Under [ADR-026](ADR-026-containers-as-sole-inter-step-storage.md),
  the producer's output already lives in the engine's image store
  as a wrapped OCI image, and the consumer mount is constructed
  from the ephemeral-container rootfs of that image. Constructing
  a mount from a path inside that rootfs is a refinement of the
  existing mount strategy, not a new mechanism. The change lives
  in `buildInputMounts` and the `InputEdge` type.
- Attestation is unchanged at the trust-anchor level: the input
  edge still references the producer step and its output, and the
  producer's digest still represents the full artifact. The
  subpath becomes part of the edge metadata recorded in the
  consumer's spec hash and provenance record. A verifier
  reconstructing the input chain sees the producer artifact's full
  digest plus the selected subpath, which is strictly more
  information than the extract pattern provides (where the
  projection is performed by arbitrary container code and the
  verifier sees only the projected artifact's digest).
- Spec-hash inputs change shape: where the previous hash
  incorporated `(name, from, mount)` per input, the new hash
  incorporates `(from, mount, subpath)` (with `subpath` as the
  empty string when the field is absent). Every existing lane's
  spec hash changes on this update; in pre-beta this invalidates
  no production cache.
- Validation moves error reporting earlier where possible: the CUE
  regex rejects malformed subpaths at parse time; `lane.Build`
  rejects `subpath` on a file output; mount construction reports
  missing subpaths with the producer's step name and output name
  in the message. The disjointness rule and its diagnostics
  remain unchanged in spirit: the check still operates on
  consumer mount paths and rejects nesting. ADR-011's guidance
  ("compose them in a pack step when paths overlap in the
  consumer") still applies for the overlapping case; subpath
  selection is the answer for the disjoint case where the
  operator previously had to extract.

## Principles

- **External references are digest-pinned.** The producer's full
  digest remains the trust anchor; subpath narrows which bytes
  inside that anchor become visible to the consumer, without
  introducing any reference whose authority is not derived from a
  signed digest.
- **Code is liability.** One new optional field (`subpath`), one
  mandatory field removed (`name`), one refinement to mount
  construction, no new transport, no new package. The class of
  extract-only steps that previously paid full container + image
  + provenance overhead for a projection collapses into edge
  metadata.
- **Reproducibility is enforced.** `(from, mount, subpath)` is the
  cache-key shape; identical triples resolve to identical content;
  differing triples are different inputs. No silent dedup, no
  cache collision between two consumers that select different
  slices of the same producer.
- **CUE first.** The field changes are made in `specs/lane.cue`
  first, `cue exp gengotypes` regenerates
  `internal/lane/cue_types_lane_gen.go`, and Go implementation
  follows. The CUE regex is the canonical acceptance criterion
  for the field's shape; the Go side adds the output-type and
  existence checks the regex cannot express.
