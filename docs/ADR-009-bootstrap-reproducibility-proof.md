# ADR-009: Bootstrap Reproducibility Proof via Stage 2 / Stage 3 Binary Equality

## Status

Accepted.

## Context

Reproducibility is asserted by `DESIGN-PRINCIPLES.md` as a property of
strike's outputs: byte-identical inputs must produce byte-identical
artifacts. Without a continuous proof of this property, it degrades
into an aspiration. Distributions handle this with reproducible-builds
infrastructure (rebuilders, comparison toolchains, attestation
networks). A small project does not have that infrastructure but can
still prove the property end-to-end on its own artifact: itself.

The trick is the diverse-double-compilation pattern adapted to a
bootstrap context. If strike can build itself, and the resulting
binary can build itself again, and the second-pass binary is
byte-identical to the first-pass binary, then the build is
reproducible at the level that matters most: the level that matters
for trust in the tool that signs everything else.

## Decision

The bootstrap process executes four stages:

1. **stage_0** (Containerfile, fetched by commit SHA): a minimal
   builder image with Go and CUE, fetches a pinned commit, generates
   types from CUE, builds the strike binary with
   `CGO_ENABLED=0 -trimpath -ldflags="-s -w"`.
2. **stage_1** (image produced by stage_0): contains the strike
   binary plus rootless podman. This is the "dirty" stage in two
   senses noted in `bootstrap/Containerfile`: legacy Containerfile,
   and one residual shell expansion for `${GIT_COMMIT}` in the git
   fetch step.
3. **stage_2** (image produced by `lane.yaml` running inside
   stage_1): rebuilds the strike image from source using strike
   itself.
4. **stage_3** (image produced by `bootstrap/lace.yaml` running
   inside stage_2): rebuilds again, producing what should be a
   byte-identical image.

The bootstrap lane verifies `stage_2 == stage_3` by manifest digest.
Equality is the reproducibility proof. If the digests differ, the
build is non-reproducible and the lane fails before publishing.

## Consequences

- Reproducibility cannot rot silently. Any change that introduces
  non-determinism (a timestamp, an unsorted iteration, a
  build-time `time.Now()`) breaks the bootstrap and is caught
  immediately.
- The path to fix the residual `${GIT_COMMIT}` shell expansion is
  to rebuild stage_1 once strike itself can fetch a commit (e.g.
  via a containerized git step), eliminating the last shell-touched
  surface in the bootstrap.
- Operators who do not trust strike-the-tool can run the bootstrap
  locally and compare digests against the published artifact. Trust
  in strike reduces to trust in the stage_0 Containerfile and one
  pinned base image.
- This pattern is intentionally similar to the
  diverse-double-compilation arguments used to defend against
  trusting-trust attacks.
  It does not provide that defense (only diverse compilers do), but
  it provides a pattern that scales there if and when a second-
  implementation strike emerges.

## Principles

- Reproducibility is enforced, not hoped for
- External references are digest-pinned (Containerfile fetched by
  commit SHA, base images by manifest digest)
- No shell (the residual shell expansion is documented as a debt to
  be retired, not a permanent compromise)

## Amendment 2026-09-14 -- the proof runs as a sibling; stage_3 is a cache-bypassed second build; three checks replace one

Status: Accepted (item-0155). Append-only: this block replaces the mechanism of the
Decision and three sentences of Context and Consequences by the readings
given at its end, without editing them in place; the title, the Status, the
Principles and every clause not named below stand unchanged.

### What was found

A review of 2026-09-14 (item-0155) found that the mechanism above cannot
run and that the compare it names cannot be written. The stage_2 image the
bootstrap lane packs is a static base plus the binary and carries no
engine; a strike inside it could build only if a step container reached
the stage_1 engine or started one of its own, and both are excluded by the
non-configurable step profile of ADR-005 and by ADR-055 D5. Three documents
described three different topologies for stage_3, which is how the gap
stayed hidden. Independently, an image output is addressed by its
producing step and has no output name (ADR-046), so no lane can mount two
images into a step that compares them; `strike compare` compares files and
cannot be fed two step images.

The single nesting of stage_1 -- an engine inside the operator-started
container -- was then weighed and retired by ADR-055 D9. The decisive
reason is recorded there: nesting enlarges the trusted computing base by
an engine image nobody attests, without taking the operator's engine out
of it, while the isolation boundary between a step and the control plane
is the same in both topologies.

### The amended mechanism

1. **stage_0** keeps its role: `bootstrap/Containerfile`, fetched by commit
   SHA, builds the strike binary from the pinned tree with the same
   reproducibility flags and the same toolchain lock as the lane's build
   step. Its second stage is a digest-pinned static base carrying the
   binary and the pinned tree. No image the tree builds installs an engine.
2. **stage_1** is that image, run by the operator's engine invocation as a
   sibling of its steps: the engine socket bound at the run line, the
   engine named through `CONTAINER_HOST`, host networking and the
   keep-id mapping -- the mechanism ADR-055 D3 measured for the executor's
   container (M2, M3), with a different image and no shell. The image's
   command names the lane file it runs explicitly. The run line is
   item-0156's measurement; the lane is item-0150's.
3. **stage_2** is the image the lane's first build produces: a source step
   fetches the pinned commit in a digest-pinned git image with a declared,
   anchored peer and a git provenance record (ADR-011; item-0157); a build
   step compiles the binary in the pinned Go image with the toolchain
   locked to that image; a pack step assembles the image in the control
   plane.
4. **stage_3** is the image the same lane produces a second time, in the
   same run, by the same control plane, with the cache bypassed
   (`forceRun`). It is no longer built by a strike inside stage_2.
5. The lane verifies `stage_2 == stage_3` through a control-plane compare
   step (item-0158): a step kind of its own, executed without a container
   like pack, consuming the two producing steps, comparing the manifest
   digests the control plane computed and, for pack outputs, the canonical
   layout bytes it assembled, and emitting the agreed digest as a file
   output the deploy consumes. The compare is a predecessor of the deploy,
   as ADR-039 D5 requires of every gate step; a mismatch fails the run
   before any deploy. Equality remains the reproducibility proof.
6. Every leaf of the lane is a registry deploy under a keyless chain
   (ADR-039 D5, ADR-040). The deploy under the local harness chain is the
   workstation proof; the deploy under the public chain is the publish.
   Which lane file carries which is decided in item-0150.

### What the checks prove

The proof is three checks, not one, and each is named for what it can and
cannot show:

- **C1, the in-lane double build** (points 4 and 5). Proves that strike's
  orchestration is deterministic for one control plane on one engine, and
  that the output is identical whether or not the cache is used -- the
  literal form of the Isolated requirement of SLSA v1.2 Build L3. Catches a
  timestamp, an unsorted iteration, a `time.Now()`, a non-canonical layer.
  Does not show anything the engine or the host contributes identically to
  both builds, and does not show that the built strike can orchestrate.
- **C2, the cross-control-plane, cross-host rebuild** (item-0160). The
  released control plane, running as a sibling on the forge runner's
  engine, is the commit gate (ADR-055 D4, item-0063); on a release commit
  its plain `go build` step is packed with this lane's pack spec, and the
  digest must equal the one the bootstrap published for the same commit
  from the operator's endpoint. Proves independence from the
  control-plane binary (genesis-built against released), from the engine
  and from the host. This is where the self-hosting property of the
  original mechanism now lives: the tool that ships is the tool that
  builds the next release. Enforced by the release procedure from the
  second release on. Does not show independence from the toolchain image.
- **C3, the strike-free rebuild** (item-0160). The release procedure
  documents a run of the pinned Go image that executes the lane's build
  command against the tagged commit; the sha256 of the binary must equal
  the binary inside the released image. Needs a rootless engine and
  nothing else (ADR-055 D1). Proves that a distrusting operator can verify
  the release without executing strike. Does not show anything about the
  compiler.

None of the three is a defense against a trusting-trust attack. The
compare tests the orchestration, not the compiler, and it is meaningful
precisely because the Go toolchain is a fixed, externally verifiable
input: Go toolchains since 1.21 are bit-for-bit reproducible and
continuously verified upstream, and the toolchain images are pinned by
digest. An informational fourth comparison rides on that: once stage_0
and the lane build with the same flags and the same Go version, the
stage_1 binary (go.dev toolchain in the golang alpine image) and the
lane-built binary (a Wolfi-built toolchain) should agree -- two
independently built compilers of one version producing one output, the
cheapest toolchain diversity available. It is informational until
item-0062 aligns the two, and it is given up if the builder stage moves
onto the lane's toolchain image; item-0062 names that trade.

Reproducibility is a property strike enforces beyond SLSA Build L3, not a
part of it: the specification lists hermetic and reproducible builds under
future directions and requires from a Build L3 platform unforgeable,
control-plane-generated provenance and isolated, ephemeral, cache-safe
execution -- which the lane's deploy and ADR-005 provide independently of
this proof.

### The trusted computing base, named

Trust in the released binary reduces to: the builder image and the static
base of the Containerfile; the toolchain, static and git images of the
lane; the git installed into the builder stage from a distribution
repository without a pin (item-0151 decides the pin gate); the module
proxy and the checksum database the build step reaches as declared
peers; the source fetch from the forge, pinned by commit; and the
operator's engine, which starts the control plane and every step and is
inside the base in every topology. It does not include an engine image,
because there is none.

### Consequences

- `bootstrap/Containerfile` loses its engine stage, the third-party engine
  image at the root of the chain, the proc unmask and the tmpfs storage
  of the published run line (item-0062). The README run line takes the
  shape of the executor container's engine access and is corrected to
  what item-0156 measures.
- The residual `${GIT_COMMIT}` shell expansion stays a stage_0 debt: the
  Containerfile must still fetch the tree to compile it. From stage_2 on,
  the source enters only through the lane's fetch step, and the tree the
  Containerfile bakes is read for the lane file alone.
- `strike compare` and the host-write exemption it carries become
  redundant once the compare step exists; item-0158 retires them and
  item-0125 records the exemption's disappearance.
- Every record the bootstrap produces carries the operator's engine
  identity, like every other record; one builder id suffices (ADR-055 D9).
- SECURITY.md, README.md and the Containerfile header describe this
  mechanism, not the previous three.

**Supersedes, in Context above:** "If strike can build itself, and the
resulting binary can build itself again, and the second-pass binary is
byte-identical to the first-pass binary, then the build is reproducible at
the level that matters most: the level that matters for trust in the tool
that signs everything else." is read as: "If strike's own build, run
twice by one control plane with the cache bypassed on the second run,
yields byte-identical images, then strike's orchestration is
reproducible; and if the released strike, running elsewhere, and a plain
build in the pinned Go image reproduce the same digest and binary, then
that reproducibility does not depend on the control plane, the engine or
the host that produced the release."

**Supersedes, in Decision above, item 2:** "**stage_1** (image produced by
stage_0): contains the strike binary plus rootless podman." is read as:
"**stage_1** (image produced by stage_0): a digest-pinned static base
carrying the strike binary and the pinned tree, with no engine; it runs
as a sibling of its steps against the operator's engine." The rest of
item 2, on the "dirty" stage and the residual shell expansion, stands.

**Supersedes, in Decision above, item 3:** "(image produced by `lane.yaml`
running inside stage_1): rebuilds the strike image from source using
strike itself." is read as: "(image produced by the bootstrap lane's first
build, run by stage_1 on the operator's engine): rebuilds the strike image
from the pinned commit using strike itself."

**Supersedes, in Decision above, item 4:** "(image produced by
`bootstrap/lace.yaml` running inside stage_2): rebuilds again, producing
what should be a byte-identical image." is read as: "(image produced by
the same lane's second build in the same run, with the cache bypassed):
rebuilds again, producing what must be a byte-identical image."

**Supersedes, in Decision above:** "The bootstrap lane verifies `stage_2 ==
stage_3` by manifest digest." is read as: "The bootstrap lane verifies
`stage_2 == stage_3` through the control-plane compare step, by the
manifest digests the control plane computed and, for pack outputs, by
the canonical layout bytes it assembled."

**Supersedes, in Consequences above:** "Operators who do not trust
strike-the-tool can run the bootstrap locally and compare digests against
the published artifact. Trust in strike reduces to trust in the stage_0
Containerfile and one pinned base image." is read as: "Operators who do
not trust strike-the-tool rebuild the binary without strike, from the
tagged commit in the pinned Go image, and compare its sha256 with the
binary in the released image. Trust in strike reduces to the trusted
computing base named in the amendment of 2026-09-14."

**Supersedes, in Consequences above:** "This pattern is intentionally
similar to the diverse-double-compilation arguments used to defend
against trusting-trust attacks. It does not provide that defense (only
diverse compilers do), but it provides a pattern that scales there if and
when a second-implementation strike emerges." is read as: "This pattern
is a reproducibility proof of strike's orchestration, meaningful because
the compiler is a fixed, externally verified input. It does not defend
against a trusting-trust attack; that defense needs a second,
independently produced toolchain of the same version yielding the same
output, of which the informational stage_1-versus-lane comparison is the
first, weak form."
