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
