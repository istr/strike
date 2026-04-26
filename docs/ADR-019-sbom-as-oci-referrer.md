# ADR-019: SBOMs as OCI 1.1 Referrer Artifacts

## Status

Accepted.

## Context

A signed image asserts "this artifact came from this build". A
signed SBOM asserts "this artifact contains these components". Both
are needed for supply-chain accountability, and both have to live
*somewhere*. Options that have circulated in the ecosystem:

- *Embedded in the image*. The SBOM is a file inside one of the
  image's layers. Discoverable only by extracting and looking; not
  signed independently; mutates the image's content for the sake of
  describing it.
- *Cosign tag convention*. A separate image at
  `<repo>:sha256-<hex>.att` contains the SBOM. Discoverable by tag
  pattern matching; works with any registry; predates the OCI 1.1
  referrers API.
- *OCI 1.1 referrers API*. An artifact whose `subject` field points
  at the original image's manifest. Discoverable through the
  registry's `/v2/<name>/referrers/<digest>` endpoint; requires a
  registry that implements the OCI 1.1 spec; the canonical solution
  going forward.

The cosign tag convention is the path of least resistance for older
registries; the referrers API is the right answer for any registry
that supports it. Using the referrers API as primary, with cosign
tag convention as fallback, gives both forward-looking correctness
and current-day operability.

The format of the SBOM itself is a separate question. CycloneDX and
SPDX are the two widely-deployed standards. CycloneDX 1.6 (the
current version at time of decision) has better tooling support in
the Go ecosystem and is the format the Sigstore tooling defaults to;
SPDX is more common in regulated-industry contexts. Strike uses
CycloneDX as its primary format and is structured to support SPDX
parsing of base-image SBOMs (because the upstream image might have
been built with either).

## Decision

Strike attaches SBOMs to the images it produces as OCI 1.1 referrer
artifacts. The SBOM is in CycloneDX 1.6 JSON format, with the
artifact type `application/vnd.cyclonedx+json`. The referrer's
`subject` field points at the digest of the image being described.

When packing an image, strike:

1. Generates the CycloneDX SBOM from the binary's Go module
   buildinfo (`debug/buildinfo`) and the base image's components
   (recursively read from the base's own SBOM, if it has one).
2. Pushes the SBOM as a new artifact, with the image manifest
   digest as its subject.
3. Signs the SBOM artifact with the same key used for the image,
   producing a separate signature also attached as a referrer.
4. Submits the SBOM signature to Rekor (per ADR-013).

When deploying or verifying, strike resolves base-image SBOMs in
this order:

1. **Referrers API**. Query `remote.Referrers(digestRef)` for any
   manifest whose `artifactType` is one of
   `application/vnd.cyclonedx+json`, `application/vnd.cyclonedx`,
   `application/spdx+json`, or `application/vnd.syft+json`.
2. **Cosign tag fallback**. If the referrers API returns no
   matches, check for the `<repo>:sha256-<hex>.att` tag and parse
   its content.
3. **No SBOM**. Both lookups failing is non-fatal: strike emits a
   warning, generates an SBOM that lists only the binary's own
   components (not the base's), and proceeds. A consumer can detect
   this case by the absence of base-image components in the
   resulting SBOM.

Format support is asymmetric: strike *generates* CycloneDX only,
but *parses* CycloneDX and SPDX when reading base-image SBOMs. This
matches the practical situation where strike-produced SBOMs are
under strike's control (one format suffices) but base images come
from arbitrary publishers (multiple formats must be tolerated).

## Consequences

- A registry that implements OCI 1.1 referrers gives strike
  consumers a clean, standardized discovery path: query the
  referrers endpoint, find SBOMs and signatures alongside the
  image without tag-pattern guessing.
- A registry that does not implement referrers still works, with
  one extra HEAD request per lookup to check the tag fallback.
  When all major registries support referrers (OCI 1.1 is final),
  the fallback can be retired.
- The SBOM is content-addressed via its own digest and signed
  independently. A tampered SBOM is detectable without inspecting
  the image; a tampered image is detectable without inspecting the
  SBOM. Both remain linked through the `subject` reference and
  through their independent presence in Rekor.
- Base images without SBOMs degrade gracefully. The deploy proceeds
  with a strike-only SBOM; the resulting attestation records that
  the base components were not enumerable, which is information a
  consumer can act on.
- The CycloneDX-only generation path is one less code path than
  supporting both formats. SPDX support could be added if a
  consumer requires it, but is not currently a use case.

## Principles

- Runtime is attested (SBOM is part of the artifact's runtime
  context, signed and submitted to the same transparency log)
- External references are digest-pinned (subject reference is the
  manifest digest of the described image)
- Identity is asymmetric (SBOM signature is separate from image
  signature, both verifiable independently)
- Code is liability (one generation format, two parse formats,
  matches actual deployment realities without speculative
  symmetry)
