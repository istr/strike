# Binding strike's per-artifact SBOMs to the image and the provenance -- ecosystem evidence and recommendation (as of 2026-11-15)

This survey was written on 2026-11-15, before [ADR-059](../ADR-059-sbom-sealed-digest-and-signed-statement.md)
was decided. It names the binding forms by what they do. Where ADR-059
decides differently, the record decides: it keeps SHA-256 as the only
hash of the sealed entries, publishes no SPDX document, and splits the
image SBOM into two hash-linked levels. The measurements taken after this
survey are in [the measurement record](adr-059-sbom-measurements.md).

**Bottom line: strike should seal the digest of every SBOM document it publishes into `runDetails.byproducts` of its SLSA Provenance statement (sealed digests), and also publish the whole-image SBOM pair as cosign-compatible signed in-toto attestations with the image as subject (signed SBOM statements, limited to the image-level pair). The raw referrers stay in place for scanners, and the verifier fails closed on any strike-annotated SBOM referrer that the provenance does not name.** The sealed digests alone are the smallest change that makes the project's documented claims true. Signed SBOM statements are what the ecosystem and the regulators' tooling expect by default. Both together, with a later reference from the release's verification summary, are a pioneer position that still uses only standard fields. Confidence: high on the sealed digests and on signed statements for the image-level pair; medium on the exact field for the sealed digests (byproducts versus the SLSA v1.3 draft's resolvedDependencies wording); medium-low on region SBOMs, where no ecosystem convention exists.

## TL;DR

- **Seal the digests now, in `runDetails.byproducts`.** Use `{name, digest:{sha256,sha512} of the document bytes, mediaType}`, one entry per SBOM document (2+2N). Name the document content digest, never a bundle or attestation-manifest digest: Sigstore bundles carry certificates, log entries and timestamps, so naming them would break the byte-identical sealed statement. This turns the SBOM claim of corollary C3 in the soundness note from false to true, with no new dependency and no new field type.
- **Add signed SBOM statements for the image-level CycloneDX + SPDX pair only.** Each document becomes a DSSE/in-toto statement with predicate types `https://cyclonedx.org/bom` and `https://spdx.dev/Document`, subject = the pushed manifest digest, pushed as a cosign-v3-style bundle referrer. Every relevant signal points the same way. cosign deprecated raw SBOM attachments and points to attestations.\[1\] GitHub folded attest-sbom into actions/attest.\[2\] The CISA-led 2026 Minimum Elements, co-sealed by BSI and ANSSI, add an "SBOM Author Signature" element, and BSI TR-03183-2 says SBOMs should ideally be signed.\[3\] It also closes strike's own asymmetry: a strike-built base image would then satisfy strike's base-SBOM rule.
- **The bigger regulatory gap is format, not signing.** BSI TR-03183-2 v2.1.0 accepts only CycloneDX >=1.6 or SPDX >=3.0.1, and wants SHA-512 hashes of deployable components.\[4\] strike's SPDX 2.3 output is therefore not TR-conformant. Under CRA, signing is not legally required today: Article 13(24) lets the Commission "specify the format and elements" of the SBOM by implementing act, and per sbomify's CRA guide "No such implementing act has been adopted." "CRA-ready" for strike means a TR-conformant, signed, artifact-bound, reproducible SBOM per released version.

## Key Findings

1. **SLSA texts (normative).**
   - SLSA v1.2 is the current approved version. The working draft (labeled "Draft (v1.3)") adds a Build L4 with "dependencies complete" and states that "a build-time SBOM MAY be referenced" in `resolvedDependencies` "at any build level" (with `uri`, `digest`, `mediaType`). At L4, verifiers "MUST follow the reference and validate the SBOM's digest" (slsa-framework/slsa PR #1646, issue #1531).\[5\]\[6\]
   - That text is about an SBOM as the *input/dependency record* of a build. strike's SBOMs are post-push catalogs of the *output*, so the objection that an output catalog is no dependency record survives the draft.
   - `byproducts` (unchanged since v1.0) is defined as "additional artifacts generated during the build that are not considered the 'output' of the build but that might be needed during debugging or incident response".\[5\] A deploy-time SBOM consumed for vulnerability response fits this reading better than any other field.
   - SLSA's `subject` is "the build process outputs".\[7\] Adding SBOMs there is permitted but changes the subject set that policy engines compare (see Conforma below).
   - The ResourceDescriptor offers `name`, `uri`, `digest`, `downloadLocation`, `mediaType`, `content`, `annotations`.\[8\] strike needs none of the omitted ones.
2. **cosign / Sigstore (shipped behavior).**
   - cosign's own docs mark `attach sbom` and `download sbom` deprecated: "support will be removed in a Cosign release soon after 2024-02-22 (see sigstore/cosign#2755). Instead, please use SBOM attestations." A secondary source reports that cosign v3.1.3 announces removal of the attach family for v4.0.0.\[9\]
   - cosign 3.x defaults to the bundle format.\[10\] Each signature or attestation is an OCI 1.1 referrer with `artifactType application/vnd.dev.sigstore.bundle.v0.3+json` and an *unsigned* `dev.sigstore.bundle.predicateType` annotation.\[11\]
   - Sigstore's own docs say SBOM predicate types "are not recommended" because the whole SBOM must be downloaded on every verification. They suggest attesting a path and hash instead.\[12\] This is the strongest counter-evidence to signed SBOM statements.
3. **Rekor v2 removes the payload-size objection for strike.**
   - Rekor v2 reached GA on 10 October 2025 (Sigstore blog "Rekor v2 GA", Hayden Blauzvern). It has "no attestation storage", and DSSE is now logged as `hashedrekord` over the PAE digest, so "the whole envelope is no longer sent".
   - The Sigstore blog post "sigstore.dev and Rekor evolution" (June 2026) says the public-good instance "will continue using Rekor v1 as the default log for the foreseeable future". Rekor v1's public instance documents a 100 KB attestation limit.
   - strike already writes to Rekor v2, so SBOM size limits move to the registry and the verifiers.
4. **Practice converges on "SBOM as signed attestation, subject = image digest".** GitHub (actions/attest, SBOM mode, 16 MB cap), Chainguard (`https://spdx.dev/Document` attestations per image), and Konflux/Tekton Chains (SBOM signed separately; `SBOM_BLOB_URL` result surfaced through provenance) all do this.\[13\]\[14\]\[15\]\[16\]\[17\]\[18\]\[19\] Docker BuildKit is the outlier: it uses unsigned in-toto attestation manifests inside the image index, linked by `vnd.docker.reference.digest`, which are not OCI referrers.\[20\]\[21\]\[22\]\[23\]\[24\]
5. **Bidirectional binding is partly occupied, not white space.** Konflux already carries an SBOM blob reference in Chains-signed provenance, and its tooling verifies SBOMs against the provenance digest.\[25\] What I found no shipped example of:
   - provenance and SBOM attestations sealed in one act, under one identity, with byte-reproducible SBOMs a verifier can recompute;
   - a verifier that fails closed on unbound SBOM referrers;
   - a VSA that names the SBOM attestations it approved.
6. **Regulation.**
   - CRA: SBOM required under Annex I Part II(1). Art. 13(24) lets the Commission "specify the format and elements" of the SBOM by implementing act; per sbomify's CRA guide, "No such implementing act has been adopted." Reporting obligations apply from 11 September 2026, full application from 11 December 2027.
   - BSI TR-03183-2 v2.1.0: CycloneDX >=1.6 / SPDX >=3.0.1, SHA-512 component hashes, "Ideally, SBOMs should be digitally signed".\[3\]\[4\]\[26\]\[27\]
   - CISA 2026 Minimum Elements (29 July 2026, co-authored with BSI, ANSSI, METI, CERT-In and others): new "SBOM Author Signature" and "Component Hash" elements, while stating they "do not create new requirements".\[28\]\[29\]
   - No text found requires a cryptographic SBOM-to-provenance link.

## Details

### A. Specification analysis

**A1 -- SLSA Provenance.**
- *Versions.* v1.0 introduced `byproducts` and the ResourceDescriptor fields `annotations`, `content`, `downloadLocation`, `mediaType`, `name`.\[5\] v1.1 and v1.2 kept the predicate type `https://slsa.dev/provenance/v1`, and minor versions are backward compatible by the parsing rules. The SLSA project's "Announcing SLSA v1.2" blog post (slsa.dev, 24 November 2025) announces the release and states that v1.2 "is backwards compatible with SLSA v1.1". The draft marked "v1.3" adds the L4 and SBOM-reference text quoted above. It is labeled "may be modified, replaced, or discarded at any time" (normative status: draft).\[7\]
- *Is a strike SBOM a subject, a byproduct or a dependency?*
  - Dependency: no. `resolvedDependencies` is "artifacts needed at build time".\[5\] Even the v1.3 draft's SBOM sentence makes the SBOM "the full dependency record", which strike's three-parser catalog does not claim to be.\[7\]
  - Subject: permitted but not recommended. It turns the provenance into a claim about SBOM bytes as primary outputs, and multi-subject policies such as Conforma's `subject_build_task_matches`, which checks every subject, would need to understand it.\[30\]
  - Byproduct: the best fit. It is generated by the build platform during the sealing act, it is not "the output", and it is needed for incident response.
- *Annotations.* The spec allows them, but nothing requires them. `name` + `digest` + `mediaType` carry everything strike needs, so the no-open-maps rule holds.
- *Side finding at the same freeze event.* At the anchor strike emits each artifact (image and regions) as `{name, digest}` in `resolvedDependencies`. Regions of the output are not build-time inputs. The same freeze should move those entries to `byproducts`, or drop them, since each region is named again in its SBOM byproduct entries.
- *Extension fields.* `<vendor>_<field>` names are allowed but "MUST NOT alter the meaning" of other fields.\[5\] They are unnecessary here, and avoiding them keeps ADR-057's "invent no field" stance intact.

**A2 -- VSA.** The SLSA VSA's `inputAttestations` lists the attestations used to reach the verification result. Naming SBOM attestation bundles there is permitted whenever the approver's policy actually evaluated them; it is not a reserved provenance-only list. I found no deployment that does this.

**A3 -- in-toto predicates.**
- CycloneDX predicate page: "Type URI: https://cyclonedx.org/bom", page version 1.4. Its example also shows a versioned `https://cyclonedx.org/bom/v1.4`, \[31\] while tools (cosign `--type cyclonedx`, GitHub, in-toto-golang) emit the unversioned URI.\[32\]\[33\]
- SPDX: `https://spdx.dev/Document`, which is what cosign and in-toto-golang emit for SPDX 2.\[19\]\[33\]
- Reference predicate: `https://in-toto.io/attestation/reference/v0.1`, with `attester` and `references[] {downloadLocation, digest, mediaType}` (field names from GUAC's implementation; the spec file itself could not be fetched).\[34\]
- Google Artifact Analysis signs a *different* schema: a DSSE-signed `SbomReferenceIntotoPredicate {referrerId, location, mimeType, digest}`, so "SBOM reference" is not one standard.\[35\]\[36\]

**A4 -- Sigstore.**
- Bundle v0.3 is the current OCI artifactType. cosign 3.x writes it by default.\[11\]
- Discovery is via the referrers API plus the `dev.sigstore.bundle.predicateType` annotation. Because that annotation is unsigned, verifiers must re-check the signed `predicateType`; Ratify's cosign-v3 verifier does exactly this.\[37\]
- cosign issue #5154 (2026) shows `cosign verify` downloading every attestation layer on an image. PR #5155 proposes filtering by the annotation.\[38\]\[39\] This is relevant if strike ever attaches many large SBOM attestations.

**A5 -- OCI.** strike's referrers-only stance matches cosign 3.x's writer.\[40\] Registries are still catching up on classifying attestations:
- zot PR #4492 fixes cosign v3 bundles being classified as signatures.\[41\]
- Harbor issue #22848 (July 2026) adds handling for BuildKit attestation manifests as accessories.\[42\]
- I did not verify per-registry garbage-collection behavior for referrers (measurement candidate).

**A6 -- SBOM standards.**
- CycloneDX 1.7 was released October 2025.\[43\]\[44\] ECMA-424 2nd edition (December 2025) defines 1.7.
- cyclonedx-go v0.12.0 (published 22 August 2026) supports spec versions 1.0 to 1.7 and now strips newer fields when downgrading.\[45\]\[46\] I could not confirm from documentation which version its constructor uses by default. This is a measurement candidate: emit with strike's code at the anchor and read `specVersion`.
- SPDX: 3.0.1 (December 2024) is the latest final release; 3.1 RC1 dates from January 2026. ISO/IEC 5962:2021 codifies 2.2.1.\[47\]\[48\] SPDX 3's Build profile can express build relationships natively, but no mainstream verifier consumes it.
- Both standards let the SBOM name its subject by hash: CycloneDX `metadata.component.hashes`; SPDX package checksums. That is the SBOM-internal half of a binding.

**A7 -- SCITT.** Not researched in depth in this pass. Its RFC status and registration patterns are listed under open questions.

### B. Practice survey

| Project | Pattern | Digest bound | Signed by | Discovery | Out-of-box verifier |
|---|---|---|---|---|---|
| cosign 3.x | signed statement (attach-sbom: plain referrer or referrer signature, deprecated) | image manifest digest as subject | signer identity (Fulcio/key) | OCI referrers + predicateType annotation | `cosign verify-attestation --type cyclonedx\|spdxjson` |
| GitHub actions/attest | signed statement (attest-sbom deprecated wrapper since v4) | subject digest; SBOM <=16 MB | GitHub Actions workflow identity via Sigstore | attestation API; optional `push-to-registry` | `gh attestation verify` |
| Docker BuildKit | in-index attestation manifest (unsigned) | `vnd.docker.reference.digest` -> platform manifest | none | image index walk | none for authenticity |
| Konflux / Tekton Chains | signed statement plus a reference in the provenance (SBOM_BLOB_URL) | SBOM blob digest; image digest | Chains key | referrers / tags (Quay) | Conforma policies; mobster verifies provenance digest |
| Chainguard images | signed statement (SPDX predicate + apko config) | per-image digest | Chainguard identity | cosign download/verify-attestation | cosign |
| Google Artifact Analysis | reference statement (Google SBOM reference schema) | SBOM hash + GCS location | Artifact Analysis | Grafeas occurrence | gcloud / custom |
| Trivy (consumer) | reads plain SBOM referrers | n/a | n/a | `--sbom-sources oci` (referrers); `rekor` legacy only | none (no signature check on raw referrer) |
| Ratify (consumer) | verifies cosign v3 bundles | subject digest | -- | referrers | Ratify verifier-go |
| strike today | plain referrers + record-only digests | none signed | none | referrers by artifactType | none |

Not verified in this pass, so not tabulated: Notation/ORAS SBOM signing, ACR, AWS Signer/Inspector, GitLab, JFrog Evidence, Kyverno's SBOM conditions, PyPI PEP 740/770, npm, SBOMit, protobom, bomctl.

- **Consensus for container images:** a signed in-toto attestation with the SBOM as predicate and the image digest as subject, discovered via OCI referrers (Sigstore bundle) or a platform attestation API.
- **Declining:** raw SBOM attachments (cosign attach sbom, `.sbom` tags) and signing the SBOM artifact separately (a signature over the referrer, in cosign's world). kubernetes-sigs/promo-tools dropped `.sbom` handling entirely.\[49\]
- **Emerging:** reference-style attestations (digest + location) for large SBOMs (Sigstore docs, Google, in-toto Reference);\[50\]\[51\] scanners learning to read bundle-wrapped SBOMs (Trivy discussion #9501); registries treating bundles as typed referrers.\[52\]

### C. Security analysis

**C1.** The weakness of plain referrers is the documented reason for cosign's deprecation: cosign itself warns that downloading SBOMs this way "does not ensure its authenticity".\[53\] Referrer listings are registry-asserted. Anyone with push rights can add a conflicting SBOM referrer, and Trivy's OCI source would consume it.\[54\]\[55\] The `dev.sigstore.bundle.predicateType` annotation is also unsigned, so annotation spoofing is a real confusion vector unless the verifier checks the signed predicate type.\[37\]

**C2 -- per-option verifier table.**

| Option | What the verifier does | What it learns | Standard tool today | strike-specific code |
|---|---|---|---|---|
| Plain referrers | list referrers, read bytes | nothing authenticated | Trivy reads it | -- |
| Sealed digests (byproducts) | verify provenance; fetch referrer layer; check sha256/sha512 = byproduct digest | exactly which documents the builder sealed; registry can withhold, not forge | `cosign verify-attestation` verifies the statement; digest matching is not generic | digest match + "unbound referrer" check |
| Signed statement | `cosign verify-attestation --type cyclonedx` against identity | this signer says this SBOM describes this image | cosign, policy-controller, Ratify | none |
| Both | both, plus check that the statement's predicate equals the document the digest pins | uniqueness: of possibly several SBOM attestations, which one the build produced | partly (the statement half) | equality check (canonical JSON) |
| Referrer signature | verify signature on SBOM referrer manifest (referrer of a referrer) | signer vouches for that SBOM artifact | Notation/Ratify (not verified); cosign path deprecated | two-hop walk |
| Reference statement | verify reference statement; fetch by digest | same as the sealed digests, but in a second statement | cosign verifies the envelope only | digest match |
| Release names them | verify VSA; resolve inputAttestations | a human approved a release whose evidence included these SBOM attestations | cosign for the envelope | resolution logic |

Each one-way binding leaves a gap the other closes:
- Signed statements alone permit several valid-but-conflicting SBOM attestations from the same identity, and a replayed older one.
- Sealed digests alone authenticate the bytes but give generic tools nothing to verify, because they don't read byproducts.
- A reference statement is dominated by the sealed digests for strike: the same signer, act and digests, at the cost of an extra signature.

One subtle point for using both: the statement's DSSE payload embeds the SBOM as a JSON *object*, not as bytes. Matching it to the sealed byte digest needs strike's canonical serializer, or a match through the raw referrer (layer digest = sealed digest, then semantic JSON equality).

**C3 -- regions.** I found no convention for layer-scoped (`diff_id`) subjects. Several same-type SBOM attestations with one subject make "which SBOM?" ambiguous for policy engines and scanners. That argues for one pair of signed statements per image, with regions bound through the sealed digests and through hashes inside each region SBOM (`metadata.component.hashes` = the region's diff_id plus SHA-512), not through extra subjects.

**C4 -- recompute-and-compare.** I found no shipped verifier that regenerates an SBOM and compares bytes. strike's deterministic SBOMs make this possible, as an *additional* check: anyone with the image can re-run the catalog and compare against the sealed digest. It does not remove the need for a binding, because it needs strike's exact parser versions (which `builderDependencies` can pin).

### D. Regulation

| Requirement | Source (version, date) | Signed SBOM? | Artifact binding? | strike today | After recommendation |
|---|---|---|---|---|---|
| SBOM, machine-readable, >= top-level deps | CRA Annex I Part II(1), Reg. (EU) 2024/2847 | not required | not required | yes | yes |
| Format/elements by implementing act | CRA Art. 13(24) | open | open | -- | not adopted (sbomify CRA guide: "No such implementing act has been adopted") |
| SBOM in technical documentation, on request | CRA Annex VII pt 8; Art. 13(13) 10-yr retention | -- | -- | referrers only | sealed digests make retained SBOMs verifiable later |
| CycloneDX >=1.6 / SPDX >=3.0.1 | BSI TR-03183-2 v2.1.0 (Aug/Sep 2025) | -- | -- | SPDX 2.3 fails; CDX version unverified | needs SPDX 3.0.1 or a CDX-only claim |
| SHA-512 hash of deployable component | BSI TR-03183-2 v2.1.0 section 5.2 | -- | inside SBOM | unknown | add sha512 for image + regions |
| "Ideally, SBOMs should be digitally signed" | BSI TR-03183-2 v2.1.0 section 8.1.15 | recommended | -- | no | signed statement |
| SBOM Author Signature; Component Hash | CISA et al. 2026 Minimum Elements v2.1 (29 Jul 2026) | listed element (guidance) | hash inside SBOM | no | signed statement + hashes |
| US federal attestation (M-22-18/M-23-16) | rescinded by OMB M-26-05 (23 Jan 2026, signed by OMB Director Russell T. Vought: "M-22-18 and M-23-16 ... are hereby rescinded"; agencies "may choose to use" the form) | -- | -- | -- | -- |

**D4 synthesis.**
- *Signed SBOM.* CISA 2026 (guidance) lists an author signature as a minimum element; BSI recommends one. The CRA legal text is silent on signing.\[56\]\[57\]
- *Hash binding.* Every source asks for hashes *inside* the SBOM.\[58\]\[59\] None asks for a provenance link.
- *What "CRA-ready SBOM evidence" means for strike in 2027 to 2028:* per released version, a TR-conformant document (CycloneDX >=1.6, SPDX >=3.0.1) whose primary component carries the artifact's SHA-512 (and SHA-256) hash, signed by an attributable identity, retrievable and verifiable for 10 years, and tied to the release decision.
- Both bindings, plus the release naming the statements, get closest. The format upgrade is the larger compliance item.

### E. Trajectory and positioning

**E1.** Attestations are becoming the default SBOM carrier (cosign, GitHub, Chainguard, Konflux). Reference-style statements are rising for large SBOMs. SLSA is moving toward explicit SBOM linkage, but on the dependency side (v1.3 draft). Format floors are rising (BSI v2.1.0). Signing has entered the multinational minimum-elements baseline.\[60\]

**E2 -- white space check.**
- (i) Bidirectional binding: partly occupied by Konflux. Same-act, same-identity sealing plus reproducibility is not seen elsewhere.
- (ii) Recomputable SBOMs: no shipped example found.
- (iii) Region decomposition bound to diff_ids: unoccupied, but there is no convention to lean on, so keep it inside SBOM-internal hashes and byproducts.
- (iv) A VSA naming the SBOM attestations: unoccupied.
- (v) A fail-closed verifier for unbound SBOM referrers: no example found.

**E3 -- stranding risks.**
- SPDX 3 predicate type: if strike moves to SPDX 3, the `https://spdx.dev/Document` URI may not be the one consumers expect. Keep the unversioned URIs that cosign aliases use today.
- SLSA v1.3 wording on SBOMs in resolvedDependencies: byproducts stays valid either way, and a later minor version can add a resolvedDependencies reference if strike ever claims dependency completeness.
- Bundle v0.3 -> later: the media type is versioned, so readers will keep accepting v0.3.
- JSF enveloped signatures: avoid them. ECDSA signatures inside the document would break byte-reproducibility of the SBOM.

**Assessment against strike's principles.**

| Principle | Sealed digests | Signed statements (image pair) | Referrer signature | Reference statement | Release names them |
|---|---|---|---|---|---|
| C3 soundness | yes (digest dereference) | yes | yes | yes | yes |
| Registry not trust-bearing | yes | yes | yes | yes | yes |
| Invent nothing | standard field | standard predicates | deprecated path | second statement | standard field |
| Code is liability | small | small (reuse producer) | larger | redundant | small, later |
| Reproducibility | yes (content digests only) | separate, non-sealed statements | -- | -- | -- |
| No open maps | yes | predicate = SBOM (typed by its own schema) | -- | -- | yes |
| cosign-verifiable | envelope yes | fully | no | envelope | envelope |
| Wire freeze | changes sealed statement now | additive referrers | -- | -- | ADR-057 pending |

## Recommendations

1. **Minimum (makes documented claims true): sealed digests.**
   - At the freeze event of this decision, write one `runDetails.byproducts` entry per SBOM document: `name` = `<artifact>/<format>`, `digest` = `{sha256, sha512}` of the document bytes, `mediaType` = the document media type.
   - Move per-artifact region entries out of `resolvedDependencies`.
   - Add verifier code: fetch the strike-annotated SBOM referrers and check their hashes. Fail closed when a `dev.strike.artifact` SBOM referrer is unnamed or a named one is missing.
   - Correct SECURITY.md, ADR-019, ADR-040 and the trust-layer map.
2. **Ecosystem default: add signed SBOM statements for the image-level CycloneDX + SPDX pair.**
   - Same ephemeral key and certificate; subject = pushed manifest digest; predicate types `https://cyclonedx.org/bom` and `https://spdx.dev/Document`.
   - Keep the raw referrers for Trivy-style scanners.
   - That is 2 extra signatures, Rekor entries and timestamps per deploy, not 2+2N.
   - A strike-built base image then satisfies strike's own base-SBOM rule.
3. **Pioneer: both bindings, the release naming the statements, reproducibility, format floor.**
   - Check in `strike verify` that the statement's predicate equals the sealed document.
   - Name the SBOM attestation bundles in the approver VSA's `inputAttestations` once ADR-057 lands.
   - Publish a recompute-and-compare procedure.
   - Emit CycloneDX >=1.6 with SHA-512 component hashes (image manifest bytes; region diff_id content).
   - Schedule SPDX 3.0.1 before claiming TR-03183-2 conformance.
4. **Not recommended:** a signature over the SBOM referrer (deprecated path in the Sigstore world, two-hop verification); a separate reference statement (dominated by the sealed digests); SBOMs as extra provenance subjects; diff_id subjects.

**Evidence against, and what would change it.**
- Sigstore's docs discourage SBOM predicates. If strike's image SBOMs grow to multi-MB and cosign #5154 is not fixed, switch the signed statements to an in-toto Reference statement.
- If SLSA v1.3 final explicitly places *output* SBOMs in `resolvedDependencies`, mirror the entries there.
- If an Art. 13(24) implementing act mandates a specific carrier or signature format, follow it.

## Caveats

- **Open questions and measurement candidates (local harness: zot, Sigstore stack, cosign in a container):**
  - cyclonedx-go v0.12.0's default `specVersion` as strike actually emits it.
  - Whether spdx/tools-golang can emit SPDX 3.0.1.
  - Whether `cosign verify-attestation` passes offline and flag-clean on strike's SBOM statement bundles with Rekor v2 hashedrekord-for-DSSE entries.
  - Whether Trivy's OCI source picks the raw CycloneDX referrer when bundle referrers coexist.
  - zot referrer garbage collection after the subject is deleted.
  - Kyverno's behavior when several same-type SBOM attestations exist.
  - SCITT RFC status.
  - Whether Rekor v2 still accepts a native `dsse` request type: the GA blog says yes, CLIENTS.md says no.\[61\]\[62\]
- **Secondary-only claims:** the cosign v4 removal date and the CRA implementing-act status come from secondary sources; the OMB M-26-05 rescission text is quoted via Covington's Inside Government Contracts. The in-toto Reference spec text could not be fetched; its fields come from GUAC's implementation.
- **Conflicting sources:** one vendor page states that BSI wants SHA-256.\[63\] Sources quoting the TR text state SHA-512; this report follows SHA-512.\[64\]\[65\]
- **Not covered in this pass:** PyPI, npm, Maven, Notation/ORAS, AWS, GitLab, JFrog, OpenSSF SBOMit/protobom and CycloneDX 2.0 status.

## Sources

1. [Deprecate \`--attachment sbom\` commands - Issue #2755 - sigstore/cosign - GitHub](https://github.com/sigstore/cosign/issues/2755)
2. [chore(deps): update actions/attest-sbom action to v4 by renovate\[bot\] - Pull Request #1726 - manuc66/node-hp-scan-to - GitHub](https://github.com/manuc66/node-hp-scan-to/pull/1726)
3. [BSI TR-03183-2 explained: SBOM required fields](https://www.legacymind.de/en/knowledge/bsi-tr-03183-2)
4. [Free SBOM Validator - Check CycloneDX/SPDX Against BSI TR-03183-2 and the 2026 Minimum Elements](https://cvdportal.com/tools/sbom-validator)
5. [slsa/spec/build-provenance.md at main - slsa-framework/slsa - GitHub](https://github.com/slsa-framework/slsa/blob/main/spec/build-provenance.md)
6. [content: Add SLSA Build Level 4 with dependency completeness requirement by arewm - Pull Request #1646 - slsa-framework/slsa - GitHub](https://github.com/slsa-framework/slsa/pull/1646)
7. [Build: Provenance](https://slsa.dev/spec/draft/build-provenance)
8. [SLSA - Provenance](https://slsa.dev/spec/v1.0/provenance)
9. [Cosign: signing and verifying your container images](https://www.stephane-robert.info/en/docs/devsecops/supply-chain/cosign/)
10. [Software Bill of Materials -- Cilium 1.21.0-dev documentation](https://docs.cilium.io/en/latest/configuration/sbom/)
11. [feat: bundle\_format parameter to pin the signature storage format by juburr - Pull Request #46 - juburr/cosign-orb - GitHub](https://github.com/juburr/cosign-orb/pull/46)
12. [Signing Other Types - Sigstore](https://docs.sigstore.dev/cosign/signing/other_types/)
13. [Generate Generic Attestations - Actions - GitHub Marketplace - GitHub](https://github.com/marketplace/actions/generate-generic-attestations)
14. [SBOMs and SLSA provenance - GitHub](https://gist.github.com/brooksphilip/cfa3376542770ac2559774250f7f274e)
15. [Indicating that the build system has a completed set of resolved dependencies - Issue #1279 - slsa-framework/slsa - GitHub](https://github.com/slsa-framework/slsa/issues/1279)
16. [attest sbom](https://github.com/actions/attest-sbom)
17. [GitHub - gbenhaim/byob-pipeline: Bring-your-own-build Tekton pipelines for Konflux - GitHub](https://github.com/gbenhaim/byob-pipeline)
18. [From Podman to Production: Building Trusted Container Images with Konflux - DEV Community](https://dev.to/4sokol/from-podman-to-production-building-trusted-container-images-with-konflux-1lgn)
19. [tekton-chains Provenance - Image Signatures and Attestations](https://images.chainguard.dev/directory/image/tekton-chains/provenance)
20. [Attest SLSA provenance per platform manifest, not only the index - Issue #2728 - NVIDIA/aicr - GitHub](https://github.com/NVIDIA/aicr/issues/2728)
21. [An image cannot say which commit built it: no OCI labels, so provenance is only in an attestation nobody reads on call - Issue #462 - toise-dev/toise - GitHub](https://github.com/toise-dev/toise/issues/462)
22. [\[FEA\]: Sign the container image with cosign and attest SBOM and OpenVEX - Issue #595 - dsx-ai-factory/topograph - GitHub](https://github.com/dsx-ai-factory/topograph/issues/595)
23. [First impressions and learnings on the new BuildKit's supply chain security features](https://www.felipecruz.es/buildkit-supply-chain-features/)
24. [Image attestation storage](https://www.aidoczh.com/docker/build/metadata/attestations/attestation-storage/index.html)
25. [feat(ISV-7784): add CBOM augmentation by BorekZnovustvoritel - Pull Request #543 - konflux-ci/mobster - GitHub](https://github.com/konflux-ci/mobster/pull/543)
26. [SBOM Regulations Guide](https://www.cybeats.com/regulations)
27. [The 2026 SBOM minimum elements: what changed, and where it collides with the CRA](https://cvdportal.com/blog/sbom-minimum-elements-2026-what-changed)
28. [2026 Minimum Elements for a Software Bill of Materials ( ...](https://media.defense.gov/2026/Jul/29/2003971159/-1/-1/1/CSI_2026_cisa_sbom_minimum_elements_508c.PDF)
29. [2026 SBOM Minimum Elements: What Changed to Stay Compliant](https://bearingpoint.services/foss/en/newsblogs/2026-sbom-minimum-elements-software-bill-of-materials-compliance/)
30. [70\. Support for zstd:chunked image compression](https://konflux-ci.dev/architecture/ADR/0070-dual-compression-for-container-builds/)
31. [attestation/spec/predicates/cyclonedx.md at main - in-toto/attestation - GitHub](https://github.com/in-toto/attestation/blob/main/spec/predicates/cyclonedx.md)
32. [in\_toto package - github.com/in-toto/in-toto-golang/in\_toto - Go Packages](https://pkg.go.dev/github.com/in-toto/in-toto-golang/in_toto)
33. [CycloneDX Attestations (CDXA) vs in-toto, SLSA and Sigstore Bundles](https://safeguard.sh/resources/blog/cyclonedx-attestations-cdxa-vs-in-toto-slsa-provenance-and-sigstore-bundles)
34. [attestation package - github.com/guacsec/guac/pkg/certifier/attestation/reference - Go Packages](https://pkg.go.dev/github.com/guacsec/guac/pkg/certifier/attestation/reference)
35. [SBOM overview | Artifact Analysis | Google Cloud Documentation](https://docs.cloud.google.com/artifact-analysis/docs/sbom-overview)
36. [ondemandscanning package - github.com/sp0n-7/google-api-go-client/ondemandscanning/v1 - Go Packages](https://pkg.go.dev/github.com/sp0n-7/google-api-go-client/ondemandscanning/v1)
37. [feat(cosign): support cosign v3 Sigstore bundle signatures by fseldow - Pull Request #83 - notaryproject/ratify-verifier-go - GitHub](https://github.com/notaryproject/ratify-verifier-go/pull/83)
38. [\`cosign verify\` downloads every attestation bundle on an image, though it only checks signatures - Issue #5154 - sigstore/cosign - GitHub](https://github.com/sigstore/cosign/issues/5154)
39. [verify: avoid downloading unrelated bundle layers by jstar0 - Pull Request #5155 - sigstore/cosign - GitHub](https://github.com/sigstore/cosign/pull/5155)
40. [Where Cosign Stores Image Signatures: Referrers and Repositories](https://oneuptime.com/blog/post/2026-08-11-cosign-signature-storage-oci-referrers-separate-repositories/view)
41. [bug: treat cosign attestations as referrers, not signatures by FStelzer - Pull Request #4492 - project-zot/zot - GitHub](https://github.com/project-zot/zot/pull/4492)
42. [BuildKit attestation manifests shown as unknown/unknown in multi-arch artifact list - Issue #22848 - goharbor/harbor - GitHub](https://github.com/goharbor/harbor/issues/22848)
43. [SPDX vs CycloneDX: Choosing an SBOM Format](https://nhimg.org/spdx-vs-cyclonedx-guide)
44. [CycloneDX vs SPDX: Picking Your CRA-Compliant SBOM Format](https://craevidence.com/cra-compliance/sbom/cyclonedx-vs-spdx)
45. [Update module github.com/CycloneDX/cyclonedx-go to v0.12.0 by manifest-self-hosted-renovate\[bot\] - Pull Request #13 - manifest-cyber/protobom - GitHub](https://github.com/manifest-cyber/protobom/pull/13)
46. [cyclonedx package - github.com/CycloneDX/cyclonedx-go - Go Packages](https://pkg.go.dev/github.com/CycloneDX/cyclonedx-go)
47. [CycloneDX vs SPDX: Which SBOM Format to Choose in 2026](https://www.interlynk.io/resources/cyclonedx-vs-spdx-sbom-format)
48. [SPDX Versions Explained: 1.0 to 3.0.1 and Migrating from 2.3](https://safeguard.sh/resources/blog/spdx-versions-explained-1-0-to-3-0-1-and-migrating-from-2-3)
49. [Use cosign OCI APIs for provenance attestations, drop SBOMs by saschagrunert - Pull Request #1764 - kubernetes-sigs/promo-tools - GitHub](https://github.com/kubernetes-sigs/promo-tools/pull/1764)
50. [Cosign Signature vs Attestation vs SBOM: What Does Each One Prove?](https://oneuptime.com/blog/post/2026-08-11-cosign-signature-attestation-sbom-differences/view)
51. [in-toto Community Meetings - HackMD](https://hackmd.io/@lukpueh/ry_e70Qqw)
52. [Discover remote SBOMs on container images wrapped in Sigstore Bundles - aquasecurity/trivy - Discussion #9501 - GitHub](https://github.com/aquasecurity/trivy/discussions/9501)
53. [sbom handling deprecated? - Issue #1346 - ko-build/ko - GitHub](https://github.com/ko-build/ko/issues/1346)
54. [Trivy - Container Image](https://trivy.dev/docs/latest/guide/target/container_image/)
55. [Docker Container Vulnerability Scanning Tool Using Trivy Project](https://www.projectsatbangalore.com/cybersecurity-projects-for-final-year-students/docker-container-vulnerability-scanning-tool-using-trivy/)
56. [SBOM under the Cyber Resilience Act](https://www.legalithm.com/en/blog/cra-sbom-pflicht)
57. [CISA Releases the 2026 SBOM Minimum Elements](https://fossa.com/blog/cisa-releases-2026-minimum-sbom-elements/)
58. [2025 Minimum Elements for a Software Bill of Materials ( ...](https://www.cisa.gov/sites/default/files/2025-08/2025_CISA_SBOM_Minimum_Elements.pdf)
59. [SBOM: definition, formats and CRA requirements](https://phinasoft.com/en/blog/sbom-software-bill-of-materials/)
60. [SBOM Guide: SPDX, CycloneDX, VEX and Minimum Elements](https://nhimg.org/sbom-guide)
61. [Rekor v2 GA - Cheaper to run, simpler to maintain - Sigstore Blog](https://blog.sigstore.dev/rekor-v2-ga/)
62. [rekor-tiles/CLIENTS.md at main - sigstore/rekor-tiles - GitHub](https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md)
63. [BSI TR-03183: SBOM Data Fields and Formats for the EU CRA](https://www.interlynk.io/resources/sbom-requirements-for-cra)
64. [BSI TR-03183: SBOM Quality Levels and CRA Compliance](https://craevidence.com/cra-compliance/sbom/bsi-tr-03183)
65. [BSI TR-03183-2: SBOM Data Fields 2026](https://alev-b.com/en/blog/bsi-tr-03183-teil-2-sbom-anforderungen)
