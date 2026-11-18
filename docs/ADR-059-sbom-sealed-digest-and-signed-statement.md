# ADR-059: Every published SBOM is named by the sealed provenance, and the image SBOM is a signed statement of its own

## Status

Accepted, 2026-11-16. Drafted against
`39297fc8e5f3e3a37b704a37a7b048fcb68b7e72` and completed against
`1495407aa93a7d7e8a0d6b37f5f41be4932c39ef`. Every design fork behind
this record was surfaced and ratified by the operator on 2026-11-15 and
2026-11-16. The survey behind the context is
[the state of play](research/adr-059-sbom-binding-state-of-play.md); the
measurements the decisions rest on are
[the measurement record](research/adr-059-sbom-measurements.md); the
primary sources consulted at authoring are listed at the end.

Settles a question [ADR-051](ADR-051-deploy-as-sealing-point.md) D9
raised without answering: whether the SBOM digests that a deploy records
for each artifact reach a verifier. Refines ADR-051 (D2, D3, D9) and
[ADR-040](ADR-040-control-plane-sbom-and-keyless-attestation.md) (D1, D3)
by fixing how an SBOM is bound to the subject and to the provenance, and
restores, in keyless form, the independent SBOM signature that
[ADR-019](ADR-019-sbom-as-oci-referrer.md) decided and ADR-040 moved to
keyless signing. Extends
[ADR-041](ADR-041-lane-as-verification-policy.md) (the registry is not
trust-bearing) to the SBOM referrers,
[ADR-057](ADR-057-release-authorization-two-signatures.md) (D4 to D7) by
the SBOM statements a release approves and by the recomputation its
approver runs, and
[ADR-009](ADR-009-bootstrap-reproducibility-proof.md) by a reproduction
of the SBOM. Supersedes in part ADR-040 D1, whose second format, SPDX,
is no longer produced. Amends, by dated amendment sections in the
respective records, [ADR-008](ADR-008-cryptographic-primitives.md) (the
hash clause), ADR-019, ADR-040 (D1, D3 and the verify consequence),
ADR-051 (D2, D9 and the read-after-write amendment) and ADR-057 (D4 to
D7).

Changes what the sealed statement carries, which is a freeze event under
the attest wire freeze of the
[Beta Definition of Done](BETA-DEFINITION-OF-DONE.md). All changes to
the sealed statement that this record decides land in that one event:
the entries under `byproducts`, the source date and the builder version.
Changes the lane schema (`contract/lane`) for the facts a lane declares
under D7 and D9.

## Context

### The principle

A non-executing control plane attests soundly what it seals by its own
action: it signs a digest, and the consumer dereferences by that digest
and checks the hash (corollary C3 of the
[soundness note](ATTESTATION-SOUNDNESS-AND-THE-TRUST-BOUNDARY.md)).
ADR-040 D1 and the soundness note place the SBOM among these sealed
claims, and ADR-041 adds that a registry may withhold but never forge.
For an SBOM both hold only when a signed, published statement names the
document's digest. This record makes that true, in the form the
ecosystem verifies, and carries it through to the release.

It also states a goal no earlier record states: what a deploy publishes
lets a manufacturer meet the legal requirements for software bills of
materials, and strike's own releases meet them. D7 names the
requirements, the measure and the path.

### What the tree does at the anchor

- `internal/deploy/push.go`: `pushSBOMPair` pushes, for every entry of
  the deploy's `artifacts`, one CycloneDX and one SPDX document as OCI
  referrers of the pushed manifest: artifact type
  `application/vnd.cyclonedx+json` or `application/spdx+json`, one layer
  with the document bytes, annotation `dev.strike.artifact`. No document
  is signed.
- The sha256 of each document is kept in `sealed.artifacts[].sbom` of the
  attestation record (`record.#SBOMSet`). That record is neither signed
  nor published. `ProjectStatements` projects it into three statements;
  of the record itself only its sha256 leaves the process, in the
  unsigned state line of the run log. `runDetails.byproducts` is declared
  in `contract/attest` and written by nothing.
- `projectProducedArtifacts` writes name and digest of each artifact into
  `resolvedDependencies` and nothing of its SBOM. These are the produced
  identities: the manifest digest the control plane produced before the
  engine re-encoded the image on export, and the layer identity of each
  region. The field has this one writer and no reader; it also holds the
  verified base-SBOM statements.
- No signed, published byte therefore names an SBOM document. The
  referrer relationship, which the registry asserts, is the only binding.
- The documentation says otherwise. SECURITY.md: "SBOMs are attached as
  signed OCI 1.1 referrer artifacts." `contract/trustlayers` lists the
  artifact SBOM as published in the SLSA provenance, and its conformance
  test exempts rows nested below a collection. ADR-040 names "SBOM
  predicate validation" among what `strike verify` does;
  `cmd/strike/verify.go` and `internal/verify` hold no SBOM code.
- For a base image strike accepts an SBOM only as a signed statement:
  `FetchBaseSBOMReferrers` lists referrers of the Sigstore bundle type
  and selects by cosign's predicate-type annotation
  (`https://cyclonedx.org/bom`, `https://spdx.dev/Document`),
  `verifyOneBaseSBOM` checks the declared signer and the subject, and the
  verified statement enters `resolvedDependencies` by its
  referrer-manifest digest. strike's own documents are not in that form:
  an image strike built yields no base SBOM to a lane that builds on it.
- `internal/deploy/catalog.go` reads `package-lock.json`, the dpkg status
  database and Go build information, and renders name, version and
  package URL per component. Creators, licenses, dependencies, hashes and
  file components are absent. The CycloneDX specification version is the
  library's default, 1.7 with the pinned module, while the comment in the
  file still says 1.6. The serial number derives from the subject digest
  alone. The only test for an executable file is the execute bit.
- The document's timestamp is `SOURCE_DATE_EPOCH` of the deploy process,
  the epoch when unset or malformed. It is the only consumer of the
  reproducible clock; image content carries fixed times. No statement
  records the value.
- A region's document describes the output layer of the producing step,
  by its diff_id, read from an engine export. `internal/executor/pack.go`
  builds one layer per packed file entry from re-rooted content, so that
  layer is in general no layer of the pushed image.
- `internal/deploy/canonical.go` serializes the signed statements in a
  subset of RFC 8785 (objects, arrays, strings, the three literals) and
  rejects JSON numbers; a test guards that the signed graph carries none.
- `internal/deploy/keyless_producer.go` signs a set of statements under
  one key and one certificate and logs each as a hashedrekord entry over
  the signed digest, so the size of a statement is no constraint of the
  log. `internal/registry/referrer.go` bounds a fetched bundle at 8 MiB,
  a bound sized for bundles of a few KiB.
- The sealed statement names the builder by `builder.id` alone. The lane
  builds strike without version-control stamping, and the binary carries
  no version of its own.
- Lane validation rejects the cluster deploy method
  ([ADR-054](ADR-054-kubernetes-deploy-via-cluster-api.md)), so every
  executable deploy is a registry deploy.

### What the survey found

The survey read specifications, shipped tools and regulation as of
2026-11-15. In short:

- SLSA defines `byproducts` as artifacts a build generates that are not
  its output and may be needed for debugging or incident response, and
  `resolvedDependencies` as artifacts needed at build time. The working
  draft lets a build-time SBOM be referenced under
  `resolvedDependencies`, as the dependency record of the build; it says
  nothing on an SBOM cataloged over the output.
- The practice for container images is a signed in-toto statement with
  the SBOM as predicate and the image digest as subject. cosign, GitHub
  artifact attestations, Chainguard and Konflux publish that form, and
  strike's base-SBOM rule reads it. cosign deprecates plain SBOM
  attachments: "Instead, please use SBOM attestations." Scanners still
  discover plain SBOM referrers.
- The counter-evidence: the Sigstore documentation says of SBOM predicate
  types that "they are not recommended", because the whole document
  travels in the bundle, and suggests signing a pointer with location and
  hash instead.
- A Verification Summary Attestation that names its input attestations
  names all the verification used.
- Nobody was found to ship: provenance and SBOM sealed in one act under
  one identity and bound in both directions; a reproducible SBOM that a
  verifier recomputes; a verifier that fails closed on an SBOM the
  provenance does not name; a release statement that names the SBOM
  statements it approved. Konflux comes closest, with an SBOM reference
  in its signed provenance.
- No regulation asks for a link between SBOM and provenance. The joint
  minimum-elements guidance of 2026 lists an author signature and
  component hashes; the BSI guideline recommends a signature.

### The legal frame

Regulation (EU) 2024/2847 (Cyber Resilience Act) obliges a manufacturer
to draw up a software bill of materials "in a commonly used and
machine-readable format" that covers at least the top-level dependencies
(Annex I, Part II, point 1), to hold it in the technical documentation
for a reasoned request of a market surveillance authority (Annex VII,
point 8), and to keep that documentation for at least ten years
(Article 13(13)). The Regulation applies from 11 December 2027
(Article 71). Article 13(24) empowers the Commission to specify format
and elements by implementing act; none is known at authoring. The
provisions cited ask for no signature and for no link to build
provenance.

The most specific public measure of what such a document contains is BSI
TR-03183-2, version 2.1.0 of 2025-08-20, the current version at
authoring. It is a technical guideline, not law and not a harmonized
standard; BSI states that it is not binding and gives no presumption of
conformity. What it fixes for this record:

- **Format** (section 4): the document is valid CycloneDX from 1.6 or
  SPDX from 3.0.1, in JSON or XML, in a released version of the
  specification. One format satisfies the section.
- **Level** (5.1, 8.3.4): dependencies are resolved for every component
  in the scope of delivery, up to and including the first component
  outside it. That is the delivery item level of section 8.3, and the
  scope of delivery is everything delivered with the product, third-party
  parts included (8.1.11).
- **Class** (5.1, 8.4.3): the document contains the information
  available during the build process. That is the build SBOM of section
  8.4.
- **Components** (3.2.1, 3.2.2, 3.2.6): a component is a logical
  component, a single executable file or an archive file, and each is
  listed. An executable file is any file with code a computer runs,
  directly or through a runtime, so interpreted code counts. A logical
  component, such as a package, needs neither file name nor hash.
  Information that is unavailable because a component was assembled is
  omitted.
- **Fields** (5.2): for each component a creator, name and version, the
  distribution licenses and the dependencies with their completeness
  stated; for a file its name, its SHA-512 hash and three properties:
  executable, archive, structured.
- **References** (5.1, 3.2.5, 8.1.16): the SBOM of a used component may
  be referenced instead of merged when it is compliant, and its
  availability stays with the provider of the referencing SBOM.
- **Other**: a separate SBOM for each software version and no
  vulnerability information in it (3.1); the most recent version of the
  guideline binds, its predecessor for six more months (7); an SBOM
  should ideally be signed (8.1.15, an explanation).

SPDX 2.2.1 is ISO/IEC 5962:2021. Its second edition, titled SPDX
Specification V3.0, was in the approval stage at authoring (stage 50.20
since 2026-10-19, publication dated 2026-12).

### Facts measured at authoring

- cyclonedx-go v0.12.0: `NewBOM` sets specification version 1.7 and the
  integer `version: 1`, the only number a document of strike carries.
  The JSON encoder ends the document with a newline. The model has no
  map-typed field, so every key comes from a struct tag. It carries
  every field D7 needs: manufacturer, license acknowledgment, external
  references with hashes (the type `bom` among them), SHA-512,
  compositions, properties and lifecycles.
- spdx/tools-golang v0.6.0-rc4, the newest upstream tag: `spdx/v3/v3_0`
  is the 3.0.1 model. Its document type marshals itself as compact
  JSON-LD and converts from the 2.3 model. The JSON package strike
  imports for the 2.3 writer already imports that model and, through it,
  a JSON-LD module. A comment in the source calls license expressions
  broken in 3.0 and fixed only in 3.1, which is not released.
  `software_sbomType` carries the six classes of the guideline's
  section 8.4.
- RFC 8785 serializes numbers as ECMAScript does; an integer within the
  exact range is its plain digits. It sorts names by UTF-16 code units,
  which byte order reproduces for ASCII names only. The signature format
  CycloneDX references for an enveloped signature canonicalizes with RFC
  8785, and the canonical serialization of SPDX 3.0.1 states integers in
  base 10 without leading zeros and has no rule for other numbers.
- in-toto attestation framework: the CycloneDX predicate type is
  `https://cyclonedx.org/bom`, the SPDX 2 type
  `https://spdx.dev/Document`; SPDX 3 has a type of its own,
  `https://spdx.dev/Document/v3`; the reference predicate is at v0.1.
  The envelope rules ask that security not depend on canonicalization.
- cosign, main at 2026-11-12 with v3.1.4 as its latest tag, documents
  `cyclonedx` and `spdxjson` as predicate types of `attest` and
  `verify-attestation`, and `download sbom` as deprecated. It builds its
  own SBOM statements by parsing the file and encoding it again, and it
  reads an attached layer up to 128 MiB by default.
- The BSI property taxonomy for CycloneDX, v0.1.2, defines
  `bsi:component:executable`, `:archive` and `:structured`, each exactly
  once per component, and `:filename`.
- Measured on eight real images (the measurement record): a file
  component takes about 0.5 to 0.6 KiB; the largest delivery item
  document, of an application image with 122,656 files, is 43.9 MB, and
  its signed envelope 58.6 MB.

## Terms

- **SBOM document**: one CycloneDX JSON document the deploy generates
  over one entry of `artifacts` (ADR-051 D9), in the canonical form of
  D2.
- **Image SBOM**: the documents cataloged over the whole pushed image,
  the image entry of `artifacts`. It has two levels (D7):
  the **top-level document** and the **delivery item document**.
- **Region document**: a document of a file or directory entry.
- **Statement document**: the document that the SBOM statement carries,
  the top-level document.
- **Document digest**: the sha256 of a document's bytes. It is the blob
  digest of the layer that the document's referrer carries.
- **SBOM statement**: an in-toto statement whose predicate is an SBOM
  document, signed and published like the provenance statements.
- **Plain referrer**: the unsigned OCI referrer that carries a document
  as its single layer.
- **The guideline**: BSI TR-03183-2 in the version D7 names.

## Decision

### D1 -- The sealed provenance names every SBOM document by its digest

The sealed SLSA provenance statement lists every SBOM document of the
deploy under `runDetails.byproducts`: one entry per document, with a
name, the document's media type (`application/vnd.cyclonedx+json`, the
referrer's artifact type) and the document digest as `digest.sha256`,
sorted by name. The name is the `artifacts` name the document belongs to
and its level: `<artifact>/sbom` for a region document,
`<artifact>/sbom/top-level` and `<artifact>/sbom/delivery-item` for the
image documents. The contract enforces this grammar and states that the
top-level document is the one an SBOM statement carries (D2), so that
the sealed statement alone tells a verifier what to expect (D4). No
annotation is added to the descriptor. An entry carries no location,
because the consumer dereferences by the digest wherever the bytes live,
and no second hash (ADR-008,
[ADR-046](ADR-046-one-canonical-digest-pinned-image.md)). An entry names
a document, never a bundle or a referrer manifest: those carry a
certificate, a log entry and a timestamp, and the sealed statement stays
byte-reproducible.

This closes corollary C3 for the SBOM. The control plane signs the
digest, the consumer checks the hash, and the registry can withhold a
document but not exchange it. The field is SLSA's own and already
declared in `contract/attest`.

The produced identities of the artifacts move from
`resolvedDependencies` to the same field, unchanged: name `<artifact>`
and `digest.sha256`, without a media type, since a region's identity is
a diff_id and no blob. SLSA defines `resolvedDependencies` as artifacts
needed at build time, and the build generates these. They stay in the
statement because a reproduction compares them (ADR-009). The verified
base-SBOM statements stay under `resolvedDependencies`: they are
inputs.

### D2 -- The image SBOM is published as a signed statement, in canonical form

Every SBOM document strike publishes is in canonical form: the RFC 8785
serialization of what the standard's library marshals. The library
decides names, structure and omission (ADR-040 D1); the byte form is
strike's. Keys are sorted, escapes minimal, and there is no whitespace,
so a document is exactly one JSON value.

For that purpose the canonical serializer of the signing path admits one
form of number: a non-negative integer written as its plain digits, `0`
or a digit from 1 to 9 followed by at most 14 digits. That is the RFC
8785 form of such an integer. Every other number fails the signing path
closed, as before, and so does a key outside ASCII. strike's own
statements stay free of numbers.

The statement document is also published as an in-toto Statement v1 of
its own. The subject is the pushed image, as in the provenance
statements. The predicate type is `https://cyclonedx.org/bom`, and the
predicate is the document. The statement passes through the canonical
serializer like the provenance statements. The canonical form of a part
does not depend on what surrounds it, so the predicate's bytes are the
document's bytes and hash to the digest D1 names. The deploy signs this
statement with the key and the certificate of its provenance statements,
logs and timestamps it the same way, and attaches it as a referrer in
the bundle form of ADR-040 D3. The referrer carries cosign's
predicate-type annotation, by which cosign and strike's base-SBOM reader
select it, and no `dev.strike.statement` annotation: it is not one of
the layer statements of
[ADR-037](ADR-037-two-engine-trust-layers.md).

`contract/attest` defines the statement as `#SBOMStatement` beside the
three statements. Its subject is non-empty and its predicate type fixed.
Of the predicate, the contract pins what strike fixes -- `bomFormat`
`CycloneDX`, `specVersion` `1.7`, `version` `1` and the form of
`serialNumber` -- and leaves the rest to the standard, whose library
produces it. The producer hands the canonical document bytes to the
statement unchanged, as raw JSON.

This is the form cosign verifies: cosign v3.1.4 verified such a
statement over six real images and rejected it under another predicate
type (measured with a key; the keyless bundle stays with the planned
independent cosign check). It is also the form strike demands of a base
image: a lane that declares another lane's builder identity as a
base-SBOM signer verifies that lane's image SBOM with the reader it
already has.

No verifier canonicalizes. A signature covers bytes and the equality of
D4 is a hash over bytes, so no security rests on canonicalization. The
canonical form is the producer's discipline: a document's bytes follow
from its content alone, and anyone can derive a document digest again
from a parsed copy with any implementation of RFC 8785.

The delivery item document and the region documents get no statement.
The delivery item document can be large; it travels as a plain referrer
and is named by two signatures all the same, through D1 and through the
hash in the signed top-level document (D7). For a region, no convention
exists for a statement about a part of an image, a second statement of
the same type on the same subject makes "which SBOM" ambiguous for a
scanner or a policy, and the layer a region document describes is in
general no layer of the pushed image.

A deploy signs no statement that its own reader would refuse. A
statement document above the reader's bound fails the deploy; there is
no unsigned fallback (ADR-040 D2). An SBOM statement bundle is read
under the bound of every other bundle, 8 MiB; the largest measured
top-level envelope is 63 KB. A document is hashed as a stream under a
bound of its own, 128 MiB, the bound cosign applies to an attached
layer; the largest measured delivery item document is 43.9 MB, that of
an application image with 122,656 files.

### D3 -- Every document stays a plain referrer

All documents, image and region, stay attached as plain referrers, as
ADR-019 and ADR-051 D2 decide. Scanners discover an SBOM there by its
artifact type, and the delivery item document and the region documents
have no other home. The `dev.strike.artifact` annotation stays a
discovery aid and marks a referrer as one strike claims to have
published. The binding is D1.

### D4 -- The verdict covers the SBOM and fails closed

`strike verify` checks the following in the consumer case and in the
operator case alike (ADR-041), as part of the sealed layer and with no
flag that lowers it:

- every document that a verified sealed statement names is served as a
  plain referrer of the subject and hashes to the named digest;
- every plain referrer of the subject that carries the
  `dev.strike.artifact` annotation is named by a verified sealed
  statement;
- for every document that a verified sealed statement names as carried
  by a statement, an SBOM statement verifies under the builder profile,
  names the subject, and carries a predicate whose bytes hash to that
  document's digest.

What is expected follows from the sealed statement alone. The rule names
no format and no predicate type, so a change of format (D7) changes no
rule.

An SBOM statement that verifies under the builder profile and matches no
named digest fails the verdict: it is a second, conflicting SBOM under
the builder's identity. A statement under another identity and a
referrer without the annotation are not strike's and are not evaluated.
A withheld document or statement fails the verdict; the registry can
deny, not deceive (ADR-041). A document is hashed as a stream, under a
bound of its own (D2). The read-after-write of the deploy (ADR-051,
amendment 2026-11-08) confirms the SBOM statements with the other
bundles.

### D5 -- A release names the SBOM statements it approved

The authorization statement of ADR-057 D5 lists, in `inputAttestations`,
the SBOM statement bundles beside the provenance bundles, each by its
referrer-manifest digest. The approver's verification uses them (D4),
and a Verification Summary Attestation that names its inputs names all
of them. `strike verify` checks the named bundles against the attached
ones, as ADR-057 D7 does for the provenance bundles, and the release
register of ADR-057 D6 lists their digests with the others. A release
thereby states which bill of materials its approver saw.

### D6 -- The image SBOM is reproducible evidence, and every input of it is sealed

A document of the image SBOM is a function of five things and of nothing
else. Each is in a verifier's hands:

- **the pushed image**, by the digest of the subject;
- **the push target**, which the sealed statement carries;
- **the facts the lane declares** (D7), which the lane digest seals. A
  consumer without the lane reads them from the document;
- **the source date**, which the sealed statement carries from this
  record on, as the required external parameter `sourceDate`: the value the
  document's timestamp was rendered from, in RFC 3339 UTC, byte-equal to
  that timestamp;
- **the cataloging code**, which the sealed statement names from this
  record on: the commit of the strike source, in SLSA's
  `builder.version` as `{"strike": "<commit>"}`. The binary learns it at
  link time; the bootstrap lane and the stage_0 build pass the commit
  they fetched, and a build that passes none, such as `make build`,
  knows no commit. Then `builder.version` is absent: the value is the
  binary's own claim and gains meaning only through the recomputation,
  so refusing such a deploy would add no security.

The last two are new. With D1 the bytes of the sealed statement depend
on the source date, through the document digests, and nothing sealed
recorded it. The commit is in the sealed statement and not in the
documents, so a document changes only when the catalog's output changes,
and documents of two strike sources can still be equal.

Anyone who holds the image can therefore derive the image SBOM again and
compare it with the digests D1 seals. The content of the SBOM then rests
on the image and on the cataloging code, not on the producer's word.
strike offers this recomputation as part of verification, on request and
without an engine: it reads the layers from the registry, catalogs them
in process and compares every document of the image SBOM.

Requested, the recomputation is part of the verdict, and a mismatch
fails it. A mismatch is conclusive only when the verifying strike is
built from the sealed commit; when the two differ, or either is unknown,
the verdict says so and names both. A match is evidence in either case.
The recomputation adds evidence and replaces no check of D4.

For a release the recomputation is required. The approver's verification
runs with it, and a mismatch means no signature, as for the reproduction
of ADR-057 D4.

A region document is not recomputable from the registry, because its
source layer is not published. No signature is ever placed inside a
document: it would make the document's bytes depend on the signing act.

### D7 -- Legal conformance is a goal, BSI TR-03183-2 its measure, and the path is the shortest one

**Goal and measure.** Meeting the legal requirements for software bills
of materials is a goal of strike, not a side effect: what a deploy
publishes lets a manufacturer who builds with strike meet them, and
strike's own releases meet them. At authoring the requirement is the
Cyber Resilience Act as cited in the context. The measure is BSI
TR-03183-2 in version 2.1.0. Its section 7 binds a producer to the most
recent version six months after issue, so the measure follows the
guideline, and an implementing act under Article 13(24) or a harmonized
standard replaces it; each such change is a dated amendment of this
record. Conformance to the guideline is evidence toward the legal
requirement. It is never a statement of legal conformity, which stays
with the manufacturer.

**Class.** strike addresses the build SBOM (guideline 8.4.3), because
section 5.1 demands the information available during the build process
and strike is the build system: it creates the documents at the sealing
point, as part of the lane. The information ends where the control
plane's observation ends: the lane, its digest-pinned inputs and the
bytes of the artifact. What a build container knew and the artifact does
not carry is omitted and reported. A file whose parts cannot be
determined, such as an opaque statically linked binary, is marked
unstructured. Content the lane did not build, the base image, is
analyzed (guideline 8.4.4). A document states both in the field its
format has for the class. strike makes no deployed and no runtime claim.

**Level.** The claim is made at the delivery item level (8.3.4) and at
no other. It is the floor of section 5.1. Everything shipped in the
image belongs to the scope of delivery, so the floor means every package
and every executable and archive file, fully described. The complete
level (8.3.5) would need the environment the image runs in, and the
other levels are below the floor.

**Two levels, linked by hash.** In CycloneDX the image SBOM is published
at two levels of the guideline's section 8.3:

- The **top-level document** (8.3.1) holds the image and the logical
  components it contains directly: the packages the catalog finds, the
  regions the lane names, and the base image where there is one. It is
  the statement document (D2). Its size follows the number of
  components, not of files.
- The **delivery item document** (8.3.4) holds the same and every
  executable and archive file under its component. It is a plain
  referrer only, complete in itself, and refers to no other document.
- The top-level document names every other document of the deploy by
  reference and hash: the delivery item document and the region
  documents. The reference is the one the guideline's mapping uses for
  another BOM; the hash is strike's addition.

Every document is thereby named under two signatures, by the sealed
provenance (D1) and by the signed top-level document. The size of an
image's file list reaches no statement. Measured, it would: the delivery
item document of an application image with a large installed
`node_modules` makes a signed envelope of 58.6 MB, seven times the
bundle bound, while its top-level envelope is 1.2 KB.

**The claim.** The claim rests on one document, the delivery item
document in CycloneDX. The guideline asks for one format. strike sets
the CycloneDX specification version itself, 1.7, and a change of it is a
dated amendment of this record. The top-level document claims nothing by
itself. Region documents are outside the claim.

**SPDX.** strike publishes no SPDX document. The guideline admits SPDX
from 3.0.1 only, and ISO/IEC 5962 replaces its SPDX 2 edition by one
that carries 3.0, so a 2.3 document could never join the claim. SPDX
3.0.1 on the pinned module failed its gate: its output is not
byte-identical over runs in one process or across processes, because the
order of the graph and the numbers of generated identifiers follow map
iteration; the converter also writes an empty `createdBy`, which 3.0.1
does not allow. No Go checker loads the 3.0.1 JSON schema, whose IRI
pattern needs lookahead. SPDX returns by amendment of this record when a
library produces 3.0.1 deterministically and an independent checker
validates it.

**Foreign SBOMs.** An SBOM that someone else produced, the creator of a
base image or a build step's own tool, enters by reference and is never
merged. The guideline's condition is that it is compliant and stays
available (5.1); strike's is that it is verified under the base-SBOM
rule or sealed as a step output. None qualifies at the anchor, so strike
analyzes those bytes itself.

**The path.** The path to the claim adds no format, no module and no
network lookup. At the anchor the document already is one per pushed
digest and carries a serial number, a timestamp, package URLs and no
vulnerability information. What is missing comes from two sources only
-- what the lane declares, and what the control plane reads in the bytes
it deploys -- in this order:

1. **Declared facts** (guideline 5.2.1, 5.2.2). The lane declares the
   creator of the SBOM and the creator, name and version of the product
   the deploy publishes. They are lane scalars, sealed with the lane
   digest, and become the document's manufacturer and its primary
   component. They enter both levels.
2. **The image as primary component** (5.2.2, 5.2.4). Its registry
   reference by digest as package URL and as the location of its
   deployable form, the SHA-512 of the pushed manifest bytes, and its
   executable, archive and structured properties. Both levels.
3. **File components** (3.2.1, 5.1, 5.2.2). Every executable file and
   every archive file of the image as a component with its file name,
   its SHA-512, its version and its three properties, under the
   component that contains it, with the completeness of the list stated.
   The delivery item document only. The control plane holds every byte,
   so the list of files is complete by construction. A regular file is
   listed when its content or name says it is executable or an archive,
   or when it carries an execute bit:
   - executable by content: ELF, an interpreter line (`#!`), a Java
     class file;
   - executable by name: a stated list of script extensions, Windows
     scripts included;
   - an archive: a format that combines several members (the zip family,
     tar, ar, 7z, rpm, by content or by a stated list of extensions, and
     compressed tar by name). A single compressed stream is no archive
     (guideline 8.1.5);
   - an execute bit, whatever the content.
   The rule is an observation of content first: the execute bit alone
   misses what the guideline names as executable, such as shared objects
   that Debian ships without it, and jars. The executable property states
   what content and name show; a file listed for its execute bit alone is
   non-executable, as measured such files are data. A hardlink is a file
   of the image under its own name: its content and its execute bit are
   those of its target, the name rules apply to its own name. Symbolic
   links, directories and devices are not files and are not listed. A
   file's version is its modification time from the layer, in RFC 3339
   (5.2.2), the epoch included where the layer states it.
4. **Package facts the image carries** (3.2.2, 5.2.2, 5.2.4, 6.1). For
   each package the catalog finds: its creator, its distribution
   licenses as SPDX expressions, its dependencies with their
   completeness stated, and the hash and location of its deployable form
   where the image records them. A package is a logical component over
   its files. Both levels.
5. **The gate.** The delivery item document is called conformant only
   behind a check an outsider can re-run: validation against the
   CycloneDX schema and against the guideline's field rules, by an
   independent checker run from a digest-pinned image
   ([ADR-055](ADR-055-hardened-endpoint-development-premise.md) D2) and
   chosen by measurement. Until that gate is green, the shipped
   documentation states the limitation in one sentence (Beta Definition
   of Done, row 14).

**Omissions.** What the image does not carry is omitted, as the
guideline rules for assembled components (3.2.1), and the deploy reports
each omission. It is never looked up and never invented. Whether a given
image yields a conformant document therefore depends on what its bytes
state and on which package databases the catalog reads. Known at the
anchor: Debian packages state their licenses outside the status
database, and a Go binary states the modules it links but not their
licenses; a lane closes a gap of that kind by carrying the facts into
the image. The catalog does not read the Alpine package database that
Wolfi-based images carry, nor an rpm database or Java archive metadata;
these gaps are catalog work under step 4. Its npm source is a file named
`package-lock.json`, which is a declaration, not an observation: it
reports the dependencies of a lockfile in Go's vendored source tree and
none of the thousands of packages an application installs under
`node_modules`. Which npm source step 4 reads is decided with step 4.

**Identity of a document.** A document's serial number is derived from
its content, and its `version` is always 1. Identical documents share
both; different documents never do, so the two levels need no rule of
their own. Two deviations are stated: CycloneDX recommends a fresh
serial number for every generated document, which reproducibility
forbids, and the guideline's new version of an SBOM (3.1) is a new
document here, because the control plane keeps no history.

**Time and hash.** The document's timestamp is the source date
(ADR-040 D1), which D6 seals; the trusted time is the RFC 3161 token of
the statements that name the document. A run without
`SOURCE_DATE_EPOCH` stamps the epoch, seals the epoch as `sourceDate`
and is outside the claim. A value that is not a non-negative integer of
seconds within the range of RFC 3339 fails the deploy before any push;
no malformed value becomes the epoch. The SHA-512 values are content
the guideline requires of the document. They are no identity that strike
resolves or verifies by, and the hash of ADR-008 stays SHA-256.

### D8 -- Four binding forms are excluded

- **No signature over an SBOM referrer.** A signature attached to the
  plain referrer authenticates the bytes D1 already authenticates, at the
  price of one signature per document and of a walk over a referrer of a
  referrer that neither strike's base-SBOM rule nor cosign's attestation
  verification performs.
- **No separate reference statement.** A statement that only points to
  the documents by digest would come from the same signer, in the same
  act, over the same digests as the sealed provenance. It is a second
  statement for what one field of the first carries, in a predicate at
  version 0.1, and its predicate would hold no bill. The top-level
  document of D7 is a bill and carries the reference as well.
- **No SBOM document as a subject of the provenance.** The subject is
  what the build is for. A further subject changes the set every policy
  compares.
- **No layer-scoped subject and no statement per region.** As D2 states.

### D9 -- What stays open, and who owns it

Each point has a decision as far as the facts reach, the information
that is missing, and an owner.

- **A deploy without a registry push.** D1 to D4 bind every deploy that
  generates an SBOM. Its documents and statements are published where
  its provenance bundles are; this record adds no second mechanism.
  Missing: the subject and the publication target of such a deploy,
  which ADR-054 D5 ties to measurement against a running cluster. Owner:
  the record that rebuilds the cluster method.
- **Completeness as a demand of the lane.** A lane may demand a complete
  delivery item document, by a typed field on the registry deploy. With
  it, a deploy fails before the push when a required field is omitted;
  without it, the deploy reports every omission and proceeds. The check
  is strike's own, in process; the independent checker of step 5 stays
  the gate of the implementation. Missing: the rule set, that is, which
  omission fails and which the rule for assembled components excuses;
  the form of the field; and whether the demand becomes the default,
  which needs the measured numbers. Owner: the work on the gate.
- **Components outside the image.** The guideline resolves dependencies
  up to and including the first component outside the scope of delivery
  (5.1), and its example of one is the environment the delivery item
  runs in. The lane may declare the components the image needs and does
  not ship, each with creator, name, version and identifier. They enter
  both levels as identified components (3.2.4). The control plane
  invents none. The claim requires the declaration: without it a
  document states the image's dependencies beyond its own content as
  unknown, never as complete, and the document is outside the claim.
  Missing: the completeness value the checker accepts and the form of
  the field. Owner: the declared facts of step 1 and their schema
  change, with the measurement at step 5.
- **Region documents.** ADR-051 D9 stands: a region document is the bill
  of a payload that does not change when the base image does, which no
  image document can be. Region documents stay at one level, outside the
  claim, bound by D1 and without a statement. Not decided: file-level
  detail, recomputation or a claim for them. Missing: a consumer that
  needs one of the three, and a measurement that the packed layer of a
  region yields the same catalog as its producer layer. Owner: an
  amendment of ADR-051 D9.
- **One reading of the guideline.** Whether a new document satisfies the
  versioning rule of section 3.1 is a question only BSI can answer. It
  stays a stated limitation.

## Consequences

- **Sealed statement (`contract/attest`, `internal/deploy`).** The
  projection writes `runDetails.byproducts` with the documents and the
  produced identities, drops the produced identities from
  `resolvedDependencies`, and adds the source date to the external
  parameters and the strike commit to `builder.version`. The statement's
  bytes change. That is the freeze event the Beta Definition of Done
  announces for this decision: it is ratified with this record, the
  signed goldens are re-baselined once, and the Definition of Done
  records the event and the new baseline. The row of the trust-layer map
  for the artifact SBOM becomes true as written.
- **Schema (`contract/attest`, `contract/record`).** In the one freeze
  event: the elements of `runDetails.byproducts` carry the name grammar
  of D1 as a constraint and stay resource descriptors; the external
  parameters gain the required `sourceDate`; the builder gains the
  optional `version`, a closed struct with the one field `strike`; and
  `#SBOMStatement` joins the statements (D2). The record's SBOM set loses
  its SPDX digest. The lane fields for the declared facts of step 1, for
  the components outside the image and for the demand of completeness
  are ratified as schema changes of their own before the work that needs
  them.
- **Canonical serializer.** It admits the integer form of D2 and rejects
  a key outside ASCII. Every signed payload stays canonical JSON, so the
  payload clause of ADR-013 and the note on field alignment stay true as
  written. The test that keeps numbers out of strike's signed types takes
  the SBOM statement as a root. The SPDX module leaves `go.mod`, and with
  it the JSON-LD module it imports; the catalog is its only user.
- **Producer.** A registry deploy signs four statements instead of
  three, under the same certificate: one more log entry and one more
  timestamp. It attaches two image documents and one document per region
  as plain referrers, and four bundles. The bootstrap lane and the
  stage_0 build pass their commit to the linker.
- **Verifier.** `strike verify` reads every document the sealed
  statement names and every SBOM statement, anonymously like every other
  read
  ([ADR-058](ADR-058-registry-client-identity-workload-token.md) D6 as
  amended). The recomputation of D6 additionally reads the image's
  layers, flattens them and runs the catalog over bytes a registry
  served. Measured, the flattened image held in memory reached 1.9 GB of
  heap for a toolchain image and 3.1 GB for an application image; the
  producer at the anchor does the same. The verdict does not compare a
  document's timestamp with the sealed source date: the recomputation
  renders the document from it, so a difference shows as a digest
  mismatch.
- **Base-SBOM path.** An image strike publishes satisfies the base-SBOM
  rule of ADR-040 for a lane that declares its builder as signer. The
  reader keeps accepting a base image's SPDX statement.
- **Release (ADR-057).** `contract/release` describes
  `inputAttestations` as covering the SBOM statement bundles, the
  authorization profile checks them against the attached ones, the
  register line lists them, and the release procedure requires the
  recomputation before the approver signs.
- **Catalog (`internal/deploy`).** D7 steps 1 to 4 extend what the
  catalog reads and renders. One catalog run renders both levels. Named
  regions and the base image become logical components.
- **Measurements.** Taken on 2026-11-15 and 2026-11-16 and recorded in
  the measurement record: SPDX 3.0.1 on the pinned module (failed, D7);
  eight real images, which yielded the rule of step 3, the bounds of D2,
  the two levels of D7, the premises of the integer token and of the
  predicate, and cosign's verification of the statement form; and the
  generator outcomes of the schema above. Still to be taken before the
  step it gates is instructed, its result entering this record by a
  dated amendment: the independent checker of step 5. Whether the packed
  layer of a region yields the same catalog as its producer layer belongs
  to the amendment of ADR-051 D9.
- **Documentation.** SECURITY.md, ARCHITECTURE.md and the README state
  what D1 to D4 make true, in the words of this record.
- **Amendments, dated, in the respective records.** ADR-008: SHA-256
  stays the hash of every identity, seal and content address; a second
  algorithm is written only where the specification governing a
  published document names it. ADR-019: the independent signature is the
  SBOM statement. ADR-040: D1, the libraries keep the mapping of content
  and strike owns the byte form, the document carries the content of D7,
  its serial number follows from its content, and SPDX is no longer
  produced; D3, the SBOM statement stands beside the three layers, the
  produced identities are byproducts, the external parameters gain the
  source date and the builder its version; the verify consequence is
  realized by D4.
  ADR-051: D2 and D9, an artifact's SBOM is bound by D1 and the image
  SBOM also by D2, and a named region is a component of the image
  documents; the read-after-write covers four bundles. ADR-057: D4, the
  approver's verification includes the recomputation of the SBOM; D5, D6
  and D7, as D5 here states. In ADR-INDEX this record gains its row,
  ADR-040 reads superseded in part by it and the other four amended by
  it.
- **Known limitations, candidates for Beta Definition of Done row 14.**
  A region document has no statement, is not recomputable and is outside
  the claim. A document is conformant only as far as the image states the
  required facts, and not before the gate of D7 exists. A mismatch of the
  recomputation is conclusive only under the sealed commit. A document
  without the lane's declaration of the components outside the image is
  outside the claim.
  The versioning rule of the guideline's section 3.1 is met by a new
  document, not by a counted version. strike publishes no SPDX
  document. A deploy without a registry push publishes nothing of this.
- **Planned work.** Work that is already planned absorbs part of this
  record: the live coverage of region SBOMs, the independent cosign
  check, the live base-SBOM path, the authorization statement's contract
  and verdict, and the release procedure with its register. New work is
  the projection with its freeze event, the canonical form and the SBOM
  statements, the verifier's SBOM checks and the recomputation, the two
  levels, the declared facts, the catalog steps, the removal of SPDX,
  and the conformance gate.

## Alternatives considered

- **Keep the digests in the unpublished record.** The alternative the
  open question named. It leaves the registry as the only witness of
  which SBOM belongs to an image and requires retracting what
  SECURITY.md, the trust-layer map and the soundness note say.
- **Name the documents under `resolvedDependencies`.** That field lists
  what a build needs; an SBOM cataloged over the pushed image is what
  the sealing act generates. The SLSA working draft's SBOM reference
  there is the dependency record of a build, which strike's catalog does
  not claim to be.
- **Leave the produced identities under `resolvedDependencies`, or drop
  them.** They are generated by the build, not needed by it, and a
  second freeze event would be the price of moving them later. Dropped,
  a reproduction loses what it compares.
- **Descriptor annotations or vendor extension fields.** An open
  annotations object reintroduces a map that `contract/attest` omits by
  rule.
- **A second hash in the reference, or SHA-512 throughout.** ADR-008
  allows no per-call algorithm choice, and the registry addresses the
  document by sha256. A rotation is not available where it would count:
  the OCI image specification asks for SHA-256, the pinned registry
  library computes nothing else, and the Sigstore algorithm registry
  binds the hash to the key. It would reach only the digests strike
  defines itself, reopen ADR-046 and leave the weakest link unchanged.
  Its trigger is a post-quantum signature suite, which ADR-008 already
  frames as one deliberate schema change.
- **Name the SBOM statement bundles in the sealed statement.** A bundle
  carries a certificate, a log entry and a timestamp; the sealed
  statement would stop being reproducible.
- **Trust the SBOM statement alone.** It leaves the documents without a
  statement unbound, and it admits several valid, conflicting SBOM
  statements under one identity, an older one replayed among them. D1
  pins which documents the deploy produced.
- **The four forms of D8.** Excluded there, with their reasons.
- **A signature inside the document.** CycloneDX allows an enveloped
  signature. It makes the document's bytes depend on the signing act,
  which ends the reproducibility D6 rests on.
- **Drop the plain referrers once statements exist.** Scanners read
  them, and most documents have no statement.
- **Embed the library's bytes as they are.** It needs a second way to
  produce signed bytes beside the canonical serializer, proves equality
  on raw bytes only, and leaves a document's bytes dependent on the
  library's field order, its escaping and the Go version.
- **The full number rule of RFC 8785.** Its hard part is the shortest
  form of a floating-point number. No field of the path needs one, and a
  mapping that sets one fails the deploy closed.
- **Compare parsed content in the verifier.** Equality of numbers and
  escapes would need a definition, the verifier more code, and no digest
  would tie the two.
- **One document at the delivery item level, carried by the statement.**
  A list of every executable file grows with the image; a statement of
  that size is what the Sigstore documentation advises against, and a
  bound on it would refuse images with an interpreted application.
  Measured, one such image needs 58.6 MB.
- **Above the bound, publish without a statement.** It needs a rule that
  tells a verifier that none is expected, and it makes two classes of
  image.
- **Leave the source date unsealed, or name the strike source in the
  documents.** The first leaves an input of sealed bytes unrecorded. The
  second changes every document with every strike source, so that no two
  sources could yield equal documents. A binary digest instead of the
  commit separates binaries that share their source.
- **Recomputation as a published procedure only, always on, or as a
  command of its own.** A procedure needs something to run, and running
  the lane again needs source and an engine. Always on, every
  verification pulls every layer. A command of its own leaves the
  comparison to the user.
- **Keep SPDX at 2.3, or add the facts of the path to it.** The
  guideline does not admit it and the ISO edition that standardizes it
  is being replaced, so it could never join the claim. It would keep one
  more statement, one more referrer per document and two modules for a
  bill outside the claim.
- **SPDX 3.0.1 on the pinned module.** Measured, its output is not
  reproducible, which ends D6 for it.
- **SPDX 3.0.1 with strike normalizing order and identifiers.** strike
  would own a serialization of a model it does not define, with schema
  validity still unmeasured.
- **Select files by the execute bit alone, or list every regular file.**
  The bit misses Debian's shared objects and every jar of a Java image.
  Every regular file lists data the guideline does not ask for and, in
  a toolchain image, makes a document of 4.7 MB.
- **Retire the region documents.** ADR-051 D9 gives them a purpose no
  image document serves.
- **Complete the document from package registries or license
  databases.** A network peer in the sealing path, a result that is not
  reproducible, and a declaration where the project records
  observations.

### What would change this record

- A released SLSA version that places an SBOM of the output under
  `resolvedDependencies`: the entries are mirrored there.
- A field of a document that needs a number other than a plain integer:
  the number rule of D2 is reopened.
- A post-quantum signature suite strike can use: the hash clause of
  ADR-008 is reopened with it.
- Statement documents that outgrow what cosign and strike's reader
  verify: D2 and the second exclusion of D8 are reopened together.
- An implementing act under Article 13(24) of the Cyber Resilience Act,
  a harmonized standard, or a new version of the guideline: D7 follows.
  A library that produces SPDX 3.0.1 or later deterministically, with an
  independent checker for it: SPDX is reconsidered.
- A compliant, verified SBOM of a base image or of a build step's own
  tool: it is referenced under D7.
- A consumer of region documents that needs file-level detail,
  recomputation or a claim: ADR-051 D9 is amended.

## Principles

- Runtime is attested -- every SBOM a deploy publishes is named by a
  signed, logged statement, the image SBOM is one itself, and the sealed
  statement names the source date and the strike source that produced
  it.
- External references are digest-pinned -- a document is named by its
  digest and by nothing a registry could move, and one document names
  another by hash.
- Reproducibility is enforced, not hoped for -- a document's bytes
  follow from its content, every input of a document is sealed, no
  document carries a signature, and the image SBOM can be derived again
  and compared.
- Observation over declaration -- the catalog states what the image
  carries; a missing fact is reported, never looked up and never
  invented; the binding is checked by hash, not taken from a listing.
- Enforcement is structural, not discretionary -- the verdict fails
  closed on an unnamed or a missing SBOM, with no flag; a release
  requires the recomputation; the conformance claim exists only behind a
  gate.
- Meaning is single-sourced -- the trust-layer map, the soundness note
  and SECURITY.md become true instead of being restated; one serializer
  writes every signed byte; one document carries the conformance claim.
- CUE first -- the declared facts, the sealed additions and the
  statement wrapper are contract definitions; the predicate is typed by
  the standard that owns it.
- Code is liability -- one existing field, the existing serializer, the
  existing producer and the existing base-SBOM reader carry the binding;
  no module is added; four further binding forms are excluded rather
  than kept as options.

## Sources consulted at authoring (2026-11-15)

- SLSA specification v1.2 (approved), "Build: Provenance"; the working
  draft at slsa-framework/slsa `73fb193` (2026-11-10):
  `spec/build-provenance.md`, `spec/faq.md`,
  `spec/verification_summary.md`.
- in-toto/attestation at `50bf017` (2026-10-21): `spec/v1/envelope.md`,
  `spec/predicates/cyclonedx.md`, `spdx2.md`, `spdx3.md`,
  `reference.md`.
- sigstore/cosign at `6181e75` (2026-11-12, latest tag v3.1.4):
  `doc/cosign_download_sbom.md`, `doc/cosign_attest.md`,
  `doc/cosign_verify-attestation.md`,
  `pkg/cosign/attestation/attestation.go`,
  `internal/pkg/cosign/payload/size/size.go`; Sigstore documentation,
  "Signing other types".
- CycloneDX/cyclonedx-go v0.12.0 (`717afd1`, 2026-08-22):
  `cyclonedx.go`, `cyclonedx_json.go`, `encode.go`. CycloneDX JSON
  schema 1.6.
- spdx/tools-golang v0.6.0-rc4 (`bca9e0b`, 2026-06-18): `spdx/v3/v3_0`,
  `spdx/v3/internal/ld`, `json`, `go.mod`. SPDX specification 3.0.1,
  "Model and serializations".
- RFC 8785, JSON Canonicalization Scheme. JSON Signature Format 0.82.
- opencontainers/image-spec at `4feed4a` (2026-10-22);
  google/go-containerregistry v0.22.1; sigstore/protobuf-specs v0.5.2,
  the algorithm registry.
- BSI TR-03183-2, version 2.1.0 (2025-08-20): sections 3.1, 3.2, 4, 5,
  6.1, 7, 8.1, 8.2, 8.3 and 8.4. Read in BSI's own file of that
  version.
- BSI, the page of TR-03183 (as updated 2026-07-31), and the BSI
  property taxonomy for CycloneDX v0.1.2 (`f4c887c`, 2026-01-30).
- ISO catalog, ISO/IEC PRF 5962, edition 2 (as shown on 2026-11-15).
- Regulation (EU) 2024/2847: Article 3(39), Article 13(13) and (24),
  Article 31, Article 71, Annex I Part II point 1, Annex VII point 8.
- [The state of play](research/adr-059-sbom-binding-state-of-play.md)
  and [the measurement record](research/adr-059-sbom-measurements.md),
  each with its own source list.

## Amendment 2026-11-16 -- D7: the construction of the serial number

D7 derives a document's serial number from its content. The construction
is a name-based UUIDv8 as in RFC 9562 Appendix B.2: SHA-256 over the URL
namespace ID, `6ba7b811-9dad-11d1-80b4-00c04fd430c8`, followed by the
document's canonical bytes (D2) rendered without `serialNumber`; the
first 128 bits of the hash, with the version bits set to 8 and the
variant bits to 10, written as a `urn:uuid:` URN. The document is then
rendered once more with that serial number. RFC 9562 forbids version 5
for a name-based UUID over SHA-256, and ADR-008 forbids SHA-1, so
version 8 is the form left. A recomputation (D6) and any other
implementation derive the same serial number from the same content.

## Amendment 2026-11-17 -- D6 and D7: the source date is not sealed, and the builder version is the version of strike (ADR-060)

D6 added two things to the sealed statement: the required external
parameter `sourceDate` and the optional `builder.version`, the commit of
the strike source. No statement carried either. The first is withdrawn.
The second stays, with another value and as a required field:
[ADR-060](ADR-060-version-as-constant-of-the-source.md) decides the
version of strike. Of the changes to the sealed statement that this
record decides, the freeze event carries the entries under `byproducts`
(D1) and the builder version.

**The source date is not sealed.** D6 argued that the bytes of the
sealed statement depend on the source date, through the document
digests, and that nothing sealed recorded it. The premise behind the
argument, that an input of sealed bytes must itself be sealed, proves
too much: a digest binds the content it is taken over without repeating
it. The source date is the timestamp of every document, D1 seals the
digest of every document, and a second copy in the statement would bind
nothing further. It would also claim more than the control plane can
back. The value is read from the environment of the deploy process. By
the definitions of the
[soundness note](ATTESTATION-SOUNDNESS-AND-THE-TRUST-BOUNDARY.md) it is
host-asserted, and the rule table there places a host-asserted value in
the informational layer, never in the sealed one. Inside a document it
stays what it is, the timestamp the producer chose; the trusted time is
the RFC 3161 token (D7). Nor does the withdrawal leave a gap in the
external parameters, which SLSA requires to be complete at Build L3: the
source date reaches no byte of the image, whose content carries fixed
times. It reaches only the timestamp of the documents the sealing act
generates, and each of them is bound by its digest.

**The builder version is the version of strike.** D6 named the
cataloging code by the commit of its source, learned at link time. A
commit set at link time makes the binary a function of its commit: two
commits whose compiled files are equal yield two binaries, and only a
build that is told the commit reproduces one. The project reads
reproducibility the stricter way: the same source, built the same way,
yields the same binary, whatever commit holds it. ADR-060 makes the
version a constant of the source (D1) and requires it in the sealed
statement as `{"strike": "<version>"}` (D5). Every build knows it, so
the field is never absent.

**Every document names the version of its tool.** D6 kept the strike
source out of the documents, so that documents of two sources could be
equal. ADR-060 D7 places the version in the tool entry of every
document. A document now changes with the release that produced it, once
per release; documents of two sources that state one version can still
be equal.

**The recomputation.** It renders a document with the timestamp the
published document states and with the version the sealed statement
names, never with its own. A document that names another version than
the sealed statement therefore fails the comparison. Beyond that the two
versions decide nothing by themselves:

- a match passes, whatever strike verifies;
- a mismatch fails the verdict, whatever strike verifies;
- a mismatch is conclusive only when the verifying strike states the
  release version the sealed statement names. When the two differ, or
  either is the development version (ADR-060 D3), the catalogs may
  differ: the verdict says so and names both versions, and a run with
  the release the statement names decides.

For a release the approver recomputes with the release of strike the
sealed statement names, so a mismatch is conclusive (ADR-057 D4 as
amended).

**Known limitations.** A build from changed source that states a release
version is not told apart by its version; only the digest of a release
does that. The list gains one more, on the version of a file. D7 step 3
takes it from the file's modification time, as the guideline rules where
no version is assigned (5.2.2). Where an image carries fixed times, as
every layer strike writes does, that time does not follow the file's
content: an altered file keeps its version, while the guideline asks
that an altered component be assigned a new one (3.1). Only the file's
hash tells the two apart. Like the others it is a candidate for row 14
of the Beta Definition of Done, and step 3 is where it is resolved or
kept.

This amendment is mirrored by dated amendments of
[ADR-040](ADR-040-control-plane-sbom-and-keyless-attestation.md), whose
amendment of 2026-11-16 lists the sealed additions, and of
[ADR-057](ADR-057-release-authorization-two-signatures.md) (D4, D6).

**Supersedes, in Status above:** "the entries under `byproducts`, the
source date and the builder version" is read as: "the entries under
`byproducts` and the builder version". **In D6 above:** the heading's
", and every input of it is sealed" is withdrawn; the entry of the
source date is read as: "**the source date**, which the document states
as its timestamp"; the entry of the cataloging code is read as: "**the
cataloging code**, which the sealed statement names from this record on:
the version of strike, in SLSA's `builder.version` as
`{"strike": "<version>"}` (ADR-060 D5). The version is a constant of the
source, so every build knows it and the field is required"; "The last
two are new. With D1 the bytes of the sealed statement depend on the
source date, through the document digests, and nothing sealed recorded
it. The commit is in the sealed statement and not in the documents, so a
document changes only when the catalog's output changes, and documents
of two strike sources can still be equal." is read as: "The last is new.
The version is in the sealed statement and in every document, so a
document changes when the catalog's output or the version changes, and
documents of two strike sources that state one version can still be
equal."; "A mismatch is conclusive only when the verifying strike is
built from the sealed commit; when the two differ, or either is unknown,
the verdict says so and names both." is read as: "A mismatch is
conclusive only when the verifying strike states the release version the
sealed statement names; when the two differ, or either is the
development version, the verdict says so and names both." **In D7
above:** ", which D6 seals" and ", seals the epoch as `sourceDate`" are
withdrawn. **In Consequences:** ", and adds the source date to the
external parameters and the strike commit to `builder.version`" is read
as: ", and adds the version of strike to `builder.version`"; "the
external parameters gain the required `sourceDate`; the builder gains
the optional `version`, a closed struct with the one field `strike`;" is
read as: "the builder gains the required `version`, a closed struct with
the one field `strike`, whose value is a version by ADR-060;"; "The
bootstrap lane and the stage_0 build pass their commit to the linker."
is withdrawn; "The verdict does not compare a document's timestamp with
the sealed source date: the recomputation renders the document from it,
so a difference shows as a digest mismatch." is read as: "The
recomputation renders a document with the timestamp the published
document states and with the version the sealed statement names."; ",
the external parameters gain the source date and the builder its
version" is read as: ", and the builder gains its version"; "A mismatch
of the recomputation is conclusive only under the sealed commit." is
read as: "A mismatch of the recomputation is conclusive only when the
verifying strike states the release version the sealed statement names.
A build from changed source that states a release version is not told
apart by its version. A file whose version is its modification time
keeps that version when its content changes, wherever the image carries
fixed times." **In Alternatives considered:** of the entry "Leave the
source date unsealed, or name the strike source in the documents.", both
alternatives are decisions now, the second for the version of strike and
not for its commit; "The first leaves an input of sealed bytes
unrecorded." is withdrawn; "The second changes every document with every
strike source, so that no two sources could yield equal documents." is
read as: "A commit in the documents would change every document with
every strike source; the version changes a document once per release.";
sealing the source date and the commit of the strike source at link time
join the alternatives, with the reasons above. **In Principles:** ", and
the sealed statement names the source date and the strike source that
produced it" is read as: ", and the sealed statement names the version
of the strike that produced it"; "every input of a document is sealed,"
is read as: "every input of a document is sealed or stated by the
document,".

## Amendment 2026-11-18 -- D2: the bound a deploy applies before it signs

D2 lets a deploy sign no statement that its own reader would refuse and
names the reader's bound, 8 MiB for a bundle. A bundle exists only once
the signature, the log entry and the timestamp exist, so a deploy cannot
hold a bundle against that bound before it signs. It bounds the
statement instead, and the reader's bound follows from it.

A bundle carries its statement in base64, four bytes for every three,
beside the certificate, the log entry with its proof and the timestamp.
Measured on 2026-11-18 on the three statement bundles of the golden
fixtures, a bundle is 6,023 to 6,066 bytes larger than the base64 form
of its statement. A deploy reserves 64 KiB for that part and signs a
statement of at most 6,242,304 bytes: three quarters of what the
reader's 8 MiB leave beside the reserve. The bound holds for each of the
four statements. A deploy with a larger statement fails before its first
signature, so no certificate is requested and nothing is logged for it.

**Supersedes, in D2 above:** "A statement document above the reader's
bound fails the deploy;" is read as: "A statement of more than 6,242,304
bytes fails the deploy before it signs;".
