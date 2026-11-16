# SBOM Documents for strike: Measurements Behind ADR-059 (status: 2026-11-16)

This document records the measurements behind
[ADR-059](../ADR-059-sbom-sealed-digest-and-signed-statement.md). They
answer what the image SBOM costs and contains on real images, whether the
SPDX 3.0.1 model of the pinned SPDX module can be published, and what the
CUE generators make of the new contract shapes. The survey that preceded
them is [the state of play](adr-059-sbom-binding-state-of-play.md).

Every run was a throwaway in a scratch git worktree: it changed no tracked
file and was removed after its report. Scratch code ran inside the deploy
package so that it used strike's own catalog, renderer and canonical
serializer. Where a run needed the integer token of ADR-059 D2, the
scratch worktree admitted it in the canonical serializer before the run.

## Summary

- **The canonical form holds on every image.** In all eight images the
  only JSON number of a CycloneDX document is `1`, no key is outside
  ASCII, and the canonical document appears byte for byte as the
  predicate of the canonical statement.
- **cosign verifies the statement form.** cosign v3.1.4 verified a
  canonical in-toto Statement v1 with predicate type
  `https://cyclonedx.org/bom` over six images, and one with
  `https://spdx.dev/Document/v3`, and rejected each under another
  predicate type.
- **Selecting files by the execute bit misses executables.** Debian ships
  its shared objects without it and Java images ship jars without it. A
  rule by content and name misses only a Windows batch file and data files
  that carry the bit.
- **A large application image outgrows a statement.** The delivery item
  document of n8n under the ratified file rule is 43.9 MB, and its signed
  envelope 58.6 MB, seven times the 8 MiB bundle bound. Its top-level
  envelope is 1.2 KB.
- **The catalog's npm source is a lockfile.** The two Node.js application
  images carry no lockfile and thousands of installed packages, and the
  catalog reports none of them. Its only npm components, in the Go
  toolchain image, come from a lockfile in Go's vendored source tree.
- **SPDX 3.0.1 on the pinned module is not reproducible.** Eighteen
  outputs of the same input were eighteen different byte strings, within
  one process and across processes.
- **No Go checker loads the SPDX 3.0.1 JSON schema.** Its IRI pattern
  uses a lookahead that Go's regular expressions do not support.

## Method and scope

| Run | Date | Tree | Subject |
|---|---|---|---|
| Real images | 2026-11-15 | `39297fc` | six images, classification, sizes, cosign |
| SPDX 3.0.1 | 2026-11-15 | `39297fc` | determinism, sizes, licenses, checker candidates |
| Node.js application images | 2026-11-15 | `39297fc` | two more images, the ratified file rule on all eight |
| `byproducts` generator | 2026-11-15 | `1495407` | three CUE forms of the entry grammar |
| SBOM statement generator | 2026-11-16 | `1495407` | two CUE forms of the statement wrapper |

Images were read by digest from their registries with
go-containerregistry, flattened in memory and walked as one tar stream.
Each document was rendered with cyclonedx-go v0.12.0 as the catalog
renders it, made canonical, wrapped in a statement and signed into a DSSE
envelope with an ephemeral ECDSA P-256 key. Sizes are bytes.

### The images

| Label | Reference | Read as linux/amd64 |
|---|---|---|
| static | `cgr.dev/chainguard/static@sha256:939754fefdbdb198356dc3187310417777d4dd8561be000885e224d49a4ce727` | same |
| python | `cgr.dev/chainguard/python@sha256:4a4bb4a2b468aaa396e85b5c443855fb00d34256ab947c6df9430637cfb0a2d4` | same |
| go | `cgr.dev/chainguard/go@sha256:806b06607f346ed94cbf0c7e0821502f8a048b22f30bbd9a0e46cc28bfe2146d` | same |
| coredns | `docker.io/coredns/coredns@sha256:3429e3bbffb1e839470c4a3541d4d78aca84a1394c75a539d0200c58c63196ac` | same |
| keycloak | `quay.io/keycloak/keycloak@sha256:de6ed510b59cfcd25f129ba4118696fa10d4165eee921a8d846178b6d35d30f7` | same |
| debian-trixie | `docker.io/library/debian@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2` | `sha256:7378260c0a098d27ac206225db5e7d92b8c7c84ea7afccc86eeb513756bbd392` |
| n8n | `docker.io/n8nio/n8n@sha256:b4b90747b81fcda7e76550c0d3aa7f0f64917a1e9573cff40d6834eaf2e0f8ea` | `sha256:13087b14e4c7b2540cf1ed02adbb09818614540d883f9eafc8b6b3cbd715bee3` |
| ghost | `docker.io/library/ghost@sha256:2e3ca97643ea2a8cde6d0c97fae15ff39bfb60714f5abaab3f65263a2ed7c2a7` | `sha256:3bf9c34dc760c4b5afb47017c57485adaffd9a9a02d7fa806df2309984366f2b` |

The first five are pinned in the tree's dev container and sigstore harness.
debian-trixie is the current Debian stable slim image, n8n (2.47.7) and
ghost (6.77.0) are published Node.js applications with a large installed
`node_modules`; the operator ratified these three for the runs.

## Classification of files

Every regular file was tested for:

- the execute bit (any of the three);
- ELF magic, an interpreter line (`#!`), Java class magic;
- archive magic: zip family, gzip, xz, zstd, bzip2, 7z, ar, tar;
- a script extension (`.py .pyc .pyo .sh .bash .pl .pm .rb .js .mjs
  .cjs .php .lua .tcl .class`) or an archive extension.

Three rules were compared:

- **Mode:** the execute bit, or archive magic.
- **Content and name:** ELF, interpreter line, class file, script
  extension, archive magic or extension.
- **Ratified:** content and name, with `.bat .cmd .ps1` added, an archive
  only if it combines several members (zip family, tar, ar, 7z, rpm by
  magic, the archive extensions without the single-stream compressors,
  compressed tar by name), and every file with an execute bit. This is
  the rule of ADR-059 D7 step 3. The runs classified a hardlink by its
  target only; D7 also applies the name rules to the hardlink's own name.

| Image | Regular | Hardlinks | ELF | Interpreter line | Exec bit | Mode | Content and name | Ratified | Bit only | Single stream |
|---|---|---|---|---|---|---|---|---|---|---|
| static | 723 | 507 | 0 | 0 | 0 | 0 | 2 | 2 | 0 | 0 |
| python | 7262 | 41 | 307 | 55 | 342 | 374 | 2920 | 2925 | 3 | 0 |
| go | 10062 | 41 | 282 | 79 | 318 | 358 | 419 | 413 | 2 | 8 |
| coredns | 965 | 0 | 1 | 1 | 5 | 10 | 7 | 5 | 3 | 5 |
| keycloak | 3011 | 1044 | 149 | 144 | 294 | 782 | 829 | 832 | 0 | 0 |
| debian-trixie | 2678 | 1 | 655 | 231 | 407 | 408 | 1500 | 1498 | 0 | 2 |
| n8n | 122656 | 256 | 233 | 628 | 982 | 1001 | 75167 | 75336 | 157 | 1 |
| ghost | 65235 | 53900 | 740 | 719 | 974 | 1009 | 8369 | 8437 | 47 | 2 |

"Bit only" counts files the ratified rule lists for the execute bit alone;
"Single stream" counts files the content-and-name rule took for archives
that combine no members.

- **What the execute bit misses.** Debian's shared objects under
  `usr/lib/x86_64-linux-gnu/` are ELF files of mode 0644; keycloak's jars
  carry no execute bit; the Chainguard images ship scripts, Python
  sources and byte code without it.
- **What the bit alone adds.** In coredns: `ca-certificates.crt`,
  `copyright`, `os-release`. In python and go: `README.md` and two linker
  scripts named `libgcc_s.so`. In n8n: `package.json`, `LICENSE` and
  `README.md` files of installed packages. In keycloak the one such file
  was `kc.bat`, which the ratified rule catches by name.
- **Single-stream files.** Changelogs (`.gz`), compressed logs (`.xz`),
  Go's profile and test data (`.pgo`, `.json.zst`), one minified script
  (`.js.gz`).
- **Hardlinks.** Every hardlink resolved to a regular entry of the same
  image. ghost ships its pnpm content store as regular files with hash
  names and no extension; the `.js` names exist only on hardlink entries.
  Classified by target only, 271 of its 53900 hardlinks qualify.
- **Other entries.** The Chainguard images and n8n carry five character
  devices each.

## Document sizes

| Image | Top-level document | Top-level envelope | Delivery item document (ratified rule) | Its envelope | Every regular file | Its envelope |
|---|---|---|---|---|---|---|
| static | 506 | 1156 | 1369 | 2308 | 322531 | 430524 |
| python | 506 | 1156 | 1401195 | 1868740 | 3372203 | 4496752 |
| go | 46703 | 62752 | 236914 | 316368 | 4658275 | 6211516 |
| coredns | 36063 | 48564 | 38236 | 51464 | 465204 | 620752 |
| keycloak | 506 | 1156 | 417668 | 557372 | 1387876 | 1850984 |
| debian-trixie | 12267 | 16836 | 682950 | 911080 | 1211438 | 1615732 |
| n8n | 506 | 1156 | 43933467 | 58578436 | 71922852 | 95897616 |
| ghost | 15799 | 21548 | 4358530 | 5811856 | 42212325 | 56283580 |

- Each file component carried its name, its SHA-512 and the three BSI
  properties. An envelope is about 1.33 times its document, the base64 of
  the payload.
- Against the 8 MiB bundle bound (8388608 bytes), every top-level envelope
  fits; the delivery item envelope of n8n does not, and listing every
  regular file of n8n exceeds 64 MiB as a document.
- The CycloneDX encoder output was one byte longer than its canonical
  form in every document: the trailing newline.

## Premises of the canonical form

In all eight images:

- the set of JSON numbers in each document was exactly `{1}`, the
  `version` field;
- no key contained a byte outside ASCII;
- the canonical statement contained `"predicate":` followed by the
  canonical document's bytes unchanged.

## Catalog coverage

| Image | Components the catalog reports | What the image carries |
|---|---|---|
| static | none | Wolfi apk database |
| python | none | Wolfi apk database |
| go | 366 npm | Wolfi apk database; Go toolchain |
| coredns | 196 golang | one static Go binary |
| keycloak | none | rpm database; jars |
| debian-trixie | 78 deb | dpkg status database |
| n8n | none | 3554 `package.json` files below `node_modules/`; no lockfile |
| ghost | 88 deb, 12 golang | 1858 `package.json` files below `node_modules/`; no lockfile |

The catalog's npm source is a file named `package-lock.json`. The only
such file in the eight images is
`usr/lib/go/src/cmd/vendor/golang.org/x/telemetry/package-lock.json`, a
lockfile in Go's vendored source tree, and it is the source of the go
image's 366 npm components.

## Modification times

| Image | Distinct times | Earliest | Latest |
|---|---|---|---|
| static | 4 | 1970-01-01T00:00:00Z | 2026-10-28T20:49:35Z |
| python | 46 | 1970-01-01T00:00:00Z | 2026-11-11T16:35:23Z |
| go | 42 | 1970-01-01T00:00:00Z | 2026-11-11T16:13:40Z |
| coredns | 38 | 1970-01-01T00:00:00Z | 2026-10-21T03:07:41Z |
| keycloak | 362 | 2008-08-12T13:00:32Z | 2026-10-31T10:43:54Z |
| debian-trixie | 121 | 1999-08-26T12:06:20Z | 2026-11-04T21:23:39Z |
| n8n | 81 | 1970-01-01T00:00:00Z | 2026-11-13T09:36:08Z |
| ghost | 190 | 1985-10-26T08:15:00Z | 2026-11-11T22:55:29Z |

Five of eight images carry files at the epoch. As the version of a file
without one (BSI TR-03183-2 section 5.2.2), such files get the epoch.

## Time and memory

- Fetching and flattening took 1.2 s to 29.7 s per image and dominated
  every run.
- Rendering and canonicalizing the largest delivery item document (n8n)
  took 806 ms; wrapping and signing it took 307 ms.
- The flattened image was held in memory, as the deploy does at the
  anchor. Heap after flattening: 12 MB (static), 0.2 GB (coredns,
  debian-trixie), 1.2 GB (keycloak), 1.5 GB (python), 1.9 GB (go),
  2.4 GB (ghost), 3.1 GB (n8n, from a flattened tar of 1.29 GB).

## cosign

`cosign verify-blob-attestation` v3.1.4 ran with the ephemeral public key,
`--insecure-ignore-tlog=true` and the image manifest as the blob, so that
the claims check compared the statement's subject with the manifest's
sha256.

- With `--type cyclonedx`: `Verified OK` on all six images of the first
  run.
- With `--type spdxjson` on a CycloneDX statement: exit 1, `invalid
  predicate type, expected spdxjson got https://cyclonedx.org/bom`.
- With `--type https://spdx.dev/Document/v3` on an SPDX 3 statement:
  `Verified OK`; with `--type cyclonedx`: exit 1.
- cosign printed that `--signature` is deprecated in favor of `--bundle`.

The keyless bundle and the read from a registry were not part of these
runs.

## SPDX 3.0.1 on spdx/tools-golang v0.6.0-rc4

A 2.3 model with packages, files with SHA-512 checksums, one
`LicenseRef-` license and relationships was converted with
`v3_0.From_v2_3`, given `software_sbomType` `build`, and marshaled. One
`simplelicensing_LicenseExpression` was added in the 3.0.1 model itself.

| Size | Packages | Files | Bytes | Canonical bytes |
|---|---|---|---|---|
| small | 3 | 0 | 4964 | 4963 |
| mid | 100 | 1000 | 461216 | 461215 |
| large | 1000 | 10000 | 4592227 | 4592226 |

- **Determinism.** Three outputs per size in each of two processes: all
  eighteen were different. With the generated per-type numbers and the
  order of lists removed, the outputs of one size were equal. The order of
  the graph and the binding of the generated identifiers `<Type>-<n>`
  follow Go map iteration.
- **Identifiers.** The document's identifier is the 2.3 namespace plus
  `#`. Elements with a 2.3 identifier keep it under the prefix `SPDXRef`;
  others are numbered per type.
- **Licenses.** A 2.3 declared license `LicenseRef-scancode-public-domain
  OR MIT` becomes a disjunctive license set over a custom license and a
  listed license, not a license expression. The expression added in the
  3.0.1 model survived as written. MIT is emitted as a separate listed
  license element at every occurrence.
- **Creation info.** The converter writes `createdBy` as an empty list.
- **Numbers and keys.** No JSON number and no non-ASCII key at any size.

### Checkers for the SPDX 3.0.1 schema

| Candidate | Finding |
|---|---|
| SPDX tools-java 2.0.7 (`ghcr.io/spdx/tools-java`) | checks the bundled JSON schema and the library's own rules, not SHACL; image about 550 MB; its entrypoint is a shell wrapper that names a jar file that does not exist |
| spdx3-validate 0.0.7 | checks schema and SHACL; no published image; fetches schema, context and model from spdx.org on every run |
| rudof 0.3.39 | SHACL only; cannot expand a document whose context is a remote URL |
| spdx-zen | a parser library without a validation entry point; replaces an unloadable context with an empty one |
| jv v0.7.0 in a custom image | refuses the schema itself: `$defs/IRI` has the pattern `^(?!_:).+:.+`, and Go's regular expressions have no lookahead |

Schema validity was therefore not measured.

## Generators

### `byproducts` element

Three forms of the entry grammar
`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(/sbom(/(top-level|delivery-item))?)?$`
were generated:

- **Inline constraint** (`[...#ResourceDescriptor & {name: #ByproductName}]`):
  the Go field stays `[]ResourceDescriptor`, and a type `ByproductName
  string` is emitted.
- **Named definition** (`#Byproduct`): the field becomes `[]Byproduct`,
  with `type Byproduct ResourceDescriptor`, the same struct.
- **Named definition with a Go type override:** the field stays
  `[]ResourceDescriptor`, and both types are emitted unused.

Under every form, `cue vet` accepted a valid run-details value and
rejected the name `image/spdx` and an entry without a name. The exported
JSON schema did not change.

### SBOM statement

`#SBOMStatement` with a non-empty subject and a predicate typed as a
pinned, otherwise open `#CycloneDXDocument`, overridden in Go to
`encoding/json`'s `RawMessage`:

- With `@go(-)` on the document definition, the generator emits
  `SBOMStatement{Type, Subject []Subject, PredicateType, Predicate
  json.RawMessage}` and no document type. Without it, it also emits
  `type CycloneDXDocument map[string]any`.
- `cue vet` and the runtime schema validation accepted a valid statement
  and rejected a specification version 1.6, a missing serial number and
  an empty subject.
- The canonical statement embedded the canonical document unchanged, and
  the walk of the numbers test passed with the statement as a root.
- The exported JSON schema did not change.

## Not measured

- Validity of an SPDX 3.0.1 document against its schema.
- An independent checker for the CycloneDX document and the guideline's
  field rules.
- The keyless bundle of an SBOM statement, read from a registry by
  `cosign verify-attestation`.
- The size of the delivery item document when hardlinks are also
  classified by their own names.
- Whether the packed layer of a region yields the same catalog as its
  producer layer.

## Sources

- CycloneDX/cyclonedx-go v0.12.0; spdx/tools-golang v0.6.0-rc4
  (`spdx/v3/v3_0`, `spdx/v3/internal`); google/go-containerregistry as
  pinned in `go.mod`; sigstore/cosign v3.1.4.
- SPDX 3.0.1 JSON schema,
  https://spdx.org/schema/3.0.1/spdx-json-schema.json (read 2026-11-15).
- spdx/tools-java at `5273da2`; JPEWdev/spdx3-validate 0.0.7;
  rudof-project/rudof 0.3.39; interlynk-io/spdx-zen;
  santhosh-tekuri/jsonschema `cmd/jv` v0.7.0 (read 2026-11-15).
- BSI TR-03183-2, version 2.1.0 (2025-08-20), sections 5.2.2 and 8.1.4 to
  8.1.7.
- Spike reports of the runs in the table above (ephemeral, not
  committed).
