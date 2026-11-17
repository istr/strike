# ADR-060: The version of strike is a constant of its source, set by one commit per release

## Status

Accepted, 2026-11-17. Drafted against
`62ec79777e0cd685fb1ee320be02abfa8a9a26cf`. Every design fork behind
this record was surfaced and ratified by the operator on 2026-11-17. The
survey behind the context is
[the state of play](research/adr-060-version-identification-state-of-play.md);
the measurements the decisions rest on are
[the measurement record](research/adr-060-version-measurements.md); the
primary sources consulted at authoring are listed at the end.

Settles how the strike that produced a statement, a document or a binary
is named.
[ADR-059](ADR-059-sbom-sealed-digest-and-signed-statement.md) D6 had
answered with the commit of the strike source, passed to the linker; no
statement was ever produced with it. Amends, by dated amendment sections
in the respective records, ADR-059 (D6, D7 and their consequences),
[ADR-057](ADR-057-release-authorization-two-signatures.md) (D4, D6) and
[ADR-040](ADR-040-control-plane-sbom-and-keyless-attestation.md) (the
sealed additions). Builds on
[ADR-009](ADR-009-bootstrap-reproducibility-proof.md): a version that is
source leaves every rebuild of that source equal.

Changes what the sealed statement carries: `builder.version` becomes a
required field. The change lands in the one freeze event ADR-059
announces. Changes the content of every SBOM document strike produces,
by the version of its tool.

## Context

### The principle

Two goals meet in the version of a build tool. Reproducibility, read
strictly: the same source yields the same binary, whoever builds it and
whatever commit holds the source. Identification: a user can tell which
strike a binary is and which strike produced an artifact, can follow a
documented change to the release that made it, and can map a
vulnerability to the releases it affects. A version taken from outside
the compiled source serves the second goal at the cost of the first. A
version that is part of the source serves both.

### What the tree does at the anchor

- strike is built with `-trimpath` and `-ldflags="-s -w"`; the bootstrap
  lane adds `-buildvcs=false`. Nothing states a version: there is no
  constant and no file, and no command prints one.
- The sealed statement names the builder by `builder.id` alone;
  `contract/attest` omits `builder.version`.
- Every CycloneDX document names its tool as `strike`, without a
  version.
- ADR-059 D6 decided `builder.version` as the commit of the strike
  source, set at link time by the bootstrap lane and the stage_0 build
  and absent from a build that passes none.

### What the survey found

- No project and no regulator the survey read sets reproducibility
  against version identification. The conflict belongs to one mechanism:
  version data taken from the version-control system, such as a commit,
  a tag or a commit time. A rebuilder has to supply it or do without,
  and two commits with equal files yield two binaries.
- The Go toolchain is the working example of the other mechanism. Its
  release version is the content of a tracked file that exists on a
  release branch only, the commit of a release changes that file and
  nothing else, and the main branch carries a constant for the release
  in development. Two parts do not carry over: without the file Go
  derives a version from the version-control system, and between two
  releases the commits of a release branch keep the earlier label.
- A scanner such as Trivy takes the version of a Go binary's main module
  from the build information, the linker flags or the symbol table. A
  value compiled in as a constant is in none of them.

### The legal frame

- **Cyber Resilience Act.** A product bears an element allowing its
  identification, on the product or, where that is not possible, on its
  packaging or in an accompanying document (Article 13(15)). Information
  about a fixed vulnerability includes what allows users to identify the
  product affected (Annex I, Part II (4)). The technical documentation
  lists the versions of software affecting compliance (Annex VII 1(b)).
  The articles and annexes do not rule how a version is carried and do
  not mention reproducible builds.
- **BSI TR-03183-2, version 2.1.0.** A separate SBOM for each software
  version, and a new version for an altered component (3.1). The version
  is the identifier its creator uses; Semantic or Calendar Versioning
  SHOULD be used (5.2.2), toward a strictly increasing sequence (8.1.9).
  Reproducible builds let hash values identify components (8.4.3). The
  guideline asks nothing of the tool that generates an SBOM.
- **CISA and others, 2026 Minimum Elements for an SBOM.** Not binding.
  The name and the version of the tool that generated an SBOM are
  minimum elements; a version that is not available is to be stated as
  unknown.
- **SLSA v1.2.** `builder.version` is an optional map of the names of
  platform components to their versions. `builder.id` alone determines
  the build level, and no step of the verification reads a version.

In every text read, a defined version and a hash stand side by side.
None sets one against the other.

### Facts measured at authoring

Recorded in
[the measurement record](research/adr-060-version-measurements.md):

- A commit that changes one file and an empty commit on top of it share
  one tree. A check of what a commit changed tells the two apart, so a
  build that consulted it would yield two binaries from one source.
- After a fetch of depth 1 such a check reports every file as changed.
  Both build paths of strike fetch at depth 1.
- A Go embed pattern cannot leave its package directory, and a pattern
  without a match fails the build.
- The pattern of D2 and the expression the Semantic Versioning site
  suggests accept the same strings among 5,680,840 without build
  metadata, and the pattern rejects every string with it.

## Terms

- **Version** -- the value of the constant of D1.
- **Development version** -- `0.0.0-devel`.
- **Release version** -- every other version.
- **Version file** -- the Go source file that holds the constant and
  nothing else.
- **Release commit** -- the commit of D4, which sets a release version.

## Decision

### D1 -- The version is a constant of the source

One Go constant states the version of strike. It lives in a file of its
own, `internal/deploy/version.go`, and is compiled in. No linker flag,
no build argument, no version-control stamp, no generated file and no
embedded data file carries or changes it. Every build of one source tree
therefore states one version, whatever builds it: `make build`, the
stage_0 build and the bootstrap lane alike. The same source yields the
same binary, and nothing reaches the build beside its source.

### D2 -- The value is a Semantic Version without build metadata

The value follows Semantic Versioning 2.0.0: the core and an optional
pre-release. Build metadata is outside the grammar. Precedence ignores
it, so two strings would name one version, and it is the usual place for
a date or a hash, which D1 excludes. The grammar is the scalar `#SemVer`
of `contract/primitive`. strike compares versions for equality only. A
release tag is `v` followed by the version.

### D3 -- main states the development version

On main the constant is `0.0.0-devel` and never anything else. The value
is a valid version, and no release uses the core 0.0.0, so it ranks
below every release. It names no single source: every build from main
states it. Where a rule needs to know the source a version stands for,
the development version counts as unknown.

### D4 -- A release version is set by one commit on a branch of its own

A release branches from a commit of main and adds one commit, the
release commit. It changes the version file and no other file: the
constant becomes the release version. The branch ends with it. Nothing
is ported back to a release; a fix is a new release from main. No commit
other than a release commit therefore states a release version, and a
release version stands for one source.

The signed tag of ADR-057 D4 names the release commit and is `v`
followed by its version. The release procedure checks this with git, on
the full history and before the build: the tag names a commit whose
parent is on main and which changes the version file alone, to the
version of the tag. The check is a gate of the procedure. It is not an
input of a build: no build reads version-control data.

### D5 -- The sealed statement names the version of its builder

`runDetails.builder.version` is `{"strike": "<version>"}` and is
required. SLSA defines the field as a map; here it is a closed struct
with the one key, and it carries the version and nothing else, no date
and no commit. The value is a constant of the control plane's own
source. The signer states it about itself, as it states `builder.id`.
Nothing is received from another party, which is what keeps the engine's
version informational (ADR-057, amendment of 2026-11-02).

The field serves two readers. Whoever learns of a flaw in a release of
strike finds the artifacts that release built. The recomputation of
ADR-059 D6 learns which strike produced a document. Verification gates
on nothing in it: `builder.id` stays the sole determiner of the build
level.

### D6 -- The binary states its version

`strike version` prints the version. A scanner does not find the
constant, so without the command a user who holds the binary cannot tell
which strike it is.

### D7 -- Every SBOM document names the version of its tool

The tool entry of every CycloneDX document strike produces carries the
version beside the name. The value is known, and the minimum elements
ask for it. A document therefore changes with the release that produced
it, once per release and not with every commit. How the recomputation
treats the entry is ruled by ADR-059 D6 as amended.

## Consequences

- **Schema (`contract/primitive`, `contract/attest`).** `#SemVer` joins
  the scalars. `#SLSABuilder` gains the required `version`, a closed
  struct with the one field `strike`. The change is part of the one
  freeze event of ADR-059.
- **Producer (`internal/deploy`).** The version file exists. The
  projection writes the version beside the builder identity, and the
  CycloneDX renderer writes it into the tool entry. No test states the
  value of the constant as its expectation, and fixtures use other
  versions, so a release commit changes one file and every gate stays
  green. The golden fixtures are produced once, in the freeze event, and
  state the development version; a release does not touch them.
- **Build lines.** D1 holds for a build line that disables
  version-control stamping, as the bootstrap lane does. The stage_0
  build line does not pass the flag at the anchor. It has to before the
  first release; the alignment belongs to the bootstrap proof (ADR-009).
- **Command.** `strike version` follows the freeze event, as a change of
  its own.
- **Recomputation and release.** ADR-059 D6 and ADR-057 D4 and D6 are
  amended: which version a recomputation renders, when a mismatch is
  conclusive, the order of a release, and the strike an approver
  recomputes with.
- **Procedure (`docs/RELEASES.md`).** The gate of D4 becomes a step of
  the release procedure when that procedure is written.
- **Records.** ADR-059, ADR-057 and ADR-040 receive dated amendments and
  read "amended by ADR-060" in ADR-INDEX.
  [ADR-055](ADR-055-hardened-endpoint-development-premise.md) stands as
  written: on a release commit the genesis-built control plane states
  the version being released, and the released control plane that builds
  it (ADR-009 C2) states its own, so the two are told apart by builder
  version.
- **Known limitations.** A scanner that reads the binary does not see
  the version. The development version names no single source. A build
  from changed source that states a release version is not told apart by
  its version; only the digest of a release does that (ADR-057).

## Alternatives considered

- **The commit of the source, set at link time** (ADR-059 D6 as first
  decided). The binary becomes a function of its commit: two commits
  with equal files yield two binaries, every build line has to pass the
  value, and a build that passes none knows no version. A commit is also
  no version in the sense of the guideline, which aims at an increasing
  sequence.
- **The stamp of the Go command.** By default it records the commit, its
  time and a version derived from tags. The objection is the same, and
  the result depends on the state of the clone.
- **A data file, embedded.** A pattern cannot reach a file at the module
  root from the package that needs it, the content has to be parsed, and
  a malformed file is a failure mode a constant does not have. Without
  the file on main the build fails.
- **The procedure of the Go project in full.** It needs a generator, it
  derives the version of the main branch from the version-control
  system, and its release branches carry ported fixes that keep the
  earlier label until the next release.
- **Compile the version in only where the commit changes the version
  file.** The history becomes an input of the build: one tree yields two
  binaries, a fetch of depth 1 cannot answer, and a build step has to
  read version-control data and carry the answer into the compile. The
  same check is sound as a gate of the release procedure (D4).
- **A release commit on main, followed by a commit that resets the
  value.** Two changes per release, and main states a release version
  for one commit.
- **One branch per release line, with ported fixes.** Commits between
  two releases state the earlier release version.
- **No version.** A binary could not say what it is, an SBOM could not
  name the version of its tool, and no statement would tie an artifact
  to the release of strike that built it.
- **Build metadata in the grammar.** Excluded with D2.
- **Calendar Versioning.** The guideline admits both schemes. A Semantic
  Version also says whether a release breaks compatibility, which is
  what following a documented change needs.
- **The constant in `cmd/strike`, passed into the projection.** More
  signatures for one value.
- **Keep the version out of the documents** (ADR-059, Alternatives
  considered). With a commit every document changed with every source.
  With a release version a document changes once per release, and the
  recomputation renders the version the sealed statement names.

### What would change this record

- A Go release that lets a build state the main module's version from
  its source, without version-control data: the version also enters the
  build information, where scanners read it.
- An implementing act under Article 13(24) of the Cyber Resilience Act,
  a harmonized standard or a new version of the guideline that rules how
  a product or a tool states its version: D2, D5 and D7 follow.
- A need to maintain an earlier release: D4 is reopened.

## Principles

- Reproducibility is enforced, not hoped for -- the version is source;
  the same source yields the same binary, and no build reads
  version-control data.
- Runtime is attested -- the sealed statement names the release of
  strike that produced it, and every document names the version of its
  tool.
- No shell -- no build step reads a file to learn the version.
- No exec -- no build runs a tool to learn it.
- CUE first -- the grammar of the version is a scalar of the contract,
  and the generated type carries it.
- Code is liability -- one constant; no generator, no linker plumbing,
  no parser and no failure mode of a data file.
- Enforcement is structural, not discretionary -- a release version
  exists in one commit by construction, and the gate that checks it
  reads history where history belongs, in the release procedure.

## Sources consulted at authoring (2026-11-17)

- Regulation (EU) 2024/2847, consolidated text of 2024-11-20: Article
  13(10), 13(11), 13(15) and 13(24); Annex I, Part II; Annex II;
  Annex V; Annex VII.
- BSI TR-03183-2, version 2.1.0: 3.1, 5.2.2, 8.1.9 and 8.4.3. BSI
  TR-03183-1, version 1.0.0: 4.8.
- CISA and others, "2026 Minimum Elements for a Software Bill of
  Materials (SBOM)", 2026-07-29.
- SLSA v1.2, build provenance: `builder.id` and `builder.version`.
- Semantic Versioning 2.0.0: items 2, 9, 10 and 11, the grammar and the
  suggested expression.
- golang/go at tag `go1.27.4`
  (`7b2881024c95a11ddb86663a616340aa3a88b67f`) and at `master` of
  2026-11-17: `VERSION`, `src/cmd/dist/build.go`,
  `src/cmd/dist/buildruntime.go`,
  `src/internal/goversion/goversion.go` and `src/embed/embed.go`.
- Trivy documentation, coverage of Go binaries, read 2026-11-17.
- UNECE GRVA-2020-29, the interpretation of UN Regulation No. 156; FDA,
  premarket cybersecurity guidance of 2026-02-03; Google, response
  CISA-2023-0026-0010.
