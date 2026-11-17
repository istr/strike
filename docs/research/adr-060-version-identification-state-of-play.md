# Reproducible builds and version identification -- what projects and regulators say (as of 2026-11-17)

This survey was written on 2026-11-17, before
[ADR-060](../ADR-060-version-as-constant-of-the-source.md) was decided,
and corrected the same day against the primary documents wherever the
first pass rested on search results. It names the mechanisms by what
they do. Where ADR-060 decides, the record decides: it makes the version
a constant of the source, sets a release version in one commit on a
branch of its own, and names the version in the sealed statement and in
every SBOM document. The measurements taken beside this survey are in
[the measurement record](adr-060-version-measurements.md).

Every statement carries one of two marks. **(P)** means the primary
source itself was consulted on 2026-11-17, in full or in the passages
named; web pages were consulted through a fetch that returns extracts.
**(S)** means the statement rests on the survey's search results and was
not read at the source.

**Bottom line: no project and no regulator read here frames
reproducibility and version identification as goals in conflict. What is
debated is one mechanism, version data taken from the version-control
system. A version recorded in the source tree satisfies the strict
reading of reproducibility, and so does no embedded version with signed,
hash-bound metadata beside the artifact. Stamping from version control
does not.**

The strict reading is the project's own: the same source yields the same
binary, whatever commit holds it. No source read adopts it as a
definition.

## TL;DR

- **No framed conflict, a live debate about a mechanism.** The
  reproducible-builds project treats an embedded version as compatible
  with reproducibility as long as it is deterministic. The open debate
  runs in the Go project: stamping from version control hurts
  determinism, caching and builds from archives on one side, and a
  missing version breaks vulnerability scanners on the other.
- **Regulation asks for identification and leaves the carrier open.**
  The Cyber Resilience Act lets the identifying element sit on the
  packaging or in an accompanying document where the product cannot
  bear it. The BSI guideline and the 2026 minimum elements identify
  versions through the SBOM. Only UN Regulation No. 156 requires that
  the identifier be readable from the product. Reproducible builds
  appear in a supporting role, where they let hashes identify
  components.
- **The conflict is real for one mechanism and avoidable.** Injection at
  link time and stamping from version control break the strict reading.
  A version in a tracked, compiled file satisfies it. The price of no
  embedded version is that a scanner holding only the binary cannot
  match an advisory against it.

## Key findings

1. **The reproducible-builds project admits versions from version
   control.** Its page on version information asks that embedded version
   data be deterministic, names a dedicated source file, a changelog and
   the version-control system as sources, and recommends full or
   fixed-length commit ids, because the length of an abbreviated id
   depends on the repository.\[1\] A talk of 2015 gives the same advice:
   derive the version from the source, never per build.\[2\] (S)
2. **The Go toolchain is the working example of the strict reading.**
   Russ Cox calls a build perfectly reproducible when its source code is
   its only relevant input, and reports the Go toolchain as such since
   Go 1.21.\[3\] The time of a release is a line of the tracked
   `VERSION` file, from which the packagers take archive timestamps.\[3\]
   (P) How a release sets that file is measured in the measurement
   record. (P)
3. **The stamp of the Go command is where the debate runs.** Since
   Go 1.18 the command records revision, commit time and a modified
   flag, by the release notes of that version. Since Go 1.24 it also
   sets the main module's version from the tag or commit and marks
   uncommitted changes; `-buildvcs=false` omits all of it.\[4\] (S) The proposal behind the Go 1.24 change already
   records that tags are local, so one source can yield different
   versions.\[5\] (S)
4. **Scanners depend on a version they can find in the binary.** Trivy
   takes the main module's version from the build information, then from
   the linker flags, then from the symbol table, and reports none when
   all three fail.\[15\] (P) Third parties report that Syft records the
   main module as unknown for builds with `-trimpath`. (S)
5. **Regulators and their advisers identify through metadata.** A CISA
   paper of 2023 separates defined identifiers, which some party
   assigns, from inherent ones, which anyone can derive from the
   software, and finds that inherent identifiers do not yet group the
   versions a vulnerability report covers.\[16\] (S) Google's response
   to the same consultation adds that wide use of inherent identifiers
   needs their reproducibility and consistency to be solved.\[17\] (P)

## Details

### A. Projects

**Go.** Four threads carry the debate. (S)

- The accepted proposal to stamp a version into builds (implemented in
  Go 1.24) met two objections that still stand: advisory ranges over
  derived versions are hard to compare, and a build is marked modified
  when files outside the build changed.\[5\]
- A regression report on Go 1.24 shows scanners failing on version
  strings they had never seen; the maintainers answered that scanners
  have to follow.\[6\]
- An open issue asks to mark a build modified only when files that take
  part in the build differ.\[7\] It is the closest the project comes to
  judging by content and not by the state of the clone.
- A proposal for a flag that sets the version by hand was placed on hold
  in 2026.\[8\] Its supporters name cached source archives and container
  builds, where version-control data is unwanted; the maintainers do not
  want user-supplied data where tools expect source provenance. A
  further proposal asks the command to expose the derived version, so
  that pipelines need not rebuild the logic.\[9\]

Two consequences in the ecosystem: one project disables stamping for
untagged builds so that scanners do not match a derived version\[10\],
and a third-party report shows a release that reproduces from a checkout
and not from an archive of the same commit, because the stamp
differs.\[11\] (S)

**Practitioner writing.** One essay of April 2026 argues that every
program must report the revision it was built from.\[12\] Another
surveys ecosystems, notes that content-addressed builds strip
version-control data, and names provenance held at the registry, looked
up by the artifact's hash, as the alternative.\[13\] (S)

**Bazel.** Stamping is off by default for build performance: stamped
values make inputs volatile and defeat caching.\[14\] The project
treats it as a caching matter. (S)

**The Go toolchain's own procedure.** A tracked file on the release
branch, a constant on the main branch, a generator that turns either
into a constant of the build. Measured; see the measurement record. (P)

### B. Definitions on the project side

- **What counts as source.** The reproducible-builds definition speaks
  of the same source code, build environment and build instructions, and
  its page on version information admits version control as an origin of
  version data.\[1\] (S) Cox's definition is stricter in spirit\[3\]
  (P), and the Go toolchain meets it by putting the version into the
  tree, while the Go command does the opposite for ordinary modules.
- **Whether a version from version control is reproducible.** Under the
  usual definition, yes, if the values are deterministic. Under the
  strict reading, no: two commits with equal trees differ in revision,
  time and derived version.
- **Whether the strict reading is adopted anywhere.** Not as a
  definition. It is approximated by content-addressed builds, by the Go
  toolchain's version file and by the open issue on the modified
  flag.\[7\]\[13\] This is an inference of the survey; none of the
  sources states the strict reading as a goal.
- **What a version is for identification.** CISA's paper treats a
  content hash as the identifier of an instance and not as a substitute
  for a version that supports ranges and grouping.\[16\] (S)

### C. Regulation

| Instrument | What it asks | Carrier | Reproducible builds | Mark |
| --- | --- | --- | --- | --- |
| Cyber Resilience Act, Article 13(15) \[18\] | An element allowing identification on the product or, where that is not possible, on its packaging or in an accompanying document | Product first, document allowed | Not mentioned | P |
| Cyber Resilience Act, Annex I, Part II (4) \[18\] | With a fixed vulnerability, information allowing users to identify the product affected | Not ruled | Not mentioned | P |
| Cyber Resilience Act, Article 13(10) and 13(11), Annex VII 1(b) \[18\] | The only places in articles and annexes that speak of versions: the version last placed on the market, archives of historical versions, versions affecting compliance | Documentation | Not mentioned | P |
| Cyber Resilience Act, Article 13(24) \[18\] | Implementing acts may specify format and elements of the SBOM; none was found | -- | -- | P for the article, S for the absence |
| BSI TR-03183-2, version 2.1.0 \[19\] | A separate SBOM per software version, and a new version for an altered component (3.1); the version is the creator's identifier, Semantic or Calendar Versioning SHOULD be used, else the file's modification date (5.2.2); a strictly increasing sequence (8.1.9) | SBOM | They let hash values identify components (8.4.3) | P |
| BSI TR-03183-1, version 1.0.0 \[20\] | The assessment report names the version of hardware and software (4.8); by its own statement the document creates no obligations | Report | Not mentioned | P in part |
| CISA and others, 2026 Minimum Elements \[21\] | An SBOM per version or update; the name and version of the generating tool; all identifiers of a component; by its own statement no new requirements | SBOM | Not mentioned | P |
| NIST SP 800-218 \[23\] | Integrity and provenance data archived per release (PS.3.1, PS.3.2) | External | An optional example (PO.3.2) | S |
| FDA, premarket cybersecurity guidance of 2026-02-03 \[24\] | Version-identifiable software; version numbers signed or authenticated; the device identifiable | Mixed | Not mentioned; full build environments are to be preserved | P |
| UN Regulation No. 156 \[25\] | The software identifier unique and readable through a standard interface; software versions with integrity validation data | In the product | Not mentioned | P for the passages on identification |
| CSAF 2.0, 3.1.3.3 \[26\] | A product is identified by one of several helpers, hashes among them | External | -- | S |
| OSV schema \[27\] | Ranges of type GIT name full commit hashes | External | -- | S |

Reading the table:

- No instrument read requires a software binary to carry its own version
  string. The Cyber Resilience Act's rule is a marking rule with an
  external fallback, and its version concepts live in documentation.
- UN Regulation No. 156 is the exception and is specific to vehicles:
  the requirement attaches to the vehicle or its control units.
- Where reproducible builds appear, they serve identification or
  integrity. Nowhere do they compete with versioning.
- Every text that names both carries a defined version and a hash side
  by side: the 2026 minimum elements, Google's response and UN
  Regulation No. 156. (P)

### D. Patterns in practice

| Pattern | Usual definition | Strict reading | Version of a binary in hand | Advisories to releases |
| --- | --- | --- | --- | --- |
| A version in a tracked file that is compiled in | Met | Met: a new version is a change of the tree | Yes, where the binary exposes it | Yes; commits between two releases carry whatever the file states |
| Injection from version control (linker flag, stamp, describe) | Met if deterministic and of fixed length | Not met: equal trees at two commits differ | Yes | Yes, also by commit ranges |
| No embedded version; identity by digest and signed external metadata | Met | Met | Only by lookup from the hash | Only where the consumer reads the external SBOM or statement |
| A release label in the tree and the commit in external provenance | Met | Met | Yes | Yes |

What a scanner needs from a Go binary: the main module's path and
version, the dependencies with their sums and the build settings, all
from the build information. With stamping disabled and `-trimpath`, the
dependencies and the toolchain version remain readable and the main
module's version does not.\[15\] (P for Trivy)

What SLSA offers: `builder.version` is an optional map from the names of
platform components to their versions, `builder.id` alone determines the
build level, and the page on build provenance says nothing on how a
verifier uses a version.\[22\] (P)

### E. The premise

The conflict is a property of one mechanism, treating the state of
version control as an input of the build. It is not a property of the
two goals. What remains is a difference in cost:

- a version in the tree costs a commit per release, and without further
  rule the commits after a release carry its label;
- no embedded version costs what a scanner can tell from the binary
  alone.

## Corrections after reading the primary documents

The first pass had several regulatory texts only as search results. Read
in full or in the passages named, they changed the survey as follows.

- **The 2026 minimum elements name the tool version.** The version of
  the tool that generated an SBOM is a minimum element, to be stated as
  unknown where it is not available. The paper states that it creates no
  new requirements.\[21\]
- **The BSI guideline describes the version further than first read.**
  The creator defines it, Semantic or Calendar Versioning SHOULD be
  used, and the aim is a strictly increasing sequence (5.2.2, 8.1.9). A
  commit id fits that poorly. The sentence on reproducible builds stands
  in 8.4.3.\[19\]
- **The binding core of identification in the Cyber Resilience Act is
  Annex I, Part II (4).** The articles and annexes speak of versions in
  three places only and of hashes and build tools nowhere. The recitals
  were searched, not read.\[18\]
- **Google's sentence concerns identifiers.** It asks for
  reproducibility and consistency of inherent identifiers; that
  reproducible builds are a precondition is a conclusion, not its
  text.\[17\]
- **The document on UN Regulation No. 156** that was read is its
  interpretation document, which quotes the regulation.\[25\]
- **BSI TR-03183-1 contradicts itself on its date.** The title page says
  31.07.2026, the changelog 2025-07-31. Its controls are published as a
  separate catalog with access on request and were not read.\[20\]
- **The FDA guidance** names the version of June 2025 as the one it
  supersedes.\[24\]

## Caveats

- **Coverage of projects.** Not surveyed: the reports and lists of the
  reproducible-builds project after 2022, Debian, Arch, NixOS, Guix,
  F-Droid, Tor Browser, Bitcoin Core, the Rust, Python and Java
  ecosystems, the Linux kernel, GoReleaser, ko and Kubernetes. The
  absence of a framed conflict holds for the sources read.
- **Coverage of regions.** Not surveyed: the United Kingdom, Japan,
  South Korea, India, China, Singapore, Australia, Canada, and the ISO
  and Ecma standards on software identification.
- **Not reachable.** The drafts of the harmonized standards under the
  Cyber Resilience Act and the Commission guidance of July 2026 beyond
  its announcement. IEC 62443-4-1 was available only as a third-party
  copy and is not used.
- **Not verified.** Everything marked (S). In particular the reports on
  Syft, which come from third parties and not from its maintainers, and
  one issue that reports a Go 1.24.0 build without the modified mark.
- **The definition page of the reproducible-builds project** could not
  be fetched again; its wording is carried over from an earlier reading.

## Sources

1. reproducible-builds.org, "Version information" --
   https://reproducible-builds.org/docs/version-information/
2. Lunar, talk at CCCamp 2015 --
   https://reproducible-builds.org/_lfs/presentations/2015-08-13-CCCamp15.pdf
3. Russ Cox, "Perfectly Reproducible, Verified Go Toolchains",
   2023-08-28 -- https://go.dev/blog/rebuild
4. Go 1.24 release notes -- https://go.dev/doc/go1.24
5. golang/go issue 50603 -- https://github.com/golang/go/issues/50603
6. golang/go issue 71969 -- https://github.com/golang/go/issues/71969
7. golang/go issue 77897 -- https://github.com/golang/go/issues/77897
8. golang/go issue 77020 -- https://github.com/golang/go/issues/77020
9. golang/go issue 79789 -- https://github.com/golang/go/issues/79789
10. argoproj/argo-cd pull request 30932 --
    https://github.com/argoproj/argo-cd/pull/30932
11. jiegui2025/hwspec issue 76 --
    https://github.com/jiegui2025/hwspec/issues/76
12. Michael Stapelberg, "Stamp It! All Programs Must Report Their
    Version", 2026-04-05 --
    https://michael.stapelberg.ch/posts/2026-04-05-stamp-it-all-programs-must-report-their-version/
13. Andrew Nesbitt, "Who Built This?", 2026-04-07 --
    https://nesbitt.io/2026/04/07/who-built-this.html
14. Bazel user manual -- https://bazel.build/docs/user-manual
15. Trivy documentation, Go --
    https://trivy.dev/docs/latest/guide/coverage/language/golang/
16. CISA, "Software Identification Ecosystem Option Analysis", October
    2023 --
    https://www.cisa.gov/sites/default/files/2023-10/Software-Identification-Ecosystem-Option-Analysis-508c.pdf
17. Google, response CISA-2023-0026-0010 --
    https://downloads.regulations.gov/CISA-2023-0026-0010/attachment_1.pdf
18. Regulation (EU) 2024/2847, consolidated text of 2024-11-20 --
    https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32024R2847
19. BSI TR-03183-2, version 2.1.0 -- https://bsi.bund.de/dok/TR-03183-en
20. BSI TR-03183-1, version 1.0.0 -- https://bsi.bund.de/dok/TR-03183-en
21. CISA and others, "2026 Minimum Elements for a Software Bill of
    Materials (SBOM)", 2026-07-29 --
    https://media.defense.gov/2026/Jul/29/2003971159/-1/-1/1/CSI_2026_cisa_sbom_minimum_elements_508c.PDF
22. SLSA v1.2, build provenance --
    https://slsa.dev/spec/v1.2/build-provenance
23. NIST SP 800-218, revision 1, initial public draft --
    https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218r1.ipd.pdf
24. FDA, premarket cybersecurity guidance of 2026-02-03 --
    https://fda.gov/media/119933/download
25. UN Regulation No. 156 --
    https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:42021X0388
    and its interpretation document, UNECE GRVA-2020-29 --
    https://unece.org/DAM/trans/doc/2020/wp29grva/ECE-TRANS-WP29-GRVA-2020-29e.pdf
26. CSAF 2.0 -- https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html
27. OSV schema -- https://ossf.github.io/osv-schema/
