# ADR-057: A release is two signatures -- reproducible provenance and an authorizing verified identity

## Status

Accepted, 2026-10-29. Drafted against
`955ddb3d02d21c67fc4f89c4113611fcceaed523`. Every design fork behind this
record was surfaced and ratified by the operator between 2026-10-27 and
2026-10-29 (working paper "Decision Forks -- Release Authorization ADR",
ephemeral, not committed); the measurements this record cites were made
against primary sources on those dates and are listed at the end.

Gives the word "released" in ADR-055 D1 its first in-tree definition.
Extends [ADR-041](ADR-041-lane-as-verification-policy.md) (the lane as
verification policy) by a second signer role and a second verifier
profile, and [ADR-009](ADR-009-bootstrap-reproducibility-proof.md) by
naming which host reproduces which. Amends, by dated amendment sections
in the respective records, [ADR-040](ADR-040-control-plane-sbom-and-keyless-attestation.md)
D2, [ADR-041](ADR-041-lane-as-verification-policy.md) D6,
[ADR-055](ADR-055-hardened-endpoint-development-premise.md) D1 and D5,
and row 6 of the [Beta Definition of Done](BETA-DEFINITION-OF-DONE.md).
Changes the lane schema (`contract/lane`) and adds a schema package
(`contract/release`); touches no field of `contract/attest`, so this is
not a freeze event under the attest wire freeze.

## Context

### The principle

strike's attestation chain answers "what was built, by which control
plane, from which inputs, on which engine" and seals the answer at the
deploy (ADR-051). It does not answer "who stands behind this release".
The operator's principle for the release is: the build is executed under
a publicly verifiable identity, the release is authorized under a
publicly verifiable identity, both signatures bind to the same artifact,
and a verifier requires both. The cut runs between **securely
reproducible provenance** and **an authorizing signature by a verifiable
identity**, not between "machine" and "human": the authorizing identity
is a natural or legal person attested by an independent party, and the
provenance identity is a workload identity attested by the forge.

### What the tree does at the anchor

- `internal/verify` is Fulcio-shaped. `Leaf` chains the leaf to the
  trusted root's certificate authorities, requires the CodeSigning EKU,
  an exact SAN match, and a Fulcio issuer extension whose absence is an
  error; `SCT` requires exactly one embedded SCT; `DSSE` verifies ECDSA
  P-256 over SHA-256 only; the bundle shape is strict (one envelope, one
  signature, one log entry, one RFC 3161 timestamp).
- `cmd/strike/verify.go` gates by layer: `sealed` is Layer V,
  `engine-context` Layer E, `informational` and any unrecognized
  `dev.strike.statement` value gate nothing. One identity per
  verification (`verify.New(tm, identity, issuer)`); UC2 reads it from
  the lane's `oidc`, UC1 from flags.
- `internal/registry.fetchOneBundle` admits any referrer whose config
  media type is the sigstore bundle type and reads the layer from the
  `dev.strike.statement` annotation.
- The producer reads the OIDC token from `SIGSTORE_ID_TOKEN`
  (`ambientIDToken`), compares the token's `email`, else `sub`, with
  `oidc.identity` before any Fulcio contact (`subjectFromIDToken`), and
  logs the DSSE signature to Rekor v2 as a `hashedrekord`
  (`rekorSubmitKeyless`).
- `oidc.identity` is `primitive.#StringOrURI`, compared byte-exact. The
  bootstrap lane is rendered per commit from `bootstrap/lane.cue`.
- `#SBOMSigner` (issuer plus identity) is the one precedent for a second
  signer set declared in the lane. `endpoint.#Certificate` carries
  `mode: "rootca" | "leaf"`; `leaf` pins a certificate byte for byte
  (ADR-056).
- `ParseTrustedRoot` pools every certificate authority of a sigstore
  trusted root and keys transparency-log and CT-log keys by log ID; the
  trusted root is declared digest-pinned by reference (ADR-041).
- The capsule's SSH agent proxy speaks the agent protocol in pure Go
  (`golang.org/x/crypto/ssh/agent`, `internal/capsule`). The binary
  builds with `CGO_ENABLED=0`.
- `container.RequireVersion(engine, "5.0.0")` refuses an older engine at
  start. `docs/RELEASES.md` names itself as the home of the release
  procedure. The README bootstrap publishes to the harness registry under
  the harness keyless chain.

### What ADR-055 leaves open

ADR-055 D1 says strike is "developed, gated, bootstrapped, and released"
from an endpoint with four capabilities and decides nothing about release
authority. D4 lets the commit-gate lane run from the endpoint or a forge
runner and leaves the signing identity open by construction. D5 names the
operator's engine invocation as the only place a host path is bound. B6
leaves the public-chain token open. ADR-009 fixes the reproduction matrix
(C1 in-lane double build; C2 cross-control-plane, cross-host; C3
strike-free rebuild) but not who authorizes.

### Constraints that shape the design

- The reference endpoint has no browser and nothing installable
  (ADR-055 D1). The operator ruled (2026-10-27) that no browser-based
  OIDC flow is admissible, not even on a second device; (2026-10-28) that
  a second device without network access -- a PIN-pad card reader -- is
  admissible and one with network access is not, which excludes
  smartphones; that enrolment at a trust service provider is out of
  scope of this record; and that "publicly verifiable" for the
  authorizing identity means attested by independent parties, equivalent
  to a government eID or a key certified by several signatories, so an
  operator-run root alone does not meet the bar. The operator excluded a
  self-operated Fulcio, IdP or CT log as a model for the authorizing
  identity categorically.
- The public Fulcio issues certificates only for tokens from issuers in
  its configuration. For a person that means a browser login through
  Sigstore's Dex or a provider it federates; for a workload it means a
  CI issuer. A keyless identity for the authorizing role is therefore
  unavailable under the constraints above, and ADR-040 D2's sentence,
  "identity is gated by hardware at the IdP, not by holding a key",
  cannot hold for that role.
- The German eID function authenticates and never signs; it would gate
  an IdP the public Fulcio does not trust. The eIDAS signature
  infrastructure, by contrast, rests on long-lived signing keys in
  certified hardware with validity judged under the hybrid model: the
  certificate must have been valid at the qualified-timestamped signing
  time. Sigstore replaces revocation with ten-minute certificates.

### Precedents measured against this principle

- Debian, 2024: ftpmaster required that dak "and later, the public" can
  verify the uploader's own signature; the tag2upload compromise carries
  the maintainer's signed tag in the upload and dak re-verifies it
  (general availability 2026-02-09). The authorizing signature is carried
  along and re-verified by the final authority, never vouched for by a
  service.
- Bitcoin Core: builders reproduce with Guix and PGP-sign the digests
  they obtained; the public repository of signatures is the log;
  code-signing waits for three matching attestations. The signer's own
  reproduction is the evidence, and the signature is over the artifact
  digest.
- tag2upload's tag grammar (critical items, the version duplicated into
  the tag for replay protection) shows a pre-build intent record; what
  the tag does not pin is what reproducibility must cover.
- Sigstore root-signing: keyholders sign TUF metadata with personal
  hardware tokens in pull-request signing events; snapshot and timestamp
  are signed online. Threshold ceremonies with hardware tokens are
  practical.
- No mainstream registry binds a person's approval cryptographically:
  GitHub's `environment` claim and Fulcio's Deployment Environment
  extension record which protected environment ran, not who approved.
  Identity-first signing in open source (PGP on PyPI and Maven Central,
  Docker Content Trust) produced few verifiable signatures; registry
  policy, not identity, drove adoption. This record therefore keeps the
  provenance layer standard and adds the authorization layer beside it,
  without asking the ecosystem's tools to understand the latter.

### Facts measured at authoring

- Fulcio's per-issuer templates (`config/identity/config.yaml`, main,
  2026-10-26): the SAN is the build-signer identity and differs per
  issuer (GitHub `{url}/{job_workflow_ref}`, GitLab
  `https://{ci_config_ref_uri}`, Buildkite `{url}/{org}/{pipeline}`,
  CircleCI an opaque pipeline-definition URL); the standardized
  extensions carry the source facts -- .12 source repository URI and .14
  ref for all CI issuers but Buildkite, .13 source repository digest for
  GitHub, GitLab, Buddy and Buildkite, .11 runner environment and .21 run
  invocation URI for all six.
- Rekor v2 (rekor-tiles, main): no DSSE entry type; the PAE signature is
  logged as a `hashedrekord`; the certificate verifier parses a single
  DER certificate and validates no chain; the algorithm registry is
  server-side. `PKIX_ECDSA_P384_SHA_384` is a first-class suite in
  protobuf-specs; RSA-PSS is not in rekor-tiles' allowed algorithms. The
  public TSA is open, with a rate limit "well above 1 QPS" per its
  maintainers.
- Go's `x509.Verify` with `KeyUsages: CodeSigning` skips a certificate
  that carries no EKU extension and rejects one whose EKU lacks
  CodeSigning; sigstore-go (`FulcioCertificateAuthority.Verify`) and
  cosign (`TrustedCert`) pass the same option, as does strike's `Leaf`.
- cosign's identity check iterates the certificate's SANs; with no SAN
  the loop never runs and verification fails even with
  `--certificate-identity-regexp '.*'`; key mode (`--key`) skips chain
  validation and policy; a bundle's verification material is a oneof of
  certificate or public key.
- D-Trust Signaturkarte 5.1: CardOS 6.0; Standard RSA-3072 with one
  signature per PIN entry; M100 ECC NIST P-384 with up to 100 signatures
  per PIN entry; certificate validity up to 39 months per the Root CPS,
  card up to three years; the qualified certificate carries CN, C,
  serialNumber (an application number), GivenName/Surname or a
  TSP-assigned pseudonym, and no SAN; the ECC issuing chain is D-TRUST CA
  2-21-1 2021 under Root CA 2 2021, listed on the national trusted list;
  the TSPS reserves EKUs in CA certificates for website policies; the
  end-entity EKU is read from a test card. OpenSC 0.27.0 (2026-03-30)
  supports Cards 5.1 and 5.4 on NIST curves. The operator's REINER SCT
  cyberJack RFID komfort is listed by its maker as supporting D-Trust
  Card 4.x and 5.x and carries the PACE hardware the cards' secure PIN
  entry needs; firmware updates need a Windows-only tool, once.
- Hosted GitHub runners drift without the operator's action (Podman
  5.8.4 to 4.9.3 on ubuntu-22.04/24.04 in September 2026; ubuntu-26.04
  ships 5.7.0); the SLSA v1.1 build requirements do not prohibit
  self-hosted runners and require a distinct `builder.id` per mode of
  operation; `runner_environment` attests that the forge operated the
  VM, nothing about its image or engine.

## Terms

- **Provenance signature**: the signature of strike's control plane over
  the sealed statements of a deploy (ADR-040, ADR-051), under a forge
  workload identity through the public keyless chain. Its signer is the
  **builder**.
- **Authorization signature**: the signature of a verified identity over
  a statement whose subject is the same artifact digest. Its signer is
  the **approver**: a natural person under a qualified electronic
  signature, or a legal person under a qualified electronic seal,
  attested by a qualified trust service provider on the EU Trusted List,
  or by an anchor class this record admits later.
- **Candidate** and **release**: the two grades `strike verify` reports.
  A pushed digest is a candidate until the authorization signature is
  attached and the tree names the digest.

## Decision

### D1 -- A release is two signatures over one subject, and the verdict requires both

Every release artifact carries the provenance signature of the builder
and the authorization signature of every approver the lane declares,
each as a sigstore bundle attached as an OCI 1.1 referrer of the image
manifest digest, each verified independently, each bound to the other:
the authorization statement names the provenance bundles it approves
(D5), and the verifier checks that the named bundles are the ones
attached (D7). Neither signature stands in for the other, and no service
vouches for either: the verifier holds both roots and checks both
signatures itself.

### D2 -- The builder identity is a provider-neutral pin tuple, checked on the issued certificate

The builder's identity is declared in the lane as a tuple and matched
against the certificate Fulcio issued: `oidc.issuer` (the Fulcio issuer
extension, exact), `oidc.identity` (the SAN, exact, `#StringOrURI`), and
a closed block `oidc.extensions` in Fulcio's extension vocabulary
(`sourceRepositoryURI`, `sourceRepositoryRef`, `sourceRepositoryDigest`,
`buildConfigURI`, `runnerEnvironment`), each entry matched exactly where
declared and ignored where not. The minimum a release lane declares is
the issuer, the SAN, and at least one of `sourceRepositoryRef` or
`sourceRepositoryDigest`. The lane is rendered per release with the tag
ref and the commit, as the bootstrap lane is rendered per commit, so it
declares what the provider fills. Every CI issuer the public Fulcio
accepts is thereby expressible: GitHub and GitLab in full, CircleCI,
Codefresh and Buddy via repository plus ref, Buildkite via pipeline SAN
plus commit. The remaining coupling is Sigstore's acceptance list for the
forge the repository lives on.

The producer's fail-closed identity check compares the **issued leaf**
-- SAN and extensions -- against the lane before the first signature;
the token pre-check keeps only `iss` equality. Fail-closed is preserved;
the abort point moves from "before any Fulcio contact" to "before any
signature", because claim names differ per provider and the certificate
is what the verifier will see (observation over declaration). The sealed
`#ProvenanceOIDC` keeps issuer and identity; the pins are verifier
policy (ADR-041), not sealed claims.

### D3 -- The approver identity is a qualified certificate on a hardware signature-creation device, pinned as a leaf

The approver signs with a key generated on and never leaving a certified
hardware signature-creation device, under a qualified certificate issued
by a trust service provider on the EU Trusted List after identification
of the person (or, for a legal person, a qualified seal). The lane
declares each approver in a required block `approvers`, a list in which
every entry is required to sign (one entry today; no threshold field
until a second approver exists), each entry carrying:

- `id`: a URI naming the approver, carried into the authorization
  statement as `verifier.id` (D5);
- `leaf`: the approver's certificate as `endpoint.#Certificate` with
  `mode: "leaf"`, pinned byte for byte. The qualified certificate carries
  no SAN, so the identity is the certificate itself; the subject's name
  and serialNumber are the human-readable form, never the match;
- `validFor`: an optional window (start and end, ADR-053 semantics: an
  omitted bound constrains nothing) compared against the bundle's
  trusted time. It is a forward instrument: at declaration the lane
  bounds how long the leaf may authorize releases below the
  certificate's own validity, and every extension is a signed commit.

The issuing chain is an entry of the lane-pinned sigstore trusted root
beside the public Sigstore authorities and is committed in-tree beside
the trusted-root build inputs, so git history is the rotation record;
the EU Trusted List is the anchor beyond the tree, referenced by this
record and never read by strike. Rotation -- a new card, an expired or
lost certificate -- is a lane edit plus a trust-root re-pin under a
signed commit; earlier releases keep verifying against the leaf valid at
their trusted time. strike reads no CRL and no OCSP: the leaf-pin edit
is strike's revocation (forward), and the explicit trust-root override
of ADR-041 D4 is the retroactive channel, acting per authority. A
backward "revocation" in this model can only mean "distrust signatures
after a compromise time", expressed as a validity end compared against
authenticated time; retracting one release is procedural (D6); the
append-only log cannot unmake a signature and is not asked to.

The signature suite is ECDSA P-384 over SHA-384 of the DSSE PAE bytes,
bundle `keyDetails` `PKIX_ECDSA_P384_SHA_384`, because the public log
admits no RSA-PSS and the ECC card carries a NIST P-384 key. The approver
certificate is matched under a second verifier profile (D7). This
reverses ADR-040 D2 for one role, for the stated reason, and is not the
model ADR-043 retired: a verifying consumer exists, the key never enters
strike (D9), and the chain anchors in a public trust list rather than in
a key the project holds.

### D4 -- Authorization binds after the build, on the approver's own reproduction; intent is recorded by a signed tag

The approver signs a statement whose subject is the digest the builder
published, and signs it only after reproducing that digest on the
reference endpoint: the README bootstrap run, with its `reproducedBy`
gate, is the approver's evidence step. ADR-009 C2 keeps its two hosts
and two control planes with the direction fixed: the endpoint reproduces
the forge. Reproduction is a MUST of the release procedure; a mismatch
means no signature. The release tag is pushed as a git tag signed with
the same device, verified by git and the forge and not by `strike
verify`, so intent is recorded publicly before the build without adding
signature parsers to strike. Verification of the tag signature inside
`strike verify` is parked as a post-beta hardening candidate.

### D5 -- The authorization statement is a standard SLSA Verification Summary Attestation

The statement is an in-toto Statement v1 with the SLSA Verification
Summary Attestation v1 predicate, unmodified: no strike field is added.
Subject: the image manifest digest, the same subject as the three
provenance statements. `verifier.id`: the approver's declared `id`.
`policy.uri`: the lane in git form at the release ref;
`policy.digest`: `lane_digest`, the value the sealed provenance carries,
so the lane is the policy for both roles (ADR-041). `inputAttestations`:
the provenance bundles by referrer-manifest digest, which binds the
approver to what the builder said and the commit through the sealed
provenance. `verificationResult: PASSED`. `verifiedLevels`: the level
the lane's policy claims, measured at authoring. `timeVerified`: event
time from `clock.Wall()`; the trusted time stays the RFC 3161 token. The
reproduction evidence lives in the policy the statement names (the
lane's `reproducedBy` gate and the procedure in `docs/RELEASES.md`), not
in extra fields; a strike-specific companion predicate with explicit
reproduction evidence is parked until a consumer for it exists. The
statement form is described by a new CUE package `contract/release`
(Go types generated), which invents no field and is resolved toward the
SLSA specification wherever the two differ; `contract/attest` is
untouched.

### D6 -- The registry holds candidates, the tree names releases

The builder's deploy pushes the candidate by digest to the final
repository, private before the beta cut and public after it. The
authorization bundle is attached to that digest as a fourth referrer
under the annotation `dev.strike.statement: release`; it is the single
verification source (D7). The digest becomes a release when a commit
names it: a one-line record per release in `docs/RELEASES.md` with the
digest and the bundle digests, and the README pin. Nothing is moved or
re-pushed; the order is forge build and push, reproduction on the
endpoint, authorization and attach, register commit. Retracting a release
is the register commit that removes or marks the digest; the bundles
keep verifying, and the grade stays `release`, because the tree, not the
registry, says what is released.

### D7 -- The verdict grades what it observes; a release requires every declared approver

Every lane declares both profiles: the builder's (`oidc`, `keyless`) and
the approvers' (`approvers`). `strike verify` checks the provenance
layers as before (`sealed` Layer V, `engine-context` Layer E,
`informational` never gating) and the authorization layer under a fourth
gate class, the grade: every present bundle must be valid, a second
authorization bundle included; absence lowers the grade; invalidity is
FAIL. The authorization profile verifies: leaf equals the pinned leaf;
`verifier.id` equals the declared `id`; chain to the declared issuing
authority in the trusted root, with the CodeSigning EKU or none on every
certificate; no Fulcio issuer extension and no SCT required; ECDSA
P-384 over SHA-384; the RFC 3161 time inside the leaf's, the chain's
and the `validFor` windows (ADR-053); Rekor v2 inclusion; and
`inputAttestations` naming the provenance bundles actually attached.

The verdict: any present bundle invalid, FAIL; provenance valid and
authorization absent, grade `candidate`; both valid for every declared
approver, grade `release`. The exit status is 0 only when the required
grade is reached. The required grade defaults to `release`, because the
ordinary verification of the future verifies releases; exactly one flag,
`--allow-candidate`, lowers the requirement to `candidate`:
`strike verify image@digest` and `strike verify --allow-candidate
image@digest`. UC1 requires both input sets (`--identity`, `--issuer`,
and the approver id and leaf) unless `--allow-candidate` is set; a
present authorization bundle that cannot be checked for want of policy
inputs is FAIL, not "not counted". The verdict line names the grade; the
exact flag and line shape follow `docs/CLI-CONVENTIONS.md`. The exposure
that anyone with push rights can attach an invalid bundle and force FAIL
already exists for a second `sealed` bundle and is accepted as before:
the registry is semi-trusted and can withhold or clutter, not forge.

### D8 -- The authorization signature is logged in the public Rekor v2 and timestamped by the public TSA

The authorization bundle carries a `hashedrekord` entry of the public
Rekor v2 with the approver's certificate as verifier (the log validates
no chain and admits the suite) and an RFC 3161 token of the public TSA,
in the same strict shape as the provenance bundles. Fallbacks, each a
documented limitation under Beta DoD row 14: a `publicKey` verifier if
the public log rejects the certificate; a timestamp without a log entry
as the last resort; a private log never for a release. The direction is
an open visor: the approver's identity is traceable in the public log as
far as the law allows, the real name is the default and a TSP-assigned
pseudonym the fallback. Two checks are deferred to the authoring of the
concrete instruction: whether authorities outside the EU, or
internationally recognized ones, offer an equivalent hardware-bound
identity with Linux PKCS#11 support, so the approver identity is not
bound to one jurisdiction; and the data-protection questions of
publishing a natural person's certificate in an append-only public log.

### D9 -- strike signs through a delegate agent and never touches the approver's key

The authorization signature is produced outside any lane by an
operator-started invocation, like the published stage_1 run line: a
digest-pinned pcscd sidecar image holds the USB PIN-pad reader bound at
the operator's engine invocation; a digest-pinned agent image loads the
PKCS#11 module and serves the SSH agent protocol over a socket; a strike
subcommand (named per `docs/CLI-CONVENTIONS.md`), itself a container
process, builds the statement, requests the ECDSA P-384 signature over
the PAE bytes through the agent protocol -- the agent signs nistp384 keys
with SHA-384 natively -- converts the signature blob to the DSSE form,
assembles the bundle with the supplied leaf chain, requests the TSA
token, submits the log entry, and attaches the referrer. The PIN is
entered on the reader's pad and reaches no container. The same agent
signs the release tag (D4). No cgo enters strike; the principle "strike
mediates but does not own the keys" holds literally.

The signer verifies the returned signature with the pinned leaf's public
key over exactly the bytes it asked to have signed before assembling a
bundle; a signature over any other bytes is rejected and nothing is
attached. In ADR-037's terms: the signature's cryptographic validity,
its binding to the pinned leaf and chain, and this self-verification are
Layer V -- no engine, sidecar or agent can forge a signature that passes.
That the device signed **only** what strike requested during the
authorized session is Layer E: the PIN authorizes a signature, not a
content; a compromised agent image, PKCS#11 module, sidecar or USB path
could obtain additional signatures over other content in the same
session, up to one hundred per PIN entry on a batch card, invisible to
strike. On the reference endpoint this is no degradation -- the local
rootless engine already closes every link (SECURITY.md) -- but the agent
and sidecar images enter the ADR-009 trusted computing base, digest-
pinned, in the class of the toolchain images. Mitigations, all in the
existing vocabulary: the strict bundle shape forces every usable
signature into the public log, so the operator monitors the log for
entries under the pinned leaf it did not make, a MUST of the release
procedure; the session is bounded, the device reset after the signature
and the signatures-per-PIN count set to one where the device allows it;
and the two-signature rule with the registry push credential bounds the
blast radius. The residual -- an extra signature combined with a
candidate's valid provenance signature and push rights yields a bundle
set the verifier grades `release` -- is named here, not hidden.

ADR-055 D5 gains, by dated amendment, a third published invocation beside
the dev container and the stage_1 run line: the signer's, binding the
reader device through the sidecar and the engine socket.

### D10 -- The release build runs on forge-hosted substrate; integrity rests on reproducibility, the forge supplies the second domain

This record fixes no provider and no runner. It requires: the engine
version gate at start (`RequireVersion`, fail-closed); the observed
engine identity, and its version, in the sealed statement; a
substrate-specific `builder.id` per SLSA (a hosted runner, an operator-
pinned image on a hosted runner, and an operator-controlled runner are
distinct modes); and `runnerEnvironment` as a pinnable extension (D2),
so a lane can demand the forge-operated host by policy.

The release build runs on substrate the forge operates, with the plain
hosted image as the baseline. Integrity does not rest on the runner's
stack: digest-pinned step images, `go.sum`, the `reproducedBy` gate and
the cross-host compare mean that engine drift can fail a build but
cannot silently alter it. What the forge-operated host supplies is the
second trust domain of ADR-009 C2: a release requires the forge's engine
and the operator's endpoint engine to agree on the digest, and an
operator-controlled runner would collapse the two signatures to the
operator twice. Operator control of the stack on a hosted runner (a
digest-pinned VM booted on the runner, or a custom image on a larger
runner) is availability hardening, not an integrity requirement; an
ephemeral operator-controlled runner on a pinned image is the documented
fallback, with its own `builder.id` naming the single domain. The
measurement order belongs to the commit-gate item.

### D11 -- Third-party verifiability on two levels, honestly separated

The provenance bundles verify with cosign flag-clean against the
published trusted root and the declared identity, as Beta DoD row 6
requires; row 6 is unchanged for them. The authorization bundle is
verifiable with standard tools, and the release procedure publishes the
three steps anyone can run without strike: the chain to the EU Trusted
List (`openssl verify` with the issuing chain), the ECDSA P-384
signature over the PAE bytes (`openssl dgst -sha384 -verify`), and the
Rekor entry and TSA token; sigstore-go with `WithoutIdentitiesUnsafe`
and the trusted root is the library form. cosign cannot be the verifier
of a certificate without a SAN, and the qualified certificate carries
none; cosign is measured once at the test card and recorded either as an
invocation or as a limitation under row 14 with its cause, and is never
advertised as an identity check with catch-all patterns. Policy engines
are a follow-up item, not a beta duty. "Publicly verifiable" is
redeemed through open standards, not through one tool; row 6 receives a
dated amendment stating the two levels.

### D12 -- The cut from private to public is a sequence of visible edits

Before the beta cut every mechanism runs privately: the harness
(`test/sigstore-local`) stands in for the forge identity and the public
keyless chain for the builder role only; the approver role uses a test
card chaining to the trust service provider's test authority and is
never issued by the harness; the registry repository is private. The cut
consists of lane edits and trust-root re-pins under signed commits: the
builder's keyless endpoints move to the public Sigstore services and its
identity tuple to the forge; the trusted root moves to the public TUF-
derived root plus the production issuing chain in place of the test
authority; the repository visibility to public; and the register names
the first digest. No step moves bytes; every step is a diff.

## Consequences

- **Lane schema (`contract/lane`).** `oidc.extensions` (closed block,
  Fulcio vocabulary) and the required `approvers` list (`id`, `leaf` as
  `endpoint.#Certificate` mode `leaf`, optional `validFor`). Go types
  generated; the `genenums` and `linttypeflow` gates apply.
- **Release schema (`contract/release`).** The VSA statement form as
  consumed and produced; Go types generated; conformance fixtures from a
  test-card bundle. `contract/attest` unchanged.
- **Verifier (`internal/verify`, `cmd/strike/verify.go`).** The
  authorization profile (chain to a declared authority, no issuer
  extension, no SCT, P-384/SHA-384, leaf pin, `validFor` and chain
  windows against trusted time, inclusion); extension decoding for the
  builder's pin tuple (the same code path as the issuer extension); the
  grade gate class, the presence rules, the verdict line, the
  `--allow-candidate` flag and the UC1 approver inputs; the
  `inputAttestations` cross-check.
- **Producer (`internal/deploy`).** The identity check on the issued leaf
  before the first signature; `iss` equality on the token; the engine
  version in the sealed statement if not already there; a
  substrate-specific `builder.id`.
- **Signer.** The strike subcommand, the agent and pcscd images (built
  and pinned in-tree), the published invocation; ADR-055 D5 amendment.
- **Trusted root.** The issuing chain beside the public authorities,
  committed in-tree with the build inputs of the trusted-root image.
- **Procedure (`docs/RELEASES.md`).** Replaces the interim pin rule as
  that document announces: the order of D6; reproduction as a MUST; the
  signed tag; the public-log monitoring MUST; the device session bound;
  the standard-tool verification steps of D11; the register line per
  release; the retraction form; the window width for `validFor`; the
  firmware and reader notes; the checks deferred by D8.
- **Amendments, dated, in the respective records.** ADR-040 D2: the
  hardware-gating sentence is scoped to the builder; ADR-041 D6: the
  abort point moves to the issued certificate; ADR-055 D1: "released" is
  read under this record; ADR-055 D5: the third invocation; Beta DoD row
  6: the two levels. ADR-INDEX gains this record's row.
- **Trusted computing base (ADR-009).** The agent and pcscd images join
  the named base.
- **Roadmap.** item-0166 splits into the authenticated-push item (a typed
  registry credential, the CUE change ratified separately) and the
  public-signing item re-derived under this record; item-0062 depends on
  both; item-0160's C2 reads in this record's direction; item-0063 owns
  the substrate measurement; two parked ideation items record the
  in-verifier tag check (D4) and the companion predicate (D5); delegate-
  measure spikes precede the instructions: the verifier profile and
  grade logic against golden fixtures; the harness Rekor v2 with a
  certificate verifier; the public TSA; the sidecar, agent and PKCS#11
  path on the endpoint with the operator's reader; the forge token
  claims and SAN for a tag-triggered run and the hosted engine; the
  test-card certificate (EKU, keyUsage, subject, chain, batch counter,
  PIN-pad); the harness stand-in for the builder identity and the token
  lifetime; the signed tag with the device key.
- **Known limitations, candidates for Beta DoD row 14.** No revocation
  checking against the trust service provider; cosign as a verifier of
  the authorization bundle; the batch card's signatures per PIN; a
  verifier that distrusts forge-hosted runners by label is not strike's
  verifier.

## Alternatives considered

- **A keyless approver identity through Sigstore's public Dex or a
  device grant.** Requires a browser, on the endpoint or on a second
  device; both excluded by operator ruling.
- **An operator-run Fulcio, IdP and CT log for the approver**, with a
  hardware token as RFC 7523 client credential or with the eID function
  at every signing. Keeps ADR-040 D2 and the existing verifier, but the
  verifier would trust the operator's root for the approver, which fails
  the bar "attested by independent parties"; excluded categorically by
  the operator.
- **An operator root whose certificate is attested by qualified
  signatures and other signatories** (the web-of-trust shape). Meets the
  bar at the root, at the cost of a second anchoring mechanism outside
  the verdict; superseded by signing with the attested identity itself.
- **The eID function as the approver's authentication** (AusweisApp SDK
  without a browser, an eID-Server or eID-Service, an authorization
  certificate under PAuswG with natural persons admitted). Browser-free
  at the protocol level, but it authenticates rather than signs, needs an
  IdP and a Fulcio the public does not trust, and its pseudonym changes
  with every new card.
- **A hardware-held key under an operator-run CA.** Option 1 of the
  working paper; subsumed by D3 with a trust service provider as the
  issuer.
- **The EUDI wallet.** A smartphone application; excluded by the
  second-device ruling. Relying-party onboarding for natural persons is
  not yet defined in Germany.
- **Before-build authorization only** (tag2upload, Guix). The binding to
  the artifact is indirect and violates D1.
- **Authorization verified inside `strike verify` by parsing the tag
  signature.** A CMS or SSH parser and a git object reader in strike, or
  exec; parked.
- **A strike-specific predicate** for the authorization statement.
  Richer evidence, no ecosystem consumer, a new wire; parked.
- **A staging repository with promotion after authorization.** A copy
  path strike lacks, for the same bytes.
- **The authorization layer required for every verification, or checked
  only by external policy engines.** The first breaks the commit gate;
  the second abdicates the verdict.
- **cosign-required verification of the authorization bundle.** Not
  satisfiable by a certificate without a SAN; the form fields a trust
  service provider offers cannot add one.
- **An operator-controlled runner as the mandated substrate.** Buys
  availability, costs the second trust domain; retained as fallback.
- **A Buildkite or CircleCI identity under a SAN-only verifier.** The
  SAN carries no ref; admitted by D2's extension pins instead.
- **Podman inside Docker, or a Kubernetes runner controller, as the
  runner's engine.** Nested engines; ADR-055 D9.

## Principles

- Identity is asymmetric -- the builder's credential (a forge token
  exchanged for a ten-minute certificate) and the approver's (a
  hardware-held key under a trust service provider's certificate) are
  attested independently and carried by different mechanisms; strike
  mediates the approver's signature through an agent and owns no key.
- Runtime is attested -- the authorization statement is a DSSE envelope
  in a strict bundle, logged and timestamped, verifiable offline; the
  approver's reproduction is the evidence behind it.
- Observation over declaration -- the lane declares who may authorize
  and which forge identity builds; the verifier grades what it finds,
  and the builder's identity is checked on the certificate the forge's
  issuer produced, not on the token's claims.
- Enforcement is structural, not discretionary -- the grade is computed,
  the required grade defaults to `release`, and the producer refuses a
  mismatched certificate and a mismatched signature before anything is
  attached.
- External references are digest-pinned -- the approver is a pinned
  certificate, the trusted root a pinned image, the provenance bundles
  named by digest in the authorization statement, the tree names
  releases by digest.
- Reproducibility is enforced, not hoped for -- authorization follows a
  byte-identical reproduction on a second engine in a second domain, and
  integrity never rests on the runner's stack.
- Restricted by default, relaxed only with reason -- the required grade
  is `release`, `--allow-candidate` lowers it explicitly; `validFor`
  bounds the approver below the certificate's validity; the only
  reversal of a standing decision (ADR-040 D2, for one role) carries its
  reason.
- Code is liability -- a standard predicate rather than a new one, an
  agent protocol already in the tree rather than cgo, no tag parser in
  the verifier, no threshold field without a second approver, no
  revocation machinery the offline model cannot honor.
- Meaning is single-sourced -- the lane is the policy for both roles,
  `lane_digest` binds the authorization statement to it, and the
  procedure lives in one document.
- No shell, no exec, no root -- the signer is a container process
  talking to an agent over a socket; the PIN never enters a container;
  the reader binds at the operator's invocation, the one place host
  paths bind.

## Sources consulted at authoring (2026-10-27 to 2026-10-29)

- sigstore/fulcio: `config/identity/config.yaml` (main, 2026-10-26),
  `docs/oidc.md`, `docs/oid-info.md`, `docs/new-idp-requirements.md`.
- sigstore/rekor-tiles: `CLIENTS.md`, `pkg/verifier/certificate`,
  `pkg/types/hashedrekord`; issue #977; release v2.4.0.
- sigstore/sigstore-go: `pkg/root/certificate_authority.go`,
  `pkg/verify` (identity policies); sigstore/cosign:
  `pkg/cosign/verify.go` (`TrustedCert`, `CheckCertificatePolicy`),
  issues #3699, #3976, #4817, #5168; sigstore/protobuf-specs
  `PublicKeyDetails`; sigstore/timestamp-authority issue #1508;
  sigstore/root-signing README and `targets/`.
- Go `crypto/x509/verify.go` (`checkChainForKeyUsage`).
- D-Trust: product page and activation page for the Signaturkarte 5.1,
  Root PKI CPS v3.10, TSPS v1.7, portal completion guide 02/2023,
  support FAQ; REINER SCT cyberJack RFID komfort product page; intarsys
  note on Card 5.1 (2023-11-29); OpenSC NEWS 0.25.0 to 0.27.0,
  `card-dtrust.c`, issue #3586.
- Debian: tag2upload(5), the 2024 GR and debian-vote threads, the GA
  announcement 2026-02-09; bitcoin-core/guix.sigs and
  doc/release-process.md; SLSA v1.1 requirements and provenance;
  github/docs artifact-attestations and OIDC reference;
  actions/runner-images README and issue #14642; GitHub changelogs on
  custom images and nested virtualization.
- AusweisApp SDK (desktop, container, workflow, commands); PAuswV section 28;
  Bundesportal Leistung 584864; BSI TR-03127 and Certificate Policy eID;
  Keycloak source (`ClientCredentialsGrantType`,
  `OAuth2GrantTypeBase`) and server administration guide; podman-run(1).
