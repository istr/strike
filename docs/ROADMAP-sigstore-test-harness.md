# Local Sigstore Test Harness -- Roadmap

## Status

H1 DONE (stack-up + trust anchors + live smoke); H2 (WebAuthn/FIDO2)
remains. The harness lives at `test/sigstore-local/` and the keyless
chain runs against it end to end: ADR-040 instruction 3b-ii-b's env-gated
live test (`TestKeylessLive`) drives strike's own producer through
Fulcio, the TSA, and Rekor v2, and the 3b-ii-c cutover made that chain
the production signing path for deploy statements.

As built, three things diverged from the plan below (the plan text is
kept as the decision record):

- **TLS everywhere via Caddy.** Every service sits behind a Caddy TLS
  terminator under one exported internal root (`pki/caddy-root.crt`);
  there is no plaintext endpoint. strike pins this root as the
  `#TLSTrust` `ca_bundle` for every keyless endpoint. This came from the
  3b-ii-a hardening pass ("TLS-only harness").
- **sslip.io canonical hostnames, not keycloak.local.** The issuer
  `https://keycloak.127.0.0.1.sslip.io:8443/realms/sigstore` resolves
  byte-identically from the host (sslip.io -> 127.0.0.1) and in-network
  (Caddy network alias) without `/etc/hosts` edits or root.
- **TSA on by default, and piecemeal trust anchors instead of a single
  TrustedRoot bundle.** Rekor v2 supplies no integrated timestamp (Path 1
  requires RFC3161), so the TSA toggle resolved to on. The exported
  anchors are the Caddy root, the Rekor log public key
  (`make rekor-pubkey`), and the TSA certificate chain
  (`make tsa-certchain`); the consumer to date is strike's live test, so
  no assembled trusted-root.json was needed yet. The cosign
  verify-attestation independence check remains open (it belongs to the
  instruction-5 arc) and may motivate assembling one then.

The smoke milestone was reached with strike's own chain rather than
cosign: by the time the stack was up, 3b-i/3b-ii-b had already produced
the hand-rolled producer and the sigstore-go crossval oracle, so cosign
as an early bring-up producer was unnecessary.

## Downstream consumers -- golden-bundle regeneration is a hard dependency

The harness is no longer only an H1/H2 milestone tracker; it is a build-time
dependency for any schema or naming change that touches a file whose digest is
sealed into a golden verifier bundle under
`internal/verify/testdata/golden/`. The golden bundles seal a `laneDigest` over
`golden/lane.yaml`, and the DSSE signature covers the payload, so re-keying that
lane (or otherwise changing the sealed file's bytes) re-hashes it and invalidates
the sealed digest. Such a change is NOT hermetic and the bundle cannot be
hand-edited; it must be regenerated against this harness. This was learned the
hard way: the B-6 `#TLSTrust` rename was planned as hermetic on the strength of a
plaintext grep that cannot see into the base64 DSSE payload, and it failed
`make test` on the one golden-sealed lane digest. The gate for future
instructions: before calling a fixture-touching change hermetic, decode the
golden DSSE payloads and look for sealed `*Digest` fields over any file the
change edits, not just the literal token being renamed.

The regeneration flow (`TestVerifyGoldenGenerate`, the env-gated generator in
`internal/deploy/`, runs rootless via `CONTAINER_HOST`):

```
make -C test/sigstore-local up
make -C test/sigstore-local rekor-pubkey
make -C test/sigstore-local tsa-certchain
make -C test/sigstore-local ctlog-pubkey
SIGSTORE_ID_TOKEN="$(make -s -C test/sigstore-local token)" \
  go test ./internal/deploy/ -run '^TestVerifyGoldenGenerate$' -count=1
make -C test/sigstore-local down
```

`make up` brings the stack up rootless and exports the Caddy root
(`pki/caddy-root.crt`); `make rekor-pubkey` exports the Rekor log public key
(`pki/rekor-ed25519-pub.pem`) for trust-root assembly; `make tsa-certchain`
re-fetches the TSA chain (`pki/tsa-certchain.pem`), which must be re-fetched each
startup because the TSA mints a fresh signing cert per boot; `make ctlog-pubkey`
exports the CT log public key (`pki/ctfe-pub.pem`) for the trusted-root ctlogs
entry. The generator reads those four harness materials and rewrites all four
goldens (`sealed`, `engine-context`, `informational`.sigstore.json plus
`trusted_root.json`). The resulting golden
diff is large and non-deterministic -- fresh Fulcio / Rekor / TSA material every
run -- and that is expected: the reproducibility invariant does not apply to live
sigstore fixtures. A regenerated set must then pass `make test` fully offline (no
`SIGSTORE_ID_TOKEN`).

Cross-referenced from ROADMAP-cue-spec-review.md, whose remaining D-F items
inherit this gate when they re-key `golden/lane.yaml`.

## Purpose and relationship to ADR-040

ROADMAP-ADR-040.md lists this harness as a parallel track outside the
strike code sequence (instructions 1-5). It exists to exercise the live
keyless chain -- OIDC -> Fulcio short-lived certificate -> DSSE -> Rekor v2
-- that ADR-040 D2 drives in-process, and to provide the local trust root
that ADR-040 D5 and instruction 5 verify against.

ADR-040 resolves the client question that the earlier framing left open:

- strike is the producer. It drives the keyless chain in-process with a
  hand-rolled bundle producer (protobuf-specs for the wire format,
  ASN.1 DER ECDSA signing, direct Fulcio/Rekor/TSA HTTP clients), never
  by spawning cosign (D2; no exec). sigstore-go is a test-only crossval
  oracle (D-3b-1 ratified).
- cosign is the independent verifier. ADR-040 requires that strike's
  outputs verify offline under cosign and SLSA tooling, without contacting
  strike or the original engine. cosign verify-attestation against this
  harness is that independence check.

So the harness serves both sides: a producer path (cosign during early
bring-up, then strike's own chain) and an independent verifier path
(cosign), both against the same local Fulcio + Rekor v2 and the same
exported trust root.

The harness is not part of the trusted binary. It is test infrastructure;
its libraries and images are never linked into strike.

## Ratified decisions

- A -- Runtime: rootless-Podman-compatible. A single compose file that runs
  under `podman compose` and `docker compose`, no root, no systemd (MX Linux
  has none; Quadlet is therefore out), with host.containers.internal handled
  explicitly.
- B -- Trust root: a static TrustedRoot bundle exported from the running
  stack (Fulcio root + Rekor v2 public key, plus a TSA cert only if a TSA is
  enabled). No TUF: it is deliberately avoided, consistent with the
  ecosystem's own move away from it. cosign consumes it via --trusted-root;
  sigstore-go consumes the same file.
- C -- Location: in-tree at test/sigstore-local/, with zero code coupling to
  strike (no shared Go code, no import in either direction), so extraction to
  a sibling repo later is a pure `git mv`.

Snapshot note (refinement after reading AI-WORKFLOW.md): the harness stays
in the repomix snapshot. It is small text config, and AI-WORKFLOW's
snapshot-hygiene lesson is that the snapshot must contain everything a review
reasons about, with exclusions surgical and by path. Only the ephemeral
instruction files are excluded, by path -- never the harness, and never by a
markdown glob. This reverses the "repomix-excluded" suggestion from the
planning discussion; the reason is AI-WORKFLOW.md.

## Inventory

Lean, three mandatory services:

- Keycloak -- the IdP. Realm `sigstore`, public client `sigstore`, `email`
  scope active, one test user with a verified email. Direct access grant
  enabled during bring-up so a token can be fetched without a browser;
  WebAuthn added later (H2).
- Fulcio -- the CA. OIDCIssuers points at the Keycloak realm, type email; it
  extracts the verified email into the certificate SAN, which becomes the
  identity ADR-040 D5 cross-checks.
- Rekor v2 (rekor-server-posix) -- tile / Tessera log on POSIX storage. No
  Trillian, no MySQL: Rekor v2 replaced Trillian with Trillian-Tessera and
  ships a POSIX backend with no cloud dependencies. Only the hashedrekord and
  dsse entry types remain in v2; dsse is the one strike uses.

Omitted for the lean cut: TUF. (CT log was initially omitted too; it is re-added
in H3 below, because a CT log is required for Fulcio leaves to carry an embedded
SCT so the independent cosign conformance check verifies with no insecure flag.
TUF stays out.)

Toggle, default off: a timestamp authority. Rekor v2 no longer returns inline
signed timestamps -- clients fetch them from a separate TSA. Whether keyless
verify in the pinned cosign / sigstore-go versions requires a TSA, or is
satisfied by the v2 inclusion proof, is version-dependent and decided at the
smoke test (see Open items). The compose file carries the TSA as a service
that is off by default and can be switched on without restructuring.

All images are digest-pinned, consistent with strike's external-reference
discipline; the digests are filled in and verified at first run (see the
run-time constraint below).

## The non-containerizable boundary

This is a property of the design, not a gap to close. The chain is Variant A:
the FIDO2 token protects the identity at the IdP, and strike (like cosign) is
FIDO2-agnostic. The token is a USB-HID device and the WebAuthn ceremony is a
browser interaction with user verification -- both belong to a human, and
humans are not in containers. So:

- The backplane (Keycloak, Fulcio, Rekor v2) is fully containerized.
- The browser, the FIDO2 token, and the producer client run on the host.

During bring-up the human is removed entirely by using Keycloak's direct
access grant to fetch a token non-interactively; the browser and token enter
only at H2.

## Build sequence (instruction files)

Authored one at a time, after this roadmap, per AI-WORKFLOW.md. Names are
descriptive, not numbered -- numbering carries no meaning. Each is a
contract: Goal, out-of-scope list, confirmation gate (with the working-tree
hash the snippets were taken from), anti-initiative clause, exact file
contents, quality gates, acceptance criteria, commit message. Because the
harness is greenfield, most steps create files rather than edit them, so the
before/after-snippet discipline applies only to the one edit that touches
existing config; the rest is checked by build / run gates instead.

### stack-up (H1 core) -- DONE

Goal: the three services come up under rootless Podman, healthy, with a
single canonical issuer hostname that resolves identically from the host
browser and from inside the Fulcio container.

Creates: test/sigstore-local/compose.yaml (Keycloak + Fulcio + Rekor v2
POSIX, TSA present but off), fulcio/config.yaml (OIDCIssuers -> Keycloak
realm, type email), keycloak/realm-export.json (realm, client, email scope,
verified test user, direct access grant on, no WebAuthn yet), Makefile
(up / down), README skeleton.

The one edit to existing config: surgically exclude the ephemeral instruction
files by path from the repomix config -- by path, not by a markdown glob, per
AI-WORKFLOW's snapshot-hygiene lesson. The harness itself is not excluded.

Confirmation gate before authoring: the working-tree hash; the canonical
issuer hostname to standardize on (recommend keycloak.local, mapped via host
/etc/hosts and an in-network alias so iss is byte-identical from both
vantage points); the pinned image digests.

Acceptance: all three services report healthy; the issuer discovery document
is reachable from inside the Fulcio container at the same URL the host uses;
`iss` matches Fulcio's issuer-url character for character.

### trusted-root-and-smoke (H1 completion) -- DONE (as built: strike live test, piecemeal anchors)

Goal: a non-interactive keyless round-trip is green and offline-verifiable,
proving the stack before strike's own chain plugs in.

Creates: bootstrap/ (export trusted-root.json -- Fulcio root + Rekor v2
public key, plus TSA cert if enabled -- from the running stack), Makefile
targets trusted-root and smoke, README smoke section.

Smoke flow: fetch an ID token from Keycloak via direct access grant; run
cosign sign and cosign attest --type slsaprovenance (dsse) with
--identity-token, --fulcio-url, --rekor-url; then cosign verify-attestation
offline with --trusted-root, --certificate-identity (the verified email),
--certificate-oidc-issuer (the canonical issuer). No browser, no token.

This is the milestone that unblocks development of ADR-040 instruction 3: the
live chain exists and is independently verifiable.

Confirmation gate before authoring: the cosign version to pin (>= v3.0.1 or
>= v2.6.0 for Rekor v2); the TSA decision if the smoke surfaces a timestamp
requirement.

Depends on: stack-up.

### webauthn-fido2 (H2) -- OPEN

Goal: identity is hardware-gated at the IdP; the backplane is unchanged.

Edits the realm: WebAuthn passwordless as a required authentication flow,
user verification requirement = required. README gains token registration and
the host-side browser login. Whether direct access grant stays enabled
afterward for CI is an operator choice (Open items).

This unblocks the real identity-gated producer path -- both cosign and, via
ADR-040 instruction 3, strike's in-process oauthflow.

Depends on: trusted-root-and-smoke.

### ct-log-tessera (H3) -- CT log for non-insecure SCT conformance

Goal: Fulcio leaves carry an embedded SCT so the independent cosign conformance
check verifies offline with no `--insecure-*` flag.

The feasibility spike returned GO with Fulcio v1.6.6 unchanged: a TesseraCT POSIX
log (Tessera, no Trillian; digest-pinned image), in-network only, with Fulcio
moved to a persistent `fileca` and `--ct-log-url=.../strike-ct`, produced a leaf
whose embedded SCT cosign verified offline against the ctfe key in the trusted
root (exit 0, no insecure flag). Key validated facts: `fileca` is the clean
prerequisite (the log pins accepted roots); the CT log signer is ECDSA P256
(SEC1); CT keys need `chmod 644` for the nonroot container under rootless userns;
the CT `ctlogs` log id is RFC6962 `sha256(DER SubjectPublicKeyInfo)`, distinct
from the Rekor v2 C2SP signed-note key id the generator already hand-derives.

Sequence:

- 3a (this arc) -- harness CT enablement: TesseraCT service (in-network), Fulcio
  fileca + ct-log-url, key generation and `make ctlog-pubkey`, plus this roadmap
  record. strike's verify is left ignoring the CT material (non-breaking).
- 3b -- add the `ctlogs` entry to `goldenTrustedRoot` (RFC6962 log id; Rekor
  entry unchanged) and regenerate the goldens against the CT-enabled harness.
- 3c -- the flag-clean cosign conformance target (no `--insecure-ignore-sct`),
  gating exit on the V (sealed) layer only.

Deferred follow-on (separate ratification, production verify-path): whether
strike's own verify should enforce the embedded SCT for posture symmetry with
cosign is its own item, sequenced after this arc.

Deferred follow-on (full cosign compatibility): liveTrustRoot (the trust root
TestKeylessLive assembles) does not yet carry the ctlogs entry -- only the golden
generator does, so strike's own verify stays SCT-ignoring there. Pulling the
ctlogs entry into liveTrustRoot is the remaining step toward full cosign
compatibility of the live path; deferred until after the golden / conformance
arc (3b / 3c).

Depends on: trusted-root-and-smoke. Owns the detail for the cross-roadmap CT arc
referenced from ROADMAP-STATUS step 3.

## The four failure points to expect at run time

These are where bring-up iterates; they are the reason the stack is
multi-container rather than one box (a single box on localhost hides the
first one):

1. Issuer-URL consistency. The token `iss`, Fulcio's issuer-url, and the
   producer's --oidc-issuer must be byte-identical, and Fulcio must reach
   that URL for discovery / JWKS. The canonical-hostname approach in stack-up
   is the fix.
2. aud == client-id. The token audience must equal Fulcio's client-id and the
   producer's client id, or Fulcio rejects it.
3. email + email_verified: true must actually be in the token (email scope
   active, test user's email verified).
4. Versions. cosign >= v3.0.1 or >= v2.6.0 for Rekor v2.

## Invariants the harness must respect

- Not part of the trusted binary; zero code coupling; reversible to a sibling
  repo by git mv.
- Rootless Podman, no root, no systemd; one compose file usable under
  podman compose and docker compose.
- Static TrustedRoot, no TUF.
- Lean inventory; TUF out. (CT log re-added in H3 for non-insecure SCT
  conformance; TSA resolved on by default -- Rekor v2 Path 1.)
- FIDO2 token and browser stay on the host; strike and cosign are
  FIDO2-agnostic (Variant A).
- Images digest-pinned; the harness produces a known, declared identity so
  ADR-040 D5's cross-check (cert issuer == declared issuer, cert SAN ==
  declared identity) has a fixed target.
- Documents and config are US English, ASCII only, consistent with the rest
  of the tree.

## Open items

Resolved at run time:

- TSA on or off -- RESOLVED: on by default. Rekor v2 supplies no
  integrated timestamp (Path 1 requires RFC3161 tokens); the TSA is a
  mandatory link in the chain and its certificate chain is exported via
  `make tsa-certchain`.
- Exact image digests -- RESOLVED: pinned in `compose.yaml` (Caddy,
  Keycloak, Fulcio, rekor-tiles POSIX, timestamp-server, curl).

Still open:

- cosign independent-verify path. The original cosign smoke was overtaken
  by strike's own live test; the cosign verify-attestation independence
  check (and a possibly needed assembled trusted-root.json) belongs to
  the ADR-040 instruction-5 arc.
- Whether direct access grant stays enabled after H2 for CI convenience, or
  is removed so the only path is WebAuthn. Operator choice.

## References

- ADR-040-control-plane-sbom-and-keyless-attestation.md -- the governing ADR
- ROADMAP-ADR-040.md -- the strike code sequence; this harness is its parallel
  "Local sigstore test harness" track, supporting instructions 3 and 5
- sigstore-keyless-fido2-report.md -- keyless / FIDO2 evaluation, Variant A,
  the four failure points
- AI-WORKFLOW.md -- the instruction-file contract and snapshot-hygiene rule
  this sequence follows
