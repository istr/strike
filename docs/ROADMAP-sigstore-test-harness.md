# Local Sigstore Test Harness -- Roadmap

## Status

PLANNED. No files created. This roadmap fixes scope and decisions for the
supporting infrastructure ADR-040 calls for. The instruction files that
build it are authored one at a time after this plan, per AI-WORKFLOW.md.

## Purpose and relationship to ADR-040

ADR-040-ROADMAP.md lists this harness as a parallel track outside the
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

Omitted for the lean cut: CT log, TUF.

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

### stack-up (H1 core)

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

### trusted-root-and-smoke (H1 completion)

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

### webauthn-fido2 (H2)

Goal: identity is hardware-gated at the IdP; the backplane is unchanged.

Edits the realm: WebAuthn passwordless as a required authentication flow,
user verification requirement = required. README gains token registration and
the host-side browser login. Whether direct access grant stays enabled
afterward for CI is an operator choice (Open items).

This unblocks the real identity-gated producer path -- both cosign and, via
ADR-040 instruction 3, strike's in-process oauthflow.

Depends on: trusted-root-and-smoke.

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
- Lean inventory; CT log and TUF out; TSA off by default.
- FIDO2 token and browser stay on the host; strike and cosign are
  FIDO2-agnostic (Variant A).
- Images digest-pinned; the harness produces a known, declared identity so
  ADR-040 D5's cross-check (cert issuer == declared issuer, cert SAN ==
  declared identity) has a fixed target.
- Documents and config are US English, ASCII only, consistent with the rest
  of the tree.

## Open items (decided at run time, not now)

- TSA on or off. Driven by whether keyless verify in the pinned versions
  needs a separate signed timestamp under Rekor v2. Decided at the
  trusted-root-and-smoke smoke test. Compose carries it off by default.
- Exact image digests and cosign version. Pinned and verified at first run on
  the operator's machine; the planning environment cannot pull from container
  registries (egress is restricted to source-package mirrors), so none of the
  config has been executed.
- Whether direct access grant stays enabled after H2 for CI convenience, or
  is removed so the only path is WebAuthn. Operator choice.

## References

- ADR-040-control-plane-sbom-and-keyless-attestation.md -- the governing ADR
- ADR-040-ROADMAP.md -- the strike code sequence; this harness is its parallel
  "Local sigstore test harness" track, supporting instructions 3 and 5
- sigstore-keyless-fido2-report.md -- keyless / FIDO2 evaluation, Variant A,
  the four failure points
- AI-WORKFLOW.md -- the instruction-file contract and snapshot-hygiene rule
  this sequence follows
