# ADR-058: The registry client identity is a workload-identity token, declared apart from server trust

## Status

Accepted, 2026-10-31. Drafted against
`4c8de4be424c241c2f2ebe7b4dd1c2c34265b8e7`. Every design fork behind this
record was surfaced and ratified by the operator between 2026-10-29 and
2026-10-31 (working paper "Decision Forks -- Registry Client Identity ADR",
ephemeral, not committed); the measurements this record cites were made
against the harness, quay.io, Google Artifact Registry and Azure Container
Registry on 2026-10-29 to 2026-10-31 at `1344ed5` (spike reports, ephemeral,
not committed) and against the primary sources listed at the end. Three
research documents under `docs/research/adr-058-*.md` carry the survey
behind the context.

Closes, for OCI registries, the third deferral of
[ADR-025](ADR-025-ssh-peer-client-identity-enforcement.md) ("OIDC workload
identity for non-SSH client authentication (HTTPS peers, OCI registries).
Separate transport, separate ADR."); the HTTPS-peer half, KMS-held client
identity and agent identity filtering stay deferred with roadmap owners.
Answers, for the registry method, the open mechanism bullet of
[ADR-054](ADR-054-kubernetes-deploy-via-cluster-api.md) D5; the kubernetes
method inherits the form. Amends, by dated amendment sections in the
respective records, [ADR-006](ADR-006-secrets-as-typed-primitive.md) (the
environment clause), [ADR-007](ADR-007-asymmetric-identity.md) (the record
sentence), ADR-025 and ADR-054 D5. Changes the lane schema
(`contract/lane`); touches no field of `contract/attest`, so this is not a
freeze event under the attest wire freeze.

## Context

### The principle

ADR-007 fixes the form: client identity and server identity are separate
declarations, never one field and never one file, and credential-holding
authorities delegate without revealing key material. ADR-054 D3 fixes the
shape for control-plane dial targets: an address plus a server-trust anchor
as a method field, the client credential a separate declaration. Neither
record, nor ADR-037 D5.1 or ADR-038 D3, which name "KMS / OIDC workload
identity / keyless" as the direction, decides the mechanism. ADR-025
announced a separate ADR for it. This is that record, for the registry
push: the control plane authenticates with the same class of identity
that signs its provenance -- a short-lived workload identity attested by
an issuer -- presented or exchanged per the registry's own convention,
declared in the lane apart from the registry's trust anchor, carried as a
typed secret, never reaching a step container, and never outliving the
run. No static password and no personal access token is declarable.

### What the tree does at the anchor

- `internal/deploy/push.go`: `pushByDigest` calls `remote.Write` with the
  trust-anchored transport and no authenticator. `newRegistryTransport`
  rejects in `DialTLSContext` every address other than the declared
  `host:port`, rejects plaintext, and rewrites the scheme to https. A token
  realm on another host therefore fails before any credential matters.
- `internal/registry/referrer.go`: `AttachStatementBundles` adds
  `remote.WithAuthFromKeychain(authn.DefaultKeychain)` beside the anchored
  transport, so the three statement bundles are pushed with whatever
  Docker or Podman auth file the controller's HOME holds, while the payload
  and the SBOM referrers are pushed anonymously; the four read paths use
  the same keychain over go-containerregistry's default transport, the
  system trust store. Five sites, one file.
- `internal/lane/secret.go`: `SecretString` redacts on every string, format
  and JSON path; `ReadSecret` admits `env://NAME` and `file://path` (the
  latter through the lane directory's `os.Root`); `ResolveSecrets` serves
  step containers. `#DeployRegistryTarget{type, host, trust, name}` has no
  credential field; `#SecretRef{name, env}` binds a lane secret to a
  container variable.
- `internal/deploy/keyless_producer.go`: the builder's OIDC token is read
  from `SIGSTORE_ID_TOKEN` as a plain `string` at the deploy (ADR-040,
  amendment "as built": ambient, never interactive). ADR-055 B6 measured
  the `-e` channel: the token is in clear in the control-plane container's
  inspect for any holder of the engine socket until `--rm`.
- ADR-006 says secrets "never appear in strike's own process environment".
  The sentence entered SECURITY.md at `ad2b28e` (2026-04-01) as the rewrite
  of the removed `os.Setenv` write path and became an ADR-006 decision
  bullet and a DESIGN-PRINCIPLES sentence at the ADR reconstruction
  (`1ea1baf`); AGENTS.md invariant 4 never carried it. `env://` (since the
  initial commit) and `SIGSTORE_ID_TOKEN` (since `f2329ad`) read the
  environment; no audit or retrospective ruled on it.
- `contract/attest` is frozen (Beta DoD row 5). `#PushedArtifact{registry,
  repository, digest}` and `#ObservedTLS{serverCertFingerprint}` record
  the server side of the push; no field records the credential.
- Every `type`-discriminated shape under `contract/` is a disjunction of
  own definitions with `@go(-)` and a hand-written Go interface and
  unmarshal (`#Peer`, `#DeployMethod`, `#Engine`, `#ObservedIdentity`,
  `#Handle`, the provenance records, the crossval vectors).
- The harness: zot 2.1.20 behind Caddy with no `http.auth` block (the push
  is anonymous); Keycloak realm `sigstore` with one public client
  `sigstore`, direct grants, 600-second tokens, `aud "sigstore"`; Fulcio's
  issuer entry is `type: email`. The README run line passes the builder's
  token with `-e SIGSTORE_ID_TOKEN`, minted for one run.
- `go.mod`: go-containerregistry v0.21.9; `github.com/docker/cli` and
  `github.com/docker/docker-credential-helpers` indirect.
- [ADR-057](ADR-057-release-authorization-two-signatures.md) D6: the
  builder's deploy pushes the candidate by digest to the final repository,
  private before the beta cut and public after it; D12: the harness stands
  in for the forge identity before the cut. No tag exists anywhere;
  verification discovers bundles through the referrers API filtered by
  `artifactType`.

### Constraints that shape the design

- The engine is never assumed local: the controller may drive a remote
  engine over `CONTAINER_HOST`, so a channel that binds a host path of the
  operator's machine is not general.
- The operator ruled (2026-10-29) that the credential is a workload-
  identity token, never a static password and never a personal access
  token; that Gitea and GHCR are struck (no workload-identity exchange for
  their registries, no OCI 1.1 referrers API); and that the harness issues
  the registry-audience token.
- The reference endpoint has no browser (ADR-055 D1); the harness
  Keycloak is loopback, so no public registry can verify an assertion it
  mints. Before the cut the endpoint therefore pushes to the harness zot
  only; the first push to a public registry is the first forge build.

### Facts measured at authoring

- zot 2.1.20 `bearer.oidc` authenticates a Keycloak id token whose `aud`
  contains the configured audience, as the bearer itself, with no realm
  call; a token with `aud "sigstore"` only is refused ("token audience does
  not match any of the expected audiences"). The identity is
  `iss + "/" + sub`; access control keys on that string. zot validates
  against the issuer's discovery document and key set, fetched lazily at
  the first token through the configured certificate authority.
- go-containerregistry v0.21.9 refuses a challenge whose `realm` is not an
  http(s) URL ("realm scheme \"\" not allowed") before sending any token.
  With `authn.Bearer` the realm host is never dialed; with a basic
  credential the client exchanges once at the realm (GET with HTTP Basic;
  `RegistryToken` used directly; `IdentityToken` via the OAuth2 POST),
  through the same inner round tripper, so strike's pinned dial governs
  it. Expiry is ignored; re-exchange happens only on a new 401.
- The realm is on the registry host at quay.io (`https://quay.io/v2/auth`),
  Google Artifact Registry (`https://<region>-docker.pkg.dev/v2/token`) and
  Azure Container Registry (`https://<name>.azurecr.io/oauth2/token`); at
  Docker Hub it is `auth.docker.io`, and the client rewrites `docker.io` to
  `registry-1.docker.io` silently; at GitLab it is `gitlab.com/jwt/auth`.
- The digest-only push of a payload plus a subject-bearing referrer works
  on zot, quay.io, GAR and ACR and creates no tag; every one answered the
  referrers API during the write (otherwise go-containerregistry's default
  `referrersTagFallback` would have pushed an index to `sha256-<hex>`).
- quay.io garbage-collects a tagless manifest within 18.5 hours (the
  tagless referrer survives its subject). GAR and ACR retain tagless
  manifests at the measurement horizon (49 hours pending at authoring).
- quay.io and GAR do not surface a derived `artifactType` in the referrers
  descriptor; the explicit manifest field is surfaced and filtered; ACR and
  zot derive it. go-containerregistry's client-side `filterReferrersResponse`
  drops every descriptor without the field regardless of
  `oci-filters-applied`, so strike's own discovery finds none of its
  bundles on quay.io and GAR at the anchor.
- ACR invalidates its referrers listing on every subject-bearing write;
  the newest referrer is in every listing after its push, under `HIT` as
  well; `Oci-Subject` is returned on the referrer `PUT`.
- Quay's robot federation is `GET /oauth2/federation/robot/token` with
  HTTP Basic `<org>+<robot>:<OIDC JWT>`, answered `{"token": ...}`, valid
  one hour, organization robots only; the returned token is then the
  robot's password in the standard realm flow. Quay fetches the issuer's
  keys. An unknown robot gets 401 JSON `{"error":"Invalid robot"}`, a known
  robot with an invalid assertion 500 `text/html`. Google STS answers OAuth
  JSON errors, Entra ID OAuth JSON plus `error_codes`, ACR
  `/oauth2/exchange` a JSON registry error labelled `text/plain`.
- Podman 5.4.2: `-e` places the value in `.Config.Env`; `--secret
  type=env` masks it in inspect while the process environment carries it;
  `--secret type=mount` keeps it out of inspect as a `400 root` bind mount
  of a host file, unreadable by the image's user; `GET /secrets/{name}/json?showsecret=true`
  returns any secret's value to any socket holder.
- `authn.DefaultKeychain` (go-containerregistry `pkg/authn/keychain.go`)
  loads `~/.docker/config.json`, `$DOCKER_CONFIG/config.json`,
  `$REGISTRY_AUTH_FILE` or Podman's `auth.json`; docker/cli v29.7.2
  `GetAuthConfig` calls `GetCredentialsStore`, which returns
  `credentials.NewNativeStore` whenever `credsStore` or a matching
  `credHelpers` entry is set; docker-credential-helpers v0.9.8
  `client/command.go` imports `os/exec` and runs
  `docker-credential-<helper>`. The strike tree has zero `os/exec`
  imports; the binary links this path, and `go list -deps` of a program
  importing `remote` and `authn` without naming `DefaultKeychain` lists the
  same seven docker packages: the cluster rides on the `authn` import,
  which `remote` needs.
- The TanStack compromise (May 2026) extracted the OIDC token from runner
  memory (`/proc/<pid>/mem`); against code under the same UID neither the
  environment, a file nor memory is a boundary. On every forge the job's
  token-request token arrives through the environment; that is the
  platform's channel.

## Terms

- **Builder token**: the OIDC identity token the deploy exchanges at
  Fulcio for the provenance signature (ADR-040, ADR-057 D2), audience
  `sigstore`.
- **Registry token**: the OIDC identity token, minted for the registry's
  own audience, that authenticates the push; presented or exchanged per
  the registry's convention. A distinct token from the builder token.
- **Convention**: how a registry consumes the registry token: as the
  bearer itself (`bearer`), or exchanged on the registry host for a
  short-lived registry credential (`quayRobot`), or exchanged at a
  declared exchange endpoint on an identity-provider host (an extension
  this record admits, not builds).

## Decision

### D1 -- The registry client credential is a declared workload-identity token, apart from server trust

A registry deploy declares its client credential beside, never inside,
its server-trust anchor: `#DeployRegistryTarget` keeps `host`, `trust` and
`name` and gains a `credential` whose value is a reference to a named
registry token in `lane.secrets`. The token is an OIDC identity token
issued to the workload for the registry's audience. No static password,
robot secret or personal access token is a declarable credential; a
registry that admits only those is not a target. The credential never
reaches a step container, a log, or the record (D8).

### D2 -- Two conventions, one union; strike performs the exchange

`#RegistryCredential` is a disjunction of own definitions with a `type`
discriminator, `@go(-)`, and a hand-written interface and unmarshal after
the `#Peer` pattern, as every type-discriminated shape in `contract/` is:

- `bearer`: the registry validates the token itself (zot `bearer.oidc`);
  strike presents it as the bearer (`authn.Bearer`) and no realm is
  dialed.
- `quayRobot`: the registry exchanges the token on its own host for a
  one-hour robot credential (`GET /oauth2/federation/robot/token`, HTTP
  Basic `<org>+<robot>:<token>`); the robot name is declared in clear; the
  returned credential is the robot's password in the standard realm flow
  (`authn.Basic`), held as a `SecretString` for the deploy and discarded.
  strike performs the exchange itself over the pinned transport with the
  standard library; on a failure it reports status and content type and
  nothing more, because the endpoint's error shapes are not structured.

The extension point is a third arm for a declared exchange endpoint on an
identity-provider host apart from the registry, with its own trust anchor,
in the shape the keyless endpoints already have; whether it is built, and
whether the `quayRobot` arm lands or stays a documented reference shape,
is decided by the publication-model decision this record defers (D9).
Clients dispatch on status codes, never on content types: the measured
exchange endpoints answer OAuth JSON, registry JSON, HTML and JSON
labelled `text/plain`.

### D3 -- One token per audience

The builder token and the registry token are two tokens, each minted for
one audience. A token minted for one peer is never presented to another:
the registry validates its audience, Fulcio validates its own, and a
token obtained from either leg is worthless at the other. Before the cut
the harness Keycloak issues both from two public clients; after it the
forge mints per audience, which is the only shape a forge offers.

### D4 -- Declared in the lane, delivered by the invocation, bounded in lifetime

The registry token is a named entry in `lane.secrets` with the sources
the lane already admits, `env://` and `file://`; the credential names it.
How the engine populates the variable -- `-e`, or `--secret type=env`,
which keeps the value out of the inspect listing on Podman 5.4.2 -- is the
operator's engine invocation (ADR-055 D5) and changes nothing in the lane.
No channel hides a value from a holder of the engine socket (inspect,
`showsecret`, exec); the bound is lifetime and `--rm`, and strike enforces
the lifetime structurally: a registry token whose `exp - iat` exceeds the
bound is rejected before any use. The bound is fifteen minutes. Where an
issuer cannot mint a token that short, the lane declares that issuer's
shortest supported lifetime as the bound for that credential; the default
needs no declaration. The exposure to socket holders is a documented
limitation under Beta DoD row 14. The builder token keeps its fixed name
until the item that moves its acquisition to the deploy lands; that item
is expected to put it under the same declaration.

### D5 -- One authority; a realm elsewhere is unsupported

The push transport admits the declared `host:port` only, as before. A
registry whose token realm is on another host fails with the existing
"dial ... outside the declared target" error; this record does not add a
second authority. A registry whose token realm lives on a host other than
the declared target, or whose client library rewrites the declared host
to another, is thereby excluded. A declared realm peer with its own
anchor is parked as a post-beta ideation item, not promised. Consequence
for the harness: zot's `realm` must be an https URL on the registry's own
host, so that a run without a credential fails inside the declared
authority instead of dialing Keycloak.

### D6 -- No ambient keychain; the linked credential cluster is accepted, never invoked

`authn.DefaultKeychain` is removed from every site. Writes authenticate
with the declared credential (`remote.WithAuth`); reads authenticate with
the declared credential in UC2, with explicit inputs in UC1, and as
`authn.Anonymous` where nothing is declared. The ambient keychain was a
latent subprocess path: a `credsStore` or `credHelpers` entry in any of
the four files it reads would have made the controller run
`docker-credential-<helper>`, which AGENTS.md invariant 1 forbids. The
docker/cli and docker-credential-helpers modules cannot be dropped -- they
ride on the `authn` import that `remote` needs -- and are recorded as an
accepted, never-invoked dependency, with `go list -deps` as the measure.

### D7 -- The environment principle, sharpened

ADR-006's environment clause described a removed write path and became an
absolute by reconstruction. It is read, by dated amendment, as: strike
writes nothing into its own environment and passes nothing through it to
a step container; strike holds no credential that outlives the run; from
the environment strike reads only declared, short-lived, audience-bound
per-run tokens or the platform's capability tokens, under the lifetime
bound of D4. The literal reading -- no environment at all -- is
unreachable on every forge, whose token-request token is the platform's
channel, and buys nothing against the realistic adversary: against code
under the same UID the channel is not the boundary; lifetime, audience
binding and isolating the token holder are, and strike isolates the holder
by running every step in its own container. The path that removes the
secret zero altogether -- an attested identity from a SPIFFE Workload API,
no credential delivered -- is the named successor, parked as a post-beta
item (`spiffe://` source). SECURITY.md and DESIGN-PRINCIPLES.md carry the
same sentence.

### D8 -- The record carries no client identity

The attestation records the server side of the push as observed
(`#PushedArtifact`, `#ObservedTLS`) and, on the client side, what is
independently verifiable: the keyless signing identity in the sealed
provenance and the Rekor entry. A bearer credential's identity is the
registry's knowledge (zot logs `iss/sub` per request); recording it would
be a `contract/attest` change for a claim no verifier can check. ADR-007's
"Deploy attestations record both sides explicitly" is read, by dated
note, as "both sides declared separately, each recorded where it is
verifiable".

### D9 -- Pre-beta target and the deferred publication model

Before the beta cut the endpoint pushes to the harness zot under
`bearer.oidc` with the harness-minted registry token (ADR-057 D12
extended to the pusher role). The harness zot gains the `bearer` auth with
the harness issuer, an https realm on its own host, and an access-control
policy for the bootstrap lane's repository; the harness Keycloak gains a
second public client with an audience mapper for the registry audience;
the README run line passes the second token. This record names no public
registry: the publication model -- direct push to a registry that accepts
a federated workload-identity token, or an operator-run origin zot with a
public pull-through cache by digest -- is decided by measurement of
tagless retention and cache fidelity for referrers, as a short fork
before the forge choice. A public endpoint qualifies only if it keeps a
tagless manifest and its referrers for the measured retention window,
serves the referrers API, and accepts a workload-identity token under one
of the two conventions of D2.

## Consequences

- **Lane schema (`contract/lane`).** `#DeployRegistryTarget.credential`;
  `#RegistryCredential` union with `#CredentialType "bearer" | "quayRobot"`
  (the second arm subject to D9), the token as a reference into
  `lane.secrets`, an optional per-credential lifetime bound; hand-written
  interface and unmarshal in `internal/lane`. Ratified as a separate
  schema change before the instruction, as item-0166 requires.
- **Producer (`internal/deploy`).** `remote.WithAuth` on every write of
  the registry deploy; the federation exchange; the lifetime check on the
  registry token; the deploy resolves the registry token through the lane
  root it does not hold today.
- **Registry package (`internal/registry`).** Keychain removed at five
  sites; the read paths take an authenticator and, in a follow-up item,
  the lane's anchor. Two producer fixes land in their own item before
  item-0166: the explicit manifest `artifactType` in `ArtifactImage`
  (quay.io and GAR surface no derived type; the client filter drops the
  descriptor) and `WithReferrersTagFallback(false)` on write and read, so
  a registry without the referrers API fails loudly instead of receiving a
  tag.
- **Verify read side.** Its own item after item-0166 and before item-0062:
  UC2 reads under the lane's anchor and credential, UC1 under explicit
  inputs; `FetchBaseSBOMReferrers` likewise; a HEAD cross-check of listed
  against attached bundle digests as the registry-independent guard.
- **Harness (`test/sigstore-local`).** As D9; the user's import-time `sub`
  is either pinned in the realm export or mapped through zot's
  `claimMapping.username` to the email, decided at instruction time.
- **Amendments, dated, in the respective records.** ADR-006 (D7); ADR-007
  (D8); ADR-025 (deferral 3 closed for OCI registries; the remaining
  deferrals get owners); ADR-054 D5 (the mechanism bullet answered for the
  registry method); SECURITY.md step 3 and the DESIGN-PRINCIPLES sentence
  (D7); a dependency note for the credential cluster (D6). ADR-INDEX gains
  this record's row.
- **Known limitations, candidates for Beta DoD row 14.** Engine-socket
  exposure of per-run tokens (D4); a realm on another host unsupported
  (D5); the linked, never-invoked credential cluster (D6); no secret-zero
  elimination until the SPIFFE source exists (D7).
- **Roadmap.** item-0166's acceptance is amended: the live push
  measurement is against the harness zot; the Quay convention is verified
  against a hermetic federation stand-in and the real endpoints' shapes;
  the first public push is the forge build's. New items: the referrer
  interoperability item (before item-0166, after item-0081); the verify
  read-side item (after item-0166, before item-0062); the publication-model
  decision item (before the forge choice). Parked ideation items: the
  declared realm peer (D5); the SPIFFE source (D7); KMS-held client
  identity for the capsule's upstream SSH and agent identity filtering
  (ADR-025 deferrals 1 and 4).

## Alternatives considered

- **A static registry password or personal access token as the typed
  secret.** The common shape of every CI tool, and the one every 2025 and
  2026 incident started from; excluded by operator ruling.
- **The ambient keychain** (`~/.docker/config.json` and relatives). Ambient
  rather than declared, and a subprocess path by configuration.
- **One token with two audiences.** Fewer variables; audience confusion by
  construction, an array-valued `aud` Fulcio was not measured against, and
  a shape no forge offers.
- **A file secret through `--secret type=mount` as the published channel.**
  Needs mount ownership options, a path outside the lane root, a wider
  `os.Root` scope, and leaves the value on the host under the `file`
  driver; `showsecret` reopens it anyway.
- **Reading the token through the engine's secrets API at the deploy.**
  Keeps the letter of the environment clause, not its sense, and does not
  exist on a forge.
- **The SPIFFE Workload API now.** The only path without a secret zero;
  SPIRE in the harness, node attestation on the endpoint, a gRPC
  dependency and a second identity beside the forge's are too much for one
  item. Parked as the successor.
- **A declared second authority for the realm.** Code for a case no
  candidate needs; parked for Docker Hub.
- **Probing the registry for its convention.** Discovery where the tree
  declares.
- **One closed struct with a `type` enum and conditional fields instead of
  a union.** Fewer lines, against eight precedents in `contract/`.
- **Recording the token's `iss`/`sub` in the informational layer.** An
  attest change for an unverifiable claim.
- **quay.io as the public candidate.** Measured: a tagless manifest and
  its referrers are collected within a day, which contradicts the
  digest-only model of ADR-057 D6. Its robot federation convention is kept
  (D2) for operators who run a Quay with retention they control.
- **Gitea and GHCR as the public candidate.** No referrers API (the client
  would fall back to tags, which the tree forbids) and no workload-identity
  token exchange for pushes; both would need a static credential.
- **Docker Hub as the public candidate or as the mirror.** Its token realm
  on `auth.docker.io` is a second authority, and the client rewrites
  `docker.io` to `registry-1.docker.io` silently; both fall under D5. A
  mirror that must authenticate to a public origin adds an identity
  without adding trust.
- **A declared exchange endpoint on a cloud identity provider now** (Google
  STS, Entra ID). The third arm D2 reserves; built only if the publication
  model of D9 lands on direct push to a cloud registry.
- **GAR and ACR as the public candidate, decided now.** Both accept a
  federated token and serve the referrers API; GAR drops referrers without
  an explicit `artifactType`, ACR invalidates its referrers listing on
  write. Not excluded; their tagless retention is the open measurement D9
  waits for.

## Principles

- Identity is asymmetric -- the registry credential is declared beside
  the trust anchor, never inside it; the token is issued by an authority
  and consumed by the registry; strike mediates the exchange and owns no
  key.
- Secrets are typed -- the registry token and any derived credential are
  `SecretString` values in process memory, discarded with the run; the
  environment clause is read for what it protects.
- Peers are declared -- the registry is a declared dial target with a
  declared credential and a declared convention; the realm is inside the
  declared authority or unsupported.
- No exec -- the ambient keychain's helper path is removed, not tolerated.
- Observation over declaration -- the registry validates the token; the
  lane declares which token and which convention, nothing the registry
  could contradict.
- Enforcement is structural, not discretionary -- the lifetime bound is
  checked before use; a static credential has no schema arm; a realm
  elsewhere has no dial.
- Restricted by default, relaxed only with reason -- fifteen minutes, or
  the issuer's documented minimum, declared.
- Code is liability -- one union after an existing pattern, a twenty-line
  exchange in the standard library, no new module, no second authority,
  no engine-secret reader, no SPIRE client until it earns its keep.

## Sources consulted at authoring (2026-10-29 to 2026-10-31)

- google/go-containerregistry v0.21.9: `pkg/v1/remote/transport/bearer.go`,
  `pkg/v1/remote/referrers.go`, `pkg/v1/remote/options.go`,
  `pkg/authn/keychain.go`; release notes v0.21.4 to v0.21.9.
- docker/cli v29.7.2 `cli/config/configfile/file.go`;
  docker/docker-credential-helpers v0.9.8 `client/command.go`.
- zotregistry.dev v2.1.18 and v2.1.20: "Authentication and
  Authorization", "Retention"; project-zot/zot pull requests #4171, #4593.
- Project Quay documentation (robot federation, `FEATURE_REFERRERS_API`,
  `PUSH_TEMP_TAG_EXPIRATION_SEC`); Red Hat Developer articles of
  2025-04-22 and 2026-07-22; quay/quay pull requests #6664, #7368; the
  Red Hat announcement of the referrers API on quay.io.
- containers/podman issue #23788; podman-run(1) and podman-secret(1).
- GitHub Docs: "Working with the Container registry", "About permissions
  for GitHub Packages"; Gitea Docs: "Actions token permissions",
  "Container registry"; Docker Docs: "Docker Hub rate limit".
- `docs/research/adr-058-workload-identity-state-of-play.md`,
  `docs/research/adr-058-oidc-issuer-separation.md`,
  `docs/research/adr-058-public-registry-mirrors.md` (in-tree, with their
  own source lists).
- Spike reports (ephemeral): registry client identity against zot and
  quay.io (2026-10-29); public registry candidates GAR, ACR (2026-10-30/31)
  with two addenda on the ACR referrers listing.

## Amendment 2026-11-03 -- D2 lands with one convention, D3 is checked before use, D4's override waits for the forge, D9's registry client is its audience

**D2.** Before the beta cut only the bearer convention has a target;
whether the quayRobot arm with its hermetic stand-in, or the declared
exchange-endpoint arm, is built is decided with the publication model
D9 defers (item-0174). Until a second convention lands,
`#RegistryCredential` is the bearer arm itself: a closed definition with
its `type` discriminator and the `lane.secrets` key of the registry
token, decoded by the generated type. The disjunction with `@go(-)`, the
hand-written interface and the hand-written unmarshal of D2 arrive with
the second arm, because a union of one arm is an interface with one
implementation. The wire shape of a bearer credential does not change
when the union arrives.

**D3.** "A token minted for one peer is never presented to another" is
checked, not assumed. Before any use the deploy refuses a registry token
whose `aud` contains the lane's `oidc.audience`, and lane validation
refuses a credential that names the builder token's `lane.secrets`
entry. A builder token presented to a registry could be redeemed at
Fulcio for the builder identity by whoever reads it there.

**D1, the log clause.** The registry token stays a `SecretString` until
go-containerregistry asks for it: the deploy hands the client an
authenticator over the secret type, never a string-typed credential. A
push error is scrubbed of the token value before it leaves the deploy,
because a registry's error body is text the registry controls.

**D4.** The per-credential lifetime override is deferred, with the
builder token's, to item-0063; the fixed fifteen-minute bound applies to
both tokens. Measured on 2026-11-03 on scratch repositories: GitHub
Actions mints id tokens of 300 seconds, GitLab CI of 3600 seconds, so the
override is needed exactly if the forge is GitLab.

**D9 and Consequences, Harness.** Keycloak sets an id token's `aud` to the
client id of the requesting client. The second public client therefore
carries the registry audience as its client id,
`https://registry.127.0.0.1.sslip.io:5443`, and needs no audience mapper;
the token's `aud` is that one string. The test user's id is pinned in the
realm export, so zot's identity `iss + "/" + sub` is fixed, and the
harness zot grants `read` and `create` on exactly the repositories the
bootstrap lane and the integration tests push to. Measured on 2026-11-03
at `876fb38` by delegate spike against Keycloak 26.8.1 and zot 2.1.22;
GitHub Actions and GitLab CI both mint the same URL audience as one
string.
