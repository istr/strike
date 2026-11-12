# Publication Target for strike Releases: Registry Measurements (status: 2026-11-12)

This document records the measurements behind the publication model that
the ADR-058 amendment of 2026-11-12 ratifies. The subject is where strike's
release candidate is published and how a verifier reaches it.

The registries measured are:

- Google Artifact Registry (GAR);
- Azure Container Registry (ACR);
- quay.io;
- zot at the version the local sigstore harness pins.

The measurements were taken between 2026-10-29 and 2026-11-12. Every probe
was a throwaway: it changed no tracked file and was removed after its run.
The cloud objects named below were created for these measurements only.

## Summary

- **Retention without a tag.** quay.io collected a tagless payload within
  18.5 hours, and zot collects one at its first garbage-collection run
  after the delay. GAR and ACR kept tagless payloads and their referrers
  for more than eight days. In both quay.io and zot, the tagless referrer
  outlives its subject.
- **Retention with a tag.** A tag of the form `strike-<64 hex>` (71
  characters) is accepted by quay.io and zot. zot keeps a subject that
  carries it, together with the subject's untagged referrers.
  quay.io kept such a subject and its five untagged referrers through
  every reading, the last at t0 + 58 h 54 min.
- **Pull-through caches do not serve referrers.** The GAR remote
  repository answered the referrers API with `"manifests":null` in every
  state measured. The ACR artifact cache accepts only a fixed list of
  upstreams.
- **cosign verifies strike's bundles on all three public registries.**
  `cosign verify-attestation` v3.1.4, anonymous and flag-clean with the
  claims check on, verifies the sealed, engine-dependent and
  informational predicate layers on GAR, ACR and quay.io. A wrong
  identity fails on each.
- **Blob redirects.**
  - GAR redirects large blob GETs to its own host.
  - ACR redirects every blob GET except a 2-byte config to a storage host.
  - quay.io redirects even a 36-byte blob GET to `cdn01.quay.io`.
- **The token realm.** All three public registries keep the realm on the
  registry host.
- **The private-to-public flip.** GAR and ACR both make a repository
  readable anonymously without a re-push.

## Method and scope

Each run used one of three kinds of objects:

- real strike deployments, made by the registry-deploy integration path
  against the local sigstore harness and copied by digest;
- payloads with subject-bearing referrers in strike's referrer form, with
  an explicit manifest `artifactType`;
- random OCI payloads, in the garbage-collection runs.

Reads went through go-containerregistry v0.21.x with the referrers tag
fallback off, through `curl` on the operator's host, and through cosign
v3.1.4.

| Run | Date | Tree | Registries |
|---|---|---|---|
| Survey of public candidates | 2026-10-29 to 2026-10-31 | `1344ed5` | quay.io, GAR, ACR |
| Redirect probe | 2026-11-05 | `060225f` | GAR, ACR |
| Retention and flip readings on the host | 2026-11-08 | -- | GAR, ACR |
| Pull-through cache | 2026-11-09 | `2a52c3e` | GAR remote repository, upstream ACR |
| ACR artifact-cache rule | 2026-11-09 | -- | ACR |
| cosign on cloud registries | 2026-11-09 | `2a52c3e` | GAR, ACR, harness control |
| quay.io with referrer form and tag | 2026-11-09 | `2a52c3e` | quay.io, harness control |
| zot garbage collection | 2026-11-09 | `2a52c3e` | two zot-minimal v2.1.22 containers |
| quay.io retention with the tag | 2026-11-10 to 2026-11-12 | -- | quay.io |

GAR ran in `europe-west4`, as a standard repository with the `allUsers`
reader binding. ACR ran as the Standard SKU with anonymous pull enabled.
quay.io ran as a public repository of an organization, written with an
organization robot. zot ran as the harness pin
`zot-minimal-linux-amd64:v2.1.22`, on podman 5.4.2.

## Retention

### Tagless payloads

- **quay.io.** A tagless payload was collected within 18.5 hours. Its
  tagless referrer survived the subject.
- **GAR.** The payload and its referrers were present at t0 + 219 h 30 min,
  with their original upload times unchanged. No cleanup policy was set.
- **ACR Standard.** The payload and its referrers were present at
  t0 + 204 h 50 min, with `createdTime` equal to `lastUpdateTime` at t0.
  The retention policy reads `disabled`, and retention policies exist
  for Premium only.

### zot v2.1.22

Two throwaway containers ran with gcDelay and gcInterval set to one
minute and otherwise default settings. The variant `keep` added a
retention policy for `**` with `deleteUntagged` and `deleteReferrers`
false. Readings were taken at +0, +3, +6, +10 and +20 minutes after the
push.

- **Default retention.**
  - A tagless payload was removed at t_push + 3 min 17 s with
    `"reason":"deleteUntagged"`, although a tagless referrer names it as
    its subject. A control payload without a referrer was removed at
    t_push + 2 min 47 s.
  - Removal happens at the first per-repository run after the payload is
    older than the retention delay. The retention delay equals gcDelay
    when `retention.delay` is not set.
- **What stays.** Through 20 minutes, under default retention:
  - the referrer of the removed payload;
  - a payload under a plain tag;
  - a payload carrying `strike-<64 hex of its digest>`;
  - the untagged referrer of that payload. Its referrers listing was
    unchanged at every reading.
- **Dangling referrers.** After the payload was removed, zot kept
  answering its referrers listing with 200 and the dangling referrer.
- **The keep variant.** Nothing was removed, and zot logged no
  untagged-manifest decision.
- **Source reading confirmed.** The reading of
  `pkg/storage/gc/gc.go`, `pkg/retention/retention.go`,
  `pkg/api/config/config.go` and `pkg/cli/server/root.go` at the tag is
  confirmed on every point the runs exercise:
  - a manifest that carries a `subject` is marked as referenced, while
    its subject is not;
  - untagged deletion is on without a policy;
  - referrer deletion is off.
- **Defaults not measured.** The default one-hour delays
  (`pkg/storage/constants/constants.go`) are read from source.
- **Media type.** zot-minimal without `http.compat` refuses a Docker
  schema 2 manifest with 415, so payloads are pushed as OCI images.

### quay.io with the retention tag

t0 is `2026-11-09T21:50:01Z`, the moment the tag was written. The
repository holds a subject that carries the tag and five tagless
referrers: two SBOMs and three statement bundles.

| Reading | Time | Subject | Referrers by digest | Listing | Tag list |
|---|---|---|---|---|---|
| intermediate | 2026-11-10T08:36:32Z (t0 + 10 h 47 min) | 200 | 5 of 5 at 200 | all five | the retention tag |
| t0 + 25 h | 2026-11-10T23:14:06Z (t0 + 25 h 24 min) | 200 | 5 of 5 at 200 | all five | the retention tag |
| t0 + 49 h | 2026-11-12T08:44:01Z (t0 + 58 h 54 min) | 200 | 5 of 5 at 200 | all five | the retention tag |

The intermediate reading does not separate tagged from tagless
retention, because the tagless payload above was collected only within
18.5 hours.

## Private-to-public flip without re-push

- **GAR.** After the `allUsers` reader binding is added to the
  repository, every object reads anonymously without a challenge, as
  written at t0.
- **ACR.** Anonymous pull is registry-wide and exists on Standard and
  Premium. After it is enabled, every object reads anonymously after a
  same-host token exchange without credentials.
- **Downscoping.** Both registries answer an anonymous token request for
  `push,pull` with 200, downscoped to pull.

## Pull-through caches

### GAR remote repository, upstream ACR

- **Content.** The path maps one to one. Manifests and blobs are
  byte-identical by digest, and GAR serves the blobs without a redirect.
- **Referrers.** The referrers API answered 200 with `"manifests":null`
  in every state measured, also for strike's exact referrer form:
  - before any pull;
  - after the subject and its referrers were pulled through;
  - at +1 h 02 min;
  - after the origin deleted the payload.

  go-containerregistry's filtered read returns zero descriptors and no
  error.
- **After deletion at the origin.** ACR removed the subject, its
  referrers and their blobs. The cache kept serving all of them (one
  reading, +1 minute).

### ACR artifact cache

A cache rule with a custom upstream is refused with
`UpstreamNotSupported`. The accepted upstreams are:

- docker.io, dhi.io, quay.io, public.ecr.aws, ghcr.io, nvcr.io;
- registry.k8s.io, gcr.io, eu.gcr.io, `*.pkg.dev`;
- registry.redhat.io, registry.access.redhat.com;
- reg.echohq.com, mcr.microsoft.com.

## Referrers API and `artifactType`

- **Digest-only writes create no tag.** A digest-only push of a payload
  with subject-bearing referrers creates no tag on zot, quay.io, GAR or
  ACR. Every one of them answered the referrers API during the write.
- **The derived `artifactType`.** quay.io and GAR do not surface a
  derived `artifactType` in the referrers descriptor; ACR and zot derive
  it.
- **The explicit `artifactType`.** quay.io and GAR serve the explicit
  manifest field. quay.io surfaces it in the unfiltered and the filtered
  listing. It applies the filter server side (`OCI-Filters-Applied:
  artifactType`) and returns exactly the three statement bundles, and
  go-containerregistry's filtered read returns 3.
- **Index annotations on quay.io.** quay.io adds a top-level
  `annotations` map to the referrers index, assembled from the referrers'
  annotations. Each descriptor keeps its own annotations. The order of
  the descriptors differs from zot's.
- **ACR invalidation.** ACR invalidates its referrers listing on every
  subject-bearing write.

## cosign verification

The command was `cosign verify-attestation` v3.1.4. It ran anonymously,
with an empty Docker configuration, against the trusted root published
by the harness, the builder identity and the issuer, and with no other
flag. The subject was a real strike deployment, copied by digest with all
its referrers.

| Subject | sealed | engine-dependent | informational | wrong identity |
|---|---|---|---|---|
| harness control | verified | verified | verified | exit 1 |
| GAR | verified | verified | verified | exit 1 |
| ACR | verified | verified | verified | exit 1 |
| quay.io | verified | verified | verified | exit 1 |

Each verifying run printed exactly one attestation, with the requested
predicate type. Each wrong-identity run found the bundles and rejected
them on the certificate identity.

## Redirects

- **GAR.** A 32 MiB blob GET is redirected to GAR's own host, with the
  bearer carried. A 1 KiB blob GET is not redirected.
- **ACR.** Every blob GET except the 2-byte empty config is redirected to
  a storage host (`*.blob.core.windows.net`, a SAS URL) without the
  bearer. This includes a 21-byte bundle layer.
- **quay.io.** An anonymous GET of a 36-byte bundle layer answers 302 to
  `cdn01.quay.io`, a presigned URL under `quayio-production-s3/`. The
  same GET with a credential is not measured.
- **What is not redirected.** No registry redirected a write, a manifest
  request, a referrers request or the ping.

## Token exchange shapes and realms

| | Realm | Exchange measured |
|---|---|---|
| quay.io | `https://quay.io/v2/auth` | robot federation on the registry host, `GET /oauth2/federation/robot/token` with HTTP Basic `<org>+<robot>:<OIDC token>`, one-hour token |
| GAR | `https://<region>-docker.pkg.dev/v2/token` | registry token opaque, 12 h, obtained at the realm with a one-hour access token as Basic `oauth2accesstoken`; STS answers OAuth JSON errors |
| ACR | `https://<name>.azurecr.io/oauth2/token` | registry token a JWT of 75 min; Entra answers OAuth JSON with `error_codes`; `/oauth2/exchange` answers registry JSON labelled `text/plain` |

The GAR and ACR exchange shapes were measured with invalid assertions
only.

## Terms and cost (read 2026-11-09 and 2026-11-10)

- **quay.io.** Public repositories are free, and paid plans are for
  private repositories. Red Hat's announcement of 2023-04-10 defines
  excessive use as more than 100 GB of stored image layers or more than
  1 TB of downloads, both per month, for which quota limits may apply.
- **GAR.**
  - Storage has a free tier of 0.5 GiB per billing account and is priced
    the same for regional and multi-regional repositories.
  - Internet egress is billed per GiB delivered from the repository, to
    the billing account. The pricing page names no exception for public
    repositories or unauthenticated downloads.
  - The access-control documentation recommends capping per-user request
    quotas against misuse by unauthenticated users.
- **ACR.** Anonymous pull requires the Standard or Premium SKU, at a
  fixed price per registry, plus egress (Azure portal and ACR
  documentation, read 2026-11-08).

## Geo-replication

- **quay.io.** The service offers no choice of location, and its
  topology is not publicly documented. For the product Red Hat Quay,
  geo-replication shares one database for all metadata (manifests, tags,
  referrers) and replicates blob storage asynchronously, falling back to
  the source storage until a blob is replicated. That quay.io runs this
  way is not established.
- **GAR.** The location is chosen when the repository is created. The
  regional `europe-west4` was used here; multi-region locations exist.
- **ACR.** Geo-replication is a Premium feature. It was not used.

## Not measured

- A real federated exchange from a forge:
  - quay.io robot federation with a forge-minted token;
  - whether GAR accepts an STS token at its realm without
    service-account impersonation;
  - the lifetimes these exchanges yield.
- quay.io blob GETs carrying a credential.
- The default one-hour garbage-collection delays of zot.

## Sources

- go-containerregistry v0.21.x: `pkg/v1/remote/referrers.go`,
  `pkg/v1/remote/transport/bearer.go`.
- project-zot/zot at tag `v2.1.22`: `pkg/storage/gc/gc.go`,
  `pkg/retention/retention.go`, `pkg/api/config/config.go`,
  `pkg/cli/server/root.go`, `pkg/storage/constants/constants.go`.
- Google Cloud, "Artifact Registry pricing",
  https://cloud.google.com/artifact-registry/pricing (read 2026-11-10).
- Google Cloud, "Configure access control",
  https://docs.cloud.google.com/artifact-registry/docs/access-control
  (read 2026-11-10).
- Red Hat, "Reintroducing Quay.io" (2023-04-10),
  https://www.redhat.com/en/blog/reintroducing-quay.io-welcome (read
  2026-11-10).
- Red Hat Quay 3.14, "Geo-replication",
  https://docs.redhat.com/en/documentation/red_hat_quay/3.14/html/red_hat_quay_operator_features/georepl-intro
  (read 2026-11-09).
- Spike and host reports of the runs in the table above (ephemeral, not
  committed).
