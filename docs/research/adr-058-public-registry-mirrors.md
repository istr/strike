# Public OCI Registries as Distribution Layer for a Hidden-Primary FOSS Project (status: 31 Oct 2026)

None of the large free public registries (Docker Hub, GHCR, Quay.io, ECR Public, GitLab.com) can be configured to pull your images from an arbitrary external registry on a schedule. The only registries that do this natively are paid Harbor-based services (OVHcloud Managed Private Registry, 8gears, possibly STACKIT) and Google Artifact Registry remote repositories, which fetch on demand and bill you for egress. The best way to get "pull from primary" at no cost is a scheduled CI job run by the registry provider itself. GitHub Actions can push to GHCR with the ephemeral `GITHUB_TOKEN`, and GitLab CI can push to the GitLab.com registry with `CI_JOB_TOKEN`. The job reads anonymously from your zot primary and copies images, referrers included, by digest. Your forge then holds no write credential for any public registry.

## TL;DR
- **No free native pull replication exists.** Docker Hub, GHCR, Quay.io (hosted), ECR Public, GitLab.com, Scaleway and Codeberg only accept pushes. Harbor-based services (OVHcloud MPR, 8gears, STACKIT beta) have real scheduled pull replication but cost money. Google Artifact Registry remote repositories proxy lazily and you pay for egress. The closest no-cost equivalent is a scheduled CI job hosted by the provider (GitHub Actions -> GHCR, GitLab CI -> registry.gitlab.com). It pulls anonymously from the primary and authenticates to the target with a short-lived token the provider issues itself.
- **Recommended set for a security-focused FOSS CI/CD tool:**
  1. GHCR as primary public mirror, filled by an Actions cron job.
  2. GitLab.com registry as a second US mirror, filled by a scheduled pipeline.
  3. Quay.io (push, robot token) or Docker Hub only if you get DSOS, since anonymous Docker Hub pulls are capped at 100 per 6 h per IP.
  4. Scaleway public namespace as the best free EU option: 75 GB free, free egress, push-based with a scoped API key. OVHcloud MPR is the EU option if native pull replication is required (~ US$19.71/month, but connection caps).
- **For digest-pinned, signed images**, copy with a referrer-aware tool (`oras cp -r`, `regctl image copy --referrers`, `crane`) rather than relying on registry-side replication. Prefer cosign's tag-based signature layout (or publish both forms) so that signatures survive registries and replicators that don't walk the OCI 1.1 Referrers API. Harbor pull replication from non-Harbor sources is known to drop OCI 1.1 referrers.

## Key Findings

1. **Pull-from-origin is an enterprise or self-managed feature, not a public-registry feature.**
   - Quay's repository and organization mirroring is documented only for self-managed Red Hat Quay/Project Quay. It requires `FEATURE_REPO_MIRROR` in `config.yaml` and a separate mirroring worker, which hosted quay.io customers cannot provision.\[1\]
   - The quay.io user guide does not list mirroring as a plan feature. "Not available on quay.io" is an inference, not a sourced statement.
2. **Harbor's pull replication is real but imperfect for supply-chain metadata.**
   - Harbor docs state cosign signatures replicate with their artifact, but Harbor contributor wy65701436 stated in goharbor/harbor issue #19406 (4 Jan 2024): "Signature replication is currently limited to Harbor-to-Harbor scenarios."
   - A 2026 issue (#23210) reports that pull replication from a generic Docker Registry endpoint copies the image but misses OCI 1.1 referrers (cosign v3 bundles, attestations, SBOMs). Legacy `sha256-<digest>.sig` tags still come across.\[2\]
   - This matters directly for a zot primary, which Harbor would treat as a generic registry.
3. **Docker Hub's free anonymous tier is the weakest distribution point unless you are in DSOS.**
   - Anonymous pulls are limited to 100 per 6 hours per IPv4 address or IPv6 /64.\[3\]\[4\]
   - DSOS removes this: "Program members and all users pulling public images from the project namespace get access to unlimited pulls and unlimited egress."\[5\]
   - DSOS eligibility requires "no pathway to commercialization".\[5\]
4. **GHCR is the most generous free US option on paper.**
   - GitHub's billing docs state: "Container image storage and bandwidth for the Container registry is currently free," with at least one month's notice before any change. Public packages are free.\[6\]\[7\]
   - This is a policy, not a contract.
5. **ECR Public has a hard anonymous ceiling.**
   - Anonymous transfer is capped at 500 GB/month ("max amount of data supported and isn't adjustable"). After that, anonymous pulls are blocked, not billed.\[8\]\[9\]
   - Unauthenticated pulls are limited to 1 per second (non-adjustable).\[9\] Storage is free up to 50 GB.\[10\]
6. **The EU options are small-scale.**
   - Scaleway's public namespaces (free <=75 GB, free egress) are the only EU option that is genuinely free at meaningful scale.\[11\]
   - Codeberg works only as a small secondary mirror (1.5 GiB package quota by default).\[12\] It also has new ToU clauses restricting mostly-LLM-generated projects and banning cryptocurrency projects.\[13\]\[14\]
   - OVHcloud MPR includes unlimited traffic but caps concurrent connections at 15/45/90 by plan.\[15\]\[16\]

## Comparison Table

CLOUD Act exposure: "Yes" = US company or US-controlled parent.

| Provider | Entity / HQ / CLOUD Act | FOSS program | Anonymous delivery capacity | Native pull from external origin | Free/paid cost | Awareness | Supply-chain notes |
|---|---|---|---|---|---|---|---|
| **Docker Hub** | Docker, Inc., USA -- **Yes** | DSOS: OSI license, active (push within 6 months), no pathway to commercialization, 1-yr renewable\[17\] | 100 pulls/6 h per IPv4 or IPv6 /64 anonymously; **unlimited pulls + egress for DSOS namespaces**\[4\]\[5\] | **No** (push only) | Free public repos; paid plans per seat | **High** (default registry for unqualified names) | OCI artifacts and immutable tags documented; Referrers API support not verified here |
| **GHCR (ghcr.io)** | GitHub, Inc. (Microsoft), USA -- **Yes** | None needed; public packages free\[7\] | No published anonymous pull limit (unverified); storage and bandwidth "currently free"\[6\] | **No**; workaround: scheduled GitHub Actions with `GITHUB_TOKEN` | US$0 for containers (subject to 1-month notice)\[7\] | **High** | OCI artifacts; cosign tag-based signatures work; OCI 1.1 Referrers API support not verified |
| **Quay.io** | Red Hat (IBM), USA -- **Yes** | None needed; free tier is public-only\[18\] | "Unlimited storage and serving of public repositories"; no pull quota; per-IP request throttling ("a few requests per second")\[19\]\[20\] | **Not on hosted quay.io** (mirroring is a self-managed feature) | Free public; private plans 5-50 repos (prices unverified; third-party sources cite US$15-125/month)\[19\]\[21\] | **Medium** (CNCF/Red Hat ecosystem) | Robot accounts (scoped push tokens); referrer support not verified |
| **AWS ECR Public** | Amazon Web Services, USA -- **Yes** | No registry-specific FOSS program verified (AWS credits not verified) | 500 GB/month anonymous (hard cap, then blocked); 5 TB/month for AWS-authenticated pullers; 1 unauthenticated pull/s\[8\]\[9\] | **No** (pull-through cache is private-ECR only) | 50 GB storage free, then US$0.10/GB-month\[22\] | **Medium** | IAM-based push; OCI images |
| **Google Artifact Registry** | Google LLC, USA -- **Yes** | Google OSS credits not verified | Public via `allUsers` + Artifact Registry Reader; no free egress | **Yes, lazy:** *remote repository* with custom Docker upstream URI (credentials optional via Secret Manager); fetches and caches on first request | Paid (storage + internet egress); prices not verified here | **Low** for public distribution | Pull-through preserves manifests by digest (expected, not verified); referrer handling not verified |
| **GitLab.com registry** | GitLab Inc., USA -- **Yes** | GitLab for Open Source: Ultimate + 50,000 compute min/month; every project in namespace OSI-licensed and public (one private allowed for security); no selling services or add-ons; annual renewal | Public project images pull anonymously; container registry **excluded** from storage limit; served via Google Cloud Storage/CDN | **No**; workaround: scheduled pipeline + `CI_JOB_TOKEN` | Free tier usable; storage add-on US$5/10 GiB/month (doesn't apply to registry) | **Medium-low** | OCI images; referrer support not verified |
| **Azure Container Registry** | Microsoft, USA -- **Yes** | None verified | Anonymous pull supported only on Standard and Premium, not Basic (Microsoft Learn SKU table; a preview feature) | Import/artifact-cache features exist (unverified) | Basic US$0.167/day (Microsoft Learn); Standard ~US$0.667/day, Premium ~US$1.667/day (third-party trackers citing Azure's pricing page) | **Low** for FOSS distribution | OCI artifacts (unverified) |
| **Cloudsmith** | Cloudsmith Ltd., Belfast, UK -- possible US exposure via US operations (unverified) | OSS repos: >=50 GB storage + 200 GB delivery free; must be FOSS, maintainer-controlled, not a minor fork; **attribution link required** | 200 GB/month delivery by default; CDN | Upstream/proxy features exist; arbitrary OCI pull replication not verified | Paid plans; third-party source cites ~US$1.50/GB overage | **Low** | Strong supply-chain focus (vendor claim) |
| **JFrog** | JFrog Ltd. (Israel/US, Nasdaq) -- **Yes** | 2018-dated sponsorship terms still online; "temporary and revocable"; revocable "at any time and for any reason"; application status in 2026 **unverified**\[23\] | Unknown | Artifactory remote repos (enterprise) | -- | **Low** for this use | -- |
| **Scaleway** | Scaleway SAS (Iliad group), Paris, France -- **No** | None needed | Public images: storage free up to 75 GB, outgoing transfer free; anonymous rate limits **not documented** | **No** | Private EUR 0.027/GB-month; regions fr-par, nl-ams, pl-waw | **Low** | OCI artifact/referrer support not verified |
| **Codeberg (Forgejo packages)** | Codeberg e.V., Berlin (non-profit) -- **No** | Free for FOSS; ToU bans crypto projects and restricts mostly-LLM-generated projects (July 2026) | 1.5 GiB packages/LFS/attachments default quota (more on request); no CDN\[12\] | **No**; Forgejo Actions cron is a possible workaround (token scope unverified) | Free (donations)\[12\] | **Low** | Forgejo OCI registry; referrer support not verified |
| **OVHcloud Managed Private Registry** | OVH Groupe SA, Roubaix, France -- **No** for EU entity | None | **All traffic free/unlimited**, but 15/45/90 concurrent connections (S/M/L); Harbor public projects allow anonymous read (OVH-specific setting not verified) | **Yes, native** Harbor pull replication (scheduled/cron, filters) | S 200 GiB ~US$19.71/mo; M 600 GiB ~US$44.75; L 5 TiB ~US$212.43 (excl. VAT) | **Low** | Harbor 2.15.1; cosign signing supported; OCI 1.1 referrers lost on pull replication from non-Harbor sources |
| **8gears Container Registry** | 8gears, Switzerland -- **No** (but an AWS/Cloudflare-hosted variant exists, which is exposed) | None verified | No traffic fees (vendor claim) | **Yes** (Harbor) | From ~US$249/month (third-party); Exoscale usage-based | **Low** | Harbor; run by Harbor maintainers |
| **STACKIT Container Registry** | STACKIT (Schwarz Group), Germany -- **No** | None | Unknown | Replication listed as a feature (details unverified) | Free during beta since 27 Jun 2025; pay-per-use planned | **Very low** | Beta; robot/service-account mapping added July 2026 |

## Details per provider

### Docker Hub
- **Entity:** Docker, Inc. (US). CLOUD Act applies.
- **Limits:** Anonymous users get 100 pulls per 6 h per IPv4 or IPv6 /64. Personal accounts get 200 per 6 h. Paid plans are unlimited (fair use).\[24\] A separate abuse limit of "thousands of requests per minute" per IP applies to everyone.\[3\]
- **Earlier announcements:** Docker announced 10 pulls/hour (anonymous) for 2025 but did not enforce it.\[25\] Docker's FAQ pages reportedly still print the hourly figures, while the docs table shows the 6-hour figures. Treat the docs table as authoritative, but this inconsistency is a risk.\[26\]
- **DSOS benefits:**
  - Unlimited pulls and egress for *all* users pulling the namespace.\[5\]
  - Badge, insights and analytics, Docker Scout on up to 100 repositories.\[5\]\[27\]
  - A one-year Docker Team subscription for core contributors.\[28\]
- **DSOS eligibility:**
  - Public repositories with publicly accessible source code.\[5\]\[17\]
  - OSI definition.\[5\]\[17\]
  - Active development "on Docker Hub", meaning image updates within the past 6 months.\[17\]
  - No pathway to commercialization.\[5\] Donations are allowed; commercial funding is allowed if there is no commercialization path, re-evaluated yearly.\[28\]\[29\]
  - The Hub description must link to the source repository and contributing guidelines.\[17\]
- **DSOS terms:**
  - Benefits go only to project leads and core committers.\[29\]
  - They may be used "solely for developing non-commercial open-source projects".\[29\]
  - Paid Docker subscriptions and DSOS are mutually exclusive. The CNCF blog's DSOS guide for maintainers (15 Jan 2026) says a project that "currently pays for a subscription... must transition off that plan before you can join the DSOS program."
- **No AI clause found.**
- **Replication:** Push only. Docker Hub has no inbound mirroring from external registries. Its "automated builds" are deprecated.
- **Credential reality:** Something outside Docker must hold a Docker Hub organization access token. There is no Docker-hosted scheduler to borrow.

### GitHub Container Registry
- **Entity:** GitHub, Inc., owned by Microsoft. CLOUD Act applies.
- **Cost and limits:** Storage and bandwidth are "currently free" with >=1 month notice of change. Public packages are free on all plans.\[6\] No published pull rate limit (third-party sources only; treat as unverified).\[6\]\[7\]
- **Hidden-primary workaround:** A public "mirror" repository with a `schedule:` workflow:
  1. Run `oras cp -r` / `regctl image copy --referrers` / `crane cp` from `primary.example.org` (anonymous read) to `ghcr.io/<org>/<image>`.
  2. Authenticate to GHCR with the job's `GITHUB_TOKEN` (`packages: write`).
- **What this gives you:**
  - Your forge holds no GHCR secret.
  - The write credential is minted per job by GitHub and expires with the job.
  - Copying by digest preserves manifests byte-for-byte, so digests stay identical.
- **Trade-offs:**
  - Trust moves to GitHub's runner and the workflow file. Pin actions by SHA and protect the default branch.
  - Cron cadence adds latency.
  - GitHub Docs ("Events that trigger workflows") state: "In a public repository, scheduled workflows are automatically disabled when no repository activity has occurred in 60 days." Plan a keep-alive or `workflow_dispatch`.
  - The primary must be reachable from GitHub's runners. "Hidden" here means not advertised to users, not network-isolated.

### Quay.io
- **Entity:** Red Hat (IBM). CLOUD Act applies.
- **Free tier:**
  - Public repositories only.\[18\]
  - "Unlimited storage and serving of public repositories."\[19\]
  - Anonymous pulls of public images allowed.\[18\]
  - Red Hat says it "does not restrict anonymous pulls" and only rate-limits severe abuse ("a few requests per second per IP", HTTP 429).\[20\]\[30\]
- **Repository gotcha:** Create repositories as public in the UI first. A CLI push to a non-existent repo creates a *private* one.\[18\]
- **Credentials:** Robot accounts give narrowly scoped push tokens.\[18\] This is the best push-credential hygiene among the push-only registries.
- **Pull mirroring:** Documented only for self-managed Quay (repo and org mirroring with sync intervals, tag filters, Harbor/Quay source types; deletions not replicated).\[31\]\[32\] Not established for quay.io.
- **Pricing:** Plan prices could not be fetched from quay.io/plans (unverified).

### AWS ECR Public
- **Entity:** Amazon Web Services. CLOUD Act applies.
- **Quotas:**
  - 50 GB storage always free.\[10\]
  - Anonymous: 500 GB/month, not adjustable. Anonymous pulls stop after the cap.\[8\]\[9\]
  - AWS-authenticated pullers: 5 TB/month free.\[8\]
  - Unauthenticated pull rate: 1/s.\[9\]
  - Layer max 10,000 MiB; 100,000 images per repository.\[9\]
- **Replication:** Push via IAM. A cross-cloud OIDC role assumption is possible but still a credential outside the provider. No ECR-native pull from arbitrary registries into a *public* repository.
- **Programs:** An AWS open-source credits program was not verified.
- **Best use:** A capacity-limited secondary mirror.

### Google Artifact Registry
- **How it works:** The only hyperscaler feature that matches "public registry pulls from origin":
  - A Docker-format *remote repository* takes a custom upstream URI (`--remote-docker-repo=https://my.registry`), with optional username plus a Secret Manager password.\[33\]
  - It caches on first request.\[34\]
  - Repositories can be made public with `allUsers` -> Artifact Registry Reader.\[35\]
- **Caveats:**
  - Lazy, not scheduled. The primary sees cache-miss traffic triggered by end users.
  - You pay storage and internet egress. Google credit programs were not verified.
  - Other Artifact Registry repositories are not accepted as custom upstreams.\[36\]
  - Whether referrers and signatures are fetched through the proxy was not verified.
- **CLOUD Act:** Applies (Google LLC).

### GitLab.com
- **Entity:** GitLab Inc. CLOUD Act applies.
- **GitLab for Open Source:**
  - Ultimate plus 50,000 compute minutes/month.\[37\]
  - Every project in the namespace OSI-licensed; namespace public (one private project allowed for security).\[38\]
  - Donations are fine, but you may not "make a profit by selling services, charging for enhancements or add-ons".\[39\]
  - Annual re-application. Governed by the GitLab for Open Source Program Agreement.\[40\]
  - **The OSS program is not needed for registry use**, because the container registry is not counted in the storage limit.\[41\]
- **Delivery:** Images are served from Google Cloud Storage/CDN.\[42\]
- **Hidden-primary workaround:** A scheduled pipeline copies from the primary anonymously and pushes with `CI_JOB_TOKEN`. This is the same credential profile as GHCR.

### Cloudsmith, JFrog, Azure
- **Cloudsmith OSS:**
  - At least 50 GB storage and 200 GB delivery per month.\[43\]
  - Requires a FOSS project, maintainer control, not a minor fork, and a visible attribution link to Cloudsmith.\[43\]
  - 200 GB/month is too little to be a primary distribution point. An older Cloudsmith doc page still says 10 GB/100 GB; the pricing page (50/200) is the more recent source.\[44\]\[45\]
- **JFrog:**
  - The sponsorship terms are dated 2018. Benefits are "temporary and revocable", terminable "for convenience, at any time and for any reason", and liability is capped at US$100.\[23\]
  - Whether applications are still accepted is unverified.
- **Azure:**
  - ACR has no FOSS program. Microsoft Learn's SKU table lists anonymous pull access as "N/A" on Basic and "Supported" on Standard and Premium, and describes it as a preview feature.

### European options
- **Scaleway:**
  - French company (Iliad), not subject to the CLOUD Act.
  - Public-image storage is free up to 75 GB, and the price table lists outgoing transfer for public images as free.\[46\]
  - Anonymous pull rate limits, CDN coverage and OCI referrers support are **undocumented/unverified**. Test `oras discover`, cosign, and digest pulls before relying on it.
  - Push-only. Use an IAM API key scoped to the registry namespace.
- **Codeberg:**
  - Non-profit, German.
  - Default quota is 1.5 GiB for packages;\[12\] Codeberg says "no quota for valid use-cases" but reserves the right to deny service for unreasonable usage.\[13\]
  - July 2026 ToU: content mostly generated by LLM tools is restricted; cryptocurrency projects are banned.\[47\]\[48\]
  - A security CI/CD tool should check its own contribution policy against the LLM clause.
  - Suitable only as a small EU fallback.
- **OVHcloud MPR:**
  - Harbor 2.15.1, with native scheduled pull replication from external registries.\[49\]
  - Traffic is unlimited and free, but the plan caps of 15/45/90 concurrent connections make it a poor high-fan-out public endpoint.\[15\]\[16\]
  - No FOSS program. OVH's support for public (anonymous) Harbor projects on MPR was not confirmed.
- **8gears:**
  - Swiss, Harbor-based, no traffic fees. The entry price is reported at ~US$249/month (third-party).\[50\]\[51\]
- **STACKIT:**
  - German, beta, free during beta.\[52\]\[53\] Public anonymous access and replication specifics are unverified.

## The "hidden primary / pull from origin" model

| Approach | Where it runs | Credential outside forge->primary | Attestations/referrers | Verdict |
|---|---|---|---|---|
| Harbor pull replication (OVH, 8gears, STACKIT?) | Registry provider | Optional (anonymous read on zot works) | Legacy cosign `.sig` tags copied as plain tags; **OCI 1.1 referrers dropped** from non-Harbor sources\[2\] | True AXFR analogue, but paid and lossy for referrers |
| GAR remote repository | Google | Optional read creds in Secret Manager | Unverified | Lazy proxy; paid egress |
| GitHub Actions cron -> GHCR | GitHub | **None** (ephemeral `GITHUB_TOKEN`) | Full, if you copy with a referrer-aware tool | **Best no-cost option** |
| GitLab CI schedule -> registry.gitlab.com | GitLab | **None** (`CI_JOB_TOKEN`) | Full, as above | Second-best no-cost option |
| Forgejo Actions cron -> Codeberg | Codeberg | Probably automatic token (unverified) | As above | Small-scale EU fallback |
| Forge CI pushes everywhere | Your forge | **One write token per registry** | Full | Acceptable fallback (Docker Hub, Quay, ECR Public, Scaleway) |

**Credential and attestation trade-offs:**
- Provider-hosted cron jobs replace "forge holds N secrets" with "N providers each hold a write token they mint themselves". That is the closest practical equivalent of AXFR.
- The security boundary becomes each provider's workflow-file integrity. A compromised mirror repository could push arbitrary images, but it cannot forge your cosign signatures. Users who verify signatures against the primary's signing identity are protected.
- Always copy by digest, and verify after the copy that `HEAD /v2/<name>/manifests/<digest>` matches on every mirror.
- Publish signatures and attestations so they survive registries with incomplete OCI 1.1 support. Use cosign's tag-based layout, or both forms. Referrer-only attestations may vanish on registries or replicators that don't implement the Referrers API.

## Recommendations (security-focused FOSS CI/CD tool)
1. **GHCR**, filled by a scheduled Actions job in a dedicated mirror repository (anonymous read from zot, `GITHUB_TOKEN` write, `regctl image copy --referrers` or `oras cp -r`). Best overall: free, high awareness, and no external credential.
2. **GitLab.com registry**, filled by a scheduled pipeline using `CI_JOB_TOKEN`. Gives provider diversity on a different CDN (Google Cloud) with the same credential profile.
3. **Quay.io** (push, robot token scoped to the repositories). Free and unlimited for public images. Accept one scoped secret in the forge, or run the push from the GHCR mirror workflow and keep the robot token in GitHub secrets.
4. **Docker Hub only if accepted into DSOS.** Without DSOS, anonymous users hit 100 pulls/6 h per IP, which would be a support burden.\[54\] Apply if your project truly has no commercialization path.
5. **ECR Public** optional, as a capped (500 GB/month anonymous) extra mirror.
6. **Best EU option:** **Scaleway public namespace** (free <=75 GB, free egress, not exposed to the CLOUD Act). It is push-based with one namespace-scoped key; run the push from your forge or from the GitLab/GitHub mirror job. If native pull replication is a hard requirement, use **OVHcloud MPR (M plan, ~US$44.75/month)** with a scheduled Harbor pull rule from zot. Accept that OCI 1.1 referrers won't replicate (push them separately) and that connection caps limit it to a secondary endpoint. Codeberg is a small, free second EU mirror if your project complies with its LLM clause.
7. Document all mirrors as `@sha256:` references in release notes, and tell users to verify cosign signatures, not registry identity.

## Providers examined but excluded or deprioritised
- **JFrog:** The OSS sponsorship is of uncertain 2026 status and revocable at will. Artifactory is enterprise-oriented.
- **Azure Container Registry:** No FOSS program. Anonymous pull needs paid tiers.
- **Cloudsmith OSS:** 200 GB/month delivery is too small for primary distribution, and it requires attribution. Usable as a minor mirror.
- **Google Artifact Registry:** The only native origin-pull at a hyperscaler, but egress is billed to you. Excluded under the "don't pay" rule unless credits are obtained.
- **8gears / STACKIT:** 8gears is paid at a high entry price. STACKIT is still in beta with undocumented public-access terms.
- **Self-hosted Harbor/zot mirrors:** Out of scope by definition.

## Caveats
- Quay.io plan prices, GHCR/GitLab anonymous rate limits, Scaleway/Codeberg anonymous limits, OCI 1.1 Referrers API support per registry, AWS/Google credit programs, Cloudsmith's corporate structure and JFrog's 2026 program status could not be verified from primary sources in this pass.
- GHCR's "currently free" status is a revocable policy. Docker's own pages disagree on rate-limit figures.
- Harbor digest preservation during replication is expected (manifests are copied verbatim) but not explicitly documented.
- Several prices come from third-party trackers (Azure, 8gears, Cloudsmith overage) and should be re-checked before budgeting.

## Quellen

1. [Chapter 8. Repository mirroring](https://docs.redhat.com/en/documentation/red_hat_quay/3.12/html/manage_red_hat_quay/repo-mirroring-in-red-hat-quay)
2. [OCI 1.1 referrers (Cosign v3 signatures/SBOMs) are not replicated from Artifactory to Harbor - Issue #23210 - goharbor/harbor - GitHub](https://github.com/goharbor/harbor/issues/23210)
3. [Docker Hub usage and limits](https://docs.docker.com/docker-hub/usage/)
4. [How to Fix Docker 'Too Many Requests' Rate Limit Errors](https://oneuptime.com/blog/post/2026-02-08-how-to-fix-docker-too-many-requests-rate-limit-errors/view)
5. [Docker-Sponsored Open Source Program](https://docs.docker.com/docker-hub/repos/manage/trusted-content/dsos-program/)
6. [Top 8 Container Registries for 2026: Pull Rate Limits, Retention, Scanning, and Egress Priced](https://guptadeepak.com/tools/top-8-container-registries-2026/)
7. [How use of GitHub Packages is measured](https://docs.github.com/en/billing/concepts/product-billing/github-packages)
8. [Understanding data transfer costs for AWS container services](https://aws.amazon.com/blogs/containers/understanding-data-transfer-costs-for-aws-container-services/)
9. [Amazon ECR Public service quotas - Amazon ECR Public](https://docs.aws.amazon.com/AmazonECR/latest/public/public-service-quotas.html)
10. [Amazon ECR Public Free Tier 2026: Limits, Pricing & What Changed](https://agentdeals.dev/vendor/amazon-ecr-public)
11. [Containers Pricing](https://www.scaleway.com/en/pricing/containers/)
12. [Codeberg: A Community-Owned Future for Open Source](https://laoutaris.org/blog/codeberg/)
13. [Frequently Asked Questions](https://docs.codeberg.org/getting-started/faq/)
14. [Codeberg.org](https://codeberg.org/)
15. [Price list: A comparison of our Public Cloud offers](https://www.ovhcloud.com/en/public-cloud/prices/)
16. [FAQ Managed Private Registry (MPR) - OVHcloud Documentation](https://docs.ovhcloud.com/en/guides/public-cloud/containers-orchestration/managed-private-registry/managed-private-registry-faq)
17. [Apply Today - Docker-Sponsored Open Source Program](https://docker.p2hp.com/community/open-source/application/index.html)
18. [About Quay IO](https://docs.projectquay.io/quay_io.html)
19. [Quay.io Help/Support Page - Red Hat Customer Portal](https://access.redhat.com/articles/quayio-help)
20. [Quay.io rate limiting - Red Hat Customer Portal](https://access.redhat.com/solutions/6218921)
21. [How to Choose a Container Registry: The Top 9 Picks - Bluelight](https://bluelight.co/blog/how-to-choose-a-container-registry)
22. [AWS ECR Pricing: Container Registry Costs - Wring.co](https://wring.co/blog/aws-ecr-pricing-guide)
23. [JFrog Open Source Sponsored Projects](https://jfrog.com/jfrog-open-source-sponsored-projects/)
24. [Docker Hub's Unauthenticated Pull Limits Are Still 100/6hr: When a Self-Hosted Registry Actually Pays Off](https://bex.co/blog/2026/07/31/docker-hub-pull-limits-self-hosted-registry)
25. [Revisiting Docker Hub Policies: Prioritizing Developer Experience](https://www.docker.com/blog/revisiting-docker-hub-policies-prioritizing-developer-experience/)
26. [Docker Hub pull rate limits by plan (Docker rule)](https://wiki.licenseware.io/catalog/rules/docker-docker-hub-pull-rate-limits-by-plan/)
27. [Programme Docker-Sponsored Open Source](https://docker.ubitools.com/docker-hub/repos/manage/trusted-content/dsos-program/)
28. [The Docker-Sponsored Open Source Program has a new look!](https://www.docker.com/blog/docker-sponsored-open-source-program-has-a-new-look/)
29. [Apply Today - Docker-Sponsored Open Source Program](https://www.docker.com/community/open-source/application/)
30. [DockerHub and Quay.io returning 429 due to rate limits](https://support.sonatype.com/hc/en-us/articles/32093607704723-DockerHub-and-Quay-io-returning-429-due-to-rate-limits)
31. [Manage Project Quay](https://docs.projectquay.io/manage_quay.html)
32. [Chapter 7. Mirroring images with Red Hat Quay](https://docs.redhat.com/en/documentation/red_hat_quay/3/html/manage_red_hat_quay/arch-mirroring-intro)
33. [docs.cloud.google.com](https://docs.cloud.google.com/sdk/gcloud/reference/artifacts/repositories/create?authuser=00)
34. [remote repo](https://cloud.google.com/artifact-registry/docs/repositories/remote-repo)
35. [Publish a Docker container image to Google Artifact Registry (GAR)](https://support.terra.bio/hc/en-us/articles/360035638032-Publish-a-Docker-container-image-to-Google-Artifact-Registry-GAR)
36. [Using another GCP project's Artifact Registry as the upstream for a remote repo - Issue #46 - GoogleCloudPlatform/terraform-google-artifact-registry - GitHub](https://github.com/GoogleCloudPlatform/terraform-google-artifact-registry/issues/46)
37. [Community programs](https://docs.gitlab.com/ee/subscriptions/community_programs.html)
38. [Community programs](https://docs.gitlab.com/subscriptions/community_programs/)
39. [GitLab San Francisco -- How to Apply](https://www.startupgrantsindia.com/providers/gitlab)
40. [Join the GitLab for Open Source Program](https://about.gitlab.com/solutions/open-source/join/)
41. [storage usage quotas](https://docs.gitlab.com/user/storage_usage_quotas)
42. [GitLab.com settings](https://docs.gitlab.com/user/gitlab_com/)
43. [Open-source hosting policy](https://help.cloudsmith.io/docs/open-source-hosting-policy)
44. [Developer community](https://docs.cloudsmith.com/developer-tools/developer-community)
45. [Cloudsmith Pricing](https://cloudsmith.com/pricing)
46. [Container Registry FAQ](https://www.scaleway.com/en/docs/faq/containerregistry/)
47. [Codeberg writes cryptocurrency projects into its terms as reputation harm - freenode](https://ingest.freenode.net/article/codeberg-writes-cryptocurrency-projects-into-its-terms-as-reputation-harm)
48. [Codeberg: The Non-Profit GitHub Alternative](https://codetocloud.io/blog/codeberg-github-alternative/)
49. [FAQ Managed Private Registry (MPR) - OVHcloud Documentation](https://help.ovhcloud.com/csm/en-public-cloud-private-registry-faq?id=kb_article_view&sysparm_article=KB0050360)
50. [Container Registry - Harbor-based Container Image Management](https://www.exoscale.com/marketplace/listing/container-registry/)
51. [Best Government Container Registries of 2026 - Reviews & Comparison](https://sourceforge.net/software/container-registries/for-government/)
52. [STACKIT Container Registry - Secure Image Management - innFactory - Software Development, Cloud & AI](https://innfactory.de/en/cloud/stackit/products/container-registry/)
53. [Container Registry](https://docs.stackit.cloud/products/developer-platform/container-registry/)
54. [Docker Hub pull usage and limits](https://docs.docker.com/docker-hub/usage/pulls/)
