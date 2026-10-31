# Separating the OIDC Issuer from the Forge for Container Publishing: Registry Support, Candidate IdPs, and What Actually Moves

## TL;DR

- **Partially yes.** The cloud registries (AWS ECR, Google Artifact Registry, Azure Container Registry) and several self-hostable or SaaS registries (Quay/Red Hat Quay, Zot, JFrog Artifactory, Cloudsmith, and 8gears' commercial Harbor build) accept tokens from an issuer *you* configure. The forge-native registries do not: ghcr.io accepts only GitHub credentials, GitLab's registry only GitLab credentials, and Docker Hub's new OIDC connections "support only GitHub as a trusted third party".\[1\]\[2\] So the lock-in comes from specific registry products, not from the federation model itself.
- **Signing is the stricter half.** Public-good Sigstore Fulcio trusts a curated issuer list that only grows through PRs.\[3\] Codeberg/Forgejo is not on it. sigstore/fulcio#2442 proposes adding `https://codeberg.org/api/actions` as a ci-provider "with metadata mirroring the GitHub Actions provider." A secondary source (conda/rattler PR #2888) says the Fulcio maintainers "have agreed to add it," but Fulcio does not accept Codeberg tokens yet. A private Fulcio, or KMS-key signing with cosign or Notation, can trust any issuer or none.
- **Separation moves the tier-0 key; it does not remove it.** Option (a), a broker that exchanges forge tokens, leaves the forge key as an indirect root. Option (b), independent attestation of the runner (for example SPIRE), takes the forge key out of the *publishing* trust path. The SPIRE signing key (ideally in KMS/HSM) and the node-attestation roots become the new tier-0. The forge stays authoritative for *source* claims (repo, ref, commit) unless you verify those independently. For strike, the recommendation is: SPIRE-attested runners, JWT-SVIDs pushed to registries that federate arbitrary issuers (Zot/Quay self-hosted; ECR/GAR/ACR via cloud STS), KMS-backed DSSE signing, and source identity verified by strike itself, not taken from forge claims.

## Direct answer

The trusted-publishing / workload-identity-federation model **does allow separating the issuer from the forge**, but only on registries that implement *generic* OIDC federation (issuer URL + JWKS discovery + claim rules). It does **not** allow it on registries that hard-code a forge issuer. The model's underlying standards (OIDC discovery, RFC 7523 JWT bearer, RFC 8693 token exchange) are issuer-agnostic. The forge binding is a product decision by individual registry operators. The Open VSX team described this explicitly: trusted publishing is "a token exchange, not a login ... Architecturally, that is workload identity federation: the JWT-bearer and token-exchange patterns of RFC 7523 and RFC 8693."\[4\]

Per registry:

| Registry | Keyless/short-lived push mechanism | Issuer model | Separation possible? |
|---|---|---|---|
| Docker Hub | OIDC connections (org-level, Team/Business/DHI/DSOS) | **Fixed: GitHub only** ("OIDC connections support only GitHub as a trusted third party") | **No** |
| ghcr.io | `GITHUB_TOKEN` in Actions; classic PAT outside | **Forge-internal only** | **No** |
| GitLab Container Registry | `CI_JOB_TOKEN`, deploy/PAT/group tokens | **Forge-internal only**; GitLab WIF is a design document/Secrets-Manager issue, not shipped for the registry | **No (today)** |
| Quay.io / Red Hat Quay / Project Quay | Robot account federation -> 1 h robot token | **Arbitrary issuer**\[5\] (issuer + subject exact match; audiences being added) | **Yes** |
| Harbor (upstream goharbor) | None for workloads (robot secrets) | n/a | **No upstream**; 8gears commercial build: trusted issuers + claim rules (**Yes, commercial**) |
| AWS ECR | IAM OIDC provider + `AssumeRoleWithWebIdentity` -> `ecr:GetAuthorizationToken` | **Arbitrary issuer** (one IAM provider per issuer per account) | **Yes (via AWS STS)** |
| Google Artifact Registry | Workload Identity Federation (OIDC provider, attribute mapping/condition, local JWKS supported) | **Arbitrary issuer** | **Yes (via Google STS)** |
| Azure Container Registry | Entra federated identity credential -> Entra token -> `/oauth2/exchange` ACR refresh token | **Arbitrary issuer**, RS256 only, exact issuer/subject/audience match, 20 FICs per identity\[6\] | **Yes (via Entra)** |
| Forgejo/Gitea built-in registry | Forge tokens (PAT/automatic job token) | **Forge-internal**; no inbound OIDC federation found | **No (not found)** |
| Zot | `auth.bearer.oidc` "OIDC Bearer (Workload Identity)", since v2.1.14 | **Arbitrary, multiple issuers**; claim mapping incl. SPIFFE URI SAN pattern | **Yes, natively** |
| CNCF Distribution (registry v3) | Token auth: registry verifies JWTs from a token server against a static `jwks` file / cert bundle | Token must carry Distribution's `access` claim -> **needs a token-server broker** | **Indirectly (broker)** |
| JFrog Artifactory | OIDC integration: provider types GitHub, Azure, **Generic OpenID Connect** + identity mappings | **Arbitrary issuer** | **Yes** |
| Cloudsmith | OIDC provider settings (Provider URL = any `iss`), static or dynamic claim->service-account mapping | **Arbitrary issuer** (documented with GitHub, GitLab, CircleCI, Azure DevOps, AWS outbound, GCP, K8s, Pulumi)\[7\] | **Yes** |

## Key Findings

### 1. Registry-by-registry evidence

**Docker Hub: GitHub-only lock-in, confirmed.** Docker shipped OIDC connections on 31 July 2026 for organizations with Docker Team, Business, DHI or DSOS.\[8\] Docker's own docs state: "OIDC connections support only GitHub as a trusted third party," and "Only organization accounts can sign in using OIDC."\[2\] The flow: Docker "verifies the token's signature against GitHub's public key registry and checks it against rulesets configured in the Admin Console," and then issues a token that "expires in minutes."\[8\] Docker's 2024 blog had already framed this as "an integration of Docker Hub with GitHub Actions OIDC."\[9\] This is exactly the registry-operator lock-in described in the question. A Forgejo or SPIRE token cannot be used.

**ghcr.io and GitLab Registry: forge-internal credentials only.** GitHub documents `GITHUB_TOKEN` inside Actions and says that otherwise "GitHub Packages only supports authentication using a personal access token (classic)."\[1\]\[10\] GitLab's registry accepts passwords, personal/project/group access tokens, deploy tokens, and `CI_JOB_TOKEN`.\[11\] GitLab's OIDC `id_tokens` are documented for *outbound* use (AWS, Azure, GCP, Vault).\[12\] GitLab has a "GitLab Workload Identity Federation" design document ("GitLab users can map external identities onto GitLab service accounts")\[13\] and a Secrets-Manager issue for "a new Rails endpoint that accepts an external OIDC token issued by a configured trusted issuer."\[14\] Neither is a shipped registry feature. Treat inbound federation on GitLab as roadmap, not capability.

**Quay: genuinely issuer-agnostic.** Project Quay docs: "Robot federation lets a workload exchange a token from an external OIDC issuer for a short-lived Project Quay token, with no stored credential."\[15\] Details:
- Matching is "by exact string equality on issuer and subject."\[15\]
- Exchanged tokens expire after one hour.\[16\]
- Quay must have network egress to the issuer.\[15\]
- Audiences: in Quay 3.18 an optional `audiences` array exists, but "create and update requests persist issuer and subject only," and "A later release requires audiences."\[17\]
- Red Hat's own articles show Keycloak/RH-SSO, Entra ID, OpenShift service-account tokens, **SPIRE identities**, and GitHub Actions as issuers.\[18\]\[19\]\[20\]

**Weakness:** the 3.18 docs describe issuer+subject matching without audience validation. Any token from a shared issuer with the same `sub` would match regardless of `aud`. For a SPIRE issuer you control, this is acceptable. For multi-tenant issuers, it is a real gap until audience enforcement lands.

**Harbor: upstream no, commercial fork yes, with governance controversy.** The upstream request (goharbor/harbor#17520, "OIDC tokenless authentication for clients") has been open since 2022.\[21\] On goharbor/harbor#22027 a maintainer wrote "we have decided ot put this in our commercial product first."\[21\] This triggered goharbor/community#302 and a CNCF TOC health issue (cncf/toc#2338).\[22\] The 8gears build ("harbor-next" 2.15.x) has **Trusted Issuers** with issuer URL, required and immutable audience, JWKS (online or offline), and claim rules mapping to robot accounts, behind feature gates (`enable_commercial_federated_robot_accounts`).\[23\]\[24\]\[25\] Since 2.15.12, `aud`/`iss` are rejected as claim rules.\[26\] Published examples cover GitHub Actions, GitLab CI and Kubernetes (including offline JWKS).\[23\]\[27\] The design takes a generic JWKS, so a SPIRE or Keycloak issuer should work, but 8gears does not document this; mark it as inferred. The API has also churned (`/federated-idps` -> `/trusted-issuers`).\[24\]\[28\]

**Zot: the cleanest self-hosted fit.** Zot docs: "zot can now authenticate workloads using OIDC ID tokens... This is often called *workload identity federation*. You can configure one or more OIDC issuers under `auth.bearer.oidc`."\[29\]\[30\] Further details:
- The Go config exposes `Issuer`, `Audiences`, `ClaimMapping`, an optional `CertificateAuthority`, and a `URISANPattern`, documented with the example `"spiffe://example.org/workload/(.*)"`, which explicitly anticipates SPIFFE identities.\[31\]
- It accepts the algorithms the issuer advertises (RS256, ES256, PS256...).\[32\]
- It initializes providers lazily.\[29\]
- Mapped identity defaults to `iss + '/' + sub`, and authorization goes through `accessControl` policies.\[33\]
- Group membership for OIDC bearer identities was only fixed recently (PR #4620), and there was a bug where `bearer.oidc` broke `openid` login and API keys (issue #4033).\[33\]\[34\] The feature works but is young.

**CNCF Distribution: needs a broker.** Distribution v3 token auth verifies JWTs against a `jwks` file / `rootcertbundle` and a single configured `issuer`.\[35\]\[36\] It expects the Distribution token format with an `access` claim listing repository actions. A raw OIDC ID token from SPIRE or Forgejo lacks that claim. You need a token server (realm) that validates the workload's OIDC token and mints Distribution tokens. That server's signing key becomes another root. Users also reported friction with JWKS `kid` formats in v3 (issue #4533).\[37\]

**Cloud registries: arbitrary issuers via the cloud STS.**
- **ECR:** any OIDC issuer can be registered as an IAM OIDC provider. Trust policy conditions on `aud`/`sub`. AWS enforces one provider per issuer per account.\[38\] Caveats:
  - Claim richness is limited: for GitLab Self-Managed, only `sub` is supported as a condition key.\[39\]
  - AWS caps JWKS size. AWS IAM's documentation says the JWKS "can have a maximum of 100 RSA keys and 100 EC keys"; above that, `AssumeRoleWithWebIdentity` returns `InvalidIdentityToken`, which SPIRE users hit in spiffe/spire#4699. Separately, Indeed's engineering blog (July 2024) reported that AWS STS rejected SPIRE JWTs "due to invalid data type for the iat and exp claims" until "a tactical fix was pushed by Indeed so SPIRE JWT SVIDS will be accepted by AWS."
- **GAR:** Workload Identity Federation supports any OIDC provider, including "OIDC provider with local JWKs" (useful for non-public issuers), with CEL attribute conditions. Google: "Workload Identity Federation follows the OAuth 2.0 token exchange specification."\[40\]
- **ACR:** Entra federated identity credentials accept any external issuer, with constraints:
  - "Only issuers that provide tokens signed using the RS256 algorithm are supported."\[6\]\[41\]
  - issuer/subject/audience must match exactly.\[42\]\[43\]
  - 20 federated credentials per app/managed identity.\[42\]\[43\]\[44\]
  - Flexible (wildcard) FICs are preview and limited to GitHub, GitLab and Terraform Cloud issuers.\[42\]

  The Entra token is then exchanged at ACR's `POST /oauth2/exchange` for an ACR refresh token (`az acr login --expose-token`). Microsoft Learn's ACR authentication docs state "the token that az acr login uses is valid for 3 hours." Note: SPIRE's default key type is `ec-p256`, so for Entra you must set `jwt_key_type` to RSA.\[45\]

**JFrog and Cloudsmith: arbitrary issuers, SaaS root.** JFrog: provider type "GitHub, Azure, or Generic OpenID Connect," with identity mappings. CLI `jf eot --oidc-provider-type=GenericOidc`.\[5\]\[46\] Cloudsmith: "Provider URL ... must precisely match the iss (issuer) claim."\[7\] It supports dynamic claim->service-account mapping and is documented with AWS's outbound STS issuer, GCP, Azure DevOps, Kubernetes, and Pulumi ESC.\[47\]\[48\]\[49\]\[50\]\[51\] Pulumi's doc contains an important warning that applies to every shared issuer: "Every Pulumi organization shares the issuer, and any organization can mint a token for any audience, so a provider that requires only aud accepts tokens from other organizations."\[50\]

### 2. Signing: Sigstore and alternatives

**Public-good Fulcio is an allow-list by design.** The production `config/identity/config.yaml` lists curated issuers, among them:\[52\]
- Google accounts
- the Sigstore Dex (`oauth2.sigstore.dev/auth`)
- GitHub Actions
- gitlab.com plus a few named GitLab instances (gitlab.archlinux.org, ops.gitlab.net, dev.gitlab.org)
- Buildkite, CircleCI, Codefresh, Buddy
- Chainguard (`issuer.enforce.dev`), Eclipse Foundation, IBM, Kaggle, Hello

New issuers are added by pull request. The add-issuer steps in sigstore/fulcio PR #1736 are: "Add the new issuer to the configuration (config/identity/config.yaml) and to the identity folder... Add a case statement to map the issuer constant... Add a test for the new issuer." CI providers declare `type: ci-provider` with `ci-issuer-metadata` extension templates mapping claims to Fulcio OIDs (e.g. `build-config-uri`), and Fulcio docs give SAN-design guidance ("SANs should be unique for the issuer"). **Forgejo/Codeberg is not trusted.** sigstore/fulcio#2442 ("Add Codeberg Actions (Forgejo) as a trusted OIDC issuer for the public-good instance") proposes `https://codeberg.org/api/actions`. \[53\] Self-hosted Forgejo instances will realistically never be on the public list. Each would be a separate, unvetted issuer, and the community operators bear the burden of vetting.

**Private Fulcio trusts whatever you configure.** It supports `email`, `ci-provider`, SPIFFE and Kubernetes issuer types and meta-issuers (wildcard URLs).\[54\]\[55\] It can hold its CA key in a PKCS#11 HSM.\[56\] You then also operate (or reuse) a CT log, Rekor and a TUF root, and distribute that trust root to verifiers.

**Verifiers bind to the issuer string, which makes issuer choice sticky.** `cosign verify --certificate-oidc-issuer ... --certificate-identity(-regexp) ...` pins the issuer URL embedded in the certificate (OID 1.3.6.1.4.1.57264.1.8).\[57\] Policy engines (sigstore policy-controller `ClusterImagePolicy` keyless authorities, Kyverno `verifyImages` attestors, Connaisseur) expose the same issuer + subject pair. Changing issuers later therefore means rewriting every downstream verification policy. That is a second, quieter form of lock-in.

**Key-based alternatives avoid OIDC entirely for signing.** cosign supports KMS URIs (`awskms://`, `gcpkms://`, `azurekms://`, `hashivault://`) and PKCS#11. Notation/Notary Project uses X.509 signing with KMS plugins (e.g. AWS Signer, Azure Key Vault) and trust policies keyed on certificate identity; Ratify can verify both. Here the signing key is the explicit tier-0. There is no issuer lock-in, but you need your own revocation/rotation story.

### 3. Architecture: broker vs. independent attestation

| | (a) Broker / token exchange | (b) Independent workload attestation |
|---|---|---|
| Mechanism | Third IdP (Keycloak, Vault/OpenBao, custom STS) validates the Forgejo job token and re-issues its own JWT | SPIRE (or Teleport, K8s SA issuer) attests node + workload and issues JWT-SVIDs; the forge only *schedules* |
| Forge key in publish trust path? | **Yes, transitively.** A forged forge token yields a valid broker token | **No.** Registry trusts only SPIRE's key |
| What it buys | Registry portability (registry sees one stable issuer); claim normalization; central policy/audit | Registry portability **plus** removal of the forge key from push authorization |
| Residual roots | Forge JWKS key **and** broker signing key (now two tier-0 keys) | SPIRE signing key (KMS/HSM), node-attestation roots (TPM EK CA / cloud IID / join tokens), registration-entry admin |
| Source claims (repo/ref/commit) | Copied from forge token, so as trustworthy as the forge | **Not attestable** by SPIRE; must come from somewhere else |

Keycloak 26.x supports standard token exchange (internal->internal) by default.\[58\] External->internal exchange exists only in "legacy" V1, and Keycloak now recommends RFC 7523 JWT Authorization Grant (26.5+) for that case.\[59\]\[60\] Keycloak's realm keys are "stored just locally"; HSM/KMS needs third-party key-provider extensions.\[61\]\[62\]\[63\]\[64\] Vault/OpenBao `identity/oidc` tokens support custom claim templates, RS/ES/EdDSA algorithms, and 24 h default rotation.\[65\] The named keys are Vault-generated and live in Vault storage;\[66\] I found no documented HSM option for them.

**What an independent IdP can and cannot vouch for:**
- **Can (with SPIRE/TPM/confidential computing):** this process runs a specific binary (digest) on a specific attested host/VM/pod, under a specific UID or container image. In other words, *builder identity*. This matches SLSA's separation: Build L3 is about a hardened builder whose provenance the tenant cannot forge, with provenance signed by the platform rather than the job.
- **Cannot, without trusting the forge:** which repository, ref, commit or workflow triggered the job, or who approved it. The forge is the authority for those *source* facts. The way out is not to *trust* them but to *verify* them. The runner fetches source by commit hash over a channel it authenticates itself (pinned SSH host key / TLS anchor), optionally checks signed commits/tags against maintainer keys, records the resolved digest in provenance, and policy keys on the attested *builder* SPIFFE ID plus the *verified* source digest. The forge then becomes a mere job-dispatch hint.

**Separation also has a cost:** compromise of the scheduling forge can still *request* builds of malicious refs. Option (b) limits this only if strike enforces policy (e.g. protected-ref allow-lists, signed tags) on its own side.

### 4. Candidate independent issuers

| Issuer | Custom/workload claims | Signing-key custody | Workload attestation | Maturity / notes |
|---|---|---|---|---|
| **SPIRE** (+ OIDC Discovery Provider) | `sub` = SPIFFE ID, `aud`, `exp`; extra claims via CredentialComposer plugin | KeyManager plugins: `aws_kms`, `hashicorp_vault` (Transit), `kmip`, `disk`, `memory`; UpstreamAuthority (e.g. AWS PCA, cert-manager) | **Yes**: node attestors (TPM, AWS IID, K8s PSAT, join token...) + workload attestors (unix, docker/podman, k8s) | CNCF graduated; proven with AWS/GCP/Azure, OpenAI and Anthropic WIF, Quay; default JWT-SVID TTL 5 m, `ca_ttl` 24 h\[45\]\[67\] |
| **Kubernetes SA issuer** | Fixed claim set (namespace, SA, pod, node) | ExternalJWTSigner (KEP-740) **stable in v1.36** enables HSM/KMS | Yes, by kubelet/API server (trusts the cluster) | GA; good if strike runners are pods |
| **Teleport Workload Identity** | JWT-SVIDs, SPIFFE ID `sub` | Teleport CA (HSM/KMS supported for Teleport CAs) | Yes (bot joining methods, workload attestation) | Tested with AWS, GCP, Azure; v16.4.3+; issuer is the proxy URL |
| **Vault / OpenBao identity tokens** | Rich templates from entity metadata | Vault-generated, Vault storage; no documented HSM for these keys | **No**: trusts whatever auth method logged in (secret-zero unless that is cert/K8s/JWT auth) | Mature; good broker, weak attestor |
| **Keycloak** | Mappers, service accounts; std token exchange (internal) | Local keys; HSM/KMS only via 3rd-party SPI | **No**: client credentials = secret zero | Mature IAM, not a workload attestor |
| **Dex / Zitadel / Authentik / Kanidm** | Varies; mostly user-centric | Mostly DB-stored keys | **No** | Use only as brokers; not evaluated in depth here |
| **step-ca** | X.509/SSH certs (provisioners incl. ACME device-attest, cloud IID, K8s SA) | PKCS#11/KMS supported | Partial (provisioner-based) | Better suited to X.509 identity than JWT federation |
| **Cloud workload identity** (GCP SA ID tokens, AWS STS outbound issuer, Entra MI) | Cloud-defined | Cloud-held | Cloud attests the VM/function | Strong but is cloud lock-in; AWS outbound issuer documented with Cloudsmith |
| **AWS IAM Roles Anywhere** | n/a (X.509 -> AWS creds) | Your CA (SPIRE can publish bundle as trust anchor) | Via your PKI | AWS-only |

### 5. Compatibility matrix (registry x issuer type)

Legend: **D** = direct federation; **S** = via cloud STS (native, no extra component); **B** = needs a broker/token server you run; **--** = not supported.

| Registry | Forge OIDC (Forgejo) | SPIRE JWT-SVID | K8s SA token | Teleport JWT-SVID | Vault/OpenBao | Keycloak |
|---|---|---|---|---|---|---|
| Docker Hub | -- | -- | -- | -- | -- | -- |
| ghcr.io | -- | -- | -- | -- | -- | -- |
| GitLab Registry | -- | -- | -- | -- | -- | -- |
| Forgejo registry | (job token only) | -- | -- | -- | -- | -- |
| Quay | D | D (documented) | D (documented) | D | D | D (documented) |
| Harbor upstream | -- | -- | -- | -- | -- | -- |
| Harbor 8gears | D | D (inferred) | D (documented) | D (inferred) | D (inferred) | D (inferred) |
| Zot | D | D (SPIFFE pattern documented) | D (documented) | D | D | D |
| Distribution | B | B | B | B | B | B (docker-v2 protocol client) |
| AWS ECR | S | S (Indeed) | S (IRSA pattern) | S (documented) | S | S |
| GAR | S | S | S | S (documented) | S | S |
| ACR | S (RS256) | S (RSA key needed) | S | S (documented) | S | S |
| JFrog | D (Generic) | D (Generic) | D | D | D | D |
| Cloudsmith | D | D | D (documented) | D | D | D |

Universal prerequisites for "D/S":
- an HTTPS-reachable discovery document and JWKS (or upload/local JWKS for GAR, Harbor 8gears offline, OpenAI-style inline);
- a stable `iss`;
- an audience per registry.

A purely internal SPIRE behind a firewall works with self-hosted Zot/Quay/Harbor but needs a public discovery endpoint (or a local JWKS upload) for cloud and SaaS registries.

### 6. Standards and proposals

- **OpenSSF "Trusted Publishers for All Package Repositories"** (Securing Software Repositories WG) is the de facto spec.\[68\]\[69\] It is written for package indexes and frames providers as a curated set, which encourages allow-lists. William Woodruff (PyPI): "in principle this action is entirely agnostic to the index ... Trusted Publishing can be made to work with any index."\[70\] No container-registry profile exists.
- **Sigstore**: issuer onboarding via PR/`ci-issuer-metadata`; no process for self-hosted forge instances beyond private deployments.
- **IETF WIMSE**: the current drafts are draft-ietf-wimse-arch-06 and draft-ietf-wimse-workload-creds-02. The second defines the Workload Identity Token (WIT), a JWT that "binds a public key to that identity" and "MUST NOT be used as a bearer token." It is the most relevant standards track for issuer-agnostic workload identity, but it defines no registry push profile, and its proof-of-possession design does not fit today's bearer-token registry flows.
- **OCI Distribution spec**: token auth remains the Docker v2 bearer scheme. There is no standardized OIDC-ID-token-as-bearer profile, so every registry invents its own exchange endpoint (Quay `/oauth2/federation/robot/token`, Docker connection IDs, Harbor robot-password JWT, Zot raw bearer). This fragmentation is the practical obstacle to portability.
- **SLSA**: separates builder identity (Build track) from source identity (Source track), which supports the architectural split in Section 3.

## Recommendations for strike

**Mapping.** strike is a rootless, shell-free Go executor talking to Podman via API, with typed in-memory secrets, DSSE attestations to a transparency log, declared network peers with explicit trust anchors, and delegated signing (ssh-agent/KMS/OIDC). That design fits **option (b)** almost exactly:

1. **Identity: SPIRE-attested runners.** Run a SPIRE agent per runner host with TPM node attestation (or cloud IID). Use a unix/podman workload attestor selecting on strike's binary digest and UID. Issue *per-lane* SPIFFE IDs (e.g. `spiffe://ci.example/strike/lane/<project>/<lane>`). Configure the SPIRE server with a KMS/KMIP/Vault-Transit KeyManager and the OIDC Discovery Provider, with `jwt_key_type` RSA if ACR is a target. strike fetches JWT-SVIDs from the Workload API socket, a declared peer with an explicit trust anchor, and holds them as typed secrets.
2. **Push: target registries that federate arbitrary issuers.** Self-hosted: **Zot** (native `bearer.oidc` with SPIFFE URI pattern) or **Quay** (robot federation; pin audiences once enforced). Cloud: **ECR/GAR/ACR** via their STS. SaaS: **Cloudsmith/JFrog**. Avoid Docker Hub/ghcr.io/GitLab as *primary* publish targets. If you need presence there, mirror from your primary registry using a narrowly scoped long-lived token held by a separate, non-CI promotion job, and accept that this is a stored secret.
3. **Source identity: verify, don't trust the forge.** Have strike resolve the ref to a commit hash, fetch over a pinned channel, optionally verify signed tags/commits, and put `resolvedDependencies` (commit digest) in the DSSE provenance. Registry claim rules key on the *builder* SPIFFE ID. Admission policy keys on builder identity + source digest + signer key.
4. **Signing: prefer KMS over OIDC/Fulcio for now.** Public Fulcio will not accept your Forgejo or SPIRE issuer. Options:
   - **(i)** cosign/DSSE with a KMS key reached via strike's delegated-signing interface;
   - **(ii)** a private Fulcio that trusts your SPIRE issuer (`spiffe` type), giving keyless short-lived certs whose SAN is the SPIFFE ID, at the cost of operating Fulcio + CT + Rekor + TUF.

   Pick (i) unless you need per-build certs for many tenants.
5. **Treat the Forgejo OIDC issuer as optional.** Keep Forgejo's `enable-openid-connect` (Forgejo >= v15) off for publish lanes so a Forgejo key compromise cannot mint publish credentials.\[71\]\[72\]

**Remaining root keys after this design:**
- SPIRE signing key (JWT + X.509 CA), the new tier-0 for publishing; keep it in KMS/HSM with short `ca_ttl`;
- node-attestation roots (TPM manufacturer EK CAs or cloud IID roots) and the SPIRE registration-entry admin credential;
- the artifact signing KMS key (or private Fulcio CA + TUF root);
- registry-side trust configuration (who can edit issuer/claim rules);
- the forge, still as *scheduler* and *source host*, but source integrity checked by strike against signed commits/tags, whose maintainer keys become a root for source.

## Caveats

- **Separation relocates the tier-0 key; it does not shrink it.** You trade one forge JWKS key for a SPIRE key plus attestation roots. That is a win only if the SPIRE key is better protected (non-extractable KMS/HSM, smaller admin surface, short TTLs) than Forgejo's key, which typically sits on disk in the forge's data directory. Under option (a), you strictly *add* a tier-0 key.
- **Operational cost:** SPIRE, public discovery endpoints, JWKS size limits (AWS IAM documents "a maximum of 100 RSA keys and 100 EC keys"), RS256-only Entra, and per-registry exchange endpoints are non-trivial. Several features are young: Zot OIDC bearer since v2.1.14 with recent bugs, Quay audiences not yet enforced in 3.18, Harbor federation commercial-only with API churn.\[17\]\[22\]\[30\]\[34\]
- **Not verified from primary sources in this session:** Forgejo's built-in registry authentication options (no federation found); exact policy-controller/Kyverno/Connaisseur/Ratify field names; the Dex/Zitadel/Authentik/Kanidm details; the current WIMSE draft status; Teleport CA HSM specifics. Harbor-8gears acceptance of non-forge issuers is inferred from its generic JWKS design.
- **Vendor-marketing caution:** Docker's and 8gears' announcements are vendor posts. Docker's GitHub-only restriction is confirmed in its own docs. Third-party blog guides (oneuptime, lobehub etc.) were used only for corroboration.

## Quellen

1. [Working with the Docker registry - GitHub Enterprise Server 3.20 Docs](https://docs.github.com/en/enterprise-server@3.20/packages/working-with-a-github-packages-registry/working-with-the-docker-registry)
2. [Create and manage OIDC connections](https://docs.docker.com/security/authentication/oidc-connections/create-manage)
3. [fulcio/docs/oidc.md at main - sigstore/fulcio - GitHub](https://github.com/sigstore/fulcio/blob/main/docs/oidc.md)
4. [Trusted Publishing on Open VSX](https://blogs.eclipse.org/post/tamas-cservenak/trusted-publishing-open-vsx)
5. [OpenID Connect Integration](https://docs.jfrog.com/administration/docs/openid-connect-integration)
6. [workload identity federation considerations](https://github.com/MicrosoftDocs/entra-docs/blob/main/docs/workload-id/workload-identity-federation-considerations.md)
7. [Setup GitHub Actions to authenticate to Cloudsmith using OIDC](https://docs.cloudsmith.com/authentication/setup-cloudsmith-to-authenticate-with-oidc-in-github-actions)
8. [Docker OIDC connections for GitHub Actions available for Docker Orgs | Docker](https://www.docker.com/blog/docker-oidc-connections-for-github-actions-available-for-docker-orgs/)
9. [Building Trusted Content with GitHub Actions](https://www.docker.com/blog/building-trusted-content-with-github-actions/)
10. [Working with the Container registry - GitHub Docs](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
11. [Authenticate with container registry - Container registry - Packages - User - Help - GitLab](https://genboree.org/gitlab/help/user/packages/container_registry/authenticate_with_container_registry.md)
12. [Connect to cloud services](https://docs.gitlab.com/ci/cloud_services/)
13. [GitLab Workload Identity Federation](https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/gitlab_workload_identity_federation/)
14. [Secrets Manager: Workload identity federation (exchange external OIDC for SM JWT)](https://gitlab.com/gitlab-org/gitlab/-/issues/601894)
15. [Use Project Quay](https://docs.projectquay.io/use_quay.html)
16. [About Quay IO](https://docs.projectquay.io/quay_io.html)
17. [Manage Project Quay](https://docs.projectquay.io/manage_quay.html)
18. [Push images to Quay without a password](https://developers.redhat.com/articles/2026/07/22/push-images-to-quay-without-a-password)
19. [Access Quay on OpenShift with short-lived credentials](https://developers.redhat.com/articles/2025/04/22/access-quay-openshift-short-lived-credentials)
20. [Chapter 11. Keyless authentication with robot accounts](https://docs.redhat.com/en/documentation/red_hat_quay/3/html/manage_red_hat_quay/keyless-authentication-robot-accounts)
21. [Community Health and Tokenless Workload Authentication - Issue #302 - goharbor/community - GitHub](https://github.com/goharbor/community/issues/302)
22. [\[HEALTH\]: Harbor - Issue #2338 - cncf/toc - GitHub](https://github.com/cncf/toc/issues/2338)
23. [docs: Correct federated robot setup for Harbor 2.15 by bupd - Pull Request #60 - container-registry/harbor-workload-identity-federation - GitHub](https://github.com/container-registry/harbor-workload-identity-federation/pull/60)
24. [docs: Set the audience on the Trusted Issuer for Harbor 2.15.12 by Vad1mo - Pull Request #62 - container-registry/harbor-workload-identity-federation - GitHub](https://github.com/container-registry/harbor-workload-identity-federation/pull/62)
25. [README: old repo name in the token sample, and no guidance for a wrong Trusted Issuer audience - Issue #64 - container-registry/harbor-workload-identity-federation - GitHub](https://github.com/container-registry/harbor-workload-identity-federation/issues/64)
26. [Harbor 2.15.12: the setup script and chart docs still use aud/iss claim rules and the old federated-idps API - Issue #61 - container-registry/harbor-workload-identity-federation - GitHub](https://github.com/container-registry/harbor-workload-identity-federation/issues/61)
27. [GitHub - container-registry/harbor-workload-identity-federation: Examples on how to use federated identity of Harbor/8gears to push/pull images without secrets from GitHubAction/GitlabCI and Kubernetes. - GitHub](https://github.com/container-registry/harbor-workload-identity-federation)
28. [fix: provision keyless CI against the trusted-issuers API by Vad1mo - Pull Request #11 - container-registry/harbor-multi-artifact-support-examples - GitHub](https://github.com/container-registry/harbor-multi-artifact-support-examples/pull/11)
29. [Authentication and Authorization - zotregistry.dev](https://zotregistry.dev/v2.1.18/articles/authn-authz/)
30. [What's New - zotregistry.dev](https://zotregistry.dev/v2.1.14/general/whats-new/)
31. [config package - zotregistry.dev/zot/v2/pkg/api/config - Go Packages](https://pkg.go.dev/zotregistry.dev/zot/v2/pkg/api/config)
32. [zot/examples/README.md at main - project-zot/zot - GitHub](https://github.com/project-zot/zot/blob/main/examples/README.md)
33. [fix(auth): apply accessControl group membership to OpenID users by NopeCharon - Pull Request #4620 - project-zot/zot - GitHub](https://github.com/project-zot/zot/pull/4620)
34. [\[Bug\]: Failed to use openid.oidc with bearer.oidc authorization being configured - Issue #4033 - project-zot/zot - GitHub](https://github.com/project-zot/zot/issues/4033)
35. [CNCF Distribution](https://distribution.github.io/distribution/spec/auth/jwt)
36. [Configuring a registry](https://distribution.github.io/distribution/about/configuration/)
37. [JWT validation problem on 3.0.0-rc.1 (kid format mismatch) - Issue #4533 - distribution/distribution - GitHub](https://github.com/distribution/distribution/issues/4533)
38. [How to Create OIDC Identity Providers in Terraform](https://oneuptime.com/blog/post/2026-02-23-how-to-create-oidc-identity-providers-in-terraform/view)
39. [OpenID Connect (OIDC) Authentication Using ID Tokens](https://docs.gitlab.com/ci/secrets/id_token_authentication/)
40. [workload identity federation](https://cloud.google.com/iam/docs/workload-identity-federation?authuser=8)
41. [Workload identity federation for app considerations - Microsoft Entra Workload ID](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-considerations)
42. [Flexible federated identity credentials (preview) - Microsoft Entra Workload ID](https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-flexible-federated-identity-credentials)
43. [Modern authentication with Azure workload identity federation](https://www.tothenew.com/blog/modern-authentication-with-azure-workload-identity-federation/)
44. [Use a Microsoft Entra Workload ID on Azure Kubernetes Service (AKS) - Azure Kubernetes Service](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview)
45. [SPIRE Server Configuration Reference](https://spiffe.io/docs/latest/deploying/spire_server/)
46. [Exchange an OIDC Token for JFrog Access](https://docs.jfrog.com/integrations/docs/jf-exchange-oidc-token)
47. [Dynamic OIDC Mapping](https://docs.cloudsmith.com/authentication/dynamic-oidc-mapping)
48. [Cloudsmith - External Secrets Operator](https://external-secrets.io/v2.5.0/api/generator/cloudsmith/)
49. [Authenticate to Cloudsmith with Your AWS Identity](https://cloudsmith.com/blog/authenticate-to-cloudsmith-with-your-aws-identity)
50. [Configure OpenID Connect for custom audiences](https://www.pulumi.com/docs/esc/guides/configuring-oidc/custom-audience/)
51. [Native OIDC authentication for Azure DevOps](https://cloudsmith.com/changelog/native-oidc-authentication-for-azure-devops)
52. [fulcio/config/identity/config.yaml at main - sigstore/fulcio](https://github.com/sigstore/fulcio/blob/main/config/identity/config.yaml)
53. [Add Codeberg Actions (Forgejo) as a trusted OIDC issuer for the public-good instance - Issue #2442 - sigstore/fulcio - GitHub](https://github.com/sigstore/fulcio/issues/2442)
54. [Fulcio Streamlines Onboarding for CI Identity Providers - Sigstore Blog](https://blog.sigstore.dev/fulcio-ci-provider/)
55. [OIDC(openID connect) tokens in Fulcio](https://medium.com/@muhammadmoizgohar/oidc-openid-connect-tokens-in-fulcio-sigstore-ccf45eb85fa8)
56. [GitHub - sigstore/fulcio: Sigstore OIDC PKI - GitHub](https://github.com/sigstore/fulcio)
57. [oid info](https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md)
58. [keycloak/docs/documentation/upgrading/topics/changes/changes-26\_2\_0.adoc at main - keycloak/keycloak - GitHub](https://github.com/keycloak/keycloak/blob/main/docs/documentation/upgrading/topics/changes/changes-26_2_0.adoc)
59. [Release Notes](https://www.keycloak.org/docs/latest/release_notes/index.html)
60. [Upgrading Guide](https://www.keycloak.org/docs/latest/upgrading/index.html)
61. [jwks package - github.com/auth0/go-jwt-middleware/v3/jwks - Go Packages](https://pkg.go.dev/github.com/auth0/go-jwt-middleware/v3/jwks)
62. [GitHub - p2-inc/keycloak-kms: Keeps Keycloak's realm signing keys in a cloud KMS instead of in the database - GitHub](https://github.com/p2-inc/keycloak-kms)
63. [Keycloak - Thales Docs](https://www.thalesdocs.com/gphsm/integrations/guides/keycloak/index.html)
64. [Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/)
65. [Identity Secret Backend: Identity Tokens - HTTP API | Vault | HashiCorp Developer](https://developer.hashicorp.com/vault/api-docs/v1.17.x/secret/identity/tokens)
66. [Identity tokens](https://developer.hashicorp.com/vault/docs/secrets/identity/identity-token)
67. [developers.openai.com](https://developers.openai.com/de-DE/api/docs/guides/workload-identity-federation/spiffe)
68. [New Guide for Package Repositories to Adopt Trusted Publishers](https://openssf.org/blog/2024/08/05/new-guide-for-package-repositories-to-adopt-trusted-publishers/)
69. [Trusted Publishing](https://learn.microsoft.com/en-us/nuget/nuget-org/trusted-publishing)
70. [Any way of using this with GCP AR/Trusted publishing? - pypa/gh-action-pypi-publish - Discussion #389 - GitHub](https://github.com/pypa/gh-action-pypi-publish/discussions/389)
71. [Forgejo Actions](https://forgejo.org/docs/latest/user/actions/reference/)
72. [Forgejo v15.0 adds repo-scoped tokens, OIDC for Actions, and major usability upgrades](https://alternativeto.net/news/2026/4/forgejo-v15-0-adds-repo-scoped-tokens-oidc-for-actions-and-major-usability-upgrades/)
