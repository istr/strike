# Machine/Workload Identity Without Long-Lived Credentials in Forges, Runners and Deploy Paths: State of Play, Late 2026

The problem is only partially solved. Short-lived, federated identity from CI to cloud APIs and the major package registries is mature and should be the default. Self-hosted runner bootstrap, non-OIDC targets (SSH, on-prem, legacy registries) and the forges' own root keys still rest on long-lived secrets or long-lived private keys. No current design removes the last root of trust. The honest goal is narrower: replace every *bearer secret* with a *non-exportable, attested, narrowly scoped key*, and keep the few remaining roots small, hardware-bound and audited.

## TL;DR

- **Mostly solved:** CI->cloud and CI->registry credentials. GitHub, GitLab and, since Forgejo v15.0 (April 2026), Forgejo mint per-job OIDC tokens. AWS, GCP and Azure accept them. npm, PyPI, crates.io, NuGet and RubyGems accept them for "trusted publishing". **Not solved:** runner integrity. The May 2026 TanStack compromise shows an attacker who runs code inside a trusted job can lift the OIDC token from runner memory and publish with valid provenance.
- **The problem has several names, with different emphases:**
  - "Secret zero": the artifact, used across the industry.
  - "Secure introduction": the delivery problem, HashiCorp Vault's term.
  - "Bottom turtle": the regress and its attestation-based end, from the SPIFFE book *Solving the Bottom Turtle*.
  - "Bootstrapping workload identifiers and credentials": the neutral standards term in the IETF WIMSE architecture draft.
- **For a self-hosted Gitea/Forgejo-style setup like strike:** use Forgejo >= v15 OIDC (Gitea's support is still an open pull request), ephemeral one-job runners, and OIDC->SSH-certificate brokers (opkssh, step-ca, Vault SSH) for non-OIDC targets. Do signing through ssh-agent, KMS or TPM. You will still hold a small set of roots: the forge's OIDC signing key, the runner-provisioning credential, any SSH/X.509 CA keys, and a human break-glass path. Put them in HSM/TPM/KMS, give them short-TTL delegations, and log them in a transparency log.

## Key Findings

| Area | Verdict (late 2026) | Main evidence | Residual root |
|---|---|---|---|
| CI -> cloud (AWS/GCP/Azure) via OIDC federation | **Solved for hosted forges; works for Forgejo >= v15** | GitHub OIDC reference; Forgejo v15 OIDC docs; cloud federation docs | Forge's JWKS signing key; correctness of the trust policy; runner integrity |
| CI -> package registries (trusted publishing) | **Largely solved for npm, PyPI, crates.io, NuGet, RubyGems; not Maven Central; not Forgejo as an issuer** | npm GA July 2025; crates.io July 2025/Jan 2026; Maven Central has no TP | Same as above, plus registry's trust configuration |
| Keyless signing (Sigstore) | **Solved for signer key management**; trust shifts to the OIDC issuer and Fulcio/Rekor/TUF | Sigstore TUF root 3-of-5 hardware keys | TUF root keys, Fulcio CA key, Rekor log key |
| Self-hosted runner identity | **Partially solved** | GitHub JIT runners (2023); Forgejo ephemeral runners (v15); GitLab `glrt-` runner auth tokens | Credential that *creates* runners (App key, admin API token) |
| SSH / on-prem deploy | **Partially solved via OIDC->SSH-cert brokers** | opkssh Forgejo support (needs v15); Vault SSH; step-ca | SSH CA key or the opkssh provider allow-list |
| git push to the forge itself | **Partially solved** | Job tokens (per-run), GitHub App installation tokens (1 h) | GitHub App private key / long-lived admin token |
| Secrets managers (Vault/OpenBao) | **Shifts, does not remove, the root** | Vault "secure introduction" docs; AppRole SecretID | Platform identity or trusted orchestrator credential |
| Bare-metal / on-prem node identity | **Solved only with hardware (TPM DevID / confidential computing)** | SPIRE `tpm_devid`, `x509pop`; Red Hat SPIRE+CoCo (Jan 2026) | Manufacturer/DevID CA, the TEE attestation service |
| Standards (IETF WIMSE) | **Not finished**; architecture draft -08 (July 2026), Informational | Datatracker | n/a |

## 1. Terminology: what the "key 0" problem is called

No single name is authoritative. The terms overlap but differ in emphasis.

- **"Secret zero"** is the most common name for the *artifact*: the first credential an entity needs before any secrets manager or identity system will talk to it. HashiCorp uses it in its own material. One webinar says that when you choose auto-unseal over Shamir sharing, "you'll encounter the 'secret-zero' problem".\[1\] Another HashiCorp blog (on OpenShift Virtualization) defines it as "an initial credential that must be delivered to the guest using a secure, trusted mechanism".\[2\] I found no primary source that identifies who coined it. Treat it as industry folklore rather than an attributed term.
- **"Secure introduction"** is HashiCorp Vault's documented name for the *process/problem*. The Vault tutorial says "Getting the first secret to the consumer, is the secure introduction challenge."\[3\] It defines three solution patterns: **platform integration**, **trusted orchestrator** and **Vault Agent** (the last automates the other two). It also states the on-prem limit plainly: "VMware does not provide a cryptographic identity, so a platform integration isn't possible."\[4\] In practice secret zero is *what* you deliver and secure introduction is *how* you deliver it safely.
- **"Bottom turtle" / "turtles all the way down"** is the SPIFFE community's framing, from the book *Solving the Bottom Turtle* (Feldman, Fox, Gilman, Haken, Kautz, Khan, Lambrecht, Lum, Martinez Fayo, Nesterov, Vega, Wardrop). It names the *infinite regress*: "Protecting one secret requires coming up with some way to protect another secret, which then requires protecting that secret, and so on." It also sets the *design goal*: the workload "needs to be able to obtain this identity without a secret or some other credential".\[5\] So the bottom turtle should be attestation, not another secret. A July 2026 SPIFFE blog post ties this to secret zero explicitly: "Somewhere at the bottom of that stack there is a first credential -- 'secret zero'".\[6\]
- **"Bootstrapping" / "credential bootstrapping"** is the neutral standards term. The IETF WIMSE architecture draft has a use-case section titled "Bootstrapping Workload Identifiers and Credentials". It states that "Workloads need to be provisioned with an identity when they are started."\[7\]
- **Related terms worth using precisely:**
  - **Trusted orchestrator** (Vault): an already-privileged system injects the first credential. This is a secret zero that is pushed rather than stored.
  - **Platform/node attestation** (SPIFFE): the platform vouches with evidence.
  - **Root of trust** (TCG/hardware): the component whose misbehaviour cannot be detected. This is the honest name for what remains once secret zero is eliminated.
  - **Response wrapping** (Vault): a single-use, short-TTL envelope around secret zero.
  - **Trust on first use (TOFU)**: the server-identity analogue, e.g. SSH host keys.

**Do the terms differ in meaning?** Yes, slightly:
- Secret zero = a *secret*, which implies a bearer credential that can be copied.
- Secure introduction = the *delivery channel* problem.
- Bottom turtle = the *regress*, and the claim that it should end in non-secret evidence.
- Bootstrapping = the *lifecycle phase*.

The distinction that matters most: you can often eliminate **secret zero** (a copyable bearer secret), but you cannot eliminate a **root of trust** (some key or authority you must trust). The rest of this report uses that distinction.

## 2. Identity vs. credentials; client vs. server identity

The nhimg.org FAQ the user cited could not be fetched (bot protection). Its premise is nonetheless reflected in the primary standards. The WIMSE architecture separates the **workload identifier** (a URI scoped to a trust domain, e.g. a SPIFFE ID) from **workload identity credentials** (X.509 certificates or JWTs, ideally key-bound). It warns that JWT bearer tokens "could be stolen and reused elsewhere". That is why WIMSE defines key-bound credentials (WIT + proof-of-possession).\[7\]

The practical consequence: rotating a credential does not change who the workload is. Equating "identity" with "the API key" leads to rotation-as-security (see SANS metrics below). The real goal is to bind an identity to evidence and issue disposable credentials from it.

**Client vs. server identity.** Everything in OIDC federation is about *client* identity: how the job proves who it is. A deploy also needs *server* identity, meaning which peers the job trusts:
- the OIDC issuer's JWKS;
- the registry's TLS chain;
- the SSH host key or host CA;
- the transparency log's public key.

WIMSE says a trust domain must map to trust anchors through "a secure mechanism that ensures the authenticity and integrity of the mapping", and then declares that mechanism "out of scope".\[7\] That is the server-side bootstrapping problem, and it is unsolved by the standards. strike's "declared network peers with trust anchors" addresses exactly this gap.

## 3. State of the art by area

### 3.1 OIDC workload identity federation from CI

**How it works:**
1. The forge signs a short-lived JWT per job. Claims include `iss`, `aud`, `sub`, repo, ref and workflow.
2. The cloud STS validates it against the issuer's published JWKS and a trust policy.
3. The STS returns short-lived cloud credentials.

**Status by forge:**
- **GitHub Actions:** issuer `https://token.actions.githubusercontent.com`. The job requests the token with `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` after declaring `id-token: write`.\[8\]
- **GitLab CI:** `id_tokens` in the job definition.
- **Forgejo:** shipped in **v15.0 (April 2026, LTS)**. It needs Forgejo Runner > v12.5.0 and `enable-openid-connect: true` at workflow or job level.\[9\]\[10\] The issuer is `[instance]/api/actions`.\[11\] It uses the same request contract as GitHub, so tools like Flux's `actionsoidc` package and opkssh treat both forges alike.\[12\]\[13\] Forgejo's docs warn: "Improperly configured trust relationships can allow for unintended access to third party systems. The `sub`, `iss`, and `aud` claims should be validated in the trust relationship at the minimum."\[11\] The reference docs add that with OIDC enabled, "interacting with untrusted code in the pull request may leak these variables and request OIDC ID tokens."\[14\] Current docs list v17.0.1 as latest and v15.0.11 as LTS.\[11\]
- **Gitea:** **not shipped as far as verifiable.** Feature requests #26383 and #33681 ask for it. PR #39052 ("add OIDC workload identity support", with discovery, JWKS, token endpoints and permission clamping) was still under review in late August 2026.\[15\]\[16\]\[17\] Gitea's variables page lists `ACTIONS_ID_TOKEN_REQUEST_URL`, but I could not confirm that a released Gitea version issues federation-grade tokens.\[18\] Treat Gitea OIDC as **not yet available** until a release note says otherwise.
- **Buildkite, CircleCI and others:** also issue OIDC tokens. npm's trusted publishing list includes CircleCI. I did not re-verify their current claim sets for this report.

**Root of trust:**
- **(a) The forge's OIDC signing key.** Whoever holds it can mint any `sub`. For a self-hosted Forgejo that key lives on your forge server. Your forge therefore becomes an identity provider for your cloud, and its compromise is a cloud compromise.
- **(b) Runner integrity.** The token is only as trustworthy as the code that can reach it.

**Claims-design pitfalls (documented):**
- **Missing or wildcard `sub` conditions.** Datadog Security Labs showed real AWS roles, including one in a UK government account, that any GitHub repository could assume because the trust policy lacked a `sub` condition.\[19\] Tinder's security team found the same pattern, including in AWS's own roles.\[20\] A secondary source says AWS added a guardrail in June 2025 that blocks *new* overly permissive GitHub OIDC trust policies.\[21\] I did not verify this against an AWS primary source.
- **Name recycling.** A deleted org or repo name re-registered by an attacker matches name-based `sub` patterns. GitHub's fix is **immutable subject claims**, announced 23 April 2026. The subject becomes `repo:octocat@123456/my-repo@456789:ref:...`, default for repositories created, renamed or transferred after **15 July 2026**, and opt-in for older repositories. It applies to **github.com only, not GHES**.\[22\] Microsoft Entra published migration guidance for federated credentials.\[23\]\[24\]
- **Trigger confusion.** `pull_request_target` and `workflow_run` run with base-repo privileges. crates.io explicitly blocks trusted publishing from these triggers.\[25\]
- **Terminology.** The IETF WIMSE practices draft notes the pattern is commonly called "OIDC", but the platform-issued tokens "are not 'ID Tokens' in the sense of OIDC".\[26\] It is really JWT-bearer assertion (RFC 7521/7523) federation. This matters when reasoning about replay: the tokens are bearer tokens.

### 3.2 Trusted publishing and Sigstore keyless signing

**Registry status (as of October 2026):**
- **PyPI:** first, launched on 20 April 2023 with GitHub Actions as the only initial issuer (PyPI blog, "Introducing 'Trusted Publishers'"); by August 2024 OpenSSF reported "over 14,000 projects voluntarily adopt Trusted Publishers".
- **crates.io:** GitHub Actions in July 2025, GitLab in January 2026. Owners can now enforce a trusted-publishing-only mode.\[25\]\[27\]
- **npm:** GA on 31 July 2025 for GitHub Actions and GitLab, requiring npm CLI >= 11.5.1. Provenance is generated automatically.\[28\]
- **NuGet:** September 2025, announced on Microsoft's .NET Blog ("New Trusted Publishing enhances security on NuGet.org"). The GitHub OIDC token is exchanged for "a temporary, single-use NuGet API key", and after first use the policy "is bound to immutable GitHub IDs".
- **RubyGems:** launched 14 December 2023 (RubyGems blog, "Announcing Trusted Publishing on RubyGems.org": "Inspired by the Python package index, we're calling it Trusted Publishing.").
- **Hex:** added in October 2026.\[27\]
- **Maven Central:** **no** trusted publishing. Every file still needs a PGP `.asc` signature. Optional `.sigstore.json` files have been validated since January 2025.\[27\]\[29\]
- **Forgejo as an issuer:** **not yet accepted** by any major registry. PyPI has a discussion thread and crates.io has named it as a possibility.\[27\]

**npm's forced migration (from GitHub changelogs):**
- Classic tokens: creation disabled on 5 November 2025; all revoked on 9 December 2025.\[30\]
- Granular write tokens: capped at 90 days (7-day default).\[31\]
- `npm login` now issues 2-hour session tokens.\[32\]
- A secondary guide reports that direct publishing with granular tokens is scheduled for removal in January 2027.\[30\] I did not confirm this in a GitHub primary post.

**What trusted publishing removes:** stored registry tokens that can be stolen off laptops or out of CI secret stores.

**What it relies on:** the OIDC issuer, the registry's trust binding, and runner integrity.

**What it does *not* fix:** malicious code running inside the trusted job. The **TanStack postmortem (11 May 2026)** is the definitive case. The attacker chained a `pull_request_target` "Pwn Request", GitHub Actions cache poisoning across the fork<->base boundary, and "OIDC token extraction from runner memory" (reading `/proc/<pid>/mem` of `Runner.Worker`). The result was 84 malicious versions across 42 `@tanstack/*` packages.\[33\] Because they were published through the real release workflow's binding, they carried valid provenance.\[34\] TanStack's own lesson: the "OIDC trusted-publisher binding has no per-publish review."\[33\]

**Sigstore keyless:**
- **How it works:** Fulcio issues a short-lived certificate binding an ephemeral key to an OIDC identity, and Rekor logs the signature.\[35\]
- **What it removes:** long-lived *signer* keys.
- **What it relies on:**
  - the OIDC issuer;
  - Fulcio's CA key and Rekor's log key;
  - the Sigstore **TUF root**. This is held by 5 keyholders on hardware YubiKeys with a **3-of-5** threshold. Online timestamp and snapshot roles use cloud KMS keys,\[36\]\[37\] and the npm delegation key is in Azure Key Vault.\[38\]

How the public-good Fulcio CA and Rekor keys are stored is **not publicly documented** today. An old Fulcio README said the root ran on GCP Private CA, and Fulcio supports KMS, Google CA Service, Tink and PKCS#11 backends.\[39\]\[40\] Assume KMS/HSM custody, but treat that as inference.

### 3.3 SPIFFE/SPIRE and IETF WIMSE

**How SPIRE avoids secret zero:** two-stage attestation.
1. **Node attestation:** the agent proves which machine it runs on.
2. **Workload attestation:** the agent inspects the calling process (kernel/container metadata) and issues an SVID.

Built-in node attestors:
- `aws_iid`, `azure_imds`, `azure_msi`, `gcp_iit` (cloud identity documents);\[41\]
- `k8s_psat` (projected service-account tokens);\[41\]
- `tpm_devid` (TPM with a DevID certificate);\[41\]
- `x509pop` and `sshpop` (proof of possession of an existing cert);\[41\]
- `join_token` (a server-generated one-time token).\[41\]

**Limits:**
- `join_token` *is* a secret zero, albeit single-use.
- `x509pop` and `sshpop` move the problem to whoever provisioned that certificate.
- Cloud and k8s attestors trust the platform. Red Hat's January 2026 write-up says: "compromise the platform and you can register rogue agents."\[42\]
- On bare metal or on-prem, the only attestor that is not a secret is hardware: **TPM DevID**, or confidential-computing attestation. Red Hat's SPIRE + Confidential Containers design has a Key Broker Service that releases the `x509pop` bootstrap certificate only after TEE attestation.\[42\] This moves the root to the manufacturer's endorsement chain and the attestation verifier.

For self-hosted runners on generic VMs without vTPM, SPIRE gives you good workload identity *after* the node is attested. Node attestation itself still falls back to a join token or a provisioned certificate.

**WIMSE status:**
- `draft-ietf-wimse-arch-08`: published 6 July 2026, expires 7 January 2027, intended status **Informational**.\[7\] The charter milestone was submission to the IESG in July 2026.\[43\]
- Companion drafts: workload credentials (WIT/WPT), `draft-ietf-wimse-mutual-tls-02` (July 2026), `draft-ietf-wimse-wpt-01`, and workload-identity-practices -07. The practices draft includes a CI/CD section.\[44\]\[45\]\[46\]

None is an RFC. WIMSE standardizes formats and flows; it explicitly does **not** solve bootstrapping, saying "The protocol interaction for obtaining credentials varies with deployment and is not detailed here".\[7\]

### 3.4 Self-hosted runners and build agents

This is where secret zero most visibly comes back.

**GitHub:**
- Classic registration tokens expire after one hour, but the resulting runner keeps a long-lived credential file on disk.\[47\]
- **Just-in-time (JIT) runners** (REST `generate-jitconfig`, June 2023) create single-use runners "without time-limited registration tokens", to limit "the exposure of long lived credentials".\[48\]
- Whatever *calls* `generate-jitconfig` (a GitHub App private key or a PAT) remains long-lived.

**GitLab:**
- Since 16.0 the model is a runner authentication token (`glrt-`) created in the UI or API and stored in `config.toml`. Executors see only the per-job token.\[49\]\[50\]
- The legacy registration-token workflow is deprecated. The removal date has moved: GitLab docs said 18.0, a current docs mirror says registration tokens will be disabled in **20.0**.\[51\]\[52\] The `glrt-` token is itself a long-lived per-runner secret, with optional expiry and rotation.\[52\]

**Forgejo v15:**
- Adds **ephemeral runners**, which "can run at most one job before they get deleted by Forgejo". The mode is "enforced by Forgejo and cannot be disabled or ignored".\[53\]
- They can be created via the admin API and run with `forgejo-runner one-job`.\[54\]\[55\]
- Caveat in the docs: unassigned ephemeral runners "can continue asking Forgejo for a job until one is available and potentially linger forever".\[55\]
- The community `forgejo-ephemeral-runner` controller for Kubernetes states the residual root plainly: "The long-lived Forgejo API token is mounted only into the controller replicas."\[56\]

**Hardware-rooted alternatives:**
- TPM-bound runner keys (SPIRE `tpm_devid`, or a TPM-resident key that signs the forge challenge).
- Confidential VMs whose attestation gates the release of the runner credential (the KBS pattern).

As far as I can find, no forge natively accepts TPM or TEE attestation for runner registration. You would have to build it as an orchestrator: a broker verifies the attestation, then calls the forge's ephemeral-runner API.

### 3.5 Push/deploy to targets that do not speak OIDC

**SSH:**
- **Pattern:** exchange the CI OIDC token for a short-lived SSH certificate.
- **opkssh (OpenPubkey):** embeds the OIDC proof in an SSH certificate and verifies it in `sshd` via `AuthorizedKeysCommand`. It supports GitHub Actions and, since Forgejo v15, Forgejo/Codeberg (`opkssh login forgejo`; the server lists the issuer in `/etc/opk/providers`).\[12\]\[57\] The docs recommend the `oidc` expiry policy so the key dies with the token.\[12\]\[58\] The server-side root is the providers file plus `sub` allow-list, not a CA key. That is attractive, because no SSH CA private key exists to steal.
- **Vault SSH secrets engine, step-ca and Teleport:** a CA signs short-TTL certificates after JWT/OIDC auth. The root becomes the **SSH CA key**, which should be in an HSM/KMS.

**git push:**
- Deploy keys are long-lived SSH keys. Avoid them.
- Forge job tokens (`GITHUB_TOKEN`, Forgejo's automatic token, destroyed when the workflow finishes) cover same-repo pushes.\[59\]
- Cross-repo push on GitHub uses **App installation tokens (1-hour lifetime)**.\[60\] The App's private key is long-lived. GitHub's own docs call it "the single most valuable secret for a GitHub App" and recommend Azure Key Vault "sign-only... it can never be read from there".\[61\] There is no first-party GitHub tool for KMS-signed App JWTs, and the key is generated by GitHub and imported, not generated inside the HSM.
- Forgejo's equivalent levers are repo-scoped access tokens (new in v15).\[9\] These are still bearer tokens.

**OCI registry push:**
- Cloud registries (ECR, Artifact Registry, ACR) accept tokens derived from OIDC federation.
- Forge-integrated registries accept the per-job token.
- Third-party or on-prem registries (Harbor, Docker Hub) mostly still use robot accounts or PATs unless fronted by a token broker. I did not verify Harbor's current OIDC-for-robots status.

**On-prem HTTP targets:** they need either native JWT validation against your forge's JWKS, or a broker (Vault/OpenBao JWT auth, or SPIFFE federation).

### 3.6 Secrets managers: they move the root, they do not remove it

- **Platform integration:** Vault's `jwt`/`oidc` auth with a forge-issued token, or cloud and Kubernetes auth. Vault trusts the platform's signer, so there is no secret zero on the client.\[62\]
- **Trusted orchestrator:** an authenticated system pushes a credential, typically an AppRole SecretID wrapped in a single-use, short-TTL response-wrapping token.\[63\]\[64\] The SecretID *is* secret zero. Wrapping limits replay and makes interception detectable, but the orchestrator's own credential becomes the root.
- **Vault's own unseal key** is a further turtle. With auto-unseal it moves into a KMS/HSM.\[1\]

OpenBao inherits the same model. Conclusion: a secrets manager is a policy and audit point that converts one root into many short-lived leaves. It is valuable, but it is not elimination.

## 4. Where long-lived credentials irreducibly remain

1. **Forge OIDC signing keys:** GitHub's, GitLab's, your Forgejo instance's JWKS key. For a self-hosted forge, this is now the most important key you own.
2. **Credential-minting app/admin keys:** GitHub App private keys; the Forgejo admin API token used to create ephemeral runners.
3. **CA roots:** SSH user/host CAs, internal X.509 CAs, SPIRE upstream CA, Fulcio CA.
4. **Transparency-log and TUF roots:** Rekor log key; Sigstore TUF root (3-of-5 hardware keys); your own log's key.
5. **KMS/HSM root and unseal keys,** and the cloud account credentials that administer them.
6. **Hardware roots:** TPM endorsement keys and manufacturer CAs; TEE vendor attestation keys.
7. **Runner registration/authentication material** for persistent runners (`glrt-`, runner `.credentials`).
8. **Human break-glass** accounts and their MFA factors.

**Is it honest to say the risk was merely moved?** Yes, but "moved" undersells the change. The *number* of long-lived secrets drops from hundreds of copyable bearer tokens to a handful of keys. The *exposure* changes from "readable by any job" to "usable only through a signing API". The *blast radius* becomes time-bounded and auditable.

Three things genuinely improve:
- non-exportability (HSM, TPM, KMS sign APIs, ssh-agent);
- delegation without disclosure (the holder signs, it never reveals);
- detection (every use is logged; transparency logs make misuse publicly visible).

What does not improve: whoever can *invoke* the signing API, or run code where the short-lived token appears, inherits the power. TanStack and tj-actions are both, at root, failures of that kind.

## 5. Concrete options to avoid or minimize "key 0"

In order of preference:

1. **Replace secrets with platform attestation wherever a platform exists:**
   - forge OIDC for jobs;
   - cloud instance identity or k8s PSAT for runners;
   - TPM DevID or TEE attestation for bare metal.
2. **Make every residual root non-exportable:**
   - HSM/KMS for the forge's OIDC key, CA keys and the App key;
   - TPM-resident keys for runner hosts;
   - ssh-agent or KMS sign APIs for job-time signing, so key bytes never enter the job's memory.
3. **Make bootstrap credentials single-use and short-lived:**
   - JIT/ephemeral runners;
   - SPIRE join tokens;
   - Vault response-wrapped SecretIDs with TTLs of minutes.
4. **Scope and audience-bind every federated token:**
   - pin `iss`, `aud`, immutable `sub` (repo ID, not name), ref and workflow;
   - exclude `pull_request_target`/`workflow_run`;
   - prefer per-target audiences;
   - prefer key-bound credentials (WIMSE WIT+WPT, DPoP-style PoP) over bearer JWTs as they become available.
5. **Separate the build identity from the publish/deploy identity.** Give `id-token` permission only to a minimal release job that runs no untrusted code and restores no shared caches. Add a human or policy approval gate before publish, which TanStack lacked.
6. **Use threshold or multi-party custody for the top roots:** k-of-n hardware keys, as Sigstore does for its TUF root. Run offline root ceremonies and keep only online intermediates.
7. **Log and alert on every use of a root:** transparency logs for signatures; KMS audit logs for sign calls; alarms on any token minted outside expected workflows.
8. **Keep break-glass human-held, hardware-backed (FIDO2), rarely used and loudly audited.**

## 6. Gaps specific to self-hosted forges and non-OIDC targets

- **Gitea has no released OIDC workload identity.** If strike must support Gitea, it needs a fallback, such as a sidecar broker that authenticates the runner and mints its own JWTs. That creates a new root.
- **Forgejo OIDC is new (v15, April 2026), and Forgejo is not yet an accepted trusted publisher on registries.** Publishing to npm or PyPI from Forgejo still needs tokens or a GitHub/GitLab hop.
- **Self-hosting the issuer makes the forge a tier-0 identity provider:**
  - the OIDC signing key sits on the forge server (by default not HSM-backed);
  - the JWKS must be reachable by relying parties (cloud STS needs public reachability, or uploaded JWKS where supported);
  - key rotation is your job.
  - Gitea PR discussion surfaced a bug: auto-generated ECDSA keys use P-256 even when ES384/ES512 is configured.\[17\] This is a reminder that this code is young.
- **Runner provisioning still needs an admin credential.** Forgejo ephemeral runners remove *runner* credential reuse, not the *creator's* token.
- **No forge accepts hardware attestation for runner registration.** You have to build a broker.
- **Non-OIDC targets need a translation layer:** opkssh, SSH CA, Vault. Each adds either a CA key or an allow-list as a new root.
- **Server-identity bootstrapping (which JWKS, which host CA, which log key to trust) is out of scope in WIMSE.**\[7\] It is usually solved by pinned configuration, which is itself a trust anchor that needs protected distribution.

## 7. Threat landscape and survey data (critically assessed)

**Incidents:**
- **tj-actions/changed-files (CVE-2025-30066, March 2025):** a stolen **PAT** (traced via the reviewdog/action-setup compromise, CVE-2025-30154) let attackers retag all versions. Per GitHub Advisory GHSA-mrrh-fwg8-r2c3, the malicious script "extracted secrets from the Runner Worker process memory and printed them in GitHub Actions logs", across an action used by over 23,000 repositories. Lesson: long-lived PATs in CI, plus mutable tags.\[65\]
- **Shai-Hulud (September 2025, "2.0" in November 2025):** a self-replicating npm worm driven by stolen publish tokens; CISA's 23 September 2025 alert ("Widespread Supply Chain Compromise Impacting npm Ecosystem") stated it "has compromised over 500 packages". It directly triggered npm's token revocation and the push to trusted publishing.
- **TanStack (May 2026):** the first prominent case of the attacker *going through* trusted publishing via runner-memory token extraction. Lesson: OIDC removes stored secrets but shifts the risk to runner and pipeline integrity.\[66\]\[67\]
- **Codecov (2021) and CircleCI (January 2023):** canonical older examples of CI-held long-lived secrets being exfiltrated at scale. They are not re-verified in this pass.

**Survey data:**
- **SANS 2026 State of Identity Threats & Defenses** (500+ respondents):
  - 76% report NHI growth;\[68\]
  - 92% fail to rotate the majority of NHI credentials on a 90-day cycle, and only 8% rotate more than 75%;\[69\]
  - 55% suffered an identity compromise in 12 months despite 85% running ITDR tools;\[70\]
  - 74% use AI agents or automations that need credentials.\[71\]
- **Caveats on SANS:** the survey has commercial sponsors, and vendors such as AuthMind and P0 redistribute it as lead generation.\[72\]\[73\] The 90-day rotation metric also assumes static secrets are the norm; in a well-federated pipeline there is nothing to rotate. Read it as evidence of how widespread static NHI credentials are, not as a target.
- **Sophos State of Identity Security 2026** (5,000 organizations): 71% breached, and weak NHI management a root cause in 41%.\[74\] This is vendor research; use it directionally.
- Ratios such as "NHIs outnumber humans 100:1" appear in vendor marketing without disclosed methodology.\[74\] Disregard them for decisions.

## 8. Applicability to strike (rootless, shell-free, container-native lane executor in Go)

What fits well:
- **Forgejo >= v15 OIDC as the job identity source.** strike can implement the GitHub/Forgejo token-request contract natively in Go: GET `ACTIONS_ID_TOKEN_REQUEST_URL` with the bearer request token and a per-target `audience`.\[12\]\[75\] No external tool exec is needed. Keep the request token and the minted JWT in typed in-memory secrets. Request one audience per peer and discard the token after the exchange. Note that TanStack shows "in memory" is not a boundary against same-UID code. Run untrusted build steps in separate containers/user namespaces from the process holding the token, and never mount `/proc` of the token holder into build containers.
- **Asymmetric delegation (ssh-agent, KMS, OIDC).** This matches the "non-exportable root, delegated use" principle. For SSH deploys, prefer opkssh-style certificates minted from the Forgejo token (the server trusts the issuer plus an exact `sub`) over a long-lived key in ssh-agent. Where a CA is needed, keep it in KMS/HSM and issue minute-scale certificates.
- **DSSE attestations to a transparency log.** Two options:
  - Sign with a KMS/TPM-held key, so the root is that key, logged in Rekor.
  - Sign keyless with a Fulcio that trusts your Forgejo issuer. You would likely need to run your own Fulcio/Rekor/TUF, because I could not confirm public-good Fulcio accepts arbitrary self-hosted Forgejo issuers. That makes your TUF root and CA key new roots; protect them with threshold hardware keys.
- **Declared network peers with trust anchors.** This is the right answer to server identity. Pin JWKS URLs/keys, registry CAs and SSH host CAs per lane, and distribute the pins as signed configuration.

What realistically remains as strike's unavoidable roots:
1. Forgejo's OIDC signing key (on the forge host).
2. The credential that registers ephemeral strike runners with Forgejo (admin/org API token).
3. Any SSH/X.509 CA or attestation-signing key.
4. The transparency-log/TUF root if self-hosted.
5. Break-glass.

How to contain them:
- **(1) Forgejo signing key:** run the forge on a hardened host. Monitor the JWKS for unexpected key changes. Restrict the audience/issuer trust at every relying party. If Forgejo cannot use a PKCS#11/KMS key for OIDC signing (not verified), treat the forge host as tier-0.
- **(2) Runner-registration token:** keep it only in a small provisioning broker. Ideally the broker releases it only to hosts that pass TPM or vTPM quotes (SPIRE `tpm_devid` or a KBS-style check). Create runners as ephemeral one-job runners with short lingering timeouts.
- **(3)-(4) CA and log keys:** HSM/KMS or TPM, threshold custody for roots, short-lived intermediates.
- **Everything else:** derive from these, short TTL, audience-bound, never written to disk.

## Recommendations

1. **Standardize on Forgejo >= v15.** Do not plan around Gitea OIDC until it ships in a release.
2. **Write every relying-party trust policy against immutable identifiers.** Pin `iss` and `aud`, plus an exact `sub` including the ref and workflow file. Reject `pull_request_target`/`workflow_run`-style privileged triggers for release lanes.
3. **Split strike lanes into "build" (no identity) and "release" (identity, no untrusted code, no shared cache restore).** Add an approval or policy gate before publish/deploy.
4. **Make ephemeral one-job runners the only runner type.** Put the registration credential behind an attestation-gated broker.
5. **For SSH targets, adopt opkssh with `oidc` expiry, or an HSM-backed SSH CA.** Eliminate deploy keys.
6. **Move every remaining root into a non-exportable store and alert on every use:** Forgejo signing key if possible, CA keys, attestation key, GitHub App keys if any.
7. **Track WIMSE (WIT/WPT key-bound tokens)** and adopt proof-of-possession credentials when your relying parties support them. Bearer JWTs are the main remaining replay surface.
8. **Measure success by "number of long-lived bearer secrets in the system" trending to zero,** not by rotation percentages.

## Caveats

- Several 2026 facts come from secondary sources and were not confirmed against primary posts:
  - npm's January 2027 cutoff for granular-token publishing;
  - AWS's June 2025 OIDC guardrail;
  - the GitLab registration-token removal moving to 20.0.
- Gitea OIDC status is based on an open pull request as of late August 2026. It may have merged since.
- How the public-good Fulcio CA and Rekor keys are custodied is not publicly documented. The KMS/HSM assumption is inference.
- The nhimg.org FAQ could not be retrieved. nhimg.org also publishes vendor-adjacent guides, so its statistics were treated as secondary.
- Survey statistics (SANS, Sophos) are self-reported and commercially sponsored. They indicate prevalence, not causality.

## Quellen

1. [Delivering Secret Zero: HashiCorp Vault AppRole with HashiCorp Terraform and Chef](https://www.hashicorp.com/en/resources/delivering-secret-zero-vault-approle-terraform-chef)
2. [Solving secret zero with Vault and OpenShift Virtualization](https://www.hashicorp.com/en/blog/solving-secret-zero-with-vault-and-openshift-virtualization)
3. [The secret zero problem, and how to hand it off safely](https://credenshare.io/blog/secret-zero-problem)
4. [Secure introduction of Vault clients](https://learn.hashicorp.com/vault/security/iam-secure-intro)
5. [Solving-the-bottom-turtle-SPIFFE-SPIRE-Book.pdf](https://www.slideshare.net/slideshow/solving-the-bottom-turtle-spiffe-spire-book-pdf/269820556)
6. [The Bottom Turtle That Heals Itself - Design](https://spiffe.io/blog/2026-07-19-bottom-turtle-ha-architecture/)
7. [Workload Identity in a Multi System Environment (WIMSE) Architecture](https://datatracker.ietf.org/doc/html/draft-ietf-wimse-arch)
8. [OpenID Connect reference - GitHub Docs](https://docs.github.com/actions/reference/openid-connect-reference)
9. [Forgejo v15.0 adds repo-scoped tokens, OIDC for Actions, and major usability upgrades](https://alternativeto.net/news/2026/4/forgejo-v15-0-adds-repo-scoped-tokens-oidc-for-actions-and-major-usability-upgrades/)
10. [Forgejo 15.0 Dev Platform Released with OIDC and Ephemeral Runners](https://linuxiac.com/forgejo-15-0-dev-platform-released-with-oidc-and-ephemeral-runners/)
11. [Forgejo Actions](https://forgejo.org/docs/v15.0/user/actions/security-openid-connect/)
12. [opkssh/docs/forgejo-actions.md at main - openpubkey/opkssh - GitHub](https://github.com/openpubkey/opkssh/blob/main/docs/forgejo-actions.md)
13. [pkg.go.dev](https://pkg.go.dev/github.com/fluxcd/pkg/auth/actionsoidc)
14. [Forgejo Actions](https://forgejo.org/docs/latest/user/actions/reference/)
15. [Gitea as an OIDC IdP for Actions - Issue #26383 - go-gitea/gitea - GitHub](https://github.com/go-gitea/gitea/issues/26383)
16. [Native OIDC Token for workload identity federation - Issue #33681 - go-gitea/gitea - GitHub](https://github.com/go-gitea/gitea/issues/33681)
17. [enhance(actions): add OIDC workload identity support](https://github.com/go-gitea/gitea/pull/39052)
18. [Variables](https://docs.gitea.com/usage/actions/actions-variables/)
19. [No keys attached: Exploring GitHub-to-AWS keyless authentication flaws](https://securitylabs.datadoghq.com/articles/exploring-github-to-aws-keyless-authentication-flaws/)
20. [Life at Tinder](https://www.lifeattinder.com/blog/identifying-vulnerabilities-in-github-actions-aws-oidc-configurations)
21. [The GitHub Actions OIDC Mistake That Backdoors Your AWS](https://haitmg.pl/blog/github-actions-oidc-aws-backdoor/)
22. [Immutable subject claims for GitHub Actions OIDC tokens - GitHub Changelog](https://github.blog/changelog/2026-04-23-immutable-subject-claims-for-github-actions-oidc-tokens/)
23. [workload identities github immutable subjects](https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-github-immutable-subjects)
24. [MC1447671 - Microsoft Entra: Migrate GitHub Actions federated identity credentials to immutable subjects](https://mc.merill.net/message/MC1447671)
25. [Trusted Publishing Beyond npm and PyPI - RubyGems, NuGet.org, crates.io, pub.dev, JSR, and Open VSX: Exchanged or Used Directly, What Trust Is Bound To, and What Each Registry Rejects](https://hidekazu-konishi.com/entry/trusted_publishing_beyond_npm_and_pypi.html)
26. [draft-ietf-wimse-workload-identity-practices-01.xml](https://www.ietf.org/archive/id/draft-ietf-wimse-workload-identity-practices-01.xml)
27. [Signing and Attestations Across Package Registries](https://nesbitt.io/2026/10/30/signing-and-attestations-across-package-registries.html)
28. [npm trusted publishing with OIDC is generally available - GitHub Changelog](https://github.blog/changelog/2025-07-31-npm-trusted-publishing-with-oidc-is-generally-available/)
29. [Package Registry Security Comparison Guide](https://nhimg.org/package-registry-security-comparison-guide)
30. [npm Tokens Security Guide: Granular and Trusted Publishing](https://nhimg.org/npm-tokens-security-guide)
31. [github.com](https://github.com/ioBroker/ioBroker.javascript/issues/2001)
32. [Node.js Security Guide: npm, Runtime Risks and Secrets](https://nhimg.org/nodejs-security-guide)
33. [Postmortem: TanStack npm supply-chain compromise](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)
34. [The TanStack npm Supply Chain Attack That Hit 170 Packages and Punishes You for Revoking Your Token - Security Boulevard](https://securityboulevard.com/2026/05/the-tanstack-npm-supply-chain-attack-that-hit-170-packages-and-punishes-you-for-revoking-your-token/)
35. [docsearch.algolia.com](https://docsearch.algolia.com/mcp/docs/repo/sigstore/fulcio)
36. [github.com](https://www.github.com/sigstore/root-signing/blob/18fce446c2858b8a463c838d37612ee2420beef0/playbooks/ORCHESTRATION.md)
37. [TUF Repository State](https://tuf-repo-cdn.sigstore.dev/)
38. [root-signing/metadata/targets.json at main - sigstore/root-signing - GitHub](https://github.com/sigstore/root-signing/blob/main/metadata/targets.json)
39. [fulcio/docs/how-certificate-issuing-works.md at main - sigstore/fulcio - GitHub](https://github.com/sigstore/fulcio/blob/main/docs/how-certificate-issuing-works.md)
40. [github.com](https://github.com/sigstore/fulcio/blob/485846c13d586e6e2d213ddb40d7ba05a993530a/README.md)
41. [SPIRE Agent Configuration Reference](https://spiffe.io/docs/latest/deploying/spire_agent/)
42. [TEE-backed zero trust: Integrating SPIRE with confidential containers](https://developers.redhat.com/articles/2026/01/07/tee-backed-zero-trust-integrating-spire-confidential-containers)
43. [Workload Identity in Multi System Environments (wimse)](https://datatracker.ietf.org/wg/wimse/about/)
44. [draft-ietf-wimse-mutual-tls-02](https://datatracker.ietf.org/doc/html/draft-ietf-wimse-mutual-tls-02)
45. [draft-ietf-wimse-wpt-01](https://datatracker.ietf.org/doc/html/draft-ietf-wimse-wpt-01)
46. [draft-ietf-wimse-workload-identity-practices-07](https://datatracker.ietf.org/doc/html/draft-ietf-wimse-workload-identity-practices)
47. [Self-hosted GitHub Actions runners: ARC, security, and cost](https://tenki.cloud/blog/self-hosted-runners-arc-security-guide)
48. [GitHub Actions - Just-in-time self-hosted runners - GitHub Changelog](https://github.blog/changelog/2023-06-02-github-actions-just-in-time-self-hosted-runners/)
49. [Install GitLab Runner Operator](https://docs.gitlab.com/runner/install/operator/)
50. [GitLab token overview](https://docs.gitlab.com/security/tokens/)
51. [Registering a Gitlab Runner - DevOps Division Guidebook](https://guidebook.devops.uis.cam.ac.uk/howtos/git-gitlab/register-a-gitlab-runner/)
52. [New creation workflow - Runners - Ci - Help - GitLab](https://salsa.debian.org/help/ci/runners/new_creation_workflow.md)
53. [Forgejo Runner Registration](https://forgejo.org/docs/latest/admin/actions/registration/)
54. [Forgejo v15.0 is available -- Forgejo](https://forgejo.org/2026-04-release-v15-0/)
55. [Securing Forgejo Actions Deployments](https://forgejo.org/docs/v15.0/admin/actions/security/)
56. [GitHub - neodymium6/forgejo-ephemeral-runner: One-job Forgejo Actions runners recycled as isolated Kubernetes Pods - GitHub](https://github.com/neodymium6/forgejo-ephemeral-runner)
57. [GitHub - openpubkey/opkssh: opkssh (OpenPubkey SSH) - GitHub](https://github.com/openpubkey/opkssh)
58. [opkssh command - github.com/openpubkey/opkssh - Go Packages](https://pkg.go.dev/github.com/openpubkey/opkssh)
59. [Forgejo Actions | Security](https://forgejo.org/docs/latest/user/actions/security)
60. [Authenticating as a GitHub App installation - GitHub Docs](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation)
61. [Managing private keys for GitHub Apps - GitHub Docs](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps)
62. [Secure introduction of Vault clients](https://developer.hashicorp.com/vault/tutorials/app-integration/secure-introduction)
63. [Use AppRole authentication](https://developer.hashicorp.com/vault/docs/auth/approle)
64. [Secret Zero Problem Solved for HashiCorp Vault](https://tekanaid.com/posts/secret-zero-problem-solved-for-hashicorp-vault)
65. [CVE-2025-30066: Tj-actions Changed-files Disclosure Flaw](https://www.sentinelone.com/vulnerability-database/cve-2025-30066/)
66. [npm Supply Chain: The Worm That Walked In Through Trusted Publishing - DEV Community](https://dev.to/marco_odev/npm-supply-chain-the-worm-that-walked-in-through-trusted-publishing-4pm8)
67. [Postmortem: TanStack npm supply-chain compromise -- HN Top](https://mindbento.com/hn-top/tanstack-npm-packages-compromised)
68. [Governance Gaps Emerge as AI Agents Drive 76% Increase in NHIs - Infosecurity Magazine](https://www.infosecurity-magazine.com/news/governance-gaps-agents-76-increase/)
69. [2026 SANS State of Identity Threats & Defenses Survey Insights Event](https://www.sans.org/white-papers/2026-state-of-identity-threats-defenses-survey-how-identity-became-new-security-perimeter)
70. [SANS 2026 State of Identity Threat Detection and Response: Key Findings](https://www.sans.org/research/identity-threat-detection-response-report)
71. [SANS survey finds machine identities surge as 76% of organisations report growth and Agentic AI exposes new governance gaps](https://www.intelligentciso.com/2026/04/09/sans-survey-finds-machine-identities-surge-as-76-of-organisations-report-growth-and-agentic-ai-exposes-new-governance-gaps/)
72. [2026 SANS State of Identity Threats and Defenses Survey Insights Report](https://www.authmind.com/2026-sans-identity-threats-and-defenses-survey-insights-report)
73. [2026 SANS survey: why identity attacks still get through](https://p0.dev/resource/2026-sans-report/)
74. [The State of Identity Security 2026: Identity is the new perimeter](https://www.sophos.com/en-us/blog/sophos-state-of-identity-security-2026)
75. [pkg.go.dev](https://pkg.go.dev/github.com/fluxcd/pkg/auth@v0.49.0/actionsoidc)
