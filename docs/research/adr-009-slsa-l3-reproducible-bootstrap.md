# Trusting-Trust-Resistant, Reproducible Bootstrap for a SLSA Build L3 Build Tool (Go Control Plane)

## 0. Executive summary

You can build a bootstrap process that is both **reproducible** and **trusting-trust resistant** for a Go build tool that must (a) ship its own releases at SLSA Build L3 and (b) act as an L3 build platform for downstream builds. But three properties must be kept strictly separate: SLSA Build L3 (v1.2, approved November 2025) is about *provenance integrity + build isolation under a trusted platform*; reproducible builds add independent *verification of outputs*; and diverse double-compiling (DDC) / full-source bootstrap remove *trust in the toolchain binary itself*. SLSA Build L3 does NOT require reproducible or hermetic builds -- those are documented as "future directions." Your two properties are additive, and each defeats a threat class L3 does not.

The good news for Go: pure-Go builds (`CGO_ENABLED=0 go build -trimpath`) are reproducible, and the Go toolchain itself has been bit-for-bit reproducible since Go 1.21 ("Go 1.21.0 is the first Go toolchain with perfectly reproducible builds," go.dev/blog/rebuild) and is continuously verified by `gorebuild`. This makes the compiler a *fixed, verifiable input*, which in turn makes a 3-stage self-build of your tool a strong test of your *orchestration* -- but note carefully: a self-build of your tool proves nothing about the compiler. Toolchain trust needs a separate, diverse path (a Guix full-source chain and/or GCC-vs-Clang-rooted Go 1.4 chains). gccgo is NOT a viable DDC partner for today's toolchain (stuck at the Go 1.18 standard library, no generics).

The recommendation is a three-tier program: **Tier 1** (gorebuild-verified go.dev toolchain + N-of-M independent rebuilds of the tool), **Tier 2** (DDC of the tool with two independently-produced toolchains of the same Go version), **Tier 3** (full-source-bootstrapped build environment + measured/attested control plane binding the signing identity to a publicly-reproduced digest).

---

## 1. Goal decomposition and what SLSA Build L3 (v1.2) does and does NOT cover

### 1.1 The L3 build-platform requirements (verbatim, slsa.dev/spec/v1.2/build-requirements)

SLSA v1.2 splits Build responsibility between the *Producer* and the *Build platform*. The build platform provides two things: **provenance generation** and **isolation between builds**. The two requirements that define L3 (both marked yes only in the L3 column) are:

**Provenance is Unforgeable** (Accuracy):
> "Provenance MUST be strongly resistant to forgery by tenants. Any secret material used for authenticating the provenance, for example the signing key used to generate a digital signature, MUST be stored in a secure management system appropriate for such material and accessible only to the build service account. Such secret material MUST NOT be accessible to the environment running the user-defined build steps. Every field in the provenance MUST be generated or verified by the build platform in a trusted control plane. The user-controlled build steps MUST NOT be able to inject or alter the contents, except as noted in Provenance is Authentic." And: "External parameters MUST be fully enumerated. Completeness of resolved dependencies is best effort."

**Isolated** (Isolation strength):
> "The build platform ensured that the build steps ran in an isolated environment, free of unintended external influence... It MUST NOT be possible for a build to access any secrets of the build platform, such as the provenance signing key... It MUST NOT be possible for two builds that overlap in time to influence one another... It MUST NOT be possible for one build to persist or influence the build environment of a subsequent build. In other words, an ephemeral build environment MUST be provisioned for each build. It MUST NOT be possible for one build to inject false entries into a build cache used by another build, also known as 'cache poisoning'. In other words, the output of the build MUST be identical whether or not the cache is used. The build platform MUST NOT open services that allow for remote influence unless all such interactions are captured as externalParameters in the provenance."

Crucially the spec adds a NOTE:
> "This requirement is not to be confused with 'Hermetic', which roughly means that the build ran with no network access. Such a requirement requires substantial changes to both the build platform and each individual build, and is considered in the future directions."

### 1.2 Future directions: hermetic, reproducible, and a possible Build L4

The v1.2 future-directions page lists as things "which may or may not be part of a future Build L4": pinned dependencies, hermetic builds, all dependencies listed in provenance, and "Reproducible builds, which enable other build platforms to corroborate the provenance." The SLSA FAQ is explicit: "SLSA does not require verified reproducible builds directly. Instead, verified reproducible builds are one option for implementing the requirements." So **reproducibility is a means, not a level requirement**. L4 is documented as a future target rather than a published production level. (The Source track, by contrast, was promoted from experimental to approved in v1.2.)

### 1.3 How the three properties relate, and which threats each addresses

- **SLSA Build L3** protects provenance integrity + isolation *assuming the build platform is trusted*. It mitigates tenant-side tampering (a malicious build step forging provenance or poisoning another build) and gives consumers an authenticated, complete record of *external parameters*. It does NOT protect against a compromised build platform, a malicious source, or compromised dependencies beyond what is recorded. The isolation requirements specifically defeat build-time cross-build influence (in-build "SUNSPOT-style" tampering) and signing-key exfiltration.
- **Reproducible builds** give *trust-but-verify*: a second, independent party rebuilds from the same inputs and confirms bit-for-bit identity. This detects a *compromised build platform* or tampered output that L3 alone would sign as authentic -- exactly the SolarWinds/XZ class that L3's isolation does not catch.
- **DDC / full-source bootstrap** removes trust in the *toolchain binaries* -- the Thompson "trusting trust" attack, where a subverted compiler reproduces its backdoor and reproducible builds alone would faithfully reproduce the malicious bits. The Go blog itself makes this point: "reproducing the Go Ubuntu package from clean sources using those malicious tools would still produce bit-for-bit identical copies of the malicious packages. This attack would be invisible to that kind of rebuild, much like Ken Thompson's compiler attack." The countermeasure is Wheeler's Diverse Double-Compiling (ACSAC 2005; PhD, George Mason University, 2009): "recompile the source code twice: once with a second (trusted) compiler, and again using the result of the first compilation. If the result is bit-for-bit identical with the untrusted binary, then the source code accurately represents the binary." DDC presupposes deterministic/reproducible compilation.

For source-level threats (malicious commits), SLSA v1.2 now has a **Source track** (L1-L4, peaking at mandatory two-person review) -- that is the correct place to address them, out of scope for this build-bootstrap report except as a pointer.

### 1.4 The Trusted Computing Base (TCB) of the stated architecture

Even with all three properties, the following remain in your TCB and must be named explicitly:

- The **control plane binary** itself (your tool).
- The **Go toolchain** used to build it.
- The **container engine**: containerd/BuildKit, Podman, or Docker Engine -- themselves large Go programs. The **runtime** matters: `runc` uses cgo; `crun` is C. A daemon running as root can read container memory and host files.
- **Base images**, the **host OS/kernel**, the **hardware/firmware**.
- **Signing infrastructure** (Sigstore Fulcio/Rekor, or KMS/HSM), the **registry**, and the **transparency log** (a new trust root, governed by a TUF root).

**Design point (recommendation):** "registry push only through the control plane" is good -- it means user build steps cannot push arbitrary artifacts or bypass provenance attachment, and it lets the control plane hash the output before it is published. But it does **not** by itself make provenance unforgeable. Unforgeability comes from (1) keeping signing material out of build-step containers and (2) generating every provenance field from the control plane's own observations. Push-through-control-plane is an *output-integrity and provenance-attachment* control, not the unforgeability control.

---

## 2. Part A -- Bootstrapping the tool itself (Go control plane)

### 2.1 Stage design (design reasoning)

**stage0** -- a minimal, auditable shell script that runs `CGO_ENABLED=0 go build -trimpath ...` with a pinned, gorebuild-verified Go toolchain in a fixed environment. No self-hosting is needed here because `go build` is itself a build tool; stage0 exists to produce a trustworthy *first* tool binary.

**stage1** -- the tool built by stage0 rebuilds itself using its own container-orchestrated pipeline (the same pipeline it will offer downstream).

**stage2** -- the stage1 tool rebuilds itself again.

**Requirement:** stage0 == stage1 == stage2, bit-identical.

Why this identity is a *strong* test here but *weak* for a compiler: because the Go compiler is a fixed, externally-verified input (gorebuild), any difference between stages is attributable to *your orchestration* (environment leakage, timestamps, non-determinism in image assembly), not to a self-perpetuating compiler payload. This is the opposite of the classic compiler self-build. Note the precedents and their limits: Gradle's "Gradleception" (Gradle builds Gradle) is the closest build-tool analogue and is a good functional/orchestration test; GCC's stage2-vs-stage3 comparison is a *self-consistency* check, not a trust guarantee; and Go's own `cmd/dist` builds toolchain1/2/3 but does **not** diff toolchain2 against toolchain3, so it is not a DDC either. A 3-stage self-build of *your tool* verifies your orchestration; it says nothing about the compiler. That is what Section 2.3 is for.

### 2.2 Go reproducibility recipe (verified against Go docs/source)

- **`-trimpath`**: removes absolute module/filesystem paths from the binary; required for reproducibility (Go blog: "For Go programs that don't need cgo, a reproducible build is as simple as compiling with `CGO_ENABLED=0 go build -trimpath`. Disabling cgo removes the host C toolchain as a relevant input, and -trimpath removes the current directory").
- **`CGO_ENABLED=0`**: removes the host C toolchain as an input. This is the user's stated assumption and materially simplifies reproducibility (no external gcc/clang version to pin).
- **`-buildvcs`**: Go 1.18+ embeds VCS info (commit, "modified" flag). For deterministic builds either set `-buildvcs=false` or ensure a clean, pinned checkout so the embedded revision is stable. The hashicorp reproducible-build action recommends `-trimpath -buildvcs=false` as the baseline.
- **`-buildid` / `-ldflags`**: even with `-trimpath`, development toolchains can differ only in the build ID; the known fix is `-ldflags=all=-buildid=` (golang/go#59525, #34186). Avoid `-X` injections of timestamps or non-deterministic values; if you must stamp a version, derive it from `SOURCE_DATE_EPOCH`/commit time, not wall clock.
- **Environment that must be pinned**: `GOOS`, `GOARCH`, `GOAMD64`/`GOARM`, `GOEXPERIMENT`, `GOFLAGS`, and build tags -- all change output.
- **`GOTOOLCHAIN=local`**: set this to prevent the `go` command from auto-downloading/switching to a toolchain named in `go.mod`/`go.work` (go.dev/doc/toolchain). Hermetic builds require `local` so the build cannot silently pull a different compiler.
- **Modules & integrity**: `GOPROXY=off` with vendored deps (`-mod=vendor`) or a pinned proxy; `go.sum` + `GOSUMDB` (the `sum.golang.org` transparency log) protect module integrity; `go mod verify` checks the module cache against `go.sum` (the `h1:` dirhash covers the module file tree). For hermetic builds, vendoring or a pre-populated, digest-verified module cache is cleanest.
- **`go:embed`** is deterministic given identical file bytes.
- **What `gorebuild` does** (pkg.go.dev/golang.org/x/build/cmd/gorebuild): starts from the Go git source and rebuilds the distributions posted on go.dev/dl, "checks that the local rebuild produces a bit-for-bit identical copy of the file posted at https://go.dev/dl/" (macOS tar.gz and the Windows MSI use relaxed content checks). It considers only Go >= 1.21 "because Go 1.20 and earlier did not ship reproducible toolchains." The go.dev/rebuild page is refreshed daily in an Ubuntu VM. gorebuild itself needs a bootstrap toolchain to run. The Go team also builds each release on two dissimilar systems (Linux/x86-64 and Windows/x86-64) that "must produce bit-for-bit identical archives or else we do not proceed with the release."
- **Current release facts (primary sources)**: **Go 1.27.0 was released 19 August 2026** (go.dev/blog/go1.27: "Today the Go team is pleased to release Go 1.27"; patch go1.27.1 followed 1 September 2026). **Go 1.26 requires Go 1.24.6 or later for bootstrap** (Go 1.26 Release Notes: "Go 1.26 now requires Go 1.24.6 or later for bootstrap. We expect that Go 1.28 will require a minor release of Go 1.26 or later for bootstrap"). The general rule in `cmd/dist`: Go 1.N needs Go 1.M where M = N-2 rounded down to even.

### 2.3 Toolchain trust / trusting-trust resistance -- the core

#### (i) The from-source chain

The Go gc toolchain roots in Go 1.4 (last C-implemented compiler). The forward chain to the current release, verified from `go.dev/doc/install/source`, release notes, and `cmd/dist` history:

- Go <= 1.4: built by a **C toolchain**.
- Go 1.5-1.19: bootstrap with Go 1.4 (the `go15bootstrap` design hard-coded 1.4 as the base).
- Go 1.20/1.21: minimum bootstrap raised to **Go 1.17.13** (cmd/dist README/build.go diff: "Build cmd/dist with Go 1.17.13").
- Go 1.22/1.23: require the final point release of **Go 1.20** or later.
- Go 1.24/1.25: require **Go 1.22.6+**.
- Go 1.26/1.27: require **go1.24.6**.

So a complete from-source chain today is approximately: **C compiler -> Go 1.4 -> 1.17.13 -> 1.20.x -> 1.22.6 -> 1.24.6 -> 1.26/1.27**. Guix's own package set mirrors this: `go@1.4-bootstrap-20171003`, then `go@1.17.13`, `go@1.20.14`, `go@1.22.12`, `go@1.24.13`, `go@1.25.10`, `go@1.26.4` are packaged.

**Diversity at the C root (DDC through the chain):** build Go 1.4 with GCC and separately with Clang (and/or a Guix full-source-bootstrapped GCC), run *both* chains forward, and compare the final toolchains. Where bit-for-bit comparison is possible: only from Go 1.21 onward are outputs *perfectly* reproducible, so the strongest equality check applies to the last hops (1.21+ -> current). For pre-1.21 hops you cannot rely on bit-identity; there you compare *behaviour* -- does hop N built via the GCC-root produce the *same* next-hop toolchain (1.21+) as hop N built via the Clang-root? The design of Go's toolchain3 stage means the final toolchain should be independent of the bootstrap compiler: toolchain2 is rebuilt by toolchain1 and (from 1.21) the result is reproducible, so the final artifacts should not depend on which conformant bootstrap was used -- precisely the property DDC exploits.

#### (ii) Existing independently bootstrapped Go toolchains as the diverse path

- **GNU Guix**: packages `go@1.4-bootstrap-20171003` and chains upward; on platforms Go 1.4 does not target, Guix bootstraps Go from **gccgo** (patch: "go automatically bootstraps from gccgo on platforms not supported by go 1.4"). Guix also provides the **full-source bootstrap**: per the GNU Guix 2023 blog "The Full-Source Bootstrap," "If you run guix pull today, you get a package graph of more than 22,000 nodes rooted in a 357-byte program" -- the hex0-seed from Jeremiah Orians' stage0-posix (hex0 -> hex1 -> catm -> hex2 -> M0 -> cc_x86 -> M1 -> M2 -> M2-Planet -> GNU Mes -> tcc -> gcc-mesboot), so a Guix-chain Go is ultimately rooted in auditable source, not a vendor binary. This is the best-in-class diverse path.
- **nixpkgs**: `pkgs/development/compilers/go/` contains `binary.nix`, `bootstrap122.nix`, `bootstrap124.nix`, plus `1.25.nix`/`1.26.nix`. nixpkgs bootstraps from an *earlier Go* (Go 1.22/1.24 bootstrap stages), themselves ultimately seeded from a prebuilt `binary.nix` -- i.e., nixpkgs does **not** currently chain from Go 1.4 source by default; it uses a binary bootstrap Go. So nixpkgs gives build-environment diversity but is a weaker trusting-trust root than Guix's full-source chain.
- **Debian / others**: Debian and Guix historically used **gccgo** to bootstrap on architectures Go 1.4 never supported; each `golang-1.N` is built from an earlier Go. Buildroot chains `go-bootstrap-stage3` -> `stage4` (e.g., Go 1.23.12 to bootstrap 1.25.1). Fedora/Alpine similarly build from an earlier Go binary.

#### (iii) gccgo as a DDC partner -- verdict

gccgo is a genuinely different implementation (GCC back end, separate front end), which is exactly what DDC wants. But it is **stuck on the Go 1.18 standard library and lacks generics support** (official Go docs; a golang-dev thread confirms it has been stuck "on basically Go 1.18 standard library features for a while, due to the lack of generics support in the frontend"). Since the current gc toolchain and cmd/compile use generics, gccgo **cannot build a current gc toolchain** (golang/go#51027 and #47771 show gccgo bootstrap of even Go 1.17 already segfaulting/failing). **Verdict: gccgo is usable only as a historical root (to build old Go such as 1.4-1.16 on exotic platforms), NOT as a DDC partner for today's toolchain.** TinyGo and llgo are LLVM-based and target a subset; they cannot build the gc toolchain/stdlib either. This directly refutes the common assumption that "gccgo is available as a DDC partner."

#### (iv) Verification against the vendor

Use go.dev/dl checksums, the daily `gorebuild` continuous verification, and -- as third-party corroboration -- the fact that distro packages (Ubuntu golang-1.21, etc.) reproduce the same binaries from source. Anyone can run `go run golang.org/x/build/cmd/gorebuild@latest` to independently reproduce the exact archives.

#### Tiered recommendation for toolchain trust

- **Tier 1** -- gorebuild-verified go.dev toolchain, pinned by sha256; build the tool on >=2 independent infrastructures with N-of-M digest agreement. *Defeats:* a tampered posted toolchain binary and a single compromised build host. *Residual:* a backdoor present in the *source* or in the reproducible upstream toolchain itself. *Cost:* low.
- **Tier 2** -- DDC: build the tool with the go.dev toolchain AND with a Guix-chain-built toolchain of the *same* Go version (optionally GCC- vs Clang-rooted Go 1.4 chains); require bit-identical tool output. *Defeats:* trusting-trust in the compiler binary. *Residual:* shared source-level backdoor; shared C-compiler/hardware root if diversity is incomplete. *Cost:* medium-high (maintaining a second toolchain path).
- **Tier 3** -- entire build environment (incl. base image) from a full-source bootstrap (`guix pack -f docker`), plus a measured/attested control plane (Part B). *Defeats:* trust in prebuilt binary seeds and in the runtime integrity of the platform. *Residual:* hardware/firmware trojans; source review gaps. *Cost:* high.

### 2.4 Container engine and base images as untrusted executors

Treat the engine and base images as executors, not roots of trust:

- **Digest-pin everything**: OCI images by `@sha256:...`, the Go toolchain archive by sha256, modules by `go.sum`.
- **No network in build steps**: hermeticity is not required by L3 but is required for *reproducibility* -- an unpinned network fetch is a non-deterministic input. This is a case where your added properties impose more than L3.
- **Cross-engine / cross-host reproduction**: outputs verified by rebuilding under a second engine and a second host.
- **Rebuild the engine binaries too**: verify runc/containerd/BuildKit/Podman against distro/nixpkgs/Guix reproducible builds where tracked (note the runc cgo caveat -- cgo reintroduces a host C toolchain as an input). Debian and NixOS reproducible-build trackers cover many of these.
- **Base image options** (increasing bootstrap strength): `scratch`; distroless static; Chainguard static; **apko/melange**-built images (apko produces reproducible, declarative images and SBOMs); Nix `dockerTools`; and `guix pack -f docker` (full-source-bootstrapped, the strongest).

### 2.5 Deterministic OCI artifact assembly in the CONTROL PLANE

OCI images are nondeterministic by default (timestamps, tar entry ordering, gzip/zstd variation, config JSON key ordering). Two robust approaches:

- **ko** (ko-build/ko): the canonical Go tool that assembles OCI images **without a container engine**, directly from the compiled Go binary. ko "omits timestamps from images by default to support reproducible output"; honors `SOURCE_DATE_EPOCH` (ko 0.19.1) for a stable config timestamp; produces SPDX SBOMs attached as OCI artifacts; and supports Sigstore signing. It can emit an OCI layout (`--oci-layout-path`) for air-gapped/controlled delivery.
- **BuildKit**: supports `SOURCE_DATE_EPOCH` and `rewrite-timestamp=true` to normalize layer timestamps (reproducible-builds.org documents both); it can also natively emit SLSA provenance (see Section 3, on why that provenance is not your signed record).

**Recommendation:** have the control plane assemble the image from the reproducible Go binary using **go-containerregistry-style code (ko-style)** rather than delegating image assembly to the engine. This keeps image bytes deterministic *and* keeps assembly inside the trusted control plane, which is exactly where unforgeable provenance must be generated. Attach attestations via the **OCI 1.1 referrers API**.

### 2.6 L3 provenance for the tool's own releases and the "genesis" problem

Use the **in-toto Statement + SLSA Provenance v1 predicate**. Verified field semantics (slsa.dev/spec/v1.2/provenance; the text description is authoritative over the informative CUE/protobuf schemas):

- Statement `_type` = `https://in-toto.io/Statement/v1`; `predicateType` = **`https://slsa.dev/provenance/v1`** (the spec warns: "Always use the above string for `predicateType` rather than what is in the URL bar" -- it is *not* a v1.2-specific URI); `subject` = the output artifacts by digest.
- `predicate.buildDefinition` = `{ buildType, externalParameters, internalParameters, resolvedDependencies }`. `buildType` and `externalParameters` are REQUIRED from L1. **`externalParameters` MUST be complete at L3** ("They MUST be complete at SLSA Build L3, meaning that there is no additional mechanism for an external party to influence the build"); verifiers "SHOULD reject unrecognized or unexpected fields within `externalParameters`." `internalParameters` is platform-controlled and "need not be verified." `resolvedDependencies` completeness is "best effort, at least through SLSA Build L3."
- `predicate.runDetails` = `{ builder{ id, builderDependencies, version }, metadata{ invocationId, startedOn, finishedOn }, byproducts }`. `builder.id` is REQUIRED and "is intended to be the sole determiner of the SLSA Build level"; "if a build platform has multiple modes of operations that have differing security attributes or SLSA Build levels, each mode MUST have a different `builder.id` and SHOULD have a different signer identity." `byproducts` is the correct home for the engine-generated BuildKit provenance and build logs ("files that are likely to be useful later and that cannot be easily reproduced"). Only `buildDefinition` and `runDetails` (and within them `buildType`, `externalParameters`, `builder.id`) are strictly REQUIRED; the only field-level requirement that escalates at L3 is `externalParameters` completeness.

For the **tool's own build**, put in `externalParameters`: source repo URI + commit digest and the pipeline-definition path; in `resolvedDependencies`: the Go toolchain archive + sha256, the module list with `go.sum` hashes, and base-image digests. Wrap in a **DSSE** envelope.

**Signing options:**
- Sigstore keyless via **Fulcio + Rekor** using the control plane's OIDC/workload identity. Note the 2026 state: **Rekor v2 ("Rekor on Tiles")** is GA -- a tile-backed transparency log (Trillian-Tessera backend); clients must fetch log-shard URLs from Sigstore's TUF `SigningConfig` and MUST NOT hardcode them; requires cosign >= v3.0.1 / v2.6.0. Rekor v1 is in maintenance mode.
- Or **KMS/HSM keys** for a self-hosted anchor.
- For a self-hosted control plane, bind identity via **SPIFFE/SPIRE** workload identity. (FRSCA -- Factory for Repeatable Secure Creation of Artifacts -- is the CNCF/Tekton reference here; treat its production-readiness as an open question to verify at adoption time.)

**builder.id lineage / genesis:** release N is built by release N-1 (or, at the root, by the stage0 script under a *distinct* "bootstrap builder" `builder.id` and signer). The chain terminates in a documented, reproducible, multi-party-verified **genesis** build. Adopt an **N-of-M independent-rebuild policy** for genesis *and every release*: independent rebuilders confirm the digest, and agreement is recorded (in Rekor). Precedents: Debian reproducible-builds infrastructure, Arch's **rebuilderd**, and Go's `gorebuild` are all working N-of-M / continuous-rebuild systems. Issue **Verification Summary Attestations (VSA)** per v1.2 to summarize the verified result for downstream consumers.

**Consumer verification tooling (2026 state):** the SLSA verifier's `build` subcommand binds a signed attestation's `builder.id` to its signer through a **builder registry**; "a builder nothing binds is reported unproven." Historically `slsa-verifier` was oriented to known CI builders (GitHub, GCB) via the BYOB model and `--builder-id`; the newer `slsa-framework/verifier` adds `--signer`, per-verifier binding, VSA verification, and `--require-signatures`. For a **custom/self-hosted builder**, the pragmatic path today is **cosign `verify-attestation` with a policy engine (CUE/Rego)** pinning your `builder.id` and signer identity, plus the SLSA verifier where your builder can be registered. Be precise with the user: out-of-the-box, first-class L3 verification is best supported for the well-known builders; a self-hosted builder requires you to publish your `builder.id` documentation and distribute your signer identity to verifiers.

### 2.7 Crisp distinction (restated)

`stage0==stage1==stage2` tests the **orchestration** you own. Cross-toolchain identity (go.dev vs Guix-chain vs GCC/Clang-rooted chains) is the **DDC test of the compiler**. Neither substitutes for the other.

---

## 3. Part B -- The tool as a SLSA v1.2 Build L3 platform for downstream builds

Mapping each requirement to the stated architecture (control plane orchestrates a container engine via API; registry push only through the control plane):

### 3.1 Unforgeable provenance
- Provenance generated **exclusively by the control plane** from its own observations of the orchestration -- never assembled by a build-step container.
- Signing material **never present** in build-step containers; held in KMS/HSM or minted via a keyless flow the data plane cannot reach.
- Put the control plane in a **separate trust domain** from the execution hosts. Argument: a container engine daemon (dockerd/containerd) running as root can read container memory and host files, so **co-locating the engine with the control plane puts the engine host inside the control plane's TCB**. Recommendation: separate host/VM for execution; mTLS from control plane to the engine API; the engine socket and control-plane API unreachable from build containers via network policy.

### 3.2 Isolated / ephemeral environments
- Fresh container **per step**; environments never reused (spec: "an ephemeral build environment MUST be provisioned for each build").
- No privileged containers; no host mounts; user namespaces / rootless engines; seccomp/AppArmor; read-only rootfs.
- For multi-tenancy, stronger sandboxes: **gVisor**, **Kata/Firecracker** microVMs.
- **Egress denied** or routed via a control-plane-owned proxy/mirror serving only pre-resolved, digest-verified inputs.
- **Caches** only if content-addressed and validated -- the spec's rule: "the output of the build MUST be identical whether or not the cache is used."
- Per-build namespaces / per-tenant hosts; **output collection by the control plane** (control plane pulls, hashes, and pushes) so user steps cannot alter artifacts or provenance after the fact. This is precisely what "registry push only through the control plane" buys you.

### 3.3 Provenance content for downstream builds
- Define a **versioned `buildType` URI** with a documented schema (per spec, the URI SHOULD resolve to a human-readable spec with schema for external/internal parameters and a complete example).
- Record for each downstream build: build-config source + digest and resolved OCI image digests in `externalParameters`/`resolvedDependencies`; the **tool version = its own verified digest** and the **engine version** in `internalParameters`. Remember: `externalParameters` MUST be fully enumerated; `resolvedDependencies` is best-effort.

### 3.4 Builder identity -- how downstream verifiers come to trust the control plane
- The anchor is **your own reproducible, L3-provenanced, N-of-M-verified release**: consumers trust the platform because its binary is independently reproducible and its `builder.id` documents its guarantees.
- **Advanced tier**: bind the signing identity to a **measured control plane** -- TPM measured boot or confidential-computing attestation (**AMD SEV-SNP / Intel TDX**), with **KMS key release conditioned on the attested image digest** matching the reproducibly-built, publicly-verified digest. Azure Key Vault "Secure Key Release" and GCP Confidential Space implement exactly this attestation-bound key-release pattern (AKV releases an exportable key only after a confidential VM presents an attested SEV-SNP platform report). Cite precedents without overclaiming: **Binary Authorization for Borg** (Google-internal origin of SLSA), **Project Oak / Transparent Release** (endorsement statements in Rekor), Google **Confidential Space**, and **Edgeless Constellation** (confidential Kubernetes).

### 3.5 Calibration against existing L3 reference platforms
- **slsa-github-generator** (reusable-workflow builder + BYOB framework) and **GitHub artifact attestations**: by itself artifact attestations give **SLSA v1.0 Build L2** -- GitHub Docs state, "Artifact attestations by itself provides SLSA v1.0 Build Level 2 ... Reusable workflows can provide isolation between the build process and the calling workflow, to meet SLSA v1.0 Build Level 3." The reason attest-build-provenance alone is L2: signing key material can be reachable by user-defined steps in the same job VM (Ian Lewis' analysis notes L3 relies on reusable workflows running "on jobs executed on separate virtual machines") -- a direct illustration of your unforgeability requirement.
- **Google Cloud Build** and **Tekton Chains** are L3-capable references; **FRSCA** is the self-hostable reference (verify maturity at adoption).
- **BuildKit's built-in provenance** (`--provenance mode=max`): useful and detailed (records buildType `https://mobyproject.org/buildkit@v1`, external parameters, resolved materials by digest), but in *this* architecture engine-generated provenance is NOT "unforgeable" from the control plane's perspective -- the engine is an untrusted executor. Capture it as a **byproduct / internal detail**, but the **signed statement of record MUST be the control plane's own** provenance.

### 3.6 Kubernetes as a large-scale Go precedent
Kubernetes' release process (kubernetes/release, `krel`/`anago`, Google Cloud Build) moved through SLSA compliance (SIG Release tracked SLSA L1 -> L3 in kubernetes/release), generating in-toto SLSA provenance from the GCB environment and promoting images through a controlled Container Image Promoter -- a working, large-scale Go example of control-plane-generated provenance. Note: their provenance reached Build L3; full bit-for-bit reproducibility of all Kubernetes artifacts is a separate, harder goal not fully claimed.

---

## 4. Part C -- Verification matrix and residual threat model

### 4.1 Comparisons that must be bit-identical

| # | Comparison | Who performs it | A mismatch indicates |
|---|-----------|-----------------|----------------------|
| 1 | go.dev toolchain vs `gorebuild` vs Guix-chain toolchain (same version) | Vendor + you + independent rebuilders | Tampered/backdoored toolchain (trusting trust) |
| 2 | Tool stage0 vs stage1 vs stage2 | Your pipeline | Non-determinism/leak in your orchestration |
| 3 | Engine A vs Engine B build of the tool/artifact | You | Engine-introduced non-determinism or tampering |
| 4 | Org/infra 1 vs infra 2 (N-of-M) | Independent orgs/rebuilders | Single-host compromise |
| 5 | Release digest vs Rekor entries | Consumers | Undisclosed/forged release |
| 6 | Downstream artifact reproductions | Downstream consumers/rebuilders | Platform compromise or tampered output |

### 4.2 Residual risks (explicit)
- **Hardware/firmware/kernel trojans** -- outside DDC unless you add hardware-diverse rebuilders.
- **Sigstore/Rekor/Fulcio as a new trust root** -- TUF root and key-compromise risk; Rekor v2 witness/co-signing (append-only guarantees via a witness network) is still maturing.
- **Source-level backdoors** -- not a build problem; use the SLSA Source track + review.
- **Dependency compromise beyond checksums** -- `go.sum` proves *what* you got, not that it is benign; add `govulncheck`, `capslock`, and vendoring review.
- **Runtime compromise of the control plane** -- mitigated only by a measured/attested control plane (Tier 3).
- **Engine as executor** -- a root daemon is powerful; isolate it.
- **Non-determinism creep** -- cgo, `GOEXPERIMENT`, build tags, `GOAMD64`, VCS stamping, `-X` ldflags, gzip levels. Guard with CI diffing (comparisons #2/#3).

### 4.3 Implicit assumptions in the user's question that the evidence challenges
1. **"SLSA L3 implies reproducible/hermetic"** -- false. L3 (v1.2) requires unforgeable provenance + isolation; reproducible and hermetic are explicitly *future directions*.
2. **"Registry push via control plane = unforgeable provenance"** -- false. It aids output integrity and attachment; unforgeability requires key isolation + control-plane-only field generation.
3. **"gccgo is available as a DDC partner"** -- false today. gccgo is stuck at the Go 1.18 stdlib without generics and cannot build the current gc toolchain.
4. **"Go's 3-toolchain bootstrap self-verifies"** -- false. `cmd/dist` builds toolchain1/2/3 but does not diff toolchain2 vs toolchain3; it is a functional bootstrap, not a DDC.
5. **"A 3-stage self-build of the tool verifies the compiler"** -- false. With a fixed compiler it verifies your orchestration only; compiler trust needs a diverse toolchain path.

---

## 5. Concrete deliverables

### 5.1 stage0 script OUTLINE

```sh
#!/bin/sh
set -eu
# --- pinned, verified inputs ---
export SOURCE_DATE_EPOCH="$(git -C "$SRC" show -s --format=%ct HEAD)"
GO_VERSION=go1.27.1
GO_SHA256=<pinned sha256 of go1.27.1.linux-amd64.tar.gz>   # cross-check go.dev/dl + gorebuild
# verify toolchain archive
echo "${GO_SHA256}  ${GO_TARBALL}" | sha256sum -c -
tar -C /opt -xzf "${GO_TARBALL}"
export PATH=/opt/go/bin:$PATH
# --- fixed, hermetic environment ---
export CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off
export GOOS=linux GOARCH=amd64 GOAMD64=v1
# --- deterministic build ---
go build -trimpath -buildvcs=false \
  -ldflags="all=-buildid= -s -w" \
  -o "$OUT/tool" ./cmd/tool
# --- hash + emit provenance ---
DIGEST="$(sha256sum "$OUT/tool" | cut -d' ' -f1)"
emit_provenance --subject "$OUT/tool@sha256:$DIGEST" \
  --builder-id "https://example.com/builders/bootstrap-stage0" \
  --source "git+$REPO@$(git -C "$SRC" rev-parse HEAD)" \
  --toolchain "${GO_VERSION}@sha256:${GO_SHA256}" > "$OUT/provenance.intoto.json"
dsse-sign --kms "$KMS_KEY" "$OUT/provenance.intoto.json" > "$OUT/provenance.dsse.json"
```

### 5.2 Reproducible-Go checklist
- `CGO_ENABLED=0`; `-trimpath`; `-buildvcs=false` (or clean pinned checkout); `-ldflags=all=-buildid=`.
- `GOTOOLCHAIN=local`; pin `GOOS/GOARCH/GOAMD64/GOARM/GOEXPERIMENT` and build tags.
- Vendored deps or digest-verified module cache; `GOPROXY=off`; `go mod verify`; `go.sum` present.
- No wall-clock timestamps; derive any version stamp from `SOURCE_DATE_EPOCH`/commit.
- Toolchain pinned by sha256 and gorebuild-verified.
- No network in build steps; all inputs digest-pinned.
- CI job that diffs two independent builds and fails on any difference.

### 5.3 SLSA v1 provenance predicate SKELETON -- tool's own release

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "tool", "digest": { "sha256": "<binary-digest>" } }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://example.com/buildtypes/go-bootstrap/v1",
      "externalParameters": {
        "source": "git+https://example.com/tool@refs/tags/v1.2.3",
        "pipeline": ".ci/release.pipeline.yaml"
      },
      "internalParameters": {
        "engine": "containerd://1.7.x",
        "GOFLAGS": "-mod=vendor", "CGO_ENABLED": "0", "GOAMD64": "v1"
      },
      "resolvedDependencies": [
        { "uri": "https://go.dev/dl/go1.27.1.src.tar.gz", "digest": { "sha256": "<go-src-digest>" } },
        { "uri": "pkg:golang/module@version", "digest": { "sha256": "<h1-mapped-digest>" } },
        { "uri": "oci://gcr.io/distroless/static@sha256:<d>", "digest": { "sha256": "<d>" } }
      ]
    },
    "runDetails": {
      "builder": {
        "id": "https://example.com/builders/control-plane@v1.2.3",
        "version": { "tool": "v1.2.3", "go": "go1.27.1" }
      },
      "metadata": {
        "invocationId": "<globally-unique-run-id>",
        "startedOn": "2026-09-14T10:00:00Z",
        "finishedOn": "2026-09-14T10:04:12Z"
      },
      "byproducts": [
        { "name": "buildkit-provenance", "digest": { "sha256": "<engine-prov-digest>" } },
        { "name": "build-log", "digest": { "sha256": "<log-digest>" } }
      ]
    }
  }
}
```

### 5.4 SLSA v1 predicate SKELETON -- downstream build (abbreviated)

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [ { "name": "app-image", "digest": { "sha256": "<image-digest>" } } ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://example.com/buildtypes/tenant-build/v1",
      "externalParameters": {
        "configSource": "git+https://tenant.example/app@<commit>",
        "buildConfigPath": "build.yaml"
      },
      "internalParameters": { "tool": "control-plane@sha256:<verified-tool-digest>", "engine": "containerd://1.7.x" },
      "resolvedDependencies": [
        { "uri": "oci://base@sha256:<d>", "digest": { "sha256": "<d>" } }
      ]
    },
    "runDetails": {
      "builder": { "id": "https://example.com/builders/control-plane@v1.2.3" },
      "metadata": { "invocationId": "<run-id>", "startedOn": "...", "finishedOn": "..." }
    }
  }
}
```

### 5.5 Tier table

| Tier | What you add | Attack defeated | Residual risk | Cost |
|------|--------------|-----------------|---------------|------|
| 1 | gorebuild-verified go.dev toolchain + N-of-M rebuilds of the tool | Tampered posted binaries; single-host compromise | Source-level or upstream-toolchain backdoor | Low |
| 2 | DDC: build with go.dev AND Guix-chain (optionally GCC/Clang-rooted) toolchains; require bit-identical output | Trusting-trust in the compiler binary | Shared source backdoor; shared C/hardware root | Medium-High |
| 3 | Full-source-bootstrapped env (`guix pack -f docker`) + measured/attested control plane; KMS key release bound to reproduced digest | Prebuilt-seed trust; runtime platform compromise | Hardware/firmware trojans; source review gaps | High |

### 5.6 Ordered implementation roadmap
1. Lock the reproducible-Go recipe (Section 5.2); add the two-build CI diff (comparison #2).
2. Pin + gorebuild-verify the toolchain; automate a daily gorebuild check.
3. Move image assembly into the control plane via ko-style go-containerregistry code; verify bit-identical images.
4. Emit + DSSE-sign SLSA v1 provenance from the control plane; define your `buildType` and `builder.id` docs.
5. Stand up N-of-M independent rebuilders (rebuilderd/Debian-style); record agreement in Rekor v2; issue VSAs.
6. Enforce build-step isolation (separate engine host, network policy, ephemeral rootless containers, egress proxy).
7. Add Tier 2 DDC with a Guix-chain toolchain.
8. (Optional) Tier 3: full-source-bootstrapped base image + measured/attested control plane with attestation-bound key release.

### 5.7 Open decisions for the user
- **Sigstore keyless (Fulcio/Rekor v2) vs KMS/HSM** signing -- public transparency vs self-contained control.
- **Which second toolchain path** for DDC -- Guix full-source chain (strongest) vs nixpkgs (weaker root) vs your own GCC/Clang-rooted Go 1.4 chain.
- **Single- vs multi-tenant isolation level** -- namespaces vs gVisor vs Kata/Firecracker microVMs.
- **Whether to adopt measured-control-plane binding** (SEV-SNP/TDX + attestation-bound key release) now or later.
- **How consumers verify** -- cosign+policy (CUE/Rego) now vs registering your builder with the SLSA verifier.

---

## Primary sources
- SLSA v1.2: build-requirements, future-directions, provenance/build-provenance, FAQ, threats, verification_summary, source-requirements (slsa.dev/spec/v1.2/...).
- Go: go.dev/doc/install/source; go.dev/doc/toolchain; go.dev/blog/rebuild; go.dev/rebuild; pkg.go.dev/golang.org/x/build/cmd/gorebuild; Go 1.22 & 1.26 Release Notes; Go 1.27 release blog; golang/go issues #44505, #54265, #64751, #75143, #59525, #34186, #51027, #47771; src/cmd/dist.
- Wheeler DDC: dwheeler.com/trusting-trust (ACSAC 2005 paper; 2009 GMU dissertation).
- Guix: guix.gnu.org Full-Source Bootstrap manual + 2023 blog; gnu/packages/golang.scm; packages.guix.gnu.org/packages/go.
- nixpkgs: pkgs/development/compilers/go (binary.nix, bootstrap122/124.nix).
- Sigstore: blog.sigstore.dev/rekor-v2-ga; github.com/sigstore/rekor-tiles.
- ko: ko-build/ko docs; reproducible-builds.org/docs/source-date-epoch.
- BuildKit: moby/buildkit docs/attestations/slsa-provenance.md; docs.docker.com/build/metadata/attestations.
- slsa-verifier / verifier / slsa-github-generator READMEs; GitHub Docs artifact-attestations.
- Confidential computing: Azure Key Vault Secure Key Release (SEV-SNP); GCP Confidential VM attestation.
- kubernetes/release SLSA issues (#2267, #2273).