# Chainguard Podman-in-Container Image: Availability and Trust-Bearing Alternatives

## TL;DR
- **No.** As of September 2026, Chainguard does not publish a general-purpose `podman` container image analogous to `quay.io/podman/stable`. The `cgr.dev/chainguard/*` catalog covers adjacent container tooling (buildah, buildkit, skopeo, crane, apko, melange, docker-cli) and a `prometheus-podman-exporter` image, but there is no `cgr.dev/chainguard/podman` in either the free Starter tier or the paid Production tier, and no evidence of a standalone `podman` package in Wolfi OS.
- **The single best trust-bearing, rootless-capable Podman-in-container image today is Red Hat's `registry.access.redhat.com/ubi9/podman`** -- built by the primary upstream employer of Podman maintainers, freely pullable without authentication, GPG/sigstore-signed, health-index rated, and current (podman 5.x on a RHEL 9.8 base). Its main weakness versus Chainguard-style images is that it does not ship cosign/SLSA-provenance attestations by default.
- **If you require a hardened / near-zero-CVE image with cosign + SLSA provenance + SBOM, the realistic path is DIY:** build a Podman image on a hardened base (Wolfi `wolfi-base`, UBI-micro, or Alpine) using the already-available `crun`, `conmon`, `netavark`, `fuse-overlayfs`, and `shadow` packages, and sign it yourself with cosign and GitHub Actions SLSA attestations. The community `mgoltzsche/podman` image is the closest off-the-shelf rootless-in-container option but lacks a Chainguard-grade trust posture.

## Key Findings

1. **Chainguard has no `podman` image.** The Chainguard Images Directory surfaces only `prometheus-podman-exporter` and `prometheus-podman-exporter-fips` when searching "podman" -- and the exporter's own docs state it expects "podman to be installed on the host," implying Chainguard does not offer a podman engine image. No `cgr.dev/chainguard/podman` repository could be found in the free or paid tier. (Chainguard's catalog is large -- the company markets "1,300+ images" in its blog "Chainguard's Catalog of 1,300+ Container Images," noting "every Chainguard image is built from source, rebuilt daily, and comes with SBOMs, SLSA provenance, and Sigstore signatures by default"; the public Directory index page rendered an even higher image count. Neither view contains a podman engine image.)

2. **Chainguard does cover the container-tooling space** with buildah, buildkit (including a `rootless`-tagged variant), skopeo, crane, apko, melange, and docker-cli/docker-dind images -- all Wolfi/Chainguard-OS based, cosign-signed via Sigstore keyless signing, with build-time SBOMs and provenance attestations.

3. **Wolfi has the building blocks but (apparently) not `podman` itself.** Confirmed Wolfi packages include `buildah`, `crun`, `fuse-overlayfs`, `netavark`, and `shadow` (which provides newuidmap/newgidmap). No `podman.yaml` package definition could be found in wolfi-dev/os, suggesting no standalone Wolfi `podman` package exists. This means a Chainguard podman image is *feasible* to assemble from Wolfi packages, but Chainguard has chosen not to publish one.

4. **The official Podman images (`quay.io/podman/stable`, `:testing`, `:upstream`) are the baseline.** They are built by the Podman project from the `containers/image_build` repo (formerly `containers/podman` contrib/podmanimage), based on Fedora, and ship a preconfigured `podman` user for rootless nested execution. They are NOT cosign-signed and carry no SLSA provenance/SBOM attestations -- their trust rests on Quay + the Podman project's reputation.

5. **Red Hat `ubi9/podman` is the strongest vendor candidate** -- freely pullable, signed, actively maintained (RHEL 9.8 base, updated within days), and built by Podman's upstream vendor.

6. **A crowded 2025-2026 hardened-image market** (Docker Hardened Images now free/Apache-2.0, Minimus, Echo, RapidFort, SUSE BCI) largely does NOT publish a ready-to-use rootless podman-in-container engine image -- most cover language runtimes and infrastructure apps, not the podman engine.

## Details

### 1. Chainguard / cgr.dev
Chainguard publishes minimal, hardened OCI images to `cgr.dev/chainguard/<name>` (free Starter tier, Wolfi-based) and `cgr.dev/<org>/<name>` (paid Production tier, Chainguard OS). Every image is built with apko from pinned, reproducible config; signed with Sigstore cosign (keyless, GitHub Actions OIDC); and ships build-time SBOMs and attestations.

**Podman engine image: does not exist.** Searching the Directory returns only:
- `prometheus-podman-exporter` and `prometheus-podman-exporter-fips` -- a Prometheus metrics exporter, NOT the podman engine. Its docs assume podman is installed on the host.

**Adjacent container tooling that DOES exist in Chainguard's catalog:**
- `buildah` -- Wolfi-based, runs as root (UID 0) to support user-namespace/filesystem operations, minimal (no shell/package manager).
- `buildkit` -- comparable to Moby's BuildKit; has `rootless`-prefixed tags mirroring upstream.
- `skopeo` (and `skopeo-fips`), `crane`, `apko`, `melange`, `docker-cli`, `docker-dind`.

**Wolfi package availability:** `crun`, `conmon`, `fuse-overlayfs`, `netavark`, `buildah`, and `shadow` (for newuidmap/newgidmap) are present in the Wolfi/Chainguard package ecosystem -- as evidenced by a Chainguard buildah Dockerfile that runs `apk add buildah crun fuse-overlayfs netavark`. However, no `podman` package definition was found in wolfi-dev/os. Note also that Chainguard has moved wolfi-dev/os to a read-only public mirror synced from an internal monorepo, and free-tier packages track only the latest upstream version.

**Custom build options:** Chainguard offers "Custom Assembly" to add packages/config/certs to existing images, which a paying customer could theoretically use to request a podman image. This could not be independently verified as producing a supported podman image.

### 2. The official Podman images (baseline)
- **Who/where:** Built by the Podman project, source in `github.com/containers/image_build` (the `podman/` directory), published to `quay.io/podman/{stable,testing,upstream}`. Base OS is Fedora.
- **Rootless story:** The image ships a `podman` user preconfigured for rootless nested containers. Red Hat's canonical guidance (Dan Walsh, "How to use Podman inside of a container") documents the patterns:
  - Rootful nested: `podman run --privileged quay.io/podman/stable podman run ...`
  - Rootless nested: `podman run --user podman --privileged quay.io/podman/stable podman run ...`
  - Minimal-privilege rootless: `podman run --security-opt label=disable --user podman --device /dev/fuse quay.io/podman/stable podman run alpine echo hello`
- **Trust posture:** These images are NOT cosign-signed and carry no published SLSA provenance or SBOM attestations. Trust rests on the Podman project's reputation and Quay hosting. Known caveat: `fuse: device not found` requires `modprobe fuse` on the host; nested rootless often needs `--device /dev/fuse`, `--security-opt label=disable`/`unmask`, and appropriate userns settings on the outer runtime.

### 3. Other vendor candidates

**Red Hat -- STRONGEST CANDIDATE.** `registry.access.redhat.com/ubi9/podman` exists in the Red Hat Ecosystem Catalog (image ID 618aa2ad4ae373968756826c), currently at version `9.8-1789046121` / `latest`, actively updated (multi-arch incl. ppc64le, amd64). Red Hat ships it as a signed, freely-redistributable UBI image on `registry.access.redhat.com` with no authentication required; per Red Hat docs, `podman pull ubi9` resolves directly to `registry.access.redhat.com/ubi9:latest`, and pulls show "Getting image source signatures / Storing signatures." Signing uses GPG (RPM-GPG-KEY-redhat-release) plus sigstore signature stores at `access.redhat.com/webassets/docker/content/sigstore` and `registry.redhat.io/containers/sigstore`; images are health-index rated. `registry.redhat.io` requires auth; `registry.access.redhat.com` does not. Rootless-in-container is documented but requires setup (`setcap cap_setuid+ep /usr/bin/newuidmap`, `setcap cap_setgid+ep /usr/bin/newgidmap`, touching /etc/subuid and /etc/subgid). A known gotcha: rootless podman inside rootless podman on ubi9-minimal requires added caps (`--cap-add=setuid,setgid,chown,sys_admin`). Caveat: Red Hat's UBI podman image is not published with cosign/SLSA-provenance attestations in the Chainguard/DHI style.

**Fedora / Toolbx.** `quay.io/fedora` and Fedora toolbox images exist; the official podman-in-container images are the Fedora-based `quay.io/podman/*` covered above.

**openSUSE / SUSE.** SUSE Base Container Images (BCI) are freely available, based on SLES, and signed with **both Sigstore cosign and GPG** (Notary v1/Docker Content Trust deprecated Feb 2026). BCI covers base + language runtimes; SLES/SLE Micro ship podman as the primary engine, but no dedicated `suse/podman` or `opensuse/podman` engine-in-container image was confirmed -- you would `zypper install podman` on top of `registry.suse.com/bci/bci-base`. Signing/attestation posture is strong; a turnkey podman image is not evident.

**Alpine / Docker Library.** There is **no** official Docker Library `podman` image (verified -- none surfaced). The most prominent community option is **`mgoltzsche/podman`** (github.com/mgoltzsche/podman-static): Alpine-based, statically linked, explicitly built "for nested and rootless containerization scenarios," bundling podman, crun, runc, conmon, fuse-overlayfs, netavark, pasta/passt, aardvark-dns, catatonit, with a preconfigured `podman` user (uid/gid 1000) and subuid/subgid mappings. It has 500K+ pulls on Docker Hub, is current at podman 5.8.1 (tags `5.8.1-minimal`/`latest`, last pushed within ~24 days as of this writing), and is a single-maintainer project without cosign/SLSA/SBOM attestations -- trust rests on the maintainer.

**Docker Hardened Images (DHI).** DHI first launched in May 2025; on **December 17, 2025**, Docker made its catalog of "more than 1,000 Docker Hardened Images ... built on ... Debian and Alpine, free and fully open source under the Apache 2.0 license" (DHI Community). Images ship a "complete Software Bill of Materials (SBOM), SLSA Build Level 3 provenance, and transparent vulnerability reporting" plus OpenVEX and cryptographic signatures. The registry is `dhi.io`, but pulling **requires authentication first** -- per Docker's guidance, "To pull the images locally, you need to log into dhi.io first: docker login dhi.io." The catalog includes a `docker` CLI image and build tooling, and language/infra images, but **no `podman` engine image** was found. Paid tiers (Select, Enterprise) add FIPS/STIG variants and SLAs (e.g., a 7-day critical-CVE remediation SLA is reserved for DHI Enterprise).

**Minimus (minimus.io).** Offers a free Community Edition (no login) of source-built, near-zero-CVE distroless images with signed SBOMs and VEX; catalog focuses on runtimes/infrastructure (nginx, Python, PostgreSQL, etc.). No podman engine image confirmed.

**Echo (echohq / Echo Images).** Newer hardened-image vendor advertising free, ~0-CVE, compliant images (SLSA L3, SBOM, FIPS) with a 24-48h CVE remediation SLA. No podman engine image confirmed.

**RapidFort.** Publishes `rapidfort/podman-ib` -- a hardened/optimized version of the Platform One (DoD Iron Bank) Podman image, free to use, "zero CVE," updated within months. This is the one third-party hardened *podman* image found, though it is a hardened rebuild of the Iron Bank image rather than a from-source build, and its trust artifacts (cosign/SLSA) were not independently verified.

**Canonical / Ubuntu Rocks, Rocky/AlmaLinux, Bitnami/Broadcom.** No dedicated rootless podman-in-container engine image was confirmed in these catalogs. Bitnami's catalog underwent significant changes in 2025 under Broadcom (the free public catalog was substantially restructured), and it does not target the podman engine.

### 4. Technical feasibility / gotchas for rootless podman-in-container
For rootless nested podman to work inside a container, the image and outer runtime must provide:
- **`newuidmap`/`newgidmap`** (from `shadow`/shadow-utils) with file capabilities `cap_setuid+ep` / `cap_setgid+ep` (or setuid). This is the crux: minimal/distroless images often omit these setuid-capable helpers.
- **`/etc/subuid` and `/etc/subgid`** entries for the non-root user.
- **`fuse-overlayfs`** (or native overlay with kernel support) and **`/dev/fuse`** exposed to the container (`--device /dev/fuse`).
- **A container runtime** (`crun` or `runc`), **`conmon`**, and a network backend (**`netavark`** + **`aardvark-dns`**, or `slirp4netns`/`passt` for rootless networking).
- **`containers-common`** config (storage.conf pointing to fuse-overlayfs, registries.conf, policy.json).
- **cgroups v2 delegation**, and on the outer runtime typically `--security-opt label=disable` (or `unmask`), `--security-opt seccomp=unconfined` in some cases, and userns settings.

**Why distroless/Chainguard-style images are structurally awkward for this:** Podman-in-podman needs a fair amount of userspace helper binaries and, critically, setuid-ish file capabilities on newuidmap/newgidmap. Chainguard's design philosophy -- no shell, no package manager, non-root by default, minimal userspace -- is at odds with shipping a cluster of setuid/file-capability helper binaries and mutable config. This structural tension is the most plausible explanation for why no Chainguard podman image exists even though the constituent packages (crun, conmon, netavark, fuse-overlayfs, shadow) are available in Wolfi.

**Known upstream issues:** containers/podman discussions document the difficulty of rootless-in-rootless nesting (e.g., "help running rootless podman in rootless podman" #23202; "Cannot run rootless podman inside rootless podman using ubi9:minimal" #24870, which required `--cap-add=setuid,setgid,chown,sys_admin` and manual `setcap` on newuidmap/newgidmap).

### 5. Comparison table

| Vendor / registry | Image reference | Exists? | Free/Paid | Base OS | Podman currency | Signing | SLSA provenance | SBOM | Rootless-ready OOTB | Notable caveats |
|---|---|---|---|---|---|---|---|---|---|---|
| Chainguard | `cgr.dev/chainguard/podman` | **No** | -- | (Wolfi/CG-OS) | -- | (cosign for other imgs) | (yes for other imgs) | (yes) | -- | No podman image at all; buildah/buildkit/skopeo exist |
| Podman project | `quay.io/podman/stable` | Yes | Free | Fedora | Current (5.x/6.x) | No | No | No | **Yes** (`podman` user) | Baseline; no attestations |
| Red Hat | `registry.access.redhat.com/ubi9/podman` | Yes | Free (no auth) | RHEL 9 (UBI) | Current (9.8) | GPG + sigstore | No | Partial (Red Hat metadata) | Mostly (needs subuid/caps setup) | Best vendor trust; no cosign/SLSA attestations |
| Community (mgoltzsche) | `mgoltzsche/podman` | Yes | Free | Alpine | Current (5.8.1) | No | No | No | **Yes** (`podman` user, subuid/gid) | Single maintainer; purpose-built for nesting |
| RapidFort | `rapidfort/podman-ib` | Yes | Free | Iron Bank base | Months-old | Not verified | Not verified | Not verified | Iron Bank posture | Hardened rebuild of DoD Iron Bank image |
| Docker (DHI) | `dhi.io/podman` | **No** | Free (login) | Alpine/Debian | -- | cosign (other imgs) | L3 (other imgs) | Yes (other imgs) | -- | No podman image; strong posture for what exists |
| SUSE (BCI) | `registry.suse.com/bci/*` | No (engine img) | Free | SLES | via zypper | cosign + GPG | No | Partial | No | Install podman on bci-base yourself |
| Minimus / Echo | -- | No podman | Free (some) | distroless | -- | cosign | L3 | Yes | -- | Runtimes/infra focus, not podman engine |

### 6. Recommendations

**Stage 1 -- If you want the least effort and a credible vendor today:** Use **`registry.access.redhat.com/ubi9/podman`**. It is freely pullable without auth, signed, health-rated, current, and built by Podman's upstream vendor. For nested rootless, expect to add `/etc/subuid`+`/etc/subgid`, `setcap` on newuidmap/newgidmap (if not already set), run the outer container with `--device /dev/fuse --security-opt label=disable`, and possibly `--cap-add=setuid,setgid,chown,sys_admin` for rootless-in-rootless. *Threshold to move on:* if your compliance regime mandates cosign signatures + SLSA provenance + SBOM attestations (which UBI podman does not ship by default), proceed to Stage 3.

**Stage 2 -- If you just need rootless-in-container to "just work" off the shelf:** Evaluate **`mgoltzsche/podman`** (`:minimal` or full). It is purpose-built for nested/rootless use with all helper binaries and subuid/gid mappings preconfigured. Accept the trust trade-off (single maintainer, no attestations) or pin by digest and re-sign it yourself. *Threshold:* acceptable for CI/dev; not recommended as your organization's trusted base if you need vendor-backed SLAs.

**Stage 3 -- If you insist on a Chainguard-grade hardened, trust-bearing image:** There is no off-the-shelf product, so **build your own and sign it in your CI:**
1. Start from a hardened base: Wolfi (`cgr.dev/chainguard/wolfi-base`), UBI-micro, or Alpine.
2. Install the stack: `podman` (or the individual binaries), `crun`, `conmon`, `netavark`, `aardvark-dns`, `fuse-overlayfs`, `passt`/`slirp4netns`, `containers-common`, and `shadow` (for newuidmap/newgidmap). On Wolfi, note that `podman` itself may not be packaged -- you may need to request it via a Wolfi package request, use Custom Assembly as a Chainguard customer, or vendor the binary.
3. Configure a non-root `podman` user, `/etc/subuid`+`/etc/subgid`, `setcap cap_setuid+ep`/`cap_setgid+ep` on newuidmap/newgidmap, and `storage.conf` (overlay + fuse-overlayfs mount_program).
4. Sign with cosign (keyless, GitHub Actions OIDC) and emit SLSA provenance via GitHub Actions `actions/attest-build-provenance`, plus an SBOM (syft/apko).
This yields the exact trust properties you want (cosign signatures, SLSA provenance, SBOM, controlled patching cadence) while you own the maintenance burden.

**Stage 4 -- Watch these developments:** Chainguard could add a podman image (they already ship buildah/buildkit/skopeo); Docker Hardened Images (free, Apache-2.0, SLSA L3) could add a podman engine image; and RapidFort/Echo/Minimus could publish attested podman images. Re-check `images.chainguard.dev/directory`, `dhi.io`, and the containers/image_build repo quarterly. *Trigger to switch:* the moment a vendor publishes a podman engine image with cosign + SLSA + SBOM that is rootless-ready, prefer it over your DIY build to shed maintenance.

## Caveats
- **Could not capture a literal HTTP 404** for `images.chainguard.dev/directory/image/podman/overview` (the fetch tool restricts to previously-surfaced URLs). The conclusion that no Chainguard podman image exists is based on extensive Directory searches returning only the exporter images, plus the exporter docs assuming host-installed podman -- high confidence, but not a captured 404.
- **Chainguard catalog size figures differ by source** -- Chainguard's own blog cites "1,300+ images," while the live public Directory index rendered a higher count; neither contains a podman engine image.
- **Wolfi `podman` package:** absence is inferred from no `podman.yaml` surfacing in wolfi-dev/os (a repo truncated to 1,000 of ~3,500 files in the GitHub UI). A definitive check requires reading the APKINDEX at `packages.wolfi.dev/os/x86_64/APKINDEX.tar.gz` or the GitHub contents API. The constituent packages (crun, conmon, netavark, fuse-overlayfs, shadow, buildah) are confirmed present.
- **Paid/gated catalogs** (Chainguard Production tier private repos, DHI behind login, registry.redhat.io) could contain images not visible to anonymous search; where a podman image was not found, it means "not found in accessible sources," not a guarantee of non-existence.
- **RapidFort, Echo, Minimus trust artifacts** (specific cosign/SLSA/SBOM for any podman-related image) were not individually verified against primary attestation output.
- The container-image vendor landscape shifted materially in 2025-2026 (DHI going free/Apache-2.0 on December 17, 2025; Bitnami/Broadcom catalog changes; Minimus/Echo entering the market); figures and availability should be re-verified before procurement decisions.