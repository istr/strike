# ADR-031: pasta --splice-only Toolchain Dependency and Platform Support

## Status

Accepted. Companion to ADR-023 (the pasta and `--splice-only`
spike) and [ADR-028](ADR-028-step-container-egress-mediation.md)
(step-container egress mediation, whose default-deny substrate this
dependency makes operational). References
[ADR-022](ADR-022-network-opt-in-as-peer-list.md). Supersedes no
ADR.

This ADR has a deliberately bounded lifetime. The dependency it
records is transient: its friction is highest now and decreases as
distributions ship a recent enough passt. See Consequences.

## Context

The egress model (ADR-023, ADR-028) realizes default-deny rootless
egress by running pasta in `--splice-only` mode: pasta creates no
tap device and forwards only loopback traffic between the
namespaces, so there is structurally nothing to route except the
declared splice forwards. Default-deny without an explicit
deny-list.

`--splice-only` is load-bearing. It IS the structural default-deny.
Without it, pasta on a host that has a configured address creates a
tap and copies addresses and routes; the container then has general
egress through the translation layer -- the exact surface ADR-028
closes. There is no safe degradation: `--no-splice` improvisations
and slirp4netns both give the container general egress, and
`--network=none` leaves no path to the controller-side resolver and
mediator services (strike runs no-daemon; those services are not
inside the container). The pasta splice is the only rootless,
no-daemon path to those services.

The catch: `--splice-only` is newer than several distributions'
stable passt. Debian 13 (trixie) stable ships passt
`git20250503`, which does not recognize the option -- verified, not
inferred: Podman returns HTTP 500 with `unrecognized option
'--splice-only'` from that exact binary. The option landed upstream
after that snapshot.

This is distribution lag, not unversioned beta churn. passt has an
ordered lifecycle: the upstream author is also the Debian
maintainer, and dated snapshots migrate unstable -> testing ->
stable. `git20260120` is already in Debian testing (forky). The
requirement is therefore leading-edge relative to some stable
distributions, not a dependency on an unreleased branch.

### Why this is a separate ADR

The egress architecture (ADR-028) is durable. This dependency is
not: it expires as distributions ship a recent enough passt.
Binding the two would couple a permanent architectural decision to a
transient toolchain fact. ADR-031 isolates the transient part so it
can be revisited -- and eventually retired -- without touching
ADR-028.

### Engine scope

strike supports Podman only (libpod REST API; engine identity per
ADR-012). The floor is Podman 5.0, where pasta is the rootless
network default. "Supported Podman" is necessary but not sufficient:
the load-bearing requirement is a `--splice-only`-capable pasta as
the rootless network backend. A current Podman with a stale pasta
(trixie stable being the worked example) is "supported Podman" and
still fails. Podman's own lack of legacy baggage keeps this support
surface naturally small.

## Decision

### 1. pasta --splice-only is a hard, non-negotiable dependency

strike requires a `--splice-only`-capable pasta. There is no
fallback path that preserves the security property, so none is
offered. Substituting `--no-splice` arrangements or slirp4netns
would replace structural default-deny with configuration-fragile
default-deny -- precisely what `--splice-only` exists to avoid.

### 2. The operator provides a compatible execution environment;
strike stays platform-agnostic

Providing a compatible engine and pasta is the operator's
responsibility. strike does not detect, probe, or branch on
platform. Its only enforcement is a flat precondition: is a
`--splice-only`-capable pasta present? If not, strike fails fast
with a clear diagnostic (implemented separately) that translates the
opaque Podman 500 -- which otherwise surfaces as a raw pasta usage
dump -- into an actionable message naming the missing capability and
pointing to the requirement.

The version cannot be reliably gated, so the check is on capability,
not version. `podman info` reports the pasta `version` field empty
on Debian; only `package` carries a distribution-specific date
string whose format is not portable. A RequireVersion-style gate
analogous to the Podman floor check is therefore not buildable on a
reliable signal. The authoritative capability check is empirical
(see Verification gate).

### 3. Pinning by content digest, not by URL

The reference build source is the upstream author's static builds at
passt.top. The `/builds/latest/` path is a mutable reference;
pinning to it would be the same mutable-reference anti-pattern strike
rejects for OCI images (`image:latest` is a parse error, not a
silently-resolved convenience). passt.top also publishes immutable
dated directories of the form
`/builds/passt_0.0~gitYYYYMMDD.<hash>/`, each carrying a full Debian
source-and-binary set plus a `.buildinfo` (reproducible-build
provenance).

The pin is therefore: select a recent dated build (not `latest`, and
not an arbitrarily old dated build -- a build predating the
`--splice-only` introduction is pinnable and wrong), record the
SHA-256 of the validated pasta binary, and verify against that
digest before use. The mutable URL is fetch convenience; the
self-computed digest is the trust anchor. This is the
digest-pinning principle applied to the toolchain: provisioning
generates the content address itself rather than trusting an
upstream-supplied tag.

### 4. Minimal platform support matrix (aspirational)

"Minimal" means a bounded support surface -- "code is liability"
applied to the platform matrix. "Aspirational" means this is the
target state; not every row is friction-free today. The matrix is
documentation that tells operators how to satisfy the Decision-2
precondition on each platform. It is not a specification for
platform-detection code, which Decision 2 keeps out of strike.

Supported:

- **Linux, distribution out-of-the-box.** True where the
  distribution's passt is recent enough (Fedora, Arch; eventually
  Debian forky and then stable). On a lagging stable distribution
  (Debian trixie today) the operator installs a recent pasta
  (passt.top, digest-pinned per Decision 3) until the distribution
  catches up. System Podman stays untouched: either install the
  passt.top `.deb` and hold the package, or place the standalone
  binary and point Podman at it via the containers.conf helper-binary
  path. The exact configuration knob is to be confirmed at
  implementation, not assumed.
- **Linux Podman Desktop.** Uses host Podman with a GUI on top;
  identical pasta story to the row above, not a distinct
  provisioning case.
- **macOS Podman Desktop.** Podman runs inside the FCOS machine VM,
  so pasta lives in the VM. First verify whether the current
  machine-os already ships `--splice-only` (FCOS tracks recent
  Fedora; it may already qualify). If not, apply a custom bootc
  machine-os via `podman machine os apply`.
- **Windows Podman Desktop (Hyper-V).** Same FCOS-VM and
  pasta-in-VM story as macOS. Caveats: the Hyper-V provider has its
  own constraints (privileged user); a custom machine-os, if needed,
  must be built off Hyper-V (for example on the Linux host) and
  applied via `os apply`. This build path is to be verified at
  implementation, not assumed.

Not recommended:

- **Windows Podman Desktop (WSL).** Rejected on
  endpoint-security-posture grounds, not (only) on `--splice-only`
  uncertainty. WSL's shared-kernel-across-distributions model and
  broad host interop surface are inconsistent with the posture
  strike assumes for an execution substrate: running a tool whose
  purpose is to reduce supply-chain attack surface on top of a
  substrate that widens the host's attack surface is
  self-undermining. This is strike's stated position, expressed as
  a recommendation. It is NOT a runtime block: per Decision 2,
  strike does not detect WSL, and a WSL setup with a working
  `--splice-only` pasta is not refused, merely not endorsed.
  Encoding a WSL check would reintroduce the platform-awareness
  Decision 2 deliberately excludes.

## Consequences

### Adoption risk, framed by the principle/mechanism distinction

Requiring a specific execution environment is an adoption barrier.
An architecture that makes a compatible environment hard, very hard,
or impossible to build leads to non-adoption, which is not why tools
are written. The risk is real and is bounded as follows.

- **Principle vs. mechanism.** Default-deny rootless egress is the
  principle -- one of strike's core principles, and part of the
  tool's reason to exist. `--splice-only` is one mechanism that
  satisfies it today with minimal code. If the mechanism proves an
  adoption killer, the mechanism is replaced, not the principle.
- **A named fallback mechanism, already scouted.** A
  `createContainer` OCI hook installing namespaced nftables rules is
  a candidate. It needs no host root: as ADR-028 already states, the
  namespace-level egress filter requires `CAP_NET_ADMIN` within the
  user namespace owning the container's network namespace -- which
  the OCI runtime holds at namespace-setup time -- not real root.
  Open question, unresolved here: whether netns nftables sees the
  spliced loopback paths, or whether a hook-based mechanism requires
  routable addressing through a tap, which would partially revert the
  127.64.0.0/16 loopback address model. The fallback is scouted, not
  drop-in.
- **A favorable time profile.** Friction is highest now and
  decreases monotonically. With the upstream author also maintaining
  the Debian package, and `git20260120` already in testing/forky,
  `--splice-only` reaches mainstream stable distributions on the
  order of the next stable releases. The leading-edge dependency has
  a built-in expiry.
- **Target-platform overlap.** strike is a CI/CD lane executor;
  CI/CD runs overwhelmingly on Linux, where `--splice-only` is
  easiest and self-heals fastest. The hardest platform (WSL) is
  primarily local developer testing, not production execution, and
  there "run strike in a real Linux VM, or test in CI" is an
  acceptable answer. The hardest platform overlaps least with the
  primary deployment target.
- **Where the risk genuinely holds.** If strike's users were
  predominantly Windows/WSL developers and WSL could not achieve
  rootless default-deny by any mechanism, adoption there would be
  gated on Microsoft's WSL kernel -- outside strike's control and not
  fixable by mechanism cleverness. The honest response in that case
  is clarity about target audience, not mechanism acrobatics.

### Re-evaluation trigger

If provisioning a compatible engine on a required target platform
proves infeasible (notably WSL), the egress *mechanism* is
re-evaluated -- candidate: the `createContainer` hook plus namespaced
nftables, with the open question above -- NOT the default-deny
*principle*. This trigger is the durable record of the mid-term
re-evaluation: the alternative and its open question are named so the
future re-evaluation starts from a known position rather than from
scratch.

### Verification gate

Because version strings are unreliable (the empty `podman info`
pasta version; non-portable package date formats), the authoritative
capability check is empirical: `pasta --help | grep -- --splice-only`
against the installed binary, with strike's runtime fail-fast on the
actual error signature as the in-product backstop. This ADR fixes a
recorded reference digest of a validated binary rather than a fragile
date threshold.

## Open follow-ups

- **containers.conf helper-path mechanics.** The exact knob for
  pointing Podman at a non-package pasta binary (helper-binary
  directory or pasta search path) is to be confirmed at
  implementation, not assumed.
- **machine-os pasta version (macOS, Hyper-V).** Verify whether the
  current FCOS machine-os ships `--splice-only` before deciding a
  custom machine-os is required.
- **Custom machine-os build path on Windows.** If needed, confirm
  the off-Hyper-V build and `os apply` path.
- **WSL viability spike.** Whether any rootless default-deny
  mechanism works under WSL2's kernel and networking model -- needed
  only if WSL becomes a required target despite the posture
  recommendation.
- **pasta native filtering (passt issue #139).** Upstream may add
  native destination filtering. If it lands, it could simplify or
  replace parts of the mechanism. Observed, not committed.

## Principles

- **No root.** The dependency and its scouted fallback both work
  rootless; the namespaced egress mechanism needs `CAP_NET_ADMIN` in
  the owning user namespace, not host root.
- **Peers are declared.** `--splice-only` is the structural
  realization of default-deny egress; the dependency exists to
  preserve that property, not to soften it.
- **External references are digest-pinned.** The pasta binary is
  pinned by self-computed content digest, never by a mutable
  `/latest/` URL.
- **Reproducibility is enforced.** Pinning the execution-environment
  toolchain by digest extends byte-identical-inputs reasoning to the
  engine layer; the `.buildinfo` provenance of the chosen build is
  retained.
- **Code is liability.** strike grows no platform-detection code.
  The matrix is documentation; the only runtime enforcement is a
  single flat fail-fast capability check.
