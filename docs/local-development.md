# Local Development Workflow

This guide explains how to iterate on a strike lane locally without
violating the architectural principle that host filesystem state
cannot enter the DAG (see [ADR-011](ADR-011-sources-elimination.md)).

The short form: **git is the protocol boundary**. What enters a
strike step is a content-addressed git commit, not a filesystem
snapshot. A working directory with uncommitted changes does not
flow through; only what has been committed does.

This rule is not a workflow restriction added on top of strike. It
is a structural property: there is no mechanism in strike to mount
a host directory into a step, and there is no mechanism to inject
a host file as a step input. Both would be the same defect that
`sources:` was -- a host path that bypasses the DAG, has no content
address, and is invisible to the spec hash. Any workflow that
involves "make a file appear in the container without going through
a producing step" is therefore not available, regardless of what
the file is or where it comes from.

The question is therefore not "should I bind-mount my working
directory" (the answer is no, and the option does not exist), but
"how do I expose my local commits to a strike step running in a
container".

## The two options

Both options below preserve the git protocol boundary. What they
have in common is the shape: a server (any kind of git server) on
a network address the container can reach, and a containerized
git-clone step that fetches from it. The container receives a git
object database, not a filesystem snapshot. `git checkout` inside
the container can never reach a file that is not in the cloned
ref.

### Option A: local git-daemon on loopback

Run `git daemon` on the host, exposing the working repository
read-only on TCP/9418. The strike step fetches via
`git://localhost:9418/repo`.

```sh
# in the repository's parent directory:
git daemon --reuseaddr --base-path=. --export-all --verbose
```

Lane snippet:

```yaml
- name: source
  image: alpine/git@sha256:...
  args: [git, clone, --depth, "1", git://localhost:9418/repo, /out/tree]
  # Note: this snippet does not currently validate against the lane
  # schema. The git:// protocol has no trust anchor, so it has no
  # corresponding #Peer variant. Use Option B for a workflow that
  # passes schema validation, or wait for a follow-up ADR that adds
  # a plaintext-loopback peer variant.
  outputs:
    - name: tree
      type: directory
      path: /out/tree
```

**Iteration rhythm.** Each `git commit` is immediately visible to
the next strike run. Nothing else to refresh.

**Network requirement.** Per [ADR-022](ADR-022-network-opt-in-as-peer-list.md),
network access requires a typed peer declaration with a trust
anchor. The git protocol has no trust anchor, so this option is
currently in transition: the snippet above does not pass schema
validation. For a workflow that does, use Option B. A future ADR
may add a plaintext-loopback peer variant for development; until
then, treat Option A as illustrative of the underlying iteration
pattern, not as a working lane fragment.

**Caveat.** The `git://` protocol is unauthenticated. Anyone with
access to the loopback interface (which on a multi-user host
includes other users) can read the repository. On a shared host,
restrict `git daemon` to a non-default port firewalled off, or
use Option B instead.

### Option B: local HTTP server on loopback

Serve a bare clone over HTTPS using any small HTTP server
(`git http-backend` behind nginx, a Go program with
`http.FileServer`, etc.). The strike step fetches via
`https://localhost/repo.git`.

```sh
# update the bare clone whenever local commits should become visible:
git push --mirror /path/to/served-repo.git
```

Lane snippet:

```yaml
- name: source
  image: alpine/git@sha256:...
  args: [git, clone, --depth, "1", https://localhost/repo.git, /out/tree]
  peers:
    - type: https
      host: localhost
      trust:
        mode: cert_fingerprint
        fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
  outputs:
    - name: tree
      type: directory
      path: /out/tree
```

**Iteration rhythm.** Each iteration requires a `git push --mirror`
to refresh the bare clone. One extra command per iteration.

**Network requirement.** A `peers:` list with one HTTPS entry for
the local server, carrying a cert fingerprint or pinned CA bundle.
The lane snippet looks structurally identical to a production lane
fetching from a real git server, which is the point: the local
workflow exercises the same trust-declaration plumbing as
production. See [ADR-022](ADR-022-network-opt-in-as-peer-list.md).

**Why it might be worth the extra step.** This option is the only
one that produces a lane file you could ship to production
unchanged (modulo the URL and trust anchor). If you want your
local iteration to be representative of how the lane runs in CI,
this is the closest match.

## Recommendation

For routine local iteration: **Option A** (git-daemon on
loopback). Lowest setup cost, fastest iteration, and the lane
snippet is small enough to keep in a `local.yaml` next to the
production lane.

For "one last check before pushing to CI": **Option B** (local
HTTPS). The lane snippet exercises the same trust-anchor
declaration as production, which catches misconfigurations that
Option A would let through.

## What does *not* work and why

Variants that put a file or directory from the host into the
container without going through a producing step do not work, and
not because of a missing feature. They do not work because they
would be `sources:` again under a different name. This includes:

- bind-mounting the working tree (the original `sources:` shape);
- bind-mounting the `.git` directory or a bare clone;
- passing a `git bundle` file as a step input from the host;
- mounting a tar of the working tree;
- any other mechanism that takes a host path and makes it appear
  inside a container without an upstream step that produced it.

All of these would re-open the structural hole [ADR-011](ADR-011-sources-elimination.md)
closed: a piece of state enters the DAG without content
addressing and without an edge that the spec hash sees. The
attestation could not record what the input was; the cache could
not recognize equal inputs as equal; a re-run could silently
diverge from the original.

The git protocol boundary is not arbitrary. It is the mechanism
that lets every strike build correspond to exactly one
identifiable commit. The only way for state to cross from the
operator's host into the lane is through a content-addressed
commit visible to a step that fetches from a git endpoint.

## How this changes the development rhythm

Tools that allow filesystem-level inputs (`sources:`, bind-mounts,
copy-from-host, etc.) let the developer iterate on uncommitted
work and re-run the build to see what happens. The commit is a
separate, later step: "okay, that works, now I'll commit it".

In strike the order is reversed. The commit is what makes a
change *testable*. There is no "let me try this and then decide
whether to commit"; the rhythm is "commit small, see what the
build does, refine".

Three observations about this rhythm in practice:

- **Commits become smaller and more frequent.** Each iteration is
  one commit; experiments that would have lived as uncommitted
  scratch in another workflow live as small commits here. This is
  not a workflow imposed by strike for its own sake; it is the
  natural consequence of the protocol boundary, and it happens
  to align with what good git practice already recommends.
- **`git commit --amend` is the iteration loop.** A failing build
  followed by a fix becomes `commit -> build -> amend -> build`,
  not `edit -> rebuild -> edit -> rebuild -> commit`. The commit
  history at the end of the session is clean by default; the
  experimental noise lives in `--amend` rather than in the log.
- **A passing build is push-ready by construction.** If the
  commit you just built passes, it is the commit you can push.
  There is no separate "now I have to commit what I tested" step
  where uncommitted state could leak in. What was tested is what
  is in the log, byte-for-byte.

The workflow that emerges is "commit small, build, amend or
push". For developers used to filesystem-mounted CI tools this is
a behavioural shift. For developers used to careful git practice
already, it is what they were doing anyway -- now enforced by the
tool rather than by discipline.

## Lane file structure for local work

A pattern that works well in practice is to keep two lane files:

- `lane.yaml` -- the production lane, fetching from the real
  upstream git server with full trust-anchor declarations.
- `local.yaml` -- the local-iteration lane, structurally identical
  but with the source step replaced by Option A or B.

Both files reference the same downstream steps. Only the source
step differs. Switching between them is a single CLI argument.
The diff between the two files is your reminder of what exactly
the local workflow is shortcutting (the trust anchor for the git
fetch).

## See also

- [ADR-011: Host filesystem cannot enter the DAG](ADR-011-sources-elimination.md)
  -- the architectural decision this guide implements.
- [ADR-007: Asymmetric identity](ADR-007-asymmetric-identity.md)
  -- the trust-anchor declaration that Option B exercises and
  Option A skips.
- [ADR-005: Hardened container profile](ADR-005-hardened-container-profile-non-configurable.md)
  -- the per-step hardening profile.
- [ADR-022: Network opt-in as a typed peer list](ADR-022-network-opt-in-as-peer-list.md)
  -- the typed peer declaration that replaces the boolean
  network field.
