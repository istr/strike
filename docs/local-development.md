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

## The loop

No host-side git server exists on the endpoint, and none is added for local
iteration: [ADR-022](ADR-022-network-opt-in-as-peer-list.md)'s Consequences
already record that an unauthenticated loopback git-fetch protocol is not
expressible in the typed peer schema, and
[ADR-055](ADR-055-hardened-endpoint-development-premise.md) D1 grants the
reference endpoint a git *client*, not a git server -- running a local
protocol daemon or a hand-rolled HTTP server would be host-side execution
beyond the endpoint's four capabilities, on a filesystem that is `noexec`
besides. The forge is the only git peer a strike lane fetches from, in
development exactly as in CI.

The loop is therefore two gates over two different things, not two lane
variants:

1. **The working-tree gate**, run inside the dev container over the
   uncommitted, bind-mounted tree, after every code change and before
   submitting. It is unattested and discretionary; its job is the
   correctness of a change.
2. **A push**, which makes the change a content-addressed commit the forge
   can serve.
3. **The commit gate**, a strike lane that fetches the pushed revision from
   the forge, runs from the same lane file whether started from the dev
   container against the endpoint engine or from a forge runner. It is
   attested and structural: it blocks merge.

Neither gate substitutes for the other. A lane cannot see an uncommitted
tree ([ADR-011](ADR-011-sources-elimination.md)); the working-tree gate
cannot attest. A commit-gate failure after a green working-tree gate is a
round trip -- amend, push, re-run -- not a defect on `main`.

See [docs/DEVELOPMENT-ENDPOINT-PREMISES.md](DEVELOPMENT-ENDPOINT-PREMISES.md)
"Two gates, and where each runs" for the full mechanics.

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

## See also

- [ADR-011: Host filesystem cannot enter the DAG](ADR-011-sources-elimination.md)
  -- the architectural decision this guide implements.
- [ADR-007: Asymmetric identity](ADR-007-asymmetric-identity.md)
  -- the trust-anchor declaration a real git peer carries.
- [ADR-005: Hardened container profile](ADR-005-hardened-container-profile-non-configurable.md)
  -- the per-step hardening profile.
- [ADR-022: Network opt-in as a typed peer list](ADR-022-network-opt-in-as-peer-list.md)
  -- the typed peer declaration that replaces the boolean
  network field.
- [ADR-055: The hardened endpoint is the development premise](ADR-055-hardened-endpoint-development-premise.md)
  -- the endpoint's four capabilities and the two-gate loop.
- [docs/DEVELOPMENT-ENDPOINT-PREMISES.md](DEVELOPMENT-ENDPOINT-PREMISES.md)
  -- the operating procedure ADR-055 names as the reference.
