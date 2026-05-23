# ADR-034: Symlink Containment at Wrap and Mount

## Status

Accepted. Refines [ADR-026](ADR-026-containers-as-sole-inter-step-storage.md)
(directory outputs are wrapped as OCI images) and
[ADR-027](ADR-027-input-subpath-selection.md) (subpath input mounts).
First decision to apply the "restricted by default, relaxed only with
reason" principle recorded in [DESIGN-PRINCIPLES.md](../DESIGN-PRINCIPLES.md).

## Context

Directory artifacts routinely contain symbolic links. `npm install` and
`npm ci` create them under `node_modules/.bin/` (links into sibling
packages) and, in workspace repositories, under `node_modules/<pkg>`
(a link to the local package source). Python virtualenvs, build trees,
and many other real-world outputs do the same.

The initial directory-wrapping implementation rejected symlinks outright
(`wrap dir layer: symlink at "<path>": not supported`). This blocked a
primary use case -- any Node lane that produces `node_modules` -- at the
output-wrapping step, after the step's work had already succeeded. Per
"restricted by default, relaxed only with reason", a concrete need now
justifies relaxing the no-symlinks restriction. The relaxation must be
scoped so that it cannot break the property that makes artifacts
attestable: that an artifact's digest fully determines what a consuming
step reads from it.

A symlink threatens that property only when it can resolve *outside* the
tree it belongs to. Two independent moments expose this:

- **Production.** A step writes its output directory; strike wraps it. A
  symlink that escapes the output root yields an artifact that is not
  self-contained: mounted at its own root, it still reaches outside
  itself.
- **Consumption.** A step mounts an artifact, or a subpath of one
  (ADR-027), at a mountpoint. A symlink that was valid relative to the
  *full* artifact root can escape the *mounted slice* when the lane
  author mounts a subpath that separates the link from its target. The
  artifact is innocent; the mount is wrong.

These are distinct. An artifact can be self-contained yet be mounted so
that containment breaks, and a non-self-contained artifact must never be
produced in the first place. Validating only one side leaves the other
open.

One structural simplification is available. A strike mountpoint is never
the container root `/`: inputs and outputs are mounted at declared paths
under a working directory, and nothing is mounted at `/` in either
direction. An absolute symlink target can therefore never resolve within
any mountpoint root. "Absolute symlinks are always an escape" is thus not
a special case but a consequence of the mount model.

## Decision

strike validates symbolic links at both ends of an artifact's life, **per
mountpoint, independently**.

A symlink is *contained* within a root R when its target, normalized
lexically relative to the link's own location (resolving `.` and `..` as
path arithmetic, never by following links on a live filesystem), resolves
to a path within R. Absolute targets are never contained, because no
mountpoint root is `/`.

- **Output validation (production).** When wrapping a directory output
  rooted at the declared output path R, every symlink within R must be
  contained within R. A symlink that escapes R, or that is absolute,
  fails the wrap with a diagnostic naming the link and its target. This
  guarantees that a produced artifact is self-contained: mounted at its
  root, every link in it resolves inside it.

- **Input validation (consumption).** For each input mount
  independently -- R is that mount's target path, and the mounted subtree
  is the whole artifact (ADR-026) or the selected subpath (ADR-027) --
  every symlink within the mounted subtree must be contained within R. A
  symlink that escapes R fails the step before execution, with a
  diagnostic naming the mountpoint, the offending link, and its target.

The two checks share one containment routine and one rejection
vocabulary; they differ only in which root they measure against. Symlinks
are stored and mounted verbatim -- the target string is preserved and
never dereferenced. Validation gates links; it does not rewrite them.

Each mountpoint is its own containment domain. A symlink may not cross
from one mount into another, even when both are mounted under a common
working directory. Inputs mounted at `/out/packages` and
`/out/package.json` are separate domains: a link inside `packages` that
pointed at `/out/package.json` escapes the `packages` mount and is
rejected, because the digest of the `packages` artifact does not account
for the contents of a different mount. A lane that genuinely needs links
to span a tree mounts that tree as a single mountpoint.

## Consequences

- The common npm shape resolves. `node_modules/.bin/*` links point within
  `node_modules` and pass output validation unchanged. (`npm ci
  --no-bin-links` avoids creating them at all, which is also fine.)
- A workspace link such as `node_modules/website -> ../packages/hugoautogen`
  resolves to a sibling of the `node_modules` output root and is rejected
  on output, with a diagnostic. This is intended: a `node_modules`
  directory that reaches into a sibling `packages` tree is not a
  self-contained artifact. The author resolves it by wrapping the tree
  that contains both as a single output (so the link is contained), not
  by special-casing the link.
- Lane-author mounting mistakes become loud and early. Mounting a subpath
  that severs a symlink from its target fails input validation at
  assembly with a precise message, rather than producing a step whose
  filesystem silently reaches outside its attested inputs, or a dangling
  link discovered mid-build.
- The validation depends on no mount-layout assumption and no
  cross-artifact coordination. Each artifact and each mount is
  independently checkable, which is what keeps the
  digest-determines-content property intact under arbitrary lane
  topologies.
- Symlinks are not dereferenced, so the wrapped layer does not duplicate
  target contents and link semantics are preserved for the consuming
  step.
- This does not make non-deterministic trees deterministic. `node_modules`
  remains non-reproducible in general (install order, optional and
  platform-specific dependencies); reproducibility stays the lane
  author's concern (a pinned lockfile via `npm ci`; `force_run` for
  declared non-determinism). Symlink validation governs containment, not
  reproducibility.

## Alternatives considered

- **Reject all symlinks (the status quo this ADR replaces).** Simple, but
  blocks every Node and virtualenv output and pushes authors into pre-wrap
  copy steps that defeat the purpose. Rejected: the blanket restriction
  buys no safety that containment validation does not also provide.
- **Closed union mount.** Allow an artifact to carry links that escape its
  own root, and enforce containment only once, against the consuming
  step's reconstructed mount root (the union of all its mounts). This
  keeps `node_modules` lean as a standalone artifact whose workspace link
  is satisfied by a co-mounted source artifact. Rejected: containment
  would depend on the consuming step's mount layout, so the same artifact
  is safe under one consumer and unsafe under another. The per-mount
  invariant is stronger, is decidable without knowing future consumers,
  and validates both production and consumption rather than one of them.
- **Dereference symlinks at wrap time.** Replace each link with a copy of
  its target. Rejected: inflates layers, can follow a link out of the
  tree at wrap time, and destroys the link semantics the consuming tool
  relies on.

## Principles

- Restricted by default, relaxed only with reason (the no-symlinks default
  is relaxed exactly to contained links; the no-escape invariant is
  preserved at both ends, and absolute targets stay rejected as a
  structural consequence of the mount model)
- Reproducibility is enforced, not hoped for (containment is decided
  lexically and identically at wrap and at mount, with no
  filesystem-dependent resolution)
- External references are digest-pinned (the same posture applied to the
  filesystem: a step reads only what the digests of its mounts account
  for)
- Code is liability (one containment routine serves both checks; there is
  no per-tool symlink handling)
- **Enforcement is structural, not discretionary.** Containment is
  enforced at both wrap and mount, per mountpoint, with no opt-out; an
  escaping or absolute symlink fails rather than being waved through.
