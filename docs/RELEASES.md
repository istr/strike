# Releases

This document records how the tree names the commit the bootstrap builds
(docs/ADR-009-bootstrap-reproducibility-proof.md).

## Bootstrap pin (interim)

The bootstrap names one commit in two places: `GIT_COMMIT` in the README
bootstrap command, and the `--revision=` argument of the source step in
`lane.yaml`. Both name the parent of the commit that carries them. A commit
cannot name itself: its hash covers its own content.

Every commit keeps the pin current:

1. Before committing, read the parent: `git rev-parse HEAD`.
2. Write that hash into `GIT_COMMIT=` in `README.md` and into `--revision=`
   in `lane.yaml`, and stage both with the rest of the change.
3. Commit. Afterwards `git rev-parse HEAD~1` equals both values.

A commit that is amended or rebased gets a new parent and repeats the
procedure. A patch prepared outside the tree pins the commit it is based on
and is applied on that commit.

This rule is interim. The release procedure replaces it in this document;
until then every commit follows it.
