# Releases

This document records how the tree names the commit the bootstrap builds
(docs/ADR-009-bootstrap-reproducibility-proof.md).

## Bootstrap pin (interim)

The README bootstrap command names one commit, `GIT_COMMIT`, and it names
the parent of the commit that carries it. A commit cannot name itself: its
hash covers its own content.

The bootstrap lane carries no pin. The stage_0 build renders it from
`bootstrap/lane.cue` with the commit the build fetched as the source step's
revision, so the lane always builds the commit the stage_1 binary was built
from.

Every commit keeps the pin current:

1. Before committing, read the parent: `git rev-parse HEAD`.
2. Write that hash into `GIT_COMMIT=` in `README.md`, and stage it with the
   rest of the change.
3. Commit. Afterwards `git rev-parse HEAD~1` equals the value.

A commit that is amended or rebased gets a new parent and repeats the
procedure. A patch prepared outside the tree pins the commit it is based on
and is applied on that commit.

This rule is interim. The release procedure replaces it in this document;
until then every commit follows it.
