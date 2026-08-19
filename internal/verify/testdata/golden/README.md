# Keyless verifier golden fixtures

Five files that must verify together: `sealed.sigstore.json`,
`engine-context.sigstore.json`, `informational.sigstore.json`,
`trusted_root.json`, and `lane.yaml`. The first four are generated; `lane.yaml`
is hand-maintained input, not output.

## Regenerating

Regeneration is a deliberate act, not part of any test run or build gate. Bring
the local sigstore harness up, then run the generator from anywhere in the
module:

    cd test/sigstore-local && make up && make rekor-pubkey && make tsa-certchain && make ctlog-pubkey
    cd - && go tool gengolden

The generator contacts the harness, produces three real statement bundles and
the matching trust root, and writes all four files at once. It asserts nothing
and fails loudly: if the harness is down or a material is missing, it exits
non-zero and the checked-in fixtures are left untouched.

## When regeneration is forced

`lane.yaml` is policy input, not decoration, and the seal covers its **raw
bytes**: `lane.Parse` hashes the file exactly as read, comments included. The
sealed predicate carries that digest and the UC2 verify path recomputes it from
this file, so **any byte change to `lane.yaml` forces a full keyless
regeneration** -- including a change to nothing but a comment. There is no such
thing as an editorial edit to this file, and the failure mode is a lane-digest
mismatch in a test that needs no harness at all.

A cold-started harness mints fresh Fulcio and TSA certificate authorities, so
`trusted_root.json` is re-keyed even when nothing in strike changed. Only the
Rekor Ed25519 key persists. Do not gate on `trusted_root.json` being
byte-identical; gate on the five files verifying together.

## Commit shape

A regeneration forced by a schema change is cleanly separable from that change
and **lands as its own commit** beside it, never bundled into it. The fixture
diff is large, opaque, and mechanical; mixing it into a reviewable schema change
hides the part a reviewer can actually read.

## Verifying independently

`make conformance` in `test/sigstore-local` verifies the committed bundles with
cosign as an independent verifier, offline, against `trusted_root.json`.
