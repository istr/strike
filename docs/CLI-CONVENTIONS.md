# CLI conventions

strike subcommands share one shape: the positional argument is the command's
**subject**, and anything else is context supplied by flags.

- For `run`, `validate`, `dag`, the subject is the lane file; it defaults to
  `./lane.yaml` when omitted.
- For `verify`, the subject is the artifact (`<image@digest>`), and the lane --
  now context, not subject -- moves to `--lane`.

The default lane is `./lane.yaml` for both the implicit positional (run /
validate / dag) and the `--lane` flag (verify).

## verify

```
strike verify [flags] <image@digest>
```

The artifact reference must be digest-pinned (`repo@sha256:<hex>`); a tag is
rejected. Flags precede the positional.

Two modes, auto-detected:

- **UC1 (consumer).** `--identity` and `--issuer` are given explicitly, with
  `--trust-root-ref` naming a digest-pinned OCI image whose sole layer is a
  `trusted_root.json`. No lane is read.
  `strike verify --identity <id> --issuer <iss> --trust-root-ref <root-image@digest> <image@digest>`
- **UC2 (operator).** `--lane <lane.yaml>` supplies identity, issuer, and trust
  root from the lane. `--trust-root-ref` may still override the lane's root.
  `strike verify --lane <lane.yaml> <image@digest>`

`--identity`/`--issuer` together with `--lane` is an error: the lane is the
single source. The trust root has no implicit default -- it comes from
`--trust-root-ref`, the lane's `keyless.trustRoot`, or `keyless.trustRootRef`, and
absence of all three is an error.

Output: each verified statement is written to stdout; a per-bundle `OK`/`FAIL`
line with the layer sentinel on failure is written to stderr. Exit status is 0
when every attached bundle verifies and names the requested artifact, 1
otherwise.

What verify checks today: the keyless chain (DSSE signature, Fulcio leaf chain
and bound identity, RFC3161 trusted time, Rekor v2 inclusion) and that the
statement's subject is the requested artifact. Per-layer predicate validation
and the lane-digest binding are not yet wired.
