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

### Registry access

By default verify reads anonymously, in UC1 and in UC2, through the system
resolver and the system roots. That is the expected case, not a fallback: a
published artifact is read the way any consumer reads it, and what verify
reads is trusted through the digest pins and the keyless verification, not
through the transport. verify declares nothing about registry identity; the
resolver and the anchors a lane declares bound a lane run only.

A private repository needs a registry token:

- `--registry-token <source>` names where the token is read, `env://NAME` or
  `file://path`, never the token itself. The token is checked before any use:
  its lifetime is bounded, and in UC2 its audience must not contain the lane's
  oidc audience.
- The token is presented to one registry only, the target, and the subject
  must live there. The target's chain is verified against the target's
  anchor, still through the system resolver, and any redirect of a request
  carrying the token fails. Every other registry, a trust root elsewhere
  included, is read anonymously.
- **UC2.** The target is the registry deploy `--deploy-step <id>` names, with
  its declared anchor; when the lane has exactly one registry deploy, the flag
  may be omitted. `--registry-ca` is refused.
  `strike verify --lane <lane.yaml> --registry-token env://REGISTRY_ID_TOKEN <image@digest>`
- **UC1.** The target is the subject's registry. `--registry-ca file://path`
  names the root CA certificate its chain ends in: exactly one PEM
  certificate, a CA that signed itself. An intermediate or a leaf is refused.

`--deploy-step` and `--registry-ca` without `--registry-token` are errors:
they only say where a token is presented.

Output: each verified statement is written to stdout; a per-bundle `OK`/`FAIL`
line with the layer sentinel on failure is written to stderr. Exit status is 0
when every attached bundle verifies and names the requested artifact, 1
otherwise.

A registry may list a referrer late. While a layer whose absence would fail
the verification -- sealed, and engine-dependent unless `--no-engine-trust` --
is not listed, verify reads the referrers again after a wait of one second
that doubles, up to sixty seconds in all, with a `WAIT` line on stderr before
each wait; then it reports the absence. An absent informational layer is never
waited for.

What verify checks: the keyless chain (DSSE signature, Fulcio leaf chain and
bound identity, RFC3161 trusted time, Rekor v2 inclusion), that the
statement's subject is the requested artifact, and each layer's predicate. The
sealed statement is decoded whole as SLSA provenance and must carry a lane
digest, in UC2 equal to the policy lane's; the engine-dependent and
informational statements must carry their layer's predicate type.
