# ADR-016: State-Drift Recording, Not Detection or Action

## Status

Accepted.

## Context

A deploy step in strike captures the state of its target before and
after the deploy action. The two captures bracket the deploy:
anything that happens to the target between two consecutive deploys
is, by definition, drift -- a change to the target that did not pass
through strike's signed and attested deploy path.

The earliest design carried this further: strike was to load the
previous deploy's attestation, compare its post-state against the
current pre-state, embed a `DriftReport` in the new attestation,
and optionally fail the run if drift was detected.

Three design questions surfaced during principle review:

1. Where does the previous attestation come from?
2. Does strike's attestation make a verifiable claim when it
   embeds `drift_detected`?
3. Is the action on detected drift strike's responsibility?

The answers, taken together, narrow strike's role considerably.

## Decision

Drift handling decomposes into three operations:

- **Recording.** Capture pre-state and post-state; embed their
  digests in the signed attestation.
- **Detection.** Compare a previous attestation's post-state digest
  with the current attestation's pre-state digest.
- **Action.** Decide what to do about detected drift.

strike implements **only Recording**. Detection and Action are
out of scope.

The deploy attestation contains:

- `pre_state_digest`: the canonical hash of all configured pre-deploy
  state captures.
- `post_state_digest`: the canonical hash of all configured
  post-deploy state captures.
- `lane_id` and `target.id`: stable identifiers operators assign at
  authoring time.

The captures themselves are computed in step containers (per the
hardened security profile, ADR-005). The raw capture outputs do not
appear in the attestation; only the two digests do. This closes a
class of accidental secret exfiltration: a capture command that
reads sensitive data (`kubectl get secret`, `cat /etc/...`) no
longer places that data into the signed attestation, because only
the digest is recorded.

The attestation makes no claim about drift, no reference to any
predecessor attestation, and contains no policy outcome.

strike does not store attestations between runs. strike does not
look up previous attestations. strike does not compare states across
runs.

## Why each operation lands where it does

### Recording stays in strike

Recording requires the target. The container engine is the only path
strike has to the target, and capture-via-container is already the
mechanism the project commits to. No other tool can do this without
duplicating strike's runtime model. The captures are signed,
content-addressed, and reproducible from the inputs declared in the
lane.

### Detection is out of scope

Detection requires a previous attestation. Three plausible sources
(state file maintained by strike, target annotation, transparency-log
query) each violate at least one design principle: a state file
makes strike a stateful tool with mutable storage; a target
annotation makes the read path traverse a mutable target-specific
channel; a transparency-log query introduces a race between
concurrent strike runs against the same target, where whichever
lookup fires first sees a different "latest" than the second.

There is also a structural objection independent of storage: when
strike embeds `drift_detected: true` in a signed attestation, the
truth of that claim is not derivable from the attestation's own
inputs. A verifier cannot confirm the claim without performing the
same external lookup strike performed -- making strike's work
redundant. A verifier that *does* do the lookup independently does
not need strike's claim in the first place.

Recording is sufficient for any external party to detect drift
after the fact. The two pre/post digests fully determine whether
two consecutive deploys' bracket states agree.

### Action is out of scope

Action is policy. Policy is governed by who owns the target, who
operates the pipeline, what compliance regime applies, and what the
escalation paths look like. None of these are visible to strike,
and none of them should be.

Embedding action policy in the lane (`on_drift: fail | warn | ignore`)
either pushes a single binary decision onto a question that has many
correct answers, or grows into an expression language that
duplicates what dedicated policy engines already do well.

## Canonicalization of state digests

Two independent strike instances with identical capture
configurations and identical capture outputs must produce
byte-identical pre-state and post-state digests. The
canonicalization rules:

- Captures are sorted by name (lexicographic, byte-wise).
- Each capture contributes its fields (name, image, content
  digest, output bytes) in fixed order, separated and length-
  prefixed to make the encoding injective.
- The concatenated byte stream is hashed with SHA-256.
- The capture's wall-clock timestamp is excluded from the hash.
  Capture content is the source of truth; capture timing is event
  metadata and would break reproducibility across runs.

The exact byte-level encoding is documented in
`internal/deploy/digest_state.go` and tested for order-independence
and content-sensitivity.

## Consequences

- The attestation surface shrinks: `pre_state` and `post_state`
  collapse from `map[string]StateSnap` to single `lane.Digest`
  values. The class of accidental secret exfiltration through raw
  capture output is structurally closed.
- The lane schema gains two stable identifier fields (`lane_id`,
  `target.id`) and loses three fields (`on_drift`, `drift.detect`,
  the `DriftSpec` block).
- Drift policy is not strike's concern. A team that wants
  strict-block-on-drift writes a pre-deploy gate that runs against
  the most recent prior attestation and refuses to invoke strike
  if drift is shown. A team that wants alert-and-continue writes a
  post-deploy job that does the same and pages on detection.
- strike's footprint shrinks: the previous-attestation loader
  (never implemented), the detection logic, and the action
  handlers all move out. "Code is liability" applied to a feature
  that looked load-bearing turns out to remove a substantial code
  surface.

## Principles

- Code is liability (three operations collapsed to one)
- Runtime is attested (recording is preserved; the recording is
  what makes downstream detection possible)
- Reproducibility is enforced (canonical capture digest excludes
  wall-clock metadata, hashes content only)
- External references are digest-pinned (consumer pairing of
  attestations uses content-addressed identifiers, not mutable
  pointers)
- Secrets are typed (raw capture outputs no longer enter the
  signed attestation)
