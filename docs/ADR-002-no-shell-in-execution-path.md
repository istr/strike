# ADR-002: No Shell in the Execution Path

## Status

Accepted.

## Context

CI/CD systems traditionally accept shell snippets as the unit of step
expression: GitHub Actions' `run:`, GitLab's `script:`, Jenkins'
`sh '...'`. Shell snippets are convenient for authors but structurally
enable command injection, string-concatenation attacks, environment
variable interpolation surprises, and lateral movement. A shell
interpreter in the execution path means an attacker with control over
any string that flows into a step (a tag, a branch name, a YAML value,
an environment variable) potentially has command execution.

A specification language without shell forces the question: how does a
step express its work? The answer is the same one used by container
runtimes themselves: an image plus an args array.

## Decision

strike step definitions specify an image and an args array. There is
no `run:` block, no `bash -c`, no string interpolation, no template
expansion in lane definitions. Generic-purpose shells are prohibited
in the execution path -- not in steps, not in build images, not in
the runtime environment strike provides.

A feature that cannot be expressed without shell is out of scope.

## Consequences

- Step authors must build images that contain the binaries they need
  and invoke them with `args: [tool, arg1, arg2]`.
- Multi-command steps are expressed as multiple separate steps with
  declared inputs and outputs, not as `&&`-chained shell scripts.
  This forces dependency declaration to be explicit, which is also
  what the DAG needs for correct scheduling.
- An entire class of injection vulnerabilities is structurally
  impossible: a malicious string in `image`, `args`, or any other
  field cannot become a shell command, because there is no shell.
- The bootstrap Containerfile contains one historical shell expansion
  (a `git fetch` of `${GIT_COMMIT}`) noted as "dirty", to be removed
  in stage 1 once strike is self-hosting.

## Principles

- No shell
- Code is liability (rejecting features that would require shell)
