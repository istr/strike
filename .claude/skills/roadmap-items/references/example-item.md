---
id: item-0042
status: ratified
arcs: [output-model, image-from-step]
rank: "0030"
title: "Add OutputRef disjunction to deploy.artifacts.from"
goal: "deploy.artifacts.from accepts a step-only image ref or a step+output file ref as one disjunction"
acceptance_intent: "CUE validates step-only image refs and step+output file/dir refs; generated Go types follow the @go(-) hand-sewn glue pattern; goldens regenerate cleanly"
links: [ADR-046, ADR-004]
execution_profile: { class: smallest, reasoning: low }
---
Drift-invariant notes:

- Follows the verified @go(-) + hand-sewn glue pattern already used for deploy-package
  disjunctions; do not invent a new mechanism.
- Open question to confirm at authoring time: whether the producer side needs any
  change, or whether this is purely the consumer (deploy) ref shape.
- The byte-exact wire instruction is authored ephemerally against the then-current
  pin; nothing byte-exact is stored here on purpose.
