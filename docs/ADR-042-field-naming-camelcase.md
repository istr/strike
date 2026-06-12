# ADR-042: Field naming -- camelCase, matching the attestation ecosystem

## Status

Accepted.

## Context

strike's wire formats -- the lane YAML it consumes and the attestation JSON it
emits -- had no documented field-naming convention. snake_case arose by
accident, not by decision: no ADR records it, and both DESIGN-PRINCIPLES.md and
the development guide are silent on it. The one place the codebase names it, the
Sealed type's comment, treats snake_case as friction -- one of the reasons the
deploy predicate's Go types are hand-mirrored rather than generated, because
snake_case fields would need pervasive @go() annotations to match the JSON
contract.

Meanwhile the attestation strike produces is, by construction, an ecosystem
document, and that ecosystem is uniformly camelCase. The in-toto Statement
(predicateType, _type), the SLSA Provenance predicate (buildDefinition,
externalParameters, resolvedDependencies, invocationId), DSSE (payloadType),
and the sigstore bundle and trusted_root.json (mediaType, tlogEntries,
inclusionProof, certChain, rawBytes) are all camelCase, and strike cannot
change them -- they are the foreign schemas it must match. The result today is a
single document that mixes both conventions: strike's own fields (lane_id,
observed_peers, peer_attribution, engine_metadata) appear in snake_case inside
camelCase ecosystem containers, so a verifier reads
externalParameters: { observed_peers, lane_id }. The cloud-native configuration
norm is camelCase as well -- Kubernetes YAML (apiVersion, imagePullPolicy) is
camelCase, where snake_case is the Ansible and Python-tooling idiom.

## Decision

All field names in strike's CUE schemas, generated Go types, lane YAML, and
attestation JSON are camelCase. Ecosystem-defined fields are already camelCase
by mandate; strike's own fields adopt the same convention, so every document is
camelCase end to end -- the lane the user writes, the predicate strike signs,
and the trust root it embeds. A CUE field named in camelCase generates the
matching Go json tag without a per-field @go() annotation for the tag, so the
convention removes annotation surface rather than adding it.

## Consequences

- A one-time cross-cutting rename: every snake_case json tag in the hand-written
  Go types, every snake_case field in the CUE schemas, the crossval fixtures,
  and the tests that assert field names. The golden bundles carry the predicate
  inside their signed payload, so they are regenerated; the rename changes
  signed bytes, which is expected and acceptable pre-beta.
- One of the three reasons the deploy predicate types are hand-mirrored -- the
  @go() annotation burden for snake_case tags -- dissolves. The other two,
  co-located CUE packages and the lane-to-transport alias chain, remain, so the
  types stay hand-written, but with less annotation noise.
- The lane a user authors now matches the attestation they verify, and both
  match the cloud-native camelCase norm.
- The embedded sigstore trust root (trusted_root.json, camelCase) can be
  replicated as a typed CUE structure without an impedance island, which is the
  form the verification-policy work adopts.
- This ADR formalizes a convention that was previously unstated. That absence is
  precisely why snake_case arose; recording the decision keeps it from
  recurring.

## Principles

- Runtime is attested -- the attestation is an in-toto / SLSA / sigstore
  document; native camelCase makes it ecosystem-consistent end to end, which the
  offline and cross-implementation verification depends on.
- CUE first -- field naming is a schema-layer convention with a single source;
  ecosystem-standard names serve the dual-language verification the CUE-first
  principle exists to enable.
- Code is liability -- camelCase removes the per-field @go() annotation burden
  that snake_case imposed, cutting annotation surface rather than adding it.
