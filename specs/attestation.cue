// strike deploy attestation schema
//
// This schema defines the output format of every deploy step.
// The attestation is the signed record that carries the supply chain
// trust chain -- it must be formally specified, not just implicitly
// defined by Go struct tags.
//
// Companion file: artifact.cue defines #SignedArtifact and related
// provenance types (same package deploy, merged automatically by CUE).
//
// Validation flow:
//   deploy.Execute() -> Attestation struct -> JSON -> CUE validate
//
// This mirrors lane/schema.cue (input validation) but covers
// the output side. Together they provide a complete CUE-defined
// contract for strike's data model.
//
// Cross-implementation note: this schema, exported as JSON Schema
// via `cue export --out jsonschema`, is the specification contract
// for any secondary implementation (Rust verifier, policy engine,
// external audit tool).

package deploy

// ---------------------------------------------------------------------------
// Shared types -- re-exported from lane via artifact.cue
// ---------------------------------------------------------------------------

// #Digest, #AbsPath, peer types, and #DeployTarget are re-exported
// in artifact.cue (same package). They are available here without
// import or duplication.

#Timestamp: =~"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"

// ---------------------------------------------------------------------------
// Top-level attestation
// ---------------------------------------------------------------------------

#Attestation: {
	// lane_id is the stable identifier from the lane definition.
	lane_id: =~"^[a-z0-9][a-z0-9-]{0,62}$"

	// timestamp is the wall-clock time when the deploy started.
	timestamp: #Timestamp

	// target describes what was deployed to.
	target: #DeployTarget

	// artifacts maps artifact names to their signed provenance records.
	// Every artifact listed here was verified against the lane state
	// before the deploy action executed.
	artifacts: [Name=string]: #SignedArtifact

	// pre_state_digest is the canonical SHA-256 digest of all configured
	// pre-deploy state captures. Computed by internal/deploy/digest_state.go
	// over name-sorted captures with length-prefixed encoding. Independent
	// of capture order and capture timestamps.
	pre_state_digest: #Digest

	// post_state_digest is the canonical SHA-256 digest of all configured
	// post-deploy state captures. Same encoding as pre_state_digest.
	post_state_digest: #Digest

	// engine records the container engine identity at deploy time.
	// Verifiers use this to assess the trust level of the environment.
	engine?: #EngineRecord

	// provenance collects validated provenance records from transitive
	// predecessor steps. Sorted deterministically by step name.
	// Empty array when no steps declare provenance.
	provenance: [...#ProvenanceRecord]

	// peers maps step name to the network peer declarations attached to
	// that step. Only steps that declared at least one peer appear.
	peers: [Step=string]: [...#Peer]

	// rekor is the transparency log entry from a Rekor hashedrekord
	// submission. Present only when REKOR_URL is configured.
	rekor?: #RekorEntry

	// lane_ref is the digest of the lane definition file.
	// Empty string when not yet computed.
	lane_ref: #Digest | ""
}

// ---------------------------------------------------------------------------
// Engine identity
// ---------------------------------------------------------------------------

#EngineRecord: {
	// connection_type is "unix", "tls", or "mtls".
	connection_type: "unix" | "tls" | "mtls"

	// ca_trust_mode is "pinned" (explicit CA) or "system" (OS trust store).
	ca_trust_mode?: "pinned" | "system" | ""

	// server_cert_fingerprint is sha256:<hex> of the engine's leaf cert.
	server_cert_fingerprint?: string

	// client_cert_fingerprint is sha256:<hex> of the controller's cert.
	client_cert_fingerprint?: string

	// rootless indicates whether the engine runs in rootless mode.
	rootless?: bool

	// version is the engine's self-reported version string.
	version?: string
}

// #DeployTarget is re-exported from lane via artifact.cue.

// Peer types (#Peer, #HTTPSPeer, #SSHPeer, #OCIPeer, #HTTPSTrust,
// #FingerprintTrust, #CABundleTrust, #KnownHostEntry) are re-exported
// from lane via artifact.cue.
