// strike deploy attestation schema
//
// This schema defines the output format of every deploy step.
// The attestation is the signed record that carries the supply chain
// trust chain — it must be formally specified, not just implicitly
// defined by Go struct tags.
//
// Validation flow:
//   deploy.Execute() → Attestation struct → JSON → CUE validate
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
// Shared types (mirrored from lane/schema.cue for independence)
// ---------------------------------------------------------------------------

#Digest: =~"^sha256:[a-f0-9]{64}$"

#Timestamp: =~"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"

// DeployID is a 16-character hex string derived from sha256(step_name + nanos).
#DeployID: =~"^[a-f0-9]{16}$"

// ---------------------------------------------------------------------------
// Top-level attestation
// ---------------------------------------------------------------------------

#Attestation: {
	// deploy_id uniquely identifies this deploy event.
	deploy_id: #DeployID

	// timestamp is the wall-clock time when the deploy started.
	timestamp: #Timestamp

	// target describes what was deployed to.
	target: #DeployTarget

	// artifacts maps artifact names to their content-addressed digests.
	// Every artifact listed here was verified against the lane state
	// before the deploy action executed.
	// Values are typically "sha256:<hex>" but not constrained to #Digest
	// because external artifact systems may use different formats.
	artifacts: [Name=string]: string

	// pre_state captures the state of the target before the deploy.
	pre_state: [Name=string]: #StateSnap

	// post_state captures the state of the target after the deploy.
	post_state: [Name=string]: #StateSnap

	// drift is present when drift detection is enabled and a previous
	// attestation exists for comparison.
	drift?: #DriftReport

	// engine records the container engine identity at deploy time.
	// Verifiers use this to assess the trust level of the environment.
	engine?: #EngineRecord

	// source captures git provenance when source mounts are present.
	source?: #SourceProvenance

	// lane_ref is the digest of the lane definition file.
	// Empty string when not yet computed.
	lane_ref: string
}

// ---------------------------------------------------------------------------
// State snapshots
// ---------------------------------------------------------------------------

#StateSnap: {
	// name identifies this state dimension (e.g. "version", "config-hash").
	name: string

	// image is the digest-pinned container image used for capture.
	image: string

	// digest is the sha256 of the captured output.
	digest: #Digest | ""

	// timestamp is when this snapshot was taken.
	timestamp: #Timestamp

	// output is the raw capture output (base64-encoded in JSON).
	output: _
}

// ---------------------------------------------------------------------------
// Drift detection
// ---------------------------------------------------------------------------

#DriftReport: {
	// previous_deploy_id links to the attestation being compared against.
	previous_deploy_id: #DeployID

	// previous_post_state maps dimension names to their digests from
	// the previous deploy's post-state.
	previous_post_state: [Name=string]: string

	// current_pre_state maps dimension names to their digests from
	// the current deploy's pre-state.
	current_pre_state: [Name=string]: string

	// drifted lists the dimension names where digests differ.
	// null when no dimensions drifted (Go nil slice → JSON null).
	drifted: [...string] | null
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

// ---------------------------------------------------------------------------
// Deploy target (mirrors lane.DeployTarget)
// ---------------------------------------------------------------------------

#DeployTarget: {
	type:         =~"^.+$"
	description:  =~"^.+$"
	url?:         string
	namespace?:   string
}

// ---------------------------------------------------------------------------
// Source provenance
// ---------------------------------------------------------------------------

#SourceProvenance: {
	// commit is the HEAD commit hash at build time.
	commit: =~"^[a-f0-9]{40}$"

	// ref is the checked-out git ref (branch or tag).
	ref: string

	// range is the commit range since the previous known deploy.
	range?: {
		from: =~"^[a-f0-9]{40}$"
		to:   =~"^[a-f0-9]{40}$"
	}

	// signers lists verified commit signatures in the range.
	signers: [...#CommitSigner] | null

	// unsigned_commits lists commit hashes without valid signatures.
	unsigned_commits: [...=~"^[a-f0-9]{40}$"] | null

	// all_signed is true iff every commit in range has a valid signature.
	all_signed: bool
}

#CommitSigner: {
	// commit is the signed commit hash.
	commit: =~"^[a-f0-9]{40}$"

	// identity is the signer's identity (email, key ID).
	identity: string

	// method is how the commit was signed.
	method: "gpg" | "ssh" | "gitsign" | "x509"

	// fingerprint is the key fingerprint (GPG or SSH).
	fingerprint?: string

	// oidc_issuer is the OIDC issuer for gitsign signatures.
	oidc_issuer?: string

	// verified is true if the signature was successfully verified.
	verified: bool
}
