// strike deploy attestation schema
//
// This schema defines the output format of every deploy step.
// The attestation is the signed record that carries the supply chain
// trust chain -- it must be formally specified, not just implicitly
// defined by Go struct tags.
//
// The artifact record (record.#Artifact) and its SBOM record live in the record
// package; this file references them across packages.
//
// Validation flow:
//   deploy.Execute() -> Attestation struct -> JSON -> CUE validate
//
// This mirrors lane.cue (input validation) but covers
// the output side. Together they provide a complete CUE-defined
// contract for strike's data model.
//
// Cross-implementation note: this schema, exported as JSON Schema
// via `cue export --out jsonschema`, is the specification contract
// for any secondary implementation (Rust verifier, policy engine,
// external audit tool).

package attest

import (
	"github.com/istr/strike/contract/endpoint"
	"github.com/istr/strike/contract/lane"
	"github.com/istr/strike/contract/primitive"
	"github.com/istr/strike/contract/record"
	provenancepkg "github.com/istr/strike/contract/provenance"
	deploytarget "github.com/istr/strike/contract/target"
)

#Timestamp: =~"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"

// ---------------------------------------------------------------------------
// Top-level attestation
// ---------------------------------------------------------------------------

// #Attestation is the deploy attestation envelope. The three top-level
// sections classify every recorded field by the trust the consumer must
// supply to rely on it:
//
//   sealed           - sound to any verifier without engine trust. CP makes
//                      the claim true by its own action (signing, observing
//                      against declared anchors, lane-anchoring) and binds
//                      the consumer through a signed digest the consumer
//                      itself dereferences.
//   engineDependent  - sound only to a verifier who trusts the engine.
//                      Engine-action claims (step run, egress confinement,
//                      connection routing). Empty in Phase 1; populated by
//                      capsule-observed attribution in Phase 2.
//   informational    - recorded for audit and IoC purposes; the attestation
//                      puts forward no trust claim. Includes container-
//                      asserted content (containers are untrusted by threat
//                      model regardless of engine trust) and engine self-
//                      reports that do not participate in the source-to-
//                      deploy chain.
//
// See docs/ATTESTATION-SOUNDNESS-AND-THE-TRUST-BOUNDARY.md and
// ADR-037 for the trust-layer theory.
#Attestation: {
	sealed:          #Sealed
	engineDependent: #EngineDependent
	informational?:  #Informational
}

// Sealed -- CP-bound claims, sound under both trust(E) and ~trust(E).
#Sealed: {
	// laneId is the stable identifier from the lane definition.
	laneId: primitive.#Identifier

	// target describes what was deployed to. Declared, lane-anchored.
	target: deploytarget.#Deploy

	// laneDigest is the raw sha256 over the lane definition file bytes,
	// computed by CP at parse time (hash and parse read the same bytes).
	laneDigest: primitive.#Digest | ""

	// artifacts maps artifact names to their signed provenance records.
	// Each artifact's digest is consumer-dereferenceable from the registry
	// (C3 sealed boundary).
	artifacts: [ID=primitive.#Identifier]: record.#Artifact

	// resolver records the DoT resolver's observed TLS identity, matched
	// against the declared anchor at the pre-flight handshake.
	resolver: #ResolverRecord

	// peers maps step name to the network peer declarations attached to
	// that step. Declared, lane-anchored.
	peers: [ID=primitive.#Identifier]: [...lane.#Peer]

	// engine carries the CP-observed connection facts about the engine.
	// The engine's self-reports (version, rootless) live in
	// informational.engineMetadata.
	engine?: endpoint.#Engine

	// observedPeers records, per peer endpoint ("host:port"), the connection
	// identity the control plane observed and validated against the declared
	// anchor, deduplicated across steps. A key/cert mismatch aborts the run
	// before any entry is written, so every entry here is a validated identity
	// (Layer V). No step attribution: which step reached a peer is an
	// engine-asserted fact and lives in engineDependent.peerAttribution.
	observedPeers?: [Endpoint=string]: #ObservedPeer
}

// ---------------------------------------------------------------------------
// Observed peer identity (sealed.observedPeers)
// ---------------------------------------------------------------------------

// ObservedPeer is one peer endpoint the control plane connected to and
// validated against the declared anchor. Layer V: the control plane dials per
// the lane spec and verifies the presented identity itself; the engine is not
// in this path.
#ObservedPeer: {
	// resolved lists the upstream IPs the lane's DoT resolver returned for this
	// peer's host, unioned across connections (resolution can vary by
	// TTL/round-robin; the validated identity below is stable). The resolver's
	// own identity is anchored in sealed.resolver.
	resolved: [...string]

	// identity is the validated channel identity, discriminated by type.
	identity: #ObservedSSH | #ObservedTLS
}

// ObservedSSH is a validated SSH host identity. hostKeyFingerprint is the
// SHA-256 of the key the server presented that matched the declared known_hosts
// anchor; hostKeyAlgo is that key's algorithm.
#ObservedSSH: {
	type:               "ssh"
	hostKeyFingerprint: string
	hostKeyAlgo:        string
}

// ObservedTLS is a validated HTTPS server identity. serverCertFingerprint is
// the SHA-256 of the leaf certificate that matched the declared anchor.
#ObservedTLS: {
	type:                  "https"
	serverCertFingerprint: string
}

// EngineDependent -- claims sound only under trust(E). Engine-asserted: the
// binding of a network action to a step rests on the engine routing the right
// container's traffic; there is no control-plane-independent basis for it
// (ADR-037 D2, front-step-demux spike).
//
// These records are the *mediated* set: connections strike observed because
// they traversed its mediation. The set is never exhaustive, and exhaustiveness
// is not a claim a mediator can make -- a mediator certifies what passed through
// it, never that nothing else did; the complement is, by construction,
// unobservable. Engine trust does not lift this: "the container had no other
// egress path" is a separate engine proposition (confinement), not a scope of
// these records -- folding it in would be a category error. Hence there is, and
// can be, no completeness flag.
//
// Phase 1 leaves peerAttribution empty; Phase-2 wiring (a separate
// instruction) populates it from capsule-observed routing. Do not pre-populate.
#EngineDependent: {
	// peerAttribution maps each step to the peer endpoints its mediated
	// connections reached ("host:port" keys into sealed.observedPeers).
	// Engine-asserted (Layer E).
	peerAttribution?: [ID=primitive.#Identifier]: [...string]
}

// Informational -- recorded for audit and IoC purposes; no trust claim.
//
// Container-asserted content lives here because containers are untrusted
// by threat-model definition (orthogonal to trust(E)). Engine self-
// reports about itself live here because they do not participate in the
// source-to-deploy chain.
#Informational: {
	// timestamp is CP's wall-clock at deploy start. Not security-relevant
	// per SECURITY.md: the RFC3161 TSA token is the trusted time (ADR-040).
	timestamp?: #Timestamp

	// engineMetadata carries the engine's self-reports about itself.
	engineMetadata?: #EngineMetadata

	// preStateDigest is CP's canonical SHA-256 digest of pre-deploy
	// state captures. The bytes were produced by the (untrusted) capture
	// container and relayed by the engine; CP's hash transports them,
	// it does not lift them out of the container-asserted class.
	preStateDigest: primitive.#Digest

	// postStateDigest -- symmetric to preStateDigest.
	postStateDigest: primitive.#Digest

	// provenance collects validated provenance records from transitive
	// predecessor steps. Each record is container-written at step exit
	// and engine-relayed; recorded for audit and IoC cross-check against
	// future capsule-observed peer/command records.
	provenance: [...provenancepkg.#Record]
}

// ---------------------------------------------------------------------------
// Engine identity
// ---------------------------------------------------------------------------

// EngineMetadata -- engine self-reports about itself. Lives under
// informational.engineMetadata. These claims are the engine's word
// about its own properties; they do not participate in the source-to-
// deploy chain and are recorded only for audit context.
#EngineMetadata: {
	// rootless indicates whether the engine runs in rootless mode
	// (engine self-report).
	rootless?: bool

	// version is the engine's self-reported version string
	// (engine self-report).
	version?: string
}

// ---------------------------------------------------------------------------
// Resolver identity
// ---------------------------------------------------------------------------

#ResolverRecord: {
	// host is the declared DoT resolver endpoint (host:port).
	host: string

	// serverCertFingerprint is sha256:<hex> of the resolver's leaf
	// certificate, observed at the pre-flight handshake.
	serverCertFingerprint: string

	// tlsVersion is the negotiated TLS version, human-readable.
	tlsVersion: string

	// cipherSuite is the negotiated cipher suite, human-readable.
	cipherSuite: string

	// serverName is the SNI sent during the handshake. Empty for
	// IP-literal resolver hosts (RFC 6066 forbids IP-literal SNI).
	serverName?: string
}
