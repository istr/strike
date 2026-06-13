package deploy

// Sigstore bundle (v0.3) -- the published verification material strike emits
// per deploy statement and an independent verifier consumes. This is a typed
// projection of the sigstore bundle media type
// "application/vnd.dev.sigstore.bundle.v0.3+json"
// (github.com/sigstore/protobuf-specs, proto3-JSON encoding), constrained to
// the single emission profile strike produces. Like sigstore-trustroot.cue it
// projects an external standard so a cross-implementation verifier can check
// the published material from the exported schemas; it is not a private fork of
// a strike contract.
//
// This is the PRODUCER emission contract. The consumer (internal/verify) parses
// arbitrary sigstore bundles via sigstore-go and must not be narrowed to this
// profile.
//
// proto3-JSON encoding: int64 fields render as decimal strings (logIndex,
// treeSize); bytes fields render as standard padded base64. Under Rekor v2 the
// transparency-log entry carries no SET (no inclusionPromise) and no integrated
// timestamp; trusted time is the RFC3161 token (ADR-040).

// #Bundle is the top-level sigstore v0.3 bundle. strike emits the DSSE-envelope
// variant with single-leaf-certificate verification material.
#Bundle: {
	mediaType:            "application/vnd.dev.sigstore.bundle.v0.3+json"
	verificationMaterial: #VerificationMaterial
	dsseEnvelope:         #DSSEEnvelope
}

// #VerificationMaterial carries the Fulcio leaf certificate, exactly one Rekor
// v2 transparency-log entry, and exactly one RFC3161 timestamp.
#VerificationMaterial: {
	certificate: {rawBytes: #Base64}
	tlogEntries: [#TransparencyLogEntry]
	timestampVerificationData: {
		rfc3161Timestamps: [{signedTimestamp: #Base64}]
	}
}

// #DSSEEnvelope wraps the signed in-toto statement: the in-toto payload type,
// the base64 statement, and exactly one DER-ECDSA signature with no key id
// (keyless -- the signer identity is the Fulcio certificate, not a key id).
#DSSEEnvelope: {
	payloadType: "application/vnd.in-toto+json"
	payload:     #Base64
	signatures: [{sig: #Base64}]
}

// #TransparencyLogEntry is the Rekor v2 inclusion record. integratedTime and
// inclusionPromise (SET) are absent under Rekor v2; inclusion is proven by the
// Merkle proof against a C2SP signed-note checkpoint.
#TransparencyLogEntry: {
	// logIndex, inclusionProof.logIndex, and inclusionProof.hashes are optional
	// because proto3-JSON omits a scalar int64 whose value is 0 and a repeated
	// field that is empty. The first entry in a log has index 0 (omitted), and a
	// single-leaf inclusion proof has no sibling hashes (omitted). treeSize is
	// always >= 1 for a non-empty log, so it is never omitted.
	logIndex?: #Int64String
	logId: {keyId: #Base64}
	kindVersion: {
		kind:    string
		version: string
	}
	inclusionProof: {
		logIndex?: #Int64String
		rootHash:  #Base64
		treeSize:  #Int64String
		hashes?: [...#Base64]
		checkpoint: {envelope: string}
	}
	canonicalizedBody: #Base64
}

// #Base64 is standard padded base64 -- the proto3-JSON form of a bytes field.
#Base64: =~"^[A-Za-z0-9+/]+={0,2}$"

// #Int64String is a proto3-JSON int64 -- a non-negative decimal string.
#Int64String: =~"^[0-9]+$"
