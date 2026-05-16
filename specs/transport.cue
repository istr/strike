// Transport-level types: host constraint and TLS trust anchors.
//
// These definitions share package lane so that lane.cue can reference
// them directly (#Host, #TLSTrust). The @go(-) annotations suppress
// Go code generation via gengotypes; the Go types are hand-written in
// internal/transport/transport.go so they live in a separate Go package.
// Directional dependency: internal/lane imports internal/transport.
package lane

// ----------------------------------------------------------------
// Host constraint: hostname or IPv4 literal, optionally with port.
// Lowercase ASCII; punycode required for internationalized domains.
// Used by every peer kind that addresses a network endpoint by
// name (HTTPS, SSH, DoT resolver, future TLS-trusted peers).
// OCI registries use a separate constraint because their format
// includes path segments.
// ----------------------------------------------------------------
#Host: string & =~"^[a-z0-9.-]+(:[0-9]+)?$" @go(-)

// ----------------------------------------------------------------
// Trust anchors for TLS-based peers.
//
// TLSTrust is a discriminated union over the two enforceable
// server-side trust mechanisms strike supports. The system trust
// store is explicitly not an option (deferred per ADR-021); all
// trust is per-peer-declared.
//
// The discriminator is `mode`. Cross-implementation readers can
// dispatch on `mode` without parsing the rest of the object.
// ----------------------------------------------------------------
#TLSTrust: (#FingerprintTrust | #CABundleTrust) @go(-)

#FingerprintTrust: {
	@go(-)
	mode:        "cert_fingerprint"
	fingerprint: =~"^sha256:[a-f0-9]{64}$"
}

#CABundleTrust: {
	@go(-)
	mode: "ca_bundle"
	// path is a container-internal path. The executor mounts the lane-
	// relative bundle file there in Phase 2; in Phase 1 the field is
	// declaratory only.
	path: #AbsPath
}
