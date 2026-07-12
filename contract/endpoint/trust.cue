// Trust anchors for the endpoints strike contacts.
//
// Trust is a discriminated union over the enforceable server-side trust
// mechanisms strike supports. The system trust store is explicitly not an
// option (deferred per ADR-021); all trust is per-endpoint-declared. The
// discriminator is `type`; cross-implementation readers dispatch on it without
// parsing the rest of the object. The Go types are hand-written in
// internal/endpoint (annotated @go(-)); only #HostKey is generated.
package endpoint

import "github.com/istr/strike/contract/primitive"

#Trust: (#Fingerprint | #CABundle) @go(-)

#Fingerprint: {
	@go(-)
	type:        "certFingerprint"
	fingerprint: primitive.#Digest
}

#CABundle: {
	@go(-)
	type: "caBundle"
	// path is a container-internal path for the lane-relative CA bundle the
	// resolver trusts.
	path: primitive.#AbsPath
}

// #KeyType is an SSH host-key algorithm identifier.
#KeyType: "ssh-ed25519" | "ecdsa-sha2-nistp256" |
	"rsa-sha2-512" | "rsa-sha2-256"

// SSH server-trust anchor: a host key, one OpenSSH known_hosts line decomposed
// into typed fields. The trust anchor for an SSH endpoint is the set of host
// keys the server is permitted to present.
#HostKey: {
	@go(HostKey)
	keyType: #KeyType
	// key is the base64-encoded public key body (no PEM armor).
	key: primitive.#Base64 @go(Key)
}
