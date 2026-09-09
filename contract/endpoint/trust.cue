// Trust anchors for the endpoints strike contacts.
//
// A TLS anchor is one shape: the certificate itself, DER-encoded in standard
// padded base64, with a mode that says how it binds (ADR-056). There is no
// discriminator and nothing to dispatch on -- a cross-implementation reader
// decodes one field and parses it. The system trust store is explicitly not an
// option (deferred per ADR-021); all trust is per-endpoint-declared. The Go
// types are generated; internal/endpoint hand-writes only the certificate
// parse and the known_hosts rendering.
package endpoint

import "github.com/istr/strike/contract/primitive"

// #CertificateMode is how a declared certificate binds. rootca installs it as
// the sole root of a verified chain; leaf compares it byte for byte against
// the leaf the peer presents and enters no pool.
#CertificateMode: "rootca" | "leaf"

// #Certificate is the TLS server-trust anchor: the certificate a peer is
// permitted to present, or the root of the chain it presents. The type is
// named for the artifact and the field at each declaration site is named for
// the role, exactly as #SSH.knownHosts and #HostKey already divide it.
#Certificate: {
	@go(Certificate)

	// mode defaults to rootca. The default is a CUE default arm rather than a
	// Go-side resolution, so schema.FillLaneJSON materializes it before the
	// decode, the value is concrete on the attest wire, and a verifier reading
	// contract/ alone learns what an absent field meant (ADR-056 amendment
	// 2026-09-06).
	mode: *"rootca" | #CertificateMode @go(Mode,type=CertificateMode)
	// cert is the base64-encoded DER certificate body (no PEM armor), the same
	// primitive and the same discipline #HostKey.key carries for SSH.
	cert: primitive.#Base64 @go(Cert)
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
