package lane

import "github.com/istr/strike/contract/primitive"

// Typed CUE replica of the sigstore TrustedRoot, in the protojson camelCase
// wire shape. This MIRRORS an external spec:
//
//   upstream:  github.com/sigstore/protobuf-specs
//   proto:     protos/sigstore_trustroot.proto  (message TrustedRoot)
//   wire:      gen/jsonschema (protojson; snake_case proto fields -> lowerCamel)
//
// It is a SUBSET: only the fields verify.ParseTrustedRoot consumes
// (certificateAuthorities + timestampAuthorities cert chains; tlogs and
// ctlogs public key, log id, and validity window). The structure tracks the
// real trusted_root.json (internal/verify/testdata/golden/trusted_root.json).
// When upstream changes, the diff is confined to this file. Closed: a trust
// root carrying fields strike does not use is rejected, which is intended
// pre-beta.

#TrustedRootReplica: {
	@go(TrustedRootReplica)
	mediaType?: string @go(MediaType)
	tlogs: [...#TransparencyLogReplica] @go(Tlogs)
	// Required: a trust root with no certificate-transparency log is not
	// material this verifier can use, and ParseTrustedRoot rejects it.
	ctlogs: [...#TransparencyLogReplica] @go(Ctlogs)
	certificateAuthorities: [...#CertAuthorityReplica] @go(CertificateAuthorities)
	timestampAuthorities: [...#CertAuthorityReplica] @go(TimestampAuthorities)
}

// One transparency-log instance. tlogs and ctlogs are the same upstream
// message, so both project from this definition. Both validity bounds are
// carried: the replica is closed, so omitting the upper bound would reject a
// legitimate trusted root on the inline path.
#TransparencyLogReplica: {
	@go(TransparencyLogReplica)
	baseUrl?:       string @go(BaseURL)
	hashAlgorithm?: string @go(HashAlgorithm)
	publicKey: {
		rawBytes:    primitive.#Base64 @go(RawBytes)
		keyDetails?: string            @go(KeyDetails)
		validFor?: {start?: string @go(Start), end?: string @go(End)} @go(ValidFor)
	} @go(PublicKey)
	logId: {keyId: primitive.#Base64 @go(KeyID)}
}

#CertAuthorityReplica: {
	@go(CertAuthorityReplica)
	uri?: string @go(URI)
	certChain: {certificates: [...{rawBytes: primitive.#Base64 @go(RawBytes)}] @go(Certificates)} @go(CertChain)
	validFor?: {start?: string @go(Start), end?: string @go(End)} @go(ValidFor)
}
