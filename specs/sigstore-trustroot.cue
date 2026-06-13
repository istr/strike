package lane

// Typed CUE replica of the sigstore TrustedRoot, in the protojson camelCase
// wire shape. This MIRRORS an external spec:
//
//   upstream:  github.com/sigstore/protobuf-specs
//   proto:     protos/sigstore_trustroot.proto  (message TrustedRoot)
//   wire:      gen/jsonschema (protojson; snake_case proto fields -> lowerCamel)
//
// It is a SUBSET: only the fields verify.ParseTrustedRoot consumes
// (certificateAuthorities + timestampAuthorities cert chains; tlogs public
// key + log id). The structure tracks the real trusted_root.json
// (internal/verify/testdata/golden/trusted_root.json). When upstream changes,
// the diff is confined to this file. Closed: a trust root carrying fields
// strike does not use (e.g. ctlogs) is rejected, which is intended pre-beta.

#TrustedRootReplica: {
	@go(TrustedRootReplica)
	mediaType?: string @go(MediaType)
	tlogs: [...{
		baseUrl?:       string @go(BaseURL)
		hashAlgorithm?: string @go(HashAlgorithm)
		publicKey: {
			rawBytes:    string @go(RawBytes) // base64 DER
			keyDetails?: string @go(KeyDetails)
			validFor?: {start?: string @go(Start)} @go(ValidFor)
		} @go(PublicKey)
		logId: {keyId: string @go(KeyID)} @go(LogID) // base64
	}] @go(Tlogs)
	certificateAuthorities: [...#CertAuthorityReplica] @go(CertificateAuthorities)
	timestampAuthorities: [...#CertAuthorityReplica] @go(TimestampAuthorities)
}

#CertAuthorityReplica: {
	@go(CertAuthorityReplica)
	uri?: string @go(URI)
	certChain: {certificates: [...{rawBytes: string @go(RawBytes)}] @go(Certificates)} @go(CertChain)
	validFor?: {start?: string @go(Start), end?: string @go(End)} @go(ValidFor)
}
