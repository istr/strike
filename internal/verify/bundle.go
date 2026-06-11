package verify

import (
	"fmt"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// bundleV03MediaType is the only bundle media type the verifier accepts.
const bundleV03MediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

// ParseBundle validates the strict shape of a sigstore v0.3 bundle and
// extracts its content: exactly one DSSE envelope with one signature, one
// leaf certificate (not a bare public key), one transparency-log entry, one
// RFC3161 timestamp. Anything else is a hard rejection.
func ParseBundle(jsonBytes []byte) (*ParsedBundle, error) {
	var pb protobundle.Bundle
	if err := protojson.Unmarshal(jsonBytes, &pb); err != nil {
		return nil, fmt.Errorf("%w: unmarshal: %w", ErrBundleShape, err)
	}
	if pb.GetMediaType() != bundleV03MediaType {
		return nil, fmt.Errorf("%w: media type %q", ErrBundleShape, pb.GetMediaType())
	}
	env := pb.GetDsseEnvelope()
	if env == nil {
		return nil, fmt.Errorf("%w: not a DSSE-envelope bundle", ErrBundleShape)
	}
	if len(env.GetSignatures()) != 1 {
		return nil, fmt.Errorf("%w: %d signatures, want 1", ErrBundleShape, len(env.GetSignatures()))
	}
	vm := pb.GetVerificationMaterial()
	if vm == nil {
		return nil, fmt.Errorf("%w: no verification material", ErrBundleShape)
	}
	cert := vm.GetCertificate()
	if cert == nil || len(cert.GetRawBytes()) == 0 {
		return nil, fmt.Errorf("%w: no leaf certificate", ErrBundleShape)
	}
	if len(vm.GetTlogEntries()) != 1 {
		return nil, fmt.Errorf("%w: %d tlog entries, want 1", ErrBundleShape, len(vm.GetTlogEntries()))
	}
	tsv := vm.GetTimestampVerificationData()
	if tsv == nil || len(tsv.GetRfc3161Timestamps()) != 1 {
		return nil, fmt.Errorf("%w: want exactly one RFC3161 timestamp", ErrBundleShape)
	}
	return &ParsedBundle{
		Envelope: env,
		LeafDER:  cert.GetRawBytes(),
		TLE:      vm.GetTlogEntries()[0],
		RFC3161:  tsv.GetRfc3161Timestamps()[0].GetSignedTimestamp(),
	}, nil
}
