package deploy_test

import (
	"testing"

	"github.com/istr/strike/internal/deploy"
)

// validBundleJSON is a minimal sigstore v0.3 bundle that conforms to
// specs/sigstore-bundle.cue: one DSSE envelope, one leaf certificate, one Rekor
// v2 transparency-log entry (no SET, no integratedTime), one RFC3161 timestamp.
const validBundleJSON = `{
  "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
  "verificationMaterial": {
    "certificate": {"rawBytes": "AA=="},
    "tlogEntries": [{
      "logIndex": "3",
      "logId": {"keyId": "AA=="},
      "kindVersion": {"kind": "dsse", "version": "0.0.1"},
      "inclusionProof": {
        "logIndex": "3",
        "rootHash": "AA==",
        "treeSize": "4",
        "hashes": [],
        "checkpoint": {"envelope": "rekor.localhost"}
      },
      "canonicalizedBody": "AA=="
    }],
    "timestampVerificationData": {
      "rfc3161Timestamps": [{"signedTimestamp": "AA=="}]
    }
  },
  "dsseEnvelope": {
    "payloadType": "application/vnd.in-toto+json",
    "payload": "AA==",
    "signatures": [{"sig": "AA=="}]
  }
}`

func TestValidateBundleJSON_Valid(t *testing.T) {
	if err := deploy.ValidateBundleJSON([]byte(validBundleJSON)); err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}
}

// The rejection cases are the positive control: they prove the validator would
// reject a non-conforming bundle, so TestValidateBundleJSON_Valid passes for the
// right reason rather than because the schema is vacuous.
func TestValidateBundleJSON_Rejects(t *testing.T) {
	cases := map[string]string{
		"logIndex as a JSON number (proto3-JSON int64 must be a string)": `{
  "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
  "verificationMaterial": {
    "certificate": {"rawBytes": "AA=="},
    "tlogEntries": [{
      "logIndex": 3,
      "logId": {"keyId": "AA=="},
      "kindVersion": {"kind": "dsse", "version": "0.0.1"},
      "inclusionProof": {"logIndex": "3", "rootHash": "AA==", "treeSize": "4", "hashes": [], "checkpoint": {"envelope": "x"}},
      "canonicalizedBody": "AA=="
    }],
    "timestampVerificationData": {"rfc3161Timestamps": [{"signedTimestamp": "AA=="}]}
  },
  "dsseEnvelope": {"payloadType": "application/vnd.in-toto+json", "payload": "AA==", "signatures": [{"sig": "AA=="}]}
}`,
		"missing inclusion-proof checkpoint": `{
  "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
  "verificationMaterial": {
    "certificate": {"rawBytes": "AA=="},
    "tlogEntries": [{
      "logIndex": "3",
      "logId": {"keyId": "AA=="},
      "kindVersion": {"kind": "dsse", "version": "0.0.1"},
      "inclusionProof": {"logIndex": "3", "rootHash": "AA==", "treeSize": "4", "hashes": []},
      "canonicalizedBody": "AA=="
    }],
    "timestampVerificationData": {"rfc3161Timestamps": [{"signedTimestamp": "AA=="}]}
  },
  "dsseEnvelope": {"payloadType": "application/vnd.in-toto+json", "payload": "AA==", "signatures": [{"sig": "AA=="}]}
}`,
		"wrong DSSE payload type": `{
  "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
  "verificationMaterial": {
    "certificate": {"rawBytes": "AA=="},
    "tlogEntries": [{
      "logIndex": "3",
      "logId": {"keyId": "AA=="},
      "kindVersion": {"kind": "dsse", "version": "0.0.1"},
      "inclusionProof": {"logIndex": "3", "rootHash": "AA==", "treeSize": "4", "hashes": [], "checkpoint": {"envelope": "x"}},
      "canonicalizedBody": "AA=="
    }],
    "timestampVerificationData": {"rfc3161Timestamps": [{"signedTimestamp": "AA=="}]}
  },
  "dsseEnvelope": {"payloadType": "application/vnd.strike.attestation+json", "payload": "AA==", "signatures": [{"sig": "AA=="}]}
}`,
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			if err := deploy.ValidateBundleJSON([]byte(bad)); err == nil {
				t.Fatalf("non-conforming bundle accepted: %s", name)
			}
		})
	}
}

// TestValidateBundleJSON_OmittedZeroIndex covers a first-entry, single-leaf,
// fresh-log bundle: proto3-JSON omits logIndex (value 0), inclusionProof.logIndex
// (value 0), and inclusionProof.hashes (empty). The schema must accept it.
func TestValidateBundleJSON_OmittedZeroIndex(t *testing.T) {
	const bundle = `{
  "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
  "verificationMaterial": {
    "certificate": {"rawBytes": "AA=="},
    "tlogEntries": [{
      "logId": {"keyId": "AA=="},
      "kindVersion": {"kind": "dsse", "version": "0.0.1"},
      "inclusionProof": {
        "rootHash": "AA==",
        "treeSize": "1",
        "checkpoint": {"envelope": "rekor.localhost"}
      },
      "canonicalizedBody": "AA=="
    }],
    "timestampVerificationData": {"rfc3161Timestamps": [{"signedTimestamp": "AA=="}]}
  },
  "dsseEnvelope": {
    "payloadType": "application/vnd.in-toto+json",
    "payload": "AA==",
    "signatures": [{"sig": "AA=="}]
  }
}`
	if err := deploy.ValidateBundleJSON([]byte(bundle)); err != nil {
		t.Fatalf("first-entry single-leaf bundle rejected: %v", err)
	}
}
