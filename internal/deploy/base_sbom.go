package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/verify"
)

// verifyBaseSBOMs fetches and verifies the signed SBOM attestations of every
// base image in the deploy step's sub-tree, returning one resolved-dependency
// descriptor per verified base SBOM. Fail-closed (ADR-040): a base-SBOM referrer
// that does not verify against a declared signer, or whose verified SBOM subject
// does not bind to the base digest, aborts the deploy. A base with no SBOM
// referrer yields no descriptor and no error. When the lane declares no base
// SBOM signers, this is a no-op (the lane build guard guarantees a resolvable
// trust root whenever signers are present; a declared-but-unresolvable trust root
// fails closed here).
func (d *Deployer) verifyBaseSBOMs(ctx context.Context, stepID string) ([]ResourceDescriptor, error) {
	if len(d.BaseSBOMSigners) == 0 {
		return nil, nil
	}
	tm, err := verify.ResolveTrustedMaterial(ctx, "", d.Keyless)
	if err != nil {
		return nil, fmt.Errorf("base SBOM: resolve trust root: %w", err)
	}
	var deps []ResourceDescriptor
	for _, base := range d.DAG.PackBaseRefs(stepID) {
		baseDigest, ok := sha256Hex(string(base))
		if !ok {
			return nil, fmt.Errorf("base SBOM: base %q is not digest-pinned", base)
		}
		referrers, err := registry.FetchBaseSBOMReferrers(ctx, string(base))
		if err != nil {
			return nil, fmt.Errorf("base SBOM: fetch referrers of %s: %w", base, err)
		}
		for _, r := range referrers {
			dep, recorded, err := d.verifyOneBaseSBOM(tm, base, baseDigest, r)
			if err != nil {
				return nil, err
			}
			if recorded {
				deps = append(deps, dep)
			}
		}
	}
	return deps, nil
}

// verifyOneBaseSBOM applies the three-way contract to one scope-selected
// referrer. It verifies against some declared signer (else fail-closed), then
// requires the signed payload to be an SBOM predicate type (else skip -- an
// unsigned-annotation mislabel, not an SBOM) and to bind to the base digest
// (else fail-closed). The returned descriptor references the referrer-manifest
// digest, the stable handle for offline re-verification.
func (d *Deployer) verifyOneBaseSBOM(
	tm *verify.TrustedMaterial, base lane.ImageRef, baseDigest string, r registry.BaseSBOMReferrer,
) (ResourceDescriptor, bool, error) {
	var payload []byte
	var lastErr error
	matched := false
	for _, s := range d.BaseSBOMSigners {
		p, verr := verify.New(tm, s.Identity, s.Issuer).Verify(r.Bundle)
		if verr == nil {
			payload = p
			matched = true
			break
		}
		lastErr = verr
	}
	if !matched {
		return ResourceDescriptor{}, false, fmt.Errorf(
			"base SBOM: referrer %s of %s verifies against no declared signer: %w", r.Digest, base, lastErr)
	}
	var stmt struct {
		PredicateType string `json:"predicateType"`
		Subject       []struct {
			Digest struct {
				SHA256 string `json:"sha256"`
			} `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return ResourceDescriptor{}, false, fmt.Errorf("base SBOM: parse verified payload of %s: %w", r.Digest, err)
	}
	if stmt.PredicateType != registry.PredicateTypeCycloneDX && stmt.PredicateType != registry.PredicateTypeSPDX {
		return ResourceDescriptor{}, false, nil // signed payload is not an SBOM; skip
	}
	if len(stmt.Subject) == 0 || stmt.Subject[0].Digest.SHA256 != baseDigest {
		return ResourceDescriptor{}, false, fmt.Errorf(
			"base SBOM: referrer %s subject does not bind to base %s", r.Digest, base)
	}
	refDigest, ok := sha256Hex(r.Digest)
	if !ok {
		return ResourceDescriptor{}, false, fmt.Errorf("base SBOM: referrer digest %q is not sha256", r.Digest)
	}
	return ResourceDescriptor{
		Digest:    &DigestSet{SHA256: refDigest},
		Name:      baseRepo(string(base)),
		URI:       string(base),
		MediaType: stmt.PredicateType,
	}, true, nil
}

// sha256Hex returns the 64-char hex of a sha256 digest from "...@sha256:HEX" or
// "sha256:HEX", false if absent or malformed.
func sha256Hex(ref string) (string, bool) {
	_, h, ok := strings.Cut(ref, "sha256:")
	if !ok || len(h) != 64 {
		return "", false
	}
	return h, true
}

// baseRepo returns the repository portion of a digest-pinned image reference.
func baseRepo(ref string) string {
	repo, _, _ := strings.Cut(ref, "@")
	return repo
}
