package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/verify"
)

// verifyOptions are the parsed inputs for one verification.
type verifyOptions struct {
	subjectRef    string
	identity      string
	issuer        string
	trustRootRef  string // --trust-root-ref override (digest-pinned OCI image); "" if none
	laneFile      string // --lane (UC2); "" selects UC1
	noEngineTrust bool   // --no-engine-trust: degrade the engine-context layer to informational
}

// cmdVerify parses the verify flags and runs the verification, exiting non-zero
// on any failure. Verified statements go to stdout; sentinels and diagnostics
// go to stderr (via log).
func cmdVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	var opts verifyOptions
	fs.StringVar(&opts.identity, "identity", "", "expected signer identity (UC1)")
	fs.StringVar(&opts.issuer, "issuer", "", "expected OIDC issuer (UC1)")
	fs.StringVar(&opts.trustRootRef, "trust-root-ref", "", "digest-pinned OCI image whose sole layer is a trusted_root.json (override)")
	fs.StringVar(&opts.laneFile, "lane", "", "lane file as verification policy (UC2)")
	fs.BoolVar(&opts.noEngineTrust, "no-engine-trust", false, "do not gate on the engine-context layer (treat it as informational)")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	rest := fs.Args()
	if len(rest) != 1 {
		log.Fatal("usage: strike verify [--lane file | --identity id --issuer iss] [--trust-root-ref root-image@digest] <image@digest>")
	}
	opts.subjectRef = rest[0]
	if err := runVerify(context.Background(), fatalWriter{os.Stdout}, opts); err != nil {
		log.Fatalf("error: %v", err)
	}
}

// verifyPolicy is the resolved verification policy: the keyless config and the
// expected signer identity/issuer, plus the policy lane's digest in UC2 (""
// in UC1, where there is no lane to bind the attestation to).
type verifyPolicy struct {
	keyless    lane.Keyless
	identity   string
	issuer     string
	laneDigest string
}

// resolveVerifyPolicy determines the policy the bundles are checked against:
// UC1 takes identity and issuer from the flags, UC2 from the lane (which also
// carries the keyless trust-root source and, sealed into the attestation, the
// lane digest the sealed predicate must match). Combining --identity/--issuer
// with --lane is rejected -- the lane is the single source -- as is supplying
// neither mode. Split from runVerify to keep each focused.
func resolveVerifyPolicy(opts verifyOptions) (verifyPolicy, error) {
	uc1 := opts.identity != "" || opts.issuer != ""
	uc2 := opts.laneFile != ""
	switch {
	case uc1 && uc2:
		return verifyPolicy{}, fmt.Errorf("--identity/--issuer cannot be combined with --lane; the lane is the source")
	case !uc1 && !uc2:
		return verifyPolicy{}, fmt.Errorf("provide --lane (UC2), or --identity and --issuer (UC1)")
	}
	if uc2 {
		_, p, dg, _, err := validateLane(opts.laneFile)
		if err != nil {
			return verifyPolicy{}, err
		}
		return verifyPolicy{keyless: p.Keyless, identity: p.OIDC.Identity, issuer: p.OIDC.Issuer, laneDigest: dg.String()}, nil
	}
	if opts.identity == "" || opts.issuer == "" {
		return verifyPolicy{}, fmt.Errorf("UC1 requires both --identity and --issuer")
	}
	return verifyPolicy{identity: opts.identity, issuer: opts.issuer}, nil
}

// Expected predicate types per layer; mirrors the producer's projection
// (internal/deploy/project.go). A mismatch with the producer is caught by the
// golden-fixture tests, which carry the producer's real predicates.
const (
	sealedPredicateType        = "https://slsa.dev/provenance/v1"
	engineContextPredicateType = "https://istr.dev/strike/predicates/engine-context/v1"
	informationalPredicateType = "https://istr.dev/strike/predicates/informational/v1"
)

var layerPredicateType = map[string]string{
	"sealed":         sealedPredicateType,
	"engine-context": engineContextPredicateType,
	"informational":  informationalPredicateType,
}

// gateClass is how a layer's failure affects the verify exit under the current
// trust mode.
type gateClass int

const (
	gateNone gateClass = iota // never gates: informational, or engine-context under --no-engine-trust
	gateV                     // Layer V: hard fail, no opt-out
	gateE                     // Layer E: hard fail unless --no-engine-trust
)

// classifyLayer maps a bundle's layer to how its failure gates the exit under
// the current trust mode (ADR-037 V/E model).
func classifyLayer(layer string, noEngineTrust bool) gateClass {
	switch layer {
	case "sealed":
		return gateV
	case "engine-context":
		if noEngineTrust {
			return gateNone
		}
		return gateE
	default: // informational or any unrecognized layer
		return gateNone
	}
}

// validatePredicate checks the verified statement's predicate for its layer: the
// predicateType must match, and the sealed layer must carry a laneDigest --
// which, in UC2 (laneDigest != ""), must equal the policy lane's digest. It does
// not schema-validate the engine-context or informational bodies.
func validatePredicate(layer string, statement []byte, laneDigest string) error {
	var head struct {
		PredicateType string `json:"predicateType"`
	}
	if err := json.Unmarshal(statement, &head); err != nil {
		return fmt.Errorf("parse statement: %w", err)
	}
	if want, known := layerPredicateType[layer]; known && head.PredicateType != want {
		return fmt.Errorf("predicateType %q is not the expected %q for the %s layer", head.PredicateType, want, layer)
	}
	if layer != "sealed" {
		return nil
	}
	var s struct {
		Predicate struct {
			BuildDefinition struct {
				ExternalParameters struct {
					LaneDigest string `json:"laneDigest"`
				} `json:"externalParameters"`
			} `json:"buildDefinition"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(statement, &s); err != nil {
		return fmt.Errorf("parse sealed predicate: %w", err)
	}
	got := s.Predicate.BuildDefinition.ExternalParameters.LaneDigest
	if got == "" {
		return fmt.Errorf("sealed predicate carries no laneDigest")
	}
	if laneDigest != "" && got != laneDigest {
		return fmt.Errorf("lane digest mismatch: attestation has %s, policy lane is %s", got, laneDigest)
	}
	return nil
}

// runVerify resolves the verification policy (UC1 explicit, or UC2 from the
// lane), reads the attestation bundles attached to the subject, and verifies
// each layer: the keyless chain via verify.New(...).Verify, the subject-artifact check,
// and per-layer predicate validation. The exit follows the ADR-037 V/E trust
// model: a Layer-V (sealed) failure or absence is a hard fail with no opt-out;
// a Layer-E (engine-context) failure or absence is a hard fail unless
// --no-engine-trust degrades it to informational; the informational layer
// never gates. Verified statements are written to out.
func runVerify(ctx context.Context, out io.Writer, opts verifyOptions) error {
	pol, err := resolveVerifyPolicy(opts)
	if err != nil {
		return err
	}
	tm, err := verify.ResolveTrustedMaterial(ctx, opts.trustRootRef, pol.keyless)
	if err != nil {
		return err
	}
	d, err := name.NewDigest(opts.subjectRef)
	if err != nil {
		return fmt.Errorf("subject must be digest-pinned: %w", err)
	}
	wantHex := strings.TrimPrefix(d.DigestStr(), "sha256:")

	bundles, err := registry.FetchStatementBundles(ctx, opts.subjectRef)
	if err != nil {
		return err
	}
	if len(bundles) == 0 {
		return fmt.Errorf("no attestation bundles attached to %s", opts.subjectRef)
	}

	v := verify.New(tm, pol.identity, pol.issuer)
	seen := make(map[string]bool, len(bundles))
	var vFail, eFail bool
	for _, b := range bundles {
		seen[b.Statement] = true
		gate := classifyLayer(b.Statement, opts.noEngineTrust)
		if berr := verifyBundle(v, b, wantHex, pol.laneDigest, out); berr != nil {
			switch gate {
			case gateV:
				log.Printf("FAIL  %s: %v", b.Statement, berr)
				vFail = true
			case gateE:
				log.Printf("FAIL  %s: %v", b.Statement, berr)
				eFail = true
			default:
				log.Printf("INFO  %s: %v (not gating)", b.Statement, berr)
			}
			continue
		}
		log.Printf("OK    %s", b.Statement)
	}
	checkPresence(seen, opts.noEngineTrust, &vFail, &eFail)
	if vFail {
		return fmt.Errorf("verification failed: a Layer-V (sealed) check did not pass")
	}
	if eFail {
		return fmt.Errorf("verification failed: a Layer-E (engine-context) check did not pass; re-run with --no-engine-trust to verify without engine trust")
	}
	return nil
}

// verifyBundle runs, for one bundle, the keyless verify, the subject-artifact
// check, and predicate validation, writing the verified statement to out on
// success.
func verifyBundle(v *verify.Verifier, b registry.StatementBundle, wantHex, laneDigest string, out io.Writer) error {
	stmt, err := v.Verify(b.Bundle)
	if err != nil {
		return err
	}
	if !subjectMatches(stmt, wantHex) {
		return fmt.Errorf("statement subject is not the requested artifact")
	}
	if err := validatePredicate(b.Statement, stmt, laneDigest); err != nil {
		return err
	}
	if _, err := out.Write(stmt); err != nil {
		return fmt.Errorf("write statement: %w", err)
	}
	if _, err := out.Write([]byte("\n")); err != nil {
		return fmt.Errorf("write statement: %w", err)
	}
	return nil
}

// checkPresence enforces the layer presence rules: the sealed layer is
// mandatory; engine-context is mandatory unless --no-engine-trust; a missing
// engine-context (under the flag) or informational layer is reported, not gated.
func checkPresence(seen map[string]bool, noEngineTrust bool, vFail, eFail *bool) {
	if !seen["sealed"] {
		*vFail = true
		log.Printf("FAIL  sealed: required statement is absent")
	}
	if !seen["engine-context"] {
		if noEngineTrust {
			log.Printf("INFO  engine-context: absent (engine trust disabled)")
		} else {
			*eFail = true
			log.Printf("FAIL  engine-context: required statement is absent")
		}
	}
	if !seen["informational"] {
		log.Printf("INFO  informational: absent")
	}
}

// subjectMatches reports whether the in-toto statement names the requested
// artifact (by sha256) among its subjects. It parses only the subject, never
// the predicate. This is the in-statement confirmation that closes a registry
// substituting a validly signed bundle for a different artifact; the referrer
// relationship is the other half of the binding.
func subjectMatches(statement []byte, wantHex string) bool {
	var s struct {
		Subject []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(statement, &s); err != nil {
		return false
	}
	for _, sub := range s.Subject {
		if sub.Digest["sha256"] == wantHex {
			return true
		}
	}
	return false
}
