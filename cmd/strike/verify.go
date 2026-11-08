package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/record"
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
	registryToken string // --registry-token source, env://NAME or file://path; "" reads anonymously
	deployStep    string // --deploy-step (UC2): the registry deploy the token is for
	registryCA    string // --registry-ca (UC1): file://path of the target's root CA certificate
	noEngineTrust bool   // --no-engine-trust: degrade the engine-dependent layer to informational
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
	fs.BoolVar(&opts.noEngineTrust, "no-engine-trust", false, "do not gate on the engine-dependent layer (treat it as informational)")
	fs.StringVar(&opts.registryToken, "registry-token", "", "source of a registry token, env://NAME or file://path; without it every read is anonymous")
	fs.StringVar(&opts.deployStep, "deploy-step", "", "registry deploy of the lane the registry token is for (UC2; optional when the lane has one)")
	fs.StringVar(&opts.registryCA, "registry-ca", "", "file://path of the root CA certificate (PEM) the subject's registry presents (UC1, with --registry-token)")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	rest := fs.Args()
	if len(rest) != 1 {
		log.Fatal("usage: strike verify [--lane file | --identity id --issuer iss] [--trust-root-ref root-image@digest] [--registry-token env://NAME|file://path [--deploy-step id | --registry-ca file://root.pem]] <image@digest>")
	}
	opts.subjectRef = rest[0]
	if err := runVerify(context.Background(), fatalWriter{os.Stdout}, opts, registry.SystemTransports{}, clock.Wait); err != nil {
		log.Fatalf("error: %v", err)
	}
}

// verifyPolicy is the resolved verification policy: the keyless config and the
// expected signer identity/issuer, plus the policy lane's digest in UC2 (""
// in UC1, where there is no lane to bind the attestation to).
type verifyPolicy struct {
	keyless    lane.Keyless
	extensions *lane.FulcioExtensions
	policyLane *lane.Lane // the policy lane in UC2; nil in UC1
	identity   primitive.StringOrURI
	issuer     endpoint.Address
	laneDigest primitive.Digest
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
		_, p, dg, _, _, err := validateLane(opts.laneFile)
		if err != nil {
			return verifyPolicy{}, err
		}
		return verifyPolicy{keyless: p.Keyless, extensions: &p.OIDC.Extensions, policyLane: p, identity: p.OIDC.Identity, issuer: p.OIDC.Issuer, laneDigest: dg}, nil
	}
	if opts.identity == "" || opts.issuer == "" {
		return verifyPolicy{}, fmt.Errorf("UC1 requires both --identity and --issuer")
	}
	identity := primitive.StringOrURI(opts.identity)
	if err := identity.Validate(); err != nil {
		return verifyPolicy{}, fmt.Errorf("--identity: %w", err)
	}
	issuer, err := endpoint.ParseURL(opts.issuer)
	if err != nil {
		return verifyPolicy{}, fmt.Errorf("--issuer: %w", err)
	}
	return verifyPolicy{identity: identity, issuer: issuer}, nil
}

// verifyTransports returns what verify's reads go through. Without
// --registry-token every read is anonymous, through the system resolver and
// roots: the expected default in UC1 and UC2 (ADR-041 amendment 2026-11-08).
// --deploy-step and --registry-ca only say where a token is presented, so
// without one they are refused. With a token, the token is checked and
// presented to the target authority only, whose chain is verified against
// the target's anchor (registryTarget); the subject must live there. Every
// other registry, a trust root elsewhere included, is still read through
// anonymous.
func verifyTransports(opts verifyOptions, p *lane.Lane, anonymous registry.SystemTransports) (registry.Transports, error) {
	if opts.registryToken == "" {
		if opts.deployStep != "" || opts.registryCA != "" {
			return nil, errors.New("--deploy-step and --registry-ca say where a registry token is presented and need --registry-token; without it verify reads anonymously, which is the expected default")
		}
		return anonymous, nil
	}
	subject, err := name.NewDigest(opts.subjectRef)
	if err != nil {
		return nil, fmt.Errorf("subject must be digest-pinned: %w", err)
	}
	onSubject := subject.Context().RegistryStr()
	authority, anchor, audience, err := registryTarget(opts, p, onSubject)
	if err != nil {
		return nil, err
	}
	if authority != onSubject {
		return nil, fmt.Errorf("the registry token is for %s, and the subject is on %s; verify presents the token to its own registry only", authority, onSubject)
	}
	token, err := readRegistryTokenFlag(opts.registryToken)
	if err != nil {
		return nil, fmt.Errorf("--registry-token: %w", err)
	}
	if checkErr := deploy.CheckRegistryToken(token, audience); checkErr != nil {
		return nil, fmt.Errorf("--registry-token: %w", checkErr)
	}
	src, err := registry.NewTargetTransports(authority, anchor, token, anonymous)
	if err != nil {
		return nil, err
	}
	return src, nil
}

// registryTarget returns the authority a registry token is for, the anchor
// that authority must present, and the oidc audience the token must not
// carry. In UC2 they come from the registry deploy --deploy-step selects,
// which may be omitted when the lane has exactly one. In UC1, which has no
// lane, they come from the subject's registry, onSubject, and the root CA
// --registry-ca names, with no audience to check.
func registryTarget(opts verifyOptions, p *lane.Lane, onSubject string) (string, endpoint.Certificate, string, error) {
	if p != nil {
		if opts.registryCA != "" {
			return "", endpoint.Certificate{}, "", errors.New("--registry-ca is refused with --lane: the anchor is the deploy target's")
		}
		step := primitive.Identifier(opts.deployStep)
		target, err := selectDeployTarget(p, step)
		if err != nil {
			return "", endpoint.Certificate{}, "", err
		}
		authority := string(target.Address.Authority())
		return authority, target.Trust, p.OIDC.Audience, nil
	}
	if opts.deployStep != "" {
		return "", endpoint.Certificate{}, "", errors.New("--deploy-step selects a registry deploy of the lane and needs --lane")
	}
	if opts.registryCA == "" {
		return "", endpoint.Certificate{}, "", errors.New("--registry-token without --lane needs --registry-ca, the root CA the subject's registry presents")
	}
	anchor, err := readRootCA(opts.registryCA)
	if err != nil {
		return "", endpoint.Certificate{}, "", fmt.Errorf("--registry-ca: %w", err)
	}
	return onSubject, anchor, "", nil
}

// selectDeployTarget returns the target of the registry deploy step names,
// or, when step is empty, of the lane's only registry deploy.
func selectDeployTarget(p *lane.Lane, step primitive.Identifier) (lane.DeployRegistryTarget, error) {
	var ids []primitive.Identifier
	var targets []lane.DeployRegistryTarget
	for _, s := range p.Steps {
		if s.Deploy == nil {
			continue
		}
		reg, ok := s.Deploy.Method.(lane.DeployRegistry)
		if !ok {
			continue
		}
		if s.ID == step {
			return reg.Target, nil
		}
		ids = append(ids, s.ID)
		targets = append(targets, reg.Target)
	}
	if step != "" {
		return lane.DeployRegistryTarget{}, fmt.Errorf("--deploy-step %q names no registry deploy of the lane; its registry deploys are %v", step, ids)
	}
	if len(targets) != 1 {
		return lane.DeployRegistryTarget{}, fmt.Errorf("the lane has %d registry deploys %v; --deploy-step selects the one the registry token is for", len(targets), ids)
	}
	return targets[0], nil
}

// readRegistryTokenFlag reads the registry token --registry-token names. The
// flag is a source, env://NAME or file://path, never the token itself, and an
// error never repeats it. A file is read through lane.FilePath, the path
// check --lane is read through, and its trailing newlines are dropped.
func readRegistryTokenFlag(source string) (lane.SecretString, error) {
	if variable, ok := strings.CutPrefix(source, "env://"); ok && variable != "" {
		val, set := os.LookupEnv(variable)
		if !set {
			return lane.SecretString{}, fmt.Errorf("env variable %q not set", variable)
		}
		return lane.NewSecretString(val), nil
	}
	if path, ok := strings.CutPrefix(source, "file://"); ok && path != "" {
		data, err := readFlagFile(path)
		if err != nil {
			return lane.SecretString{}, err
		}
		return lane.NewSecretString(strings.TrimRight(string(data), "\n")), nil
	}
	return lane.SecretString{}, errors.New("the source is neither env://NAME nor file://path; a token is never given as a value")
}

// readRootCA reads the root CA certificate --registry-ca names, file://path.
// The file holds exactly one PEM certificate and nothing else, and the
// certificate is a CA that signed itself: an intermediate or a leaf is
// refused. It becomes the sole root the target's chain is verified against.
func readRootCA(source string) (endpoint.Certificate, error) {
	path, ok := strings.CutPrefix(source, "file://")
	if !ok || path == "" {
		return endpoint.Certificate{}, errors.New("the source is not file://path")
	}
	data, err := readFlagFile(path)
	if err != nil {
		return endpoint.Certificate{}, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return endpoint.Certificate{}, errors.New("the file must hold exactly one PEM certificate and nothing else")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return endpoint.Certificate{}, fmt.Errorf("parse certificate: %w", err)
	}
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return endpoint.Certificate{}, errors.New("the certificate is not a CA")
	}
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) || cert.CheckSignatureFrom(cert) != nil {
		return endpoint.Certificate{}, errors.New("the certificate is not a root: it is not signed by itself")
	}
	return endpoint.CertificateFromDER(block.Bytes, endpoint.CertificateModeRootca), nil
}

// readFlagFile reads the file a file:// flag names through lane.FilePath, the
// path check --lane is read through.
func readFlagFile(path string) ([]byte, error) {
	fp, err := lane.NewFilePath(path)
	if err != nil {
		return nil, err
	}
	return fp.Read()
}

// Expected predicate types per layer; mirrors the producer's projection
// (internal/deploy/project.go). A mismatch with the producer is caught by the
// golden-fixture tests, which carry the producer's real predicates.
const (
	sealedPredicateType        = "https://slsa.dev/provenance/v1"
	engineContextPredicateType = "https://istr.dev/strike/predicates/engine-context/v1"
	informationalPredicateType = "https://istr.dev/strike/predicates/informational/v1"
)

var layerPredicateType = map[record.TrustLayer]string{
	record.TrustLayerEngineDependent: engineContextPredicateType,
	record.TrustLayerInformational:   informationalPredicateType,
}

// gateClass is how a layer's failure affects the verify exit under the current
// trust mode.
type gateClass int

const (
	// gateNone never gates: the informational layer, or the engine-dependent
	// layer under --no-engine-trust.
	gateNone gateClass = iota
	// gateSealed is a hard fail with no opt-out.
	gateSealed
	// gateEngineDependent is a hard fail unless --no-engine-trust.
	gateEngineDependent
)

// classifyLayer maps a bundle's trust layer to how its failure gates the exit
// under the current trust mode (ADR-037).
func classifyLayer(layer record.TrustLayer, noEngineTrust bool) gateClass {
	switch layer {
	case record.TrustLayerSealed:
		return gateSealed
	case record.TrustLayerEngineDependent:
		if noEngineTrust {
			return gateNone
		}
		return gateEngineDependent
	case record.TrustLayerInformational:
		// The informational layer never gates.
	}
	return gateNone
}

// validatePredicate checks the verified statement's predicate for its layer.
// The sealed statement is decoded whole into the generated SLSA provenance
// statement (validateSealed); the engine-dependent and informational
// statements are checked for their predicateType only, and their bodies are
// not decoded.
func validatePredicate(layer record.TrustLayer, statement []byte, laneDigest primitive.Digest) error {
	if layer == record.TrustLayerSealed {
		return validateSealed(statement, laneDigest)
	}
	var head struct {
		PredicateType string `json:"predicateType"`
	}
	if err := json.Unmarshal(statement, &head); err != nil {
		return fmt.Errorf("parse statement: %w", err)
	}
	if want := layerPredicateType[layer]; head.PredicateType != want {
		return fmt.Errorf("predicateType %q is not the expected %q for the %s layer", head.PredicateType, want, layer)
	}
	return nil
}

// validateSealed decodes the sealed statement into the generated SLSA
// provenance statement, so every field the contract types is decoded by its
// type, and checks the predicateType and the laneDigest -- present, and in UC2
// (laneDigest != "") equal to the policy lane's digest.
func validateSealed(statement []byte, laneDigest primitive.Digest) error {
	var s deploy.SLSAProvenanceStatement
	if err := json.Unmarshal(statement, &s); err != nil {
		return fmt.Errorf("parse sealed statement: %w", err)
	}
	if s.PredicateType != sealedPredicateType {
		return fmt.Errorf("predicateType %q is not the expected %q for the %s layer", s.PredicateType, sealedPredicateType, record.TrustLayerSealed)
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
// and per-layer predicate validation. The exit follows the ADR-037 trust
// model: a sealed-layer failure or absence is a hard fail with no opt-out; an
// engine-dependent-layer failure or absence is a hard fail unless
// --no-engine-trust degrades it to informational; the informational layer
// never gates. Every read goes through verifyTransports: through anonymous
// unless a registry token is given. cmdVerify hands the zero
// SystemTransports, the system roots; a test hands roots of its own. The
// read waits, through wait, for a layer whose absence would fail the verdict
// and never for one whose absence would not (ADR-051 amendment 2026-11-08).
// Verified statements are written to out.
func runVerify(ctx context.Context, out io.Writer, opts verifyOptions, anonymous registry.SystemTransports, wait func(context.Context, clock.Duration) error) error {
	pol, err := resolveVerifyPolicy(opts)
	if err != nil {
		return err
	}
	src, err := verifyTransports(opts, pol.policyLane, anonymous)
	if err != nil {
		return err
	}
	ref := primitive.ImageRef(opts.trustRootRef)
	tm, err := verify.ResolveTrustedMaterial(ctx, ref, pol.keyless, src)
	if err != nil {
		return err
	}
	d, err := name.NewDigest(opts.subjectRef)
	if err != nil {
		return fmt.Errorf("subject must be digest-pinned: %w", err)
	}
	rawDigest := primitive.Digest(d.DigestStr())
	subjectDigest, err := primitive.ParseDigest(rawDigest)
	if err != nil {
		return fmt.Errorf("subject digest: %w", err)
	}
	wantHex := subjectDigest.Hex()

	required := []record.TrustLayer{record.TrustLayerSealed}
	if !opts.noEngineTrust {
		required = append(required, record.TrustLayerEngineDependent)
	}
	bundles, err := registry.FetchStatementBundles(ctx, opts.subjectRef, src, required, wait)
	if err != nil {
		return err
	}
	if len(bundles) == 0 {
		return fmt.Errorf("no attestation bundles attached to %s", opts.subjectRef)
	}

	v := verify.New(tm, pol.identity, pol.issuer, pol.extensions)
	seen := make(map[record.TrustLayer]bool, len(bundles))
	var sealedFail, engineDependentFail bool
	for _, b := range bundles {
		seen[b.Statement] = true
		gate := classifyLayer(b.Statement, opts.noEngineTrust)
		if berr := verifyBundle(v, b, wantHex, pol.laneDigest, out); berr != nil {
			switch gate {
			case gateSealed:
				log.Printf("FAIL  %s: %v", b.Statement, berr)
				sealedFail = true
			case gateEngineDependent:
				log.Printf("FAIL  %s: %v", b.Statement, berr)
				engineDependentFail = true
			default:
				log.Printf("INFO  %s: %v (not gating)", b.Statement, berr)
			}
			continue
		}
		log.Printf("OK    %s", b.Statement)
	}
	checkPresence(seen, opts.noEngineTrust, &sealedFail, &engineDependentFail)
	if sealedFail {
		return fmt.Errorf("verification failed: a sealed-layer check did not pass")
	}
	if engineDependentFail {
		return fmt.Errorf("verification failed: an engine-dependent-layer check did not pass; re-run with --no-engine-trust to verify without engine trust")
	}
	return nil
}

// verifyBundle runs, for one bundle, the keyless verify, the subject-artifact
// check, and predicate validation, writing the verified statement to out on
// success.
func verifyBundle(v *verify.Verifier, b registry.StatementBundle, wantHex primitive.Sha256, laneDigest primitive.Digest, out io.Writer) error {
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
// mandatory; engine-dependent is mandatory unless --no-engine-trust; a missing
// engine-dependent (under the flag) or informational layer is reported, not
// gated.
func checkPresence(seen map[record.TrustLayer]bool, noEngineTrust bool, sealedFail, engineDependentFail *bool) {
	if !seen[record.TrustLayerSealed] {
		*sealedFail = true
		log.Printf("FAIL  sealed: required statement is absent")
	}
	if !seen[record.TrustLayerEngineDependent] {
		if noEngineTrust {
			log.Printf("INFO  engine-dependent: absent (engine trust disabled)")
		} else {
			*engineDependentFail = true
			log.Printf("FAIL  engine-dependent: required statement is absent")
		}
	}
	if !seen[record.TrustLayerInformational] {
		log.Printf("INFO  informational: absent")
	}
}

// subjectMatches reports whether the in-toto statement names the requested
// artifact (by sha256) among its subjects. It decodes only the subject, in the
// generated subject shape, never the predicate. This is the in-statement
// confirmation that closes a registry substituting a validly signed bundle for
// a different artifact; the referrer relationship is the other half of the
// binding.
func subjectMatches(statement []byte, wantHex primitive.Sha256) bool {
	var s struct {
		Subject []deploy.Subject `json:"subject"`
	}
	if err := json.Unmarshal(statement, &s); err != nil {
		return false
	}
	for _, sub := range s.Subject {
		if sub.Digest != nil && sub.Digest.SHA256 == wantHex {
			return true
		}
	}
	return false
}
