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
	subjectRef string
	identity   string
	issuer     string
	trustRoot  string // --trust-root override path; "" if none
	laneFile   string // --lane (UC2); "" selects UC1
}

// cmdVerify parses the verify flags and runs the verification, exiting non-zero
// on any failure. Verified statements go to stdout; sentinels and diagnostics
// go to stderr (via log).
func cmdVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	var opts verifyOptions
	fs.StringVar(&opts.identity, "identity", "", "expected signer identity (UC1)")
	fs.StringVar(&opts.issuer, "issuer", "", "expected OIDC issuer (UC1)")
	fs.StringVar(&opts.trustRoot, "trust-root", "", "path to a trusted_root.json (override)")
	fs.StringVar(&opts.laneFile, "lane", "", "lane file as verification policy (UC2)")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	rest := fs.Args()
	if len(rest) != 1 {
		log.Fatal("usage: strike verify [--lane file | --identity id --issuer iss] [--trust-root path] <image@digest>")
	}
	opts.subjectRef = rest[0]
	if err := runVerify(context.Background(), fatalWriter{os.Stdout}, opts); err != nil {
		log.Fatalf("error: %v", err)
	}
}

// resolveVerifyPolicy determines the (keyless, identity, issuer) the bundles
// are checked against: UC1 takes identity and issuer from the flags, UC2 from
// the lane (which also carries the keyless trust-root source). Combining
// --identity/--issuer with --lane is rejected -- the lane is the single source
// -- as is supplying neither mode. Split from runVerify to keep each focused.
func resolveVerifyPolicy(opts verifyOptions) (lane.Keyless, string, string, error) {
	uc1 := opts.identity != "" || opts.issuer != ""
	uc2 := opts.laneFile != ""
	switch {
	case uc1 && uc2:
		return lane.Keyless{}, "", "", fmt.Errorf("--identity/--issuer cannot be combined with --lane; the lane is the source")
	case !uc1 && !uc2:
		return lane.Keyless{}, "", "", fmt.Errorf("provide --lane (UC2), or --identity and --issuer (UC1)")
	}
	if uc2 {
		_, p, _, _, err := validateLane(opts.laneFile)
		if err != nil {
			return lane.Keyless{}, "", "", err
		}
		return p.Keyless, p.OIDC.Identity, p.OIDC.Issuer, nil
	}
	if opts.identity == "" || opts.issuer == "" {
		return lane.Keyless{}, "", "", fmt.Errorf("UC1 requires both --identity and --issuer")
	}
	return lane.Keyless{}, opts.identity, opts.issuer, nil
}

// runVerify resolves the verification policy (UC1 explicit, or UC2 from the
// lane), reads the attestation bundles attached to the subject, and verifies
// each: the keyless chain via verify.Verify, and that the statement names the
// requested artifact. Verified statements are written to out. An error is
// returned if any bundle fails. Per-layer predicate validation and the
// lane-digest binding are not done here (instruction 3); the artifact binding
// rests on the referrer relationship and the subject check.
func runVerify(ctx context.Context, out io.Writer, opts verifyOptions) error {
	k, wantIdentity, wantIssuer, err := resolveVerifyPolicy(opts)
	if err != nil {
		return err
	}

	tm, err := verify.ResolveTrustedMaterial(ctx, opts.trustRoot, k)
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

	v := verify.New(tm, wantIdentity, wantIssuer)
	failures := 0
	for _, b := range bundles {
		stmt, verr := v.Verify(b.Bundle)
		if verr != nil {
			log.Printf("FAIL  %s: %v", b.Statement, verr)
			failures++
			continue
		}
		if !subjectMatches(stmt, wantHex) {
			log.Printf("FAIL  %s: statement subject is not %s", b.Statement, opts.subjectRef)
			failures++
			continue
		}
		if _, werr := out.Write(stmt); werr != nil {
			return fmt.Errorf("write statement: %w", werr)
		}
		if _, werr := out.Write([]byte("\n")); werr != nil {
			return fmt.Errorf("write statement: %w", werr)
		}
		log.Printf("OK    %s", b.Statement)
	}
	if failures > 0 {
		return fmt.Errorf("%d of %d bundle(s) failed verification", failures, len(bundles))
	}
	return nil
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
