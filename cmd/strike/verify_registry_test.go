package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/record"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/registry/regtest"
	"github.com/istr/strike/internal/testutil"
)

// goldenLanePath is the golden lane, the UC2 policy the golden bundles were
// sealed under. Its one registry deploy, deploy, targets registry.example.com.
var goldenLanePath = filepath.Join("..", "..", "internal", "verify", "testdata", "golden", "lane.yaml")

// unsignedToken is an identity token strike reads the claims of and never
// verifies: header, claims, signature, the claims base64url-encoded.
func unsignedToken(claims string) string {
	return "e30." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".x"
}

// writeFile writes content to name in dir and returns the file:// source of
// it.
func writeFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("open %s: %v", dir, err)
	}
	defer testutil.CloseLog(t, root, "test file root")
	if writeErr := root.WriteFile(name, content, 0o600); writeErr != nil {
		t.Fatalf("write %s: %v", name, writeErr)
	}
	return "file://" + filepath.Join(dir, name)
}

// newCert mints a certificate with a fresh key: a CA when isCA, signed by
// parent and parentKey when parent is not nil, by itself otherwise.
func newCert(t *testing.T, cn string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             clock.Wall().Add(-clock.Minute),
		NotAfter:              clock.Wall().Add(clock.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	signer, signerKey := template, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert, key
}

// certPEM is the PEM form of cert.
func certPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// TestVerifyTransports pins how strike verify decides where its reads go
// (ADR-041 amendment 2026-11-08). Without --registry-token every read is
// anonymous, and --deploy-step and --registry-ca are refused. With it, UC2
// takes the target, its anchor and the audience check from the registry
// deploy --deploy-step selects, UC1 the subject's registry and the root CA
// --registry-ca names; the subject must live on the target, the token is a
// source checked before any use, and no error repeats it.
func TestVerifyTransports(t *testing.T) {
	dir := t.TempDir()
	valid := unsignedToken(`{"aud":"https://registry.example.com","iat":1000,"exp":1600}`)
	t.Setenv("STRIKE_TEST_REGISTRY_TOKEN", valid)
	t.Setenv("STRIKE_TEST_LONG_TOKEN", unsignedToken(`{"aud":"https://registry.example.com","iat":1000,"exp":1901}`))
	t.Setenv("STRIKE_TEST_SIGSTORE_TOKEN", unsignedToken(`{"aud":"sigstore","iat":1000,"exp":1600}`))
	tokenFile := writeFile(t, dir, "token", []byte(valid+"\n"))

	root, rootKey := newCert(t, "verify test root", true, nil, nil)
	leaf, _ := newCert(t, "verify test leaf", false, nil, nil)
	intermediate, _ := newCert(t, "verify test intermediate", true, root, rootKey)
	rootFile := writeFile(t, dir, "root.pem", certPEM(root))
	leafFile := writeFile(t, dir, "leaf.pem", certPEM(leaf))
	intermediateFile := writeFile(t, dir, "intermediate.pem", certPEM(intermediate))
	twoFile := writeFile(t, dir, "two.pem", append(certPEM(root), certPEM(root)...))
	garbleFile := writeFile(t, dir, "garble.pem", []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))

	golden := goldenFile(t, "lane.yaml")
	deployBlock := string(golden[strings.Index(string(golden), "  - id: deploy\n"):])
	second := strings.Replace(strings.Replace(deployBlock, "  - id: deploy\n", "  - id: deploy-b\n", 1), "name: golden\n", "name: golden-b\n", 1)
	twoDeploys := strings.TrimPrefix(writeFile(t, dir, "two-deploys.yaml", append(golden, second...)), "file://")

	hex := strings.Repeat("ab", 32)
	uc1Subject := "127.0.0.1:1/app@sha256:" + hex
	uc2Subject := "registry.example.com/golden@sha256:" + hex
	source := "env://STRIKE_TEST_REGISTRY_TOKEN"
	longSource := "env://STRIKE_TEST_LONG_TOKEN"
	sigstoreSource := "env://STRIKE_TEST_SIGSTORE_TOKEN"
	unsetSource := "env://STRIKE_TEST_UNSET_REGISTRY_TOKEN"
	tests := []struct {
		name     string
		laneFile string
		wantErr  []string
		opts     verifyOptions
		wantPin  bool
	}{
		{name: "anonymous", opts: verifyOptions{subjectRef: uc1Subject}},
		{name: "deploy step without token", opts: verifyOptions{subjectRef: uc1Subject, deployStep: "deploy"}, wantErr: []string{"need --registry-token", "verify reads anonymously, which is the expected default"}},
		{name: "registry ca without token", opts: verifyOptions{subjectRef: uc1Subject, registryCA: rootFile}, wantErr: []string{"need --registry-token", "verify reads anonymously, which is the expected default"}},
		{name: "uc1 root", opts: verifyOptions{subjectRef: uc1Subject, registryToken: source, registryCA: rootFile}, wantPin: true},
		{name: "uc1 deploy step", opts: verifyOptions{subjectRef: uc1Subject, registryToken: source, registryCA: rootFile, deployStep: "deploy"}, wantErr: []string{"--deploy-step selects a registry deploy of the lane and needs --lane"}},
		{name: "uc1 without root", opts: verifyOptions{subjectRef: uc1Subject, registryToken: source}, wantErr: []string{"needs --registry-ca"}},
		{name: "uc1 root not a file source", opts: verifyOptions{subjectRef: uc1Subject, registryToken: source, registryCA: "/etc/root.pem"}, wantErr: []string{"--registry-ca: the source is not file://path"}},
		{name: "uc1 root missing", opts: verifyOptions{subjectRef: uc1Subject, registryToken: source, registryCA: "file://" + filepath.Join(dir, "missing.pem")}, wantErr: []string{"--registry-ca: stat"}},
		{name: "uc1 two certificates", opts: verifyOptions{subjectRef: uc1Subject, registryToken: source, registryCA: twoFile}, wantErr: []string{"exactly one PEM certificate"}},
		{name: "uc1 garbled certificate", opts: verifyOptions{subjectRef: uc1Subject, registryToken: source, registryCA: garbleFile}, wantErr: []string{"parse certificate"}},
		{name: "uc1 leaf", opts: verifyOptions{subjectRef: uc1Subject, registryToken: source, registryCA: leafFile}, wantErr: []string{"the certificate is not a CA"}},
		{name: "uc1 intermediate", opts: verifyOptions{subjectRef: uc1Subject, registryToken: source, registryCA: intermediateFile}, wantErr: []string{"the certificate is not a root"}},
		{name: "uc2 only registry deploy", laneFile: goldenLanePath, opts: verifyOptions{subjectRef: uc2Subject, registryToken: source}, wantPin: true},
		{name: "uc2 token from a file", laneFile: goldenLanePath, opts: verifyOptions{subjectRef: uc2Subject, registryToken: tokenFile, deployStep: "deploy"}, wantPin: true},
		{name: "uc2 registry ca", laneFile: goldenLanePath, opts: verifyOptions{subjectRef: uc2Subject, registryToken: source, registryCA: rootFile}, wantErr: []string{"--registry-ca is refused with --lane"}},
		{name: "uc2 step not a registry deploy", laneFile: goldenLanePath, opts: verifyOptions{subjectRef: uc2Subject, registryToken: source, deployStep: "build"}, wantErr: []string{`--deploy-step "build" names no registry deploy of the lane; its registry deploys are [deploy]`}},
		{name: "uc2 two registry deploys", laneFile: twoDeploys, opts: verifyOptions{subjectRef: uc2Subject, registryToken: source}, wantErr: []string{"the lane has 2 registry deploys [deploy deploy-b]; --deploy-step selects"}},
		{name: "uc2 subject elsewhere", laneFile: goldenLanePath, opts: verifyOptions{subjectRef: uc1Subject, registryToken: source}, wantErr: []string{"the registry token is for registry.example.com, and the subject is on 127.0.0.1:1"}},
		{name: "uc2 token given as a value", laneFile: goldenLanePath, opts: verifyOptions{subjectRef: uc2Subject, registryToken: valid}, wantErr: []string{"a token is never given as a value"}},
		{name: "uc2 token variable unset", laneFile: goldenLanePath, opts: verifyOptions{subjectRef: uc2Subject, registryToken: unsetSource}, wantErr: []string{`env variable "STRIKE_TEST_UNSET_REGISTRY_TOKEN" not set`}},
		{name: "uc2 token file missing", laneFile: goldenLanePath, opts: verifyOptions{subjectRef: uc2Subject, registryToken: "file://" + filepath.Join(dir, "missing")}, wantErr: []string{"--registry-token: stat"}},
		{name: "uc2 token over the bound", laneFile: goldenLanePath, opts: verifyOptions{subjectRef: uc2Subject, registryToken: longSource}, wantErr: []string{"exceeds the 900s bound"}},
		{name: "uc2 oidc audience", laneFile: goldenLanePath, opts: verifyOptions{subjectRef: uc2Subject, registryToken: sigstoreSource}, wantErr: []string{`its audience contains the oidc audience "sigstore"`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p *lane.Lane
			if tt.laneFile != "" {
				_, parsed, _, _, _, laneErr := validateLane(tt.laneFile)
				if laneErr != nil {
					t.Fatalf("lane %s: %v", tt.laneFile, laneErr)
				}
				p = parsed
			}
			src, err := verifyTransports(tt.opts, p)
			if len(tt.wantErr) > 0 {
				if err == nil {
					t.Fatal("want an error, got nil")
				}
				for _, want := range tt.wantErr {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("err = %v, want it to contain %q", err, want)
					}
				}
				if strings.Contains(err.Error(), valid) {
					t.Errorf("err repeats the registry token: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("verifyTransports: %v", err)
			}
			_, pinned := src.(registry.TargetTransports)
			_, anonymous := src.(registry.SystemTransports)
			if pinned != tt.wantPin || anonymous == tt.wantPin {
				t.Errorf("transports = %T, want pinned %v", src, tt.wantPin)
			}
		})
	}
}

// TestRunVerifyUC1RegistryToken runs UC1 under a registry token against a
// TLS registry that answers only requests carrying the bearer (ADR-041
// amendment 2026-11-08). With --registry-ca naming the registry's root, the
// token reaches the subject's registry and every layer verifies, while the
// trust root, on another registry, is read anonymously. Under a root the
// registry does not chain to, the read is refused before any verdict.
func TestRunVerifyUC1RegistryToken(t *testing.T) {
	token := unsignedToken(`{"aud":"https://registry.example.com","iat":1000,"exp":1600}`)
	t.Setenv("STRIKE_TEST_REGISTRY_TOKEN", token)
	source := "env://STRIKE_TEST_REGISTRY_TOKEN"
	inner := regtest.Registry(t, true)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Errorf("request without the registry token: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	host := srv.Listener.Addr().String()

	subjectHex := goldenSubjectHex(t, goldenFile(t, "sealed.sigstore.json"))
	digest, err := v1.NewHash("sha256:" + subjectHex)
	if err != nil {
		t.Fatalf("subject hash: %v", err)
	}
	layers := []record.TrustLayer{record.TrustLayerSealed, record.TrustLayerEngineDependent, record.TrustLayerInformational}
	bundles := make([]registry.StatementBundle, 0, len(layers))
	for _, layer := range layers {
		file := string(layer) + ".sigstore.json"
		bundles = append(bundles, registry.StatementBundle{Statement: layer, Bundle: goldenFile(t, file)})
	}
	rt := registry.CredentialTransport(srv.Client().Transport, host, lane.NewSecretString(token))
	if _, attachErr := registry.AttachStatementBundles(context.Background(), host+"/app:v1",
		v1.Descriptor{MediaType: types.OCIManifestSchema1, Size: 2, Digest: digest}, bundles, remote.WithTransport(rt)); attachErr != nil {
		t.Fatalf("AttachStatementBundles: %v", attachErr)
	}

	dir := t.TempDir()
	opts := verifyOptions{
		subjectRef:    host + "/app@sha256:" + subjectHex,
		identity:      goldenIdentity,
		issuer:        goldenIssuer,
		trustRootRef:  goldenTrustRootRef(t, localRegistry(t)),
		registryToken: source,
		registryCA:    writeFile(t, dir, "root.pem", certPEM(srv.Certificate())),
	}
	logBuf := captureLog(t)
	if runErr := runVerify(context.Background(), io.Discard, opts, failOnWait(t)); runErr != nil {
		t.Fatalf("runVerify under the registry token: %v", runErr)
	}
	for _, layer := range layers {
		if !strings.Contains(logBuf.String(), "OK    "+string(layer)+"\n") {
			t.Errorf("want an OK verdict for %s, got: %q", layer, logBuf.String())
		}
	}

	anchor, err := testutil.AnchorTrust().Parse()
	if err != nil {
		t.Fatalf("fixture anchor: %v", err)
	}
	wrong := opts
	wrong.registryCA = writeFile(t, dir, "other-root.pem", certPEM(anchor))
	if err := runVerify(context.Background(), io.Discard, wrong, failOnWait(t)); err == nil {
		t.Error("runVerify read a registry that does not chain to the declared root")
	}
}
