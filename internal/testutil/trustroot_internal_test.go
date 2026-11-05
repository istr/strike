package testutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	trustrootpb "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/verify"
	"github.com/istr/strike/internal/wire"
)

const testFulcioURL = "https://fulcio.test"

// roundTripFunc answers requests in-process, so the Fulcio fetch needs no
// listener.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// closeErrBody is a response body whose Close returns err.
type closeErrBody struct {
	io.Reader
	err error
}

func (b closeErrBody) Close() error { return b.err }

// serveBundle returns a client that answers GET /api/v2/trustBundle with body
// and whose response body's Close returns closeErr.
func serveBundle(body string, closeErr error) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/api/v2/trustBundle") {
			return nil, fmt.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       closeErrBody{Reader: strings.NewReader(body), err: closeErr},
		}, nil
	})}
}

// testCA creates an ephemeral CA certificate for cn, signed by parent, or
// self-signed when parent is nil.
func testCA(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate %s key: %v", cn, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             clock.Wall().Add(-clock.Hour),
		NotAfter:              clock.Wall().Add(clock.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create %s certificate: %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse %s certificate: %v", cn, err)
	}
	return cert, key
}

func pemBytes(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

// trustRootFixture is an ephemeral harness: the pki/ files HarnessTrustedRoot
// reads, the Fulcio trust bundle it fetches, and the keys the assembled
// document must name.
type trustRootFixture struct {
	files       map[string][]byte
	bundle      string
	fulcioChain []*x509.Certificate
	rekorPub    ed25519.PublicKey
	ctfeDER     []byte
}

func newTrustRootFixture(t *testing.T) trustRootFixture {
	t.Helper()
	fulcioRoot, fulcioKey := testCA(t, "fulcio-root", nil, nil)
	fulcioInter, _ := testCA(t, "fulcio-intermediate", fulcioRoot, fulcioKey)
	tsaRoot, tsaKey := testCA(t, "tsa-root", nil, nil)
	tsaLeaf, _ := testCA(t, "tsa-leaf", tsaRoot, tsaKey)

	rekorPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate rekor key: %v", err)
	}
	rekorDER, err := x509.MarshalPKIXPublicKey(rekorPub)
	if err != nil {
		t.Fatalf("marshal rekor key: %v", err)
	}
	ctfeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ctfe key: %v", err)
	}
	ctfeDER, err := x509.MarshalPKIXPublicKey(&ctfeKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal ctfe key: %v", err)
	}

	chain := []*x509.Certificate{fulcioInter, fulcioRoot}
	var pems []string
	for _, c := range chain {
		pems = append(pems, string(pemBytes("CERTIFICATE", c.Raw)))
	}
	bundle, err := json.Marshal(map[string][]map[string][]string{"chains": {{"certificates": pems}}})
	if err != nil {
		t.Fatalf("marshal trust bundle: %v", err)
	}

	return trustRootFixture{
		files: map[string][]byte{
			"rekor-ed25519-pub.pem": pemBytes("PUBLIC KEY", rekorDER),
			"tsa-certchain.pem":     append(pemBytes("CERTIFICATE", tsaLeaf.Raw), pemBytes("CERTIFICATE", tsaRoot.Raw)...),
			"ctfe-pub.pem":          pemBytes("PUBLIC KEY", ctfeDER),
		},
		bundle:      string(bundle),
		fulcioChain: chain,
		rekorPub:    rekorPub,
		ctfeDER:     ctfeDER,
	}
}

// writeHarness writes the fixture's pki/ files into a fresh harness directory.
// An entry in replace overrides the named file; a nil entry leaves it out.
func writeHarness(t *testing.T, files, replace map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	pki := filepath.Join(dir, "pki")
	if err := os.Mkdir(pki, 0o700); err != nil {
		t.Fatalf("create pki dir: %v", err)
	}
	for name, content := range files {
		if r, ok := replace[name]; ok {
			content = r
		}
		if content == nil {
			continue
		}
		if err := os.WriteFile(filepath.Join(pki, name), content, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// assertTrustRoot checks that doc is a trusted root strike's verifier accepts
// and that it carries the fixture's Fulcio chain in served order, the
// two-certificate TSA chain, and both log ids derived from the fixture keys.
func assertTrustRoot(t *testing.T, fx trustRootFixture, doc []byte) {
	t.Helper()
	if _, err := verify.ParseTrustedRoot(doc); err != nil {
		t.Fatalf("ParseTrustedRoot: %v", err)
	}
	var tr trustrootpb.TrustedRoot
	if err := protojson.Unmarshal(doc, &tr); err != nil {
		t.Fatalf("unmarshal trusted root: %v", err)
	}
	cas, tsas, tlogs, ctlogs := tr.GetCertificateAuthorities(), tr.GetTimestampAuthorities(), tr.GetTlogs(), tr.GetCtlogs()
	if len(cas) != 1 || len(tsas) != 1 || len(tlogs) != 1 || len(ctlogs) != 1 {
		t.Fatalf("authorities/tlogs/ctlogs = %d/%d/%d/%d, want 1 each", len(cas), len(tsas), len(tlogs), len(ctlogs))
	}
	if got := cas[0].GetUri(); got != testFulcioURL {
		t.Errorf("fulcio uri = %q, want %q", got, testFulcioURL)
	}
	fulcio := cas[0].GetCertChain().GetCertificates()
	if len(fulcio) != len(fx.fulcioChain) {
		t.Fatalf("fulcio chain has %d certificates, want %d", len(fulcio), len(fx.fulcioChain))
	}
	for i, c := range fulcio {
		if !bytes.Equal(c.GetRawBytes(), fx.fulcioChain[i].Raw) {
			t.Errorf("fulcio chain certificate %d differs from the served one", i)
		}
	}
	if n := len(tsas[0].GetCertChain().GetCertificates()); n != 2 {
		t.Errorf("tsa chain has %d certificates, want 2", n)
	}
	if got, want := tlogs[0].GetLogId().GetKeyId(), wire.NoteKeyID(harnessRekorOrigin, fx.rekorPub); !bytes.Equal(got, want) {
		t.Errorf("rekor log id = %x, want %x", got, want)
	}
	ctID := sha256.Sum256(fx.ctfeDER)
	if got := ctlogs[0].GetLogId().GetKeyId(); !bytes.Equal(got, ctID[:]) {
		t.Errorf("ct log id = %x, want %x", got, ctID[:])
	}
}

func TestHarnessTrustedRoot(t *testing.T) {
	fx := newTrustRootFixture(t)
	garbageCert := pemBytes("CERTIFICATE", []byte("not der"))
	unreachable := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused")
	})}

	tests := []struct {
		client  *http.Client
		replace map[string][]byte
		name    string
		url     string
		wantErr string
	}{
		{name: "assembles the harness trust root"},
		{name: "body close failure is logged, not returned", client: serveBundle(fx.bundle, errors.New("close failed"))},
		{name: "fulcio URL does not parse", url: testFulcioURL + "/\x7f", wantErr: "trustBundle request"},
		{name: "fulcio unreachable", client: unreachable, wantErr: "trustBundle fetch"},
		{name: "trust bundle is not JSON", client: serveBundle("{", nil), wantErr: "trustBundle decode"},
		{name: "trust bundle has no chains", client: serveBundle(`{"chains":[]}`, nil), wantErr: "trustBundle has no certificates"},
		{name: "trust bundle certificate is not PEM", client: serveBundle(`{"chains":[{"certificates":["x"]}]}`, nil), wantErr: "trustBundle certificate is not PEM"},
		{
			name:    "trust bundle certificate does not parse",
			client:  serveBundle(`{"chains":[{"certificates":[`+strconv.Quote(string(garbageCert))+`]}]}`, nil),
			wantErr: "parse fulcio certificate",
		},
		{name: "rekor key missing", replace: map[string][]byte{"rekor-ed25519-pub.pem": nil}, wantErr: "read rekor public key"},
		{name: "rekor key is not PEM", replace: map[string][]byte{"rekor-ed25519-pub.pem": []byte("x")}, wantErr: "rekor public key is not PEM"},
		{name: "rekor key is not ed25519", replace: map[string][]byte{"rekor-ed25519-pub.pem": fx.files["ctfe-pub.pem"]}, wantErr: "parse rekor public key"},
		{name: "tsa chain missing", replace: map[string][]byte{"tsa-certchain.pem": nil}, wantErr: "read tsa chain"},
		{name: "tsa certificate does not parse", replace: map[string][]byte{"tsa-certchain.pem": garbageCert}, wantErr: "parse tsa certificate"},
		{name: "tsa chain has one certificate", replace: map[string][]byte{"tsa-certchain.pem": pemBytes("CERTIFICATE", fx.fulcioChain[0].Raw)}, wantErr: "tsa chain has 1 certificates"},
		{name: "ctfe key missing", replace: map[string][]byte{"ctfe-pub.pem": nil}, wantErr: "read ctfe public key"},
		{name: "fulcio URI is not UTF-8", url: testFulcioURL + "/\xff", wantErr: "marshal trusted root"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, url := tc.client, tc.url
			if client == nil {
				client = serveBundle(fx.bundle, nil)
			}
			if url == "" {
				url = testFulcioURL
			}
			doc, err := HarnessTrustedRoot(t.Context(), client, url, writeHarness(t, fx.files, tc.replace))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("HarnessTrustedRoot: %v", err)
			}
			assertTrustRoot(t, fx, doc)
		})
	}
}
