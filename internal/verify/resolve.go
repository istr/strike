package verify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/registry"
)

// ErrNoTrustRoot is returned when no trust-root source is available: the lane
// declares neither keyless.trustRoot nor keyless.trustRootRef, and no
// --trust-root override was given. There is no implicit default (ADR-041): a
// verification with no declared anchor would certify against an ambient root
// nobody chose, which is the false anchor the principles forbid.
var ErrNoTrustRoot = errors.New("verify: no trust root; declare keyless.trustRoot or keyless.trustRootRef, or pass --trust-root")

// ResolveTrustedMaterial produces the TrustedMaterial from exactly one source,
// in precedence order: the --trust-root override (a local trusted_root.json),
// else the lane inline trustRoot replica, else the lane trustRootRef (a
// trusted_root.json published as a single-layer OCI image, fetched at its
// pinned digest). Absence of all three is a hard error -- no implicit default.
//
// The override path is the test/round-trip lever: it lets a caller inject a
// known root and verify a freshly produced bundle in-process, without a
// committed golden or the harness.
func ResolveTrustedMaterial(ctx context.Context, overridePath string, k lane.Keyless) (*TrustedMaterial, error) {
	switch {
	case overridePath != "":
		data, err := os.ReadFile(filepath.Clean(overridePath))
		if err != nil {
			return nil, fmt.Errorf("read trust root %q: %w", overridePath, err)
		}
		return ParseTrustedRoot(data)
	case k.TrustRoot != nil:
		data, err := json.Marshal(k.TrustRoot)
		if err != nil {
			return nil, fmt.Errorf("marshal inline trust root: %w", err)
		}
		return ParseTrustedRoot(data)
	case k.TrustRootRef != "":
		data, err := registry.FetchTrustRoot(ctx, string(k.TrustRootRef))
		if err != nil {
			return nil, err
		}
		return ParseTrustedRoot(data)
	default:
		return nil, ErrNoTrustRoot
	}
}
