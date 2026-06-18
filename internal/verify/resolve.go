package verify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/registry"
)

// ErrNoTrustRoot is returned when no trust-root source is available: the lane
// declares neither keyless.trustRoot nor keyless.trustRootRef, and no
// --trust-root-ref override was given. There is no implicit default (ADR-041): a
// verification with no declared anchor would certify against an ambient root
// nobody chose, which is the false anchor the principles forbid.
var ErrNoTrustRoot = errors.New("verify: no trust root; declare keyless.trustRoot or keyless.trustRootRef, or pass --trust-root-ref")

// ResolveTrustedMaterial produces the TrustedMaterial from exactly one source,
// in precedence order: the --trust-root-ref override (a digest-pinned OCI image
// whose sole layer is a trusted_root.json), else the lane inline trustRoot
// replica, else the lane trustRootRef (the same single-layer image, declared in
// the lane). Absence of all three is a hard error -- no implicit default. Every
// source is either lane bytes or a digest-pinned image; the verify path never
// reads a host-local file.
//
// The override ref is the operator's explicit anchor, distinct from the lane's:
// it always wins, and being digest-pinned it carries the same content-addressed
// guarantee as the lane-declared ref.
func ResolveTrustedMaterial(ctx context.Context, overrideRef string, k lane.Keyless) (*TrustedMaterial, error) {
	switch {
	case overrideRef != "":
		data, err := registry.FetchTrustRoot(ctx, overrideRef)
		if err != nil {
			return nil, err
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
