package deploy

import (
	"context"

	"github.com/istr/strike/internal/lane"
)

// PAEEncode exposes paeEncode for the external test package.
var PAEEncode = paeEncode

// ExecuteMethod exposes executeMethod for the external test package.
func (d *Deployer) ExecuteMethod(ctx context.Context, spec *lane.DeploySpec) error {
	return d.executeMethod(ctx, spec)
}
