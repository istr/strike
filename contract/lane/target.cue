// Base target type -- the deploy destination (ADR-047). Shared declaration
// named by the wire lane and the attest package.

package lane

import "github.com/istr/strike/contract/primitive"

#DeployTarget: {
	@go(DeployTarget)

	// Stable identifier assigned at authoring time. External verifiers use
	// this to pair pre/post-state digests across consecutive deploys
	// to the same target.
	id:          primitive.#Identifier @go(ID)
	type:        string                @go(Type)
	description: string                @go(Description)
	url?:        string                @go(URL,optional=nillable)
	namespace?:  string                @go(Namespace,optional=nillable)
}
