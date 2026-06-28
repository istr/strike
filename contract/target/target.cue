// Deploy destination (ADR-047). A concept-tier value type: the lane wire format
// and the attest package both name it.
package target

import "github.com/istr/strike/contract/primitive"

#Deploy: {
	@go(Deploy)

	// Stable identifier assigned at authoring time. External verifiers use
	// this to pair pre/post-state digests across consecutive deploys
	// to the same target.
	id:          primitive.#Identifier @go(ID)
	type:        string                @go(Type)
	description: string                @go(Description)
	url?:        string                @go(URL,optional=nillable)
	namespace?:  string                @go(Namespace,optional=nillable)
}
