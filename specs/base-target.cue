// Base target type -- the deploy destination (ADR-047). Shared declaration
// named by the wire lane and the attest package.

package lane

#DeployTarget: {
	@go(DeployTarget)

	// Stable identifier assigned at authoring time. External verifiers use
	// this to pair pre/post-state digests across consecutive deploys
	// to the same target.
	id:          #Identifier @go(ID)
	type:        string      @go(Type)
	description: string      @go(Description)
	url?:        string      @go(URL,optional=nillable)
	namespace?:  string      @go(Namespace,optional=nillable)
}
