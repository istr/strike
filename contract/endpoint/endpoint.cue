// TLS and SSH endpoint shapes and #Endpoint, their union: a network address
// paired with the server-trust anchor strike uses to verify the contacted
// party. Each shape carries a "type" discriminator so #Endpoint dispatches on
// one field without parsing the rest of the object (ADR-005, ADR-007). The
// host field is the packed "host:port" authority wire grammar (#Authority);
// its Go type is redirected to the representation-neutral Address concept
// (ADR-048), which ParseAuthority and Address.Authority project in and out at
// the boundary.
package endpoint

// #CarriageType is the carriage discriminator vocabulary shared by the two
// arms of #Endpoint and the observed-identity records.
#CarriageType: "https" | "ssh"

// TLS is a TLS-carriage endpoint: an address plus a single server-trust
// anchor.
#TLS: {
	@go(TLS)
	type: "https" @go(Type,type=CarriageType)
	// host (left of @go) is the packed-authority wire grammar; the Go side
	// (inside @go) is the Address concept in both name and type, since the wire
	// diverges from the concept and a diverging field maps fully, not half.
	// Address is same-package, so the override names the bare type and emits no
	// import. ParseAuthority and Address.Authority project across the boundary.
	host: #Authority @go(Address,type=Address)
	// trust is the certificate this peer is permitted to present, or the root
	// of the chain it presents. Certificate is same-package, so the override
	// names the bare type and emits no import (a contract/endpoint path would
	// self-import after the make generate contract/ -> internal/ rewrite).
	trust: #Certificate @go(Trust,type=Certificate)
}

// SSH is an SSH-carriage endpoint: an address plus the set of host keys
// the server is permitted to present.
#SSH: {
	@go(SSH)
	type: "ssh" @go(Type,type=CarriageType)
	// host (left of @go) is the packed-authority wire grammar; the Go side is
	// the Address concept in name and type; see #TLS.host.
	host: #Authority @go(Address,type=Address)
	knownHosts: [...#HostKey] @go(KnownHosts)
}

// #Endpoint is a declared endpoint: a TLS or an SSH endpoint with its
// server-trust anchor, discriminated by type. The type names what the value
// is; the field that holds it names the role it plays, as the peers of a lane
// step and of the deploy attestation do. The disjunction is annotated @go(-):
// internal/endpoint hand-writes the Go interface and the dispatching decode,
// as it does for #Engine.
#Endpoint: (#TLS | #SSH) @go(-)
