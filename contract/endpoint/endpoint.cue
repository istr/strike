// TLS and SSH endpoint shapes: a network address paired with the server-trust
// anchor strike uses to verify the contacted party. Each carries a "type"
// discriminator so the lane peer union dispatches on one field without parsing
// the rest of the object (ADR-005, ADR-007). The host field is the packed
// "host:port" authority wire grammar (#Authority); its Go type is redirected to
// the representation-neutral Address concept (ADR-048), which ParseAuthority and
// Address.Authority project in and out at the boundary.
package endpoint

// TLS is a TLS-carriage endpoint: an address plus a single server-trust
// anchor.
#TLS: {
	@go(TLS)
	type: "https" @go(Type)
	// host is the packed-authority wire grammar; the Go type is the Address
	// concept via the redirect (Address is same-package, so the override names
	// the bare type and emits no import).
	host: #Authority @go(Host,type=Address)
	// trust resolves to the hand-written Trust interface in this same package;
	// #Trust is @go(-), so the override names the bare same-package type and
	// emits no import (a contract/endpoint path would self-import after the
	// make generate contract/ -> internal/ rewrite).
	trust: #Trust @go(Trust,type=Trust)
}

// SSH is an SSH-carriage endpoint: an address plus the set of host keys
// the server is permitted to present.
#SSH: {
	@go(SSH)
	type: "ssh" @go(Type)
	// host is the packed-authority wire grammar redirected to the Address
	// concept; see #TLS.host.
	host: #Authority @go(Host,type=Address)
	knownHosts: [...#HostKey] @go(KnownHosts)
}
