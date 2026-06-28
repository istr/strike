// HTTPS service endpoint: a TLS-only base URL paired with a single server-trust
// anchor. Used by service clients (ADR-040 keyless endpoints) that append fixed
// well-known API paths under the base. Unlike #TLS/#SSH this is not a lane peer
// union member and carries no "type" discriminator; it is decoded by field name
// at its lane site. The url field (left of @go) is the https:// wire grammar
// (#URL); its Go type is the representation-neutral Address concept (ADR-048),
// projected in by ParseURL at decode and out by Address.URL at use. The https://
// regex makes a plaintext URL a parse error, not a runtime rejection.
package endpoint

#HTTPS: {
	@go(HTTPS)
	url:   #URL   @go(Address,type=Address)
	trust: #Trust @go(Trust,type=Trust)
}
