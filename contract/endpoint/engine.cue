// Engine connection identity: the control-plane-observed identity of the engine
// transport, a discriminated union over the connection kind (mirrors #Trust).
// Consumed by the deploy attestation at sealed.engine. Layer V (cpObserved):
// the control plane reads these facts off the TLS handshake itself.
//
// The discriminator is `type`. A Unix socket carries no certificate identity;
// tls adds the observed server-cert identity and how it was trusted; mtls adds
// the controller's own client-cert identity. The Go types are hand-written in
// internal/endpoint (annotated @go(-)).
package endpoint

#Engine: (#EngineUnix | #EngineTLS | #EngineMTLS) @go(-)

#EngineUnix: {
	@go(-)
	type: "unix"
}

// EngineServerTLS is the observed engine server-cert identity shared by the tls
// and mtls variants. Not a connection on its own (no discriminator).
#EngineServerTLS: {
	@go(-)

	// caTrustType is how the engine's server certificate was trusted:
	// "pinned" (explicit CA) or "system" (OS trust store).
	caTrustType: "pinned" | "system"
	// serverCertFingerprint is sha256:<hex> of the engine's leaf cert,
	// observed by CP during the TLS handshake.
	serverCertFingerprint: string
	// serverCertSubject / serverCertIssuer are the Subject CN and Issuer CN
	// of that leaf certificate, observed in the same handshake.
	serverCertSubject?: string
	serverCertIssuer?:  string
}

#EngineTLS: {
	#EngineServerTLS
	@go(-)
	type: "tls"
}

#EngineMTLS: {
	#EngineServerTLS
	@go(-)
	type: "mtls"
	// clientCertFingerprint is sha256:<hex> of the controller's own cert;
	// clientCertSubject is its Subject CN.
	clientCertFingerprint: string
	clientCertSubject?:    string
}
