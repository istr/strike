// DNS-over-TLS resolver endpoint: the full direct configuration of RFC 8310
// section 7.1 -- an authentication domain name and an IP address, both
// obtained out of band. The ADN is the only server identifier, since section
// 3 excludes IP addresses from that role, so the IP is the routing target and
// nothing else, and the presented chain is verified against the ADN as
// section 8.1 requires: the whole path per RFC 5280, the reference identifier
// matched in subjectAltName only, never in the Subject.
//
// The trust anchor is a declared root certificate and nothing else. Section
// 6.6 admits an ADN obtained from a section 7 source or an SPKI pin set, and
// a certificate pinned as a leaf is neither, so mode leaf cannot authenticate
// this endpoint. It stays available to every other declared endpoint
// (ADR-028). The anchor keeps the shape a peer declares, narrowed to the one
// mode, so this endpoint's anchor set is a strict subset of a peer's rather
// than a different mechanism.
//
// Unlike #TLS and #SSH this is not a lane peer union member and carries no
// "type" discriminator; it is decoded by field name at its lane site, as
// #HTTPS is.
package endpoint

import "github.com/istr/strike/contract/primitive"

#DoT: {
	@go(DoT)

	// adn is the authentication domain name: the reference identifier the
	// presented chain is matched against and the SNI sent on the wire. An IP
	// literal is rejected in Go -- section 3 excludes addresses as server
	// identifiers, and #Host cannot express that exclusion.
	adn: primitive.#Host @go(ADN)
	// ip is the address the dial connects to. It routes; it authenticates
	// nothing. Lax here, binding in Go (see primitive.#IP).
	ip: primitive.#IP @go(IP)
	// port is the DoT port. Absent means 853 (RFC 7858), defaulted in Go
	// rather than in a CUE default arm.
	port?: primitive.#Port @go(Port,optional=nillable)
	// trust is the root certificate the presented chain is verified against,
	// narrowed to the rootca mode: unifying the mode here is what makes a leaf
	// pin a parse error on this endpoint and valid on every other. Certificate
	// is same-package, so the override names the bare type and emits no import.
	trust: #Certificate & {mode: "rootca"} @go(Trust,type=Certificate)
}
