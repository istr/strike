// Package transport is strike's network carriage: TLS dialing against verified
// trust anchors, connection-identity capture, the ephemeral CA, and the DoT
// resolver runtime. Endpoint declaration value types are endpoint concepts and
// live in internal/endpoint (ADR-048); this package consumes them downward and
// never the reverse.
package transport
