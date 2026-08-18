// Package wire holds the constructions strike's producer and its verifier must
// reproduce byte for byte: the DSSE pre-authentication encoding, the payload
// and bundle media types the signed envelope carries, and the transparency-log
// key identity. Each lives here exactly once, because a divergence between the
// two roles is not a compile error -- it is a signature that does not verify.
// This is a contract owned by neither role package; per ADR-044 a two-role
// contract lives in a role-neutral package at the tier its dependencies
// dictate, here foundation (standard library only).
//
// The surface this package owns is the signing and transparency-log wire. The
// operator-authored input wire format is a separate concern and lives in the
// lane contract under contract/lane.
package wire
