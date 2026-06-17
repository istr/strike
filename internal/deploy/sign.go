package deploy

// SignedStatement is one projected in-toto statement, signed keylessly and
// carried as a sigstore v0.3 bundle (ADR-040 D2). The bundle subsumes the
// transparency proof (inclusion proof, checkpoint, RFC3161 timestamp), so
// no separate Rekor entry is recorded.
type SignedStatement struct {
	Bundle []byte `json:"-"`
}

// SignedStatements carries the three projected, keylessly signed in-toto
// statements (ADR-040 D3): the sealed SLSA provenance (Layer V), the
// engine-context statement (Layer E), and the informational statement (never
// gates). Each is its own sigstore bundle; on registry deploys each becomes
// its own OCI referrer of the pushed manifest digest. Replaces the single
// SignedEnvelope.
type SignedStatements struct {
	Sealed        SignedStatement
	EngineContext SignedStatement
	Informational SignedStatement
}
