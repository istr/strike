package deploy

// SignedStatement is one projected in-toto statement, signed keylessly and
// carried as a sigstore v0.3 bundle (ADR-040 D2). The bundle subsumes the
// transparency proof (inclusion proof, checkpoint, RFC3161 timestamp), so
// no separate Rekor entry is recorded.
type SignedStatement struct {
	Bundle []byte `json:"-"`
}

// SignedStatements carries the projected, keylessly signed in-toto
// statements. Three are the statements of the trust layers (ADR-040 D3): the
// sealed SLSA provenance, the engine-dependent engine-context statement, and
// the informational statement (never gates). The fourth is the SBOM
// statement over the document of the image arm (ADR-059 D2), which a
// registry deploy signs with them. Each is its own sigstore bundle; on
// registry deploys each becomes its own OCI referrer of the pushed manifest
// digest. Replaces the single SignedEnvelope.
type SignedStatements struct {
	Sealed        SignedStatement
	EngineContext SignedStatement
	Informational SignedStatement
	SBOM          SignedStatement
}
