package lane

// Peer is the interface implemented by all peer types
// (HTTPSPeer, SSHPeer, OCIPeer). The CUE disjunction is
// annotated @go(-) so the generator skips it; this hand-written
// interface provides the Go-side discriminated union, parallel
// to DeployMethod and ProvenanceRecord.
type Peer interface {
	// PeerType returns the discriminator ("https", "ssh", "oci").
	PeerType() string
}

// PeerType implements Peer.
func (p HTTPSPeer) PeerType() string { return p.Type }

// PeerType implements Peer.
func (p SSHPeer) PeerType() string { return p.Type }

// PeerType implements Peer.
func (p OCIPeer) PeerType() string { return p.Type }
