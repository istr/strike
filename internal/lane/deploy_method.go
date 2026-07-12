package lane

// DeployMethod is the interface implemented by all deploy method types
// (DeployKubernetes, DeployRegistry, DeployCustom). The CUE disjunction
// is annotated @go(-) so the generator skips it; this hand-written
// interface provides the Go-side discriminated union, parallel to
// ProvenanceRecord.
type DeployMethod interface {
	// MethodType returns the discriminator ("kubernetes", "registry", "custom").
	MethodType() DeployMethodType
}

// MethodType implements DeployMethod.
func (m DeployKubernetes) MethodType() DeployMethodType { return m.Type }

// MethodType implements DeployMethod.
func (m DeployRegistry) MethodType() DeployMethodType { return m.Type }

// MethodType implements DeployMethod.
func (m DeployCustom) MethodType() DeployMethodType { return m.Type }
