// Package deploy implements the deploy step type with mandatory state attestation.
//
// Every deploy produces a signed record of: what was running before,
// what changed, and what is running after. The attestation record
// IS the deploy output -- there is no deploy without state capture.
package deploy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/istr/strike/internal/capsule"
	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/mediator"
	"github.com/istr/strike/internal/probe"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/transport"
)

// Attestation is the signed record produced by every deploy step.
//
// The three top-level sections classify every recorded field by the trust
// the consumer must supply to rely on it. See
// docs/ATTESTATION-SOUNDNESS-AND-THE-TRUST-BOUNDARY.md and
// ADR-037 for the trust-layer theory.
type Attestation struct {
	Sealed          Sealed          `json:"sealed"`
	EngineDependent EngineDependent `json:"engine_dependent"`
	Informational   *Informational  `json:"informational,omitempty"`
	SignedEnvelope  []byte          `json:"-"` // DSSE envelope, not part of attestation JSON
}

// Sealed -- CP-bound claims, sound to any verifier without engine trust.
type Sealed struct {
	Artifacts map[string]SignedArtifact `json:"artifacts"`
	Peers     map[string][]lane.Peer    `json:"peers"`
	Resolver  *ResolverRecord           `json:"resolver,omitempty"`
	Rekor     *lane.RekorEntry          `json:"rekor,omitempty"`
	Engine    *EngineConnection         `json:"engine,omitempty"`
	Target    lane.DeployTarget         `json:"target"`
	LaneID    string                    `json:"lane_id"`
	LaneRef   string                    `json:"lane_ref"`
}

// EngineDependent -- claims sound only under trust(E).
//
// Empty by structural design in Phase 1; Phase-2 capsule-observed
// attribution will populate this. See ADR-037 / foundation note.
type EngineDependent struct{}

// Informational -- recorded for audit and IoC; no trust claim.
type Informational struct {
	Timestamp       clock.Time              `json:"timestamp,omitempty"`
	EngineMetadata  *EngineMetadata         `json:"engine_metadata,omitempty"`
	PreStateDigest  lane.Digest             `json:"pre_state_digest"`
	PostStateDigest lane.Digest             `json:"post_state_digest"`
	Provenance      []lane.ProvenanceRecord `json:"provenance"`
}

// SignedArtifact is the provenance record for one artifact.
type SignedArtifact struct {
	Signature *SignatureRecord `json:"signature,omitempty"`
	SBOM      *SBOMRecord      `json:"sbom,omitempty"`
	Rekor     *lane.RekorEntry `json:"rekor,omitempty"`
	Digest    string           `json:"digest"`
}

// SignatureRecord holds the signing metadata for an artifact.
type SignatureRecord struct {
	Annotations map[string]string `json:"annotations"`
	Algorithm   string            `json:"algorithm"`
	Payload     string            `json:"payload"`
}

// SBOMRecord holds SBOM metadata for an artifact.
type SBOMRecord struct {
	Format string `json:"format"`
	Digest string `json:"digest"`
}

// EngineConnection -- CP-observed/controlled connection facts about the
// engine. Lives under Sealed.Engine.
type EngineConnection struct {
	// ConnectionType is "unix", "tls", or "mtls".
	ConnectionType string `json:"connection_type"`

	// CATrustMode is "pinned" (explicit CA) or "system" (OS trust store).
	// Empty for Unix socket connections.
	CATrustMode string `json:"ca_trust_mode,omitempty"`

	// ServerCertFingerprint is sha256:<hex> of the engine's certificate.
	// Empty for Unix socket connections.
	ServerCertFingerprint string `json:"server_cert_fingerprint,omitempty"`

	// ClientCertFingerprint is sha256:<hex> of the controller's certificate.
	// Empty unless mTLS is configured.
	ClientCertFingerprint string `json:"client_cert_fingerprint,omitempty"`
}

// EngineMetadata -- engine self-reports about itself. Lives under
// Informational.EngineMetadata.
type EngineMetadata struct {
	// Rootless is true if the engine reported rootless mode.
	Rootless *bool `json:"rootless,omitempty"`

	// Version is the engine's self-reported version string.
	Version string `json:"version,omitempty"`
}

// ResolverRecord captures the DoT resolver's observed TLS identity,
// recorded once per lane run from the pre-flight handshake. Per
// ADR-030, the DoT resolver is the one controller-side connection
// whose channel identity is part of the trust chain: DNS answers are
// not content-addressable, so the resolver's identity is the trust
// anchor for resolution. The declared anchor (resolver.trust) was
// enforced at the handshake; this record stores what that verified
// handshake observed, for a verifier to compare against the declared
// anchor.
type ResolverRecord struct {
	// Host is the declared resolver endpoint (host:port) the probe
	// connected to and verified.
	Host string `json:"host"`

	// ServerCertFingerprint is sha256:<hex> of the resolver's leaf
	// certificate, observed at the handshake.
	ServerCertFingerprint string `json:"server_cert_fingerprint"`

	// TLSVersion is the negotiated TLS version, human-readable
	// (e.g. "TLS 1.3").
	TLSVersion string `json:"tls_version"`

	// CipherSuite is the negotiated cipher suite, human-readable
	// (e.g. "TLS_AES_128_GCM_SHA256").
	CipherSuite string `json:"cipher_suite"`

	// ServerName is the SNI sent during the handshake. Empty for
	// IP-literal resolver hosts (RFC 6066 forbids IP-literal SNI),
	// which is the common case for DoT endpoints like "1.1.1.1:853".
	ServerName string `json:"server_name,omitempty"`
}

// HardenedRunOpts returns a RunOpts with the standard security profile.
// Callers override specific fields (Image, Cmd, Network, Mounts) as needed.
func HardenedRunOpts() container.RunOpts {
	return container.DefaultSecureOpts()
}

// startUnitCapsule constructs and starts a capsule for one deploy
// container unit, keyed by name in d.StepPorts. Returns the capsule
// (always non-nil on success) for the caller to Stop. Mirrors the
// run-path dispatch: every container unit runs under pasta with a
// per-unit allowlist (empty for peer-less units).
func (d *Deployer) startUnitCapsule(ctx context.Context, name string, peers []lane.Peer) (*capsule.NetworkCapsule, error) {
	ports, ok := d.StepPorts[name]
	if !ok {
		return nil, fmt.Errorf("deploy %q: no pre-allocated host ports", name)
	}
	var trusts []mediator.PeerTrust
	for _, p := range peers {
		if hp, ok := p.(lane.HTTPSPeer); ok {
			trusts = append(trusts, mediator.PeerTrust{Host: hp.Host, Trust: hp.Trust})
		}
	}
	var targets []capsule.SSHTarget
	for _, p := range peers {
		if sp, ok := p.(lane.SSHPeer); ok {
			keys := make([]string, len(sp.KnownHosts))
			for j, e := range sp.KnownHosts {
				keys[j] = e.KeyType + " " + e.Key
			}
			targets = append(targets, capsule.SSHTarget{Host: string(sp.Host), HostKeys: keys})
		}
	}
	caps, err := capsule.New(name, ports, trusts, targets, 0, d.CA, d.UpstreamLook)
	if err != nil {
		return nil, fmt.Errorf("deploy %q: construct capsule: %w", name, err)
	}
	if err := caps.Start(ctx); err != nil {
		return nil, fmt.Errorf("deploy %q: start capsule: %w", name, err)
	}
	return caps, nil
}

// applyCapsule sets the pasta network options and appends the CA
// trust volume onto opts for a capsule-mediated deploy container.
func (d *Deployer) applyCapsule(opts *container.RunOpts, caps *capsule.NetworkCapsule) {
	opts.Network = "pasta"
	opts.PastaArgs = caps.PastaArgs()
	opts.DNSServers = []string{caps.ResolverAddr().Addr().String()}
	opts.TrustVolumes = append(opts.TrustVolumes, container.VolumeMount{
		Name: d.CAVolume,
		Dest: "/etc/ssl/certs",
	})
}

// captureKey is the stepPorts key for a state-capture container; it
// must match cmd/strike/run.go captureKey.
func captureKey(stepName, captureName string) string {
	return "capture:" + stepName + ":" + captureName
}

// Deployer executes deploy steps and produces attestations.
type Deployer struct {
	Engine       container.Engine
	ArtifactRefs map[string]string // pre-resolved: artifact name -> "step.output" state ref
	EngineID     *container.EngineIdentity
	ResolverID   *transport.ConnectionIdentity // DoT resolver identity from the pre-flight probe; nil if unavailable
	Rekor        *executor.RekorClient
	DAG          *lane.DAG
	CA           *transport.EphemeralCA
	UpstreamLook capsule.UpstreamLookupFunc
	StepPorts    map[string]capsule.HostPorts // unit name -> host ports
	LaneID       string
	StepName     string // deploy step name; method-container port key and capture-key prefix
	CAVolume     string // lane-wide CA volume name; mounted r/o at /etc/ssl/certs
	SigningKey   []byte
	KeyPassword  []byte
}

// Execute runs a deploy step: capture pre-state, execute the deploy
// action, capture post-state, and build the attestation.
func (d *Deployer) Execute(ctx context.Context, step *lane.Step, state *lane.State) (*Attestation, error) {
	if step.Deploy == nil {
		return nil, fmt.Errorf("step %q: not a deploy step", step.Name)
	}
	spec := *step.Deploy
	started := clock.Wall()

	// 1. Capture pre-state -> canonical digest.
	preCaptures, err := d.captureState(ctx, spec.Attestation.PreState)
	if err != nil {
		if spec.Attestation.PreState.Required {
			return nil, fmt.Errorf("step %q: pre-state capture failed: %w", step.Name, err)
		}
		log.Printf("WARN   deploy %s: pre-state capture failed: %v", step.Name, err)
	}
	preDigest := StateDigest(preCaptures)

	// 2. Resolve artifact digests.
	artifactDigests, err := resolveArtifactDigests(step.Name, d.ArtifactRefs, state)
	if err != nil {
		return nil, err
	}

	// 3. Collect provenance records from transitive predecessors.
	provenance := state.CollectProvenance(d.DAG, string(step.Name))

	// 4. Execute deploy action.
	if execErr := d.executeMethod(ctx, spec, step.Peers); execErr != nil {
		return nil, fmt.Errorf("step %q: deploy action failed: %w", step.Name, execErr)
	}

	// 5. Capture post-state -> canonical digest.
	postCaptures, err := d.captureState(ctx, spec.Attestation.PostState)
	if err != nil {
		if spec.Attestation.PostState.Required {
			return nil, fmt.Errorf("step %q: post-state capture failed: %w", step.Name, err)
		}
		log.Printf("WARN   deploy %s: post-state capture failed: %v", step.Name, err)
	}
	postDigest := StateDigest(postCaptures)

	// 6. Build attestation.
	engineConn, engineMeta := d.engineRecords()
	att := &Attestation{
		Sealed: Sealed{
			LaneID:    d.LaneID,
			Target:    spec.Target,
			Artifacts: artifactDigests,
			Resolver:  d.resolverRecord(),
			Peers:     d.DAG.CollectPeers(string(step.Name)),
			Engine:    engineConn,
		},
		EngineDependent: EngineDependent{},
		Informational: &Informational{
			Timestamp:       started,
			EngineMetadata:  engineMeta,
			PreStateDigest:  preDigest,
			PostStateDigest: postDigest,
			Provenance:      provenance,
		},
	}

	// 7. Validate attestation against CUE schema.
	if err := ValidateAttestation(att); err != nil {
		return nil, fmt.Errorf("step %q: attestation invalid: %w", step.Name, err)
	}

	// 8. Sign attestation (optional, key-dependent).
	if err := d.signAttestation(att, step.Name); err != nil {
		return nil, err
	}

	// 9. Submit signed attestation to Rekor transparency log (optional).
	if d.Rekor != nil && att.SignedEnvelope != nil {
		rekorEntry, rekorErr := submitAttestationToRekor(ctx, d, att)
		if rekorErr != nil {
			return nil, rekorErr
		}
		att.Sealed.Rekor = rekorEntry
	}

	// 10. Record in lane state.
	if err := d.recordAttestation(att, step, state, started); err != nil {
		return nil, fmt.Errorf("step %q: %w", step.Name, err)
	}

	return att, nil
}

// signAttestation wraps the attestation in a signed DSSE envelope if a key is configured.
func (d *Deployer) signAttestation(att *Attestation, stepName string) error {
	if d.SigningKey == nil {
		log.Printf("WARN   deploy %s: attestation unsigned (no signing key configured)", stepName)
		return nil
	}
	attJSON, err := json.Marshal(att)
	if err != nil {
		return fmt.Errorf("step %q: marshal attestation for signing: %w", stepName, err)
	}
	envelope, err := SignAttestation(attJSON, d.SigningKey, d.KeyPassword)
	if err != nil {
		return fmt.Errorf("step %q: sign attestation: %w", stepName, err)
	}
	att.SignedEnvelope = envelope
	return nil
}

const rekorMaxEnvelopeSize = 100 * 1024 // 100KB Rekor upload limit

// submitAttestationToRekor submits the signed DSSE envelope to Rekor.
// Returns nil entry on transient failure (fail open) or oversized envelope.
func submitAttestationToRekor(ctx context.Context, d *Deployer, att *Attestation) (*lane.RekorEntry, error) {
	if len(att.SignedEnvelope) > rekorMaxEnvelopeSize {
		log.Printf("WARN   deploy %s/%s: DSSE envelope %d bytes exceeds Rekor %d byte limit, skipping",
			att.Sealed.LaneID, att.Sealed.Target.ID, len(att.SignedEnvelope), rekorMaxEnvelopeSize)
		return nil, nil
	}

	pubPEM, err := executor.DerivePublicKeyPEM(d.SigningKey, d.KeyPassword)
	if err != nil {
		return nil, fmt.Errorf("rekor: derive public key: %w", err)
	}
	entry, err := d.Rekor.SubmitDSSE(ctx, att.SignedEnvelope, pubPEM)
	if err != nil {
		var w *executor.RekorTransientError
		if errors.As(err, &w) {
			log.Printf("WARN   deploy %s/%s: rekor dsse: %v", att.Sealed.LaneID, att.Sealed.Target.ID, err)
			return nil, nil
		}
		return nil, err
	}
	return entry, nil
}

// resolveArtifactDigests resolves all artifact references to their signed provenance records.
// refs maps artifact name -> "step.output" state ref (pre-resolved by the caller from DAG edges).
func resolveArtifactDigests(stepName string, refs map[string]string, state *lane.State) (map[string]SignedArtifact, error) {
	artifacts := make(map[string]SignedArtifact)
	for artName, ref := range refs {
		a, resolveErr := state.Resolve(ref)
		if resolveErr != nil {
			return nil, fmt.Errorf("step %q: artifact %q: %w", stepName, artName, resolveErr)
		}
		artifacts[artName] = SignedArtifact{
			Digest: a.Digest.String(),
			Rekor:  a.Rekor,
		}
	}
	return artifacts, nil
}

// recordAttestation marshals and records the attestation in lane state.
func (d *Deployer) recordAttestation(att *Attestation, step *lane.Step, state *lane.State, started clock.Time) error {
	attJSON, err := json.Marshal(att)
	if err != nil {
		return fmt.Errorf("marshal attestation: %w", err)
	}
	attHex := hex.EncodeToString(sha256Sum(attJSON))

	attDigest := lane.Digest{Algorithm: "sha256", Hex: attHex}
	if err := state.Register(step.Name, "attestation", lane.Artifact{
		Type:        "file",
		Digest:      attDigest,
		Size:        int64(len(attJSON)),
		ContentType: lane.Ptr("application/vnd.strike.attestation+json"),
	}); err != nil {
		return fmt.Errorf("register attestation: %w", err)
	}

	state.RecordStep(lane.StepResult{
		Name:      step.Name,
		StepType:  "deploy",
		StartedAt: started,
		Duration:  clock.Since(started),
		Outputs:   map[string]string{"attestation": attDigest.String()},
	})
	return nil
}

// JSON serializes an attestation for storage or signing.
func (a *Attestation) JSON() ([]byte, error) {
	return json.MarshalIndent(a, "", "  ")
}

// captureState runs all state capture commands and returns the raw captures.
func (d *Deployer) captureState(ctx context.Context, spec lane.StateCaptureSpec) ([]captureSnap, error) {
	var captures []captureSnap
	for _, sc := range spec.Capture {
		snap, err := d.captureOne(ctx, sc)
		if err != nil {
			return captures, fmt.Errorf("capture %q: %w", sc.Name, err)
		}
		captures = append(captures, snap)
	}
	return captures, nil
}

// captureOne runs a state capture command inside a container.
func (d *Deployer) captureOne(ctx context.Context, sc lane.StateCapture) (captureSnap, error) {
	if sc.Image == "" {
		return captureSnap{}, fmt.Errorf("capture %q: image is required", sc.Name)
	}
	if len(sc.Command) == 0 {
		return captureSnap{}, fmt.Errorf("capture %q: command is required", sc.Name)
	}

	var stdout, stderr bytes.Buffer

	var mounts []container.Mount
	for _, m := range sc.Mounts {
		mounts = append(mounts, container.Mount{
			Source:   m.Source,
			Target:   m.Target.String(),
			ReadOnly: true,
		})
	}

	caps, err := d.startUnitCapsule(ctx, captureKey(d.StepName, sc.Name), sc.Peers)
	if err != nil {
		return captureSnap{}, err
	}
	defer func() {
		if stopErr := caps.Stop(); stopErr != nil {
			log.Printf("WARN   capture %s: capsule stop: %v", sc.Name, stopErr)
		}
	}()

	if err = setupSSHEnv(sc.Peers); err != nil {
		return captureSnap{}, err
	}

	opts := HardenedRunOpts()
	opts.Image = string(sc.Image)
	opts.Cmd = sc.Command
	opts.Mounts = mounts
	opts.Stdout = &stdout
	opts.Stderr = &stderr
	d.applyCapsule(&opts, caps)

	exitCode, err := d.Engine.ContainerRun(ctx, opts)
	if err != nil {
		return captureSnap{}, fmt.Errorf("capture %q: %w", sc.Name, err)
	}
	if exitCode != 0 {
		return captureSnap{}, fmt.Errorf("capture %q: exit code %d: %s",
			sc.Name, exitCode, stderr.String())
	}

	return captureSnap{
		name:   sc.Name,
		image:  string(sc.Image),
		output: stdout.Bytes(),
	}, nil
}

// executeMethod dispatches to the appropriate deploy method.
func (d *Deployer) executeMethod(ctx context.Context, spec lane.DeploySpec, peers []lane.Peer) error {
	switch m := spec.Method.(type) {
	case lane.DeployRegistry:
		return executeRegistryDeploy(m)
	case lane.DeployKubernetes:
		return d.executeKubernetesDeploy(ctx, m, peers)
	case lane.DeployCustom:
		return d.executeCustomDeploy(ctx, m, peers)
	default:
		return fmt.Errorf("unknown deploy method type %q", spec.Method.MethodType())
	}
}

func executeRegistryDeploy(m lane.DeployRegistry) error {
	if err := registry.CopyImage(m.Source, m.Target); err != nil {
		return fmt.Errorf("registry deploy: %w", err)
	}
	return nil
}

func (d *Deployer) executeKubernetesDeploy(ctx context.Context, m lane.DeployKubernetes, peers []lane.Peer) error {
	if m.Image == "" {
		return fmt.Errorf("kubernetes deploy: image required (digest-pinned kubectl image)")
	}

	explicit := ""
	if m.Kubeconfig != nil {
		explicit = *m.Kubeconfig
	}
	kubeconfig, err := ResolveKubeconfig(explicit)
	if err != nil {
		return fmt.Errorf("kubernetes deploy: %w", err)
	}

	strategy := m.Strategy
	if strategy == "" {
		strategy = "apply"
	}

	kubectlArgs := []string{strategy, "-f", "-"}
	if m.Namespace != "" {
		kubectlArgs = append(kubectlArgs, "-n", m.Namespace)
	}

	mounts := []container.Mount{
		{Source: kubeconfig, Target: "/root/.kube/config", ReadOnly: true},
	}

	caps, err := d.startUnitCapsule(ctx, d.StepName, peers)
	if err != nil {
		return err
	}
	defer func() {
		if stopErr := caps.Stop(); stopErr != nil {
			log.Printf("WARN   deploy %s: capsule stop: %v", d.StepName, stopErr)
		}
	}()

	if err = setupSSHEnv(peers); err != nil {
		return err
	}

	opts := HardenedRunOpts()
	opts.Image = string(m.Image)
	opts.Cmd = kubectlArgs
	opts.Mounts = mounts
	opts.Stdin = os.Stdin
	opts.Stdout = os.Stdout
	opts.Stderr = os.Stderr
	d.applyCapsule(&opts, caps)

	exitCode, err := d.Engine.ContainerRun(ctx, opts)
	if err != nil {
		return fmt.Errorf("kubernetes deploy: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("kubernetes deploy: exit code %d", exitCode)
	}
	return nil
}

func (d *Deployer) executeCustomDeploy(ctx context.Context, m lane.DeployCustom, peers []lane.Peer) error {
	if m.Image == "" {
		return fmt.Errorf("custom deploy: image required")
	}

	caps, err := d.startUnitCapsule(ctx, d.StepName, peers)
	if err != nil {
		return err
	}
	defer func() {
		if stopErr := caps.Stop(); stopErr != nil {
			log.Printf("WARN   deploy %s: capsule stop: %v", d.StepName, stopErr)
		}
	}()

	if err = setupSSHEnv(peers); err != nil {
		return err
	}
	env := make(map[string]string, len(m.Env))
	for k, v := range m.Env {
		env[k] = v
	}

	opts := HardenedRunOpts()
	opts.Image = string(m.Image)
	opts.Entrypoint = m.Entrypoint
	opts.Cmd = m.Args
	opts.Env = env
	opts.Stdout = os.Stdout
	opts.Stderr = os.Stderr
	d.applyCapsule(&opts, caps)

	exitCode, err := d.Engine.ContainerRun(ctx, opts)
	if err != nil {
		return err
	}
	if exitCode != 0 {
		return fmt.Errorf("custom deploy: exit code %d", exitCode)
	}
	return nil
}

// setupSSHEnv rejects deploy units that declare SSH peers. Deploy-path SSH
// (scp/sftp/rsync over SSH) is not yet implemented and waits on the ADR-038
// front landing those protocols. It no longer sets anything up: the container
// ssh-agent socket it used to mount is gone (ADR-038 D6 -- the front
// terminates SSH and the capsule drives the host agent, so no container needs
// an agent socket). The name is now a misnomer; renaming is left to the
// naming-consistency pass.
func setupSSHEnv(peers []lane.Peer) error {
	for _, p := range peers {
		if _, ok := p.(lane.SSHPeer); ok {
			return fmt.Errorf("deploy SSH peers not yet implemented (ADR-038 roadmap)")
		}
	}
	return nil
}

func sha256Sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// ResolveKubeconfig returns the host path to the kubeconfig file.
// Priority: explicit override, $KUBECONFIG, default path.
func ResolveKubeconfig(override string) (string, error) {
	if override != "" {
		if _, err := os.Stat(override); err != nil {
			return "", fmt.Errorf("kubeconfig %q: %w", override, err)
		}
		return override, nil
	}
	if env := os.Getenv("KUBECONFIG"); env != "" {
		if _, err := probe.Stat(env); err != nil {
			return "", fmt.Errorf("$KUBECONFIG %q: %w", env, err)
		}
		return env, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	path := filepath.Join(home, ".kube", "config")
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("default kubeconfig %q: %w", path, err)
	}
	return path, nil
}

// engineRecords returns the sealed engine connection facts (CP-observed)
// and the informational engine metadata (engine self-reports).
func (d *Deployer) engineRecords() (*EngineConnection, *EngineMetadata) {
	if d.EngineID == nil {
		return nil, nil
	}
	conn := &EngineConnection{
		ConnectionType:        d.EngineID.Connection.Type,
		CATrustMode:           d.EngineID.Connection.CATrustMode,
		ServerCertFingerprint: d.EngineID.Connection.ServerCertFingerprint,
		ClientCertFingerprint: d.EngineID.Connection.ClientCertFingerprint,
	}
	meta := &EngineMetadata{}
	if d.EngineID.Runtime != nil {
		meta.Rootless = &d.EngineID.Runtime.Rootless
		meta.Version = d.EngineID.Runtime.Version
	}
	return conn, meta
}

// resolverRecord builds the ResolverRecord from the captured DoT
// resolver identity. Returns nil when no resolver identity was
// captured (e.g. ResolverID is nil). Parallel to engineRecord.
func (d *Deployer) resolverRecord() *ResolverRecord {
	if d.ResolverID == nil {
		return nil
	}
	id := d.ResolverID
	return &ResolverRecord{
		Host:                  id.PeerAddress,
		ServerCertFingerprint: id.LeafFingerprint,
		TLSVersion:            tls.VersionName(id.TLSVersion),
		CipherSuite:           tls.CipherSuiteName(id.CipherSuite),
		ServerName:            id.ServerName,
	}
}
