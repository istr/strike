package executor

import (
	"archive/tar"
	"bytes"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/istr/strike/internal/capsule"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
)

// RenderKnownHosts renders the container's ssh_known_hosts: one line per
// declared SSH peer host, all carrying the front's lane-wide synthetic host
// key (ADR-038 D5). The container connects to the peer hostname, which DNS
// points at the front; it validates the front's key here. The real peer's
// host key is not in the container -- the capsule validates it when it dials
// the peer. Output is byte-deterministic (hosts sorted). Returns nil when no
// SSH peers are present. frontKey is the front's public host key.
func RenderKnownHosts(peers []lane.Peer, frontKey ssh.PublicKey) []byte {
	var hosts []string
	for _, p := range peers {
		if sp, ok := p.(lane.SSHPeer); ok {
			hosts = append(hosts, formatHost(sp.Host))
		}
	}
	if len(hosts) == 0 {
		return nil
	}
	sort.Strings(hosts)
	keyLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(frontKey)))

	var buf bytes.Buffer
	for _, h := range hosts {
		buf.WriteString(h)
		buf.WriteByte(' ')
		buf.WriteString(keyLine)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

func formatHost(a endpoint.Address) string {
	h := string(a.Host)
	if a.Port == nil {
		return h
	}
	p := int(*a.Port)
	return "[" + h + "]:" + strconv.Itoa(p)
}

// SSHTrustContent returns the per-step SSH trust volume content: known_hosts
// (carrying the front's synthetic host key for every SSH peer) and ssh_config
// (rendered by the step's capsule, which owns the per-peer capability
// tokens). Returns nil when the step has no SSH peers; caps and frontKey may
// be nil/zero in that case.
func SSHTrustContent(peers []lane.Peer, caps *capsule.NetworkCapsule, frontKey ssh.PublicKey) (knownHosts, sshConfig []byte) {
	kh := RenderKnownHosts(peers, frontKey)
	if len(kh) == 0 {
		return nil, nil
	}
	return kh, caps.SSHConfig()
}

// SSHTrustEnv returns the env vars an SSH-enabled step needs. With the
// ssh_config and known_hosts delivered at the system-wide paths via the
// /etc/ssh trust volume, the client reads them without -F; the env set
// is therefore empty in the volume-delivery world.
func SSHTrustEnv() map[string]string {
	return map[string]string{}
}

// SSHTrustTar builds the tar payload SeedVolumes extracts into the SSH
// trust volume. The two files land at the volume root and the volume is
// mounted at /etc/ssh, so the in-container paths are
// /etc/ssh/ssh_known_hosts and /etc/ssh/ssh_config -- system-wide
// defaults read without an -F override.
func SSHTrustTar(knownHosts, sshConfig []byte) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range []struct {
		name string
		data []byte
		mode int64
	}{
		{"ssh_known_hosts", knownHosts, 0o644},
		{"ssh_config", sshConfig, 0o644},
	} {
		if err := tw.WriteHeader(&tar.Header{
			Name:     e.name,
			Mode:     e.mode,
			Size:     int64(len(e.data)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(e.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
