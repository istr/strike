package executor

import (
	"archive/tar"
	"bytes"
	"sort"
	"strconv"
	"strings"

	"github.com/istr/strike/internal/lane"
)

// RenderKnownHosts renders the SSH peer entries from the given peer list
// into an OpenSSH-format known_hosts document. The output is
// byte-deterministic: lines are sorted lexicographically by
// (formattedHost, keyType, key). Returns nil if no SSH peers with
// known_hosts entries are present.
func RenderKnownHosts(peers []lane.Peer) []byte {
	type record struct {
		formattedHost string
		keyType       string
		key           string
	}

	var records []record
	for _, p := range peers {
		sp, ok := p.(lane.SSHPeer)
		if !ok {
			continue
		}
		host := formatHost(string(sp.Host))
		for _, entry := range sp.KnownHosts {
			records = append(records, record{
				formattedHost: host,
				keyType:       entry.KeyType,
				key:           entry.Key,
			})
		}
	}

	sort.Slice(records, func(i, j int) bool {
		if records[i].formattedHost != records[j].formattedHost {
			return records[i].formattedHost < records[j].formattedHost
		}
		if records[i].keyType != records[j].keyType {
			return records[i].keyType < records[j].keyType
		}
		return records[i].key < records[j].key
	})

	if len(records) == 0 {
		return nil
	}

	var buf bytes.Buffer
	for _, r := range records {
		buf.WriteString(r.formattedHost)
		buf.WriteByte(' ')
		buf.WriteString(r.keyType)
		buf.WriteByte(' ')
		buf.WriteString(r.key)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

func formatHost(host string) string {
	idx := strings.LastIndex(host, ":")
	if idx < 0 {
		return host
	}
	h := host[:idx]
	p := host[idx+1:]
	return "[" + h + "]:" + p
}

// SSHTrustContent returns the byte content of the per-step SSH trust
// volume: known_hosts (one line per declared SSH peer) and ssh_config
// (per-peer Port directives pointing at strike-assigned loopback ports).
// Both files are produced deterministically and are the byte-identical
// payload the prior bind-mount mechanic wrote to disk. Returns nil when
// no SSH peers are present, signalling the step needs no SSH volume.
func SSHTrustContent(peers []lane.Peer, containerPorts map[string]uint16) (knownHosts, sshConfig []byte) {
	kh := RenderKnownHosts(peers)
	if len(kh) == 0 {
		return nil, nil
	}
	return kh, renderSSHConfig(containerPorts)
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

// renderSSHConfig produces a byte-deterministic ssh_config with one
// Host block per entry, sorted by host. HostName is not overridden, so
// DNS resolution flows through the capsule resolver (and is attested);
// only Port is set, pointing the client at the peer's strike-assigned
// container-side loopback port.
func renderSSHConfig(containerPorts map[string]uint16) []byte {
	hosts := make([]string, 0, len(containerPorts))
	for h := range containerPorts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	var buf bytes.Buffer
	for _, h := range hosts {
		buf.WriteString("Host ")
		buf.WriteString(h)
		buf.WriteByte('\n')
		buf.WriteString("    Port ")
		buf.WriteString(strconv.FormatUint(uint64(containerPorts[h]), 10))
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}
