package executor

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/istr/strike/internal/container"
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

// strikeSSHConfigPath is the in-container path of the strike-generated
// ssh_config carrying per-peer Port directives. It is referenced via
// -F so the SSH client connects to each peer's strike-assigned
// loopback port. strike injects this transport-config the same way it
// injects the ephemeral CA for TLS; a tool that ignores it reaches no
// forward and fails closed.
const strikeSSHConfigPath = "/etc/ssh/strike_config"

// gitSSHBase is the GIT_SSH_COMMAND prefix (ADR-024, ADR-025) shared by
// every SSH-enabled step. ConfigureSSHPeers appends "-F <config>".
const gitSSHBase = "ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/ssh/ssh_known_hosts -o GlobalKnownHostsFile=/etc/ssh/ssh_known_hosts -o PasswordAuthentication=no -o BatchMode=yes"

// ConfigureSSHPeers renders the SSH known_hosts file plus the strike
// ssh_config and returns the two mounts and the env map for injecting
// them into a container. containerPorts maps each SSH peer host (no
// port) to the container-side port the SSH client must use, allocated
// by the caller from the capsule's SSH forwards. If no SSH peers are
// present, all return values are nil.
func ConfigureSSHPeers(peers []lane.Peer, scratchDir string, containerPorts map[string]uint16) ([]container.Mount, map[string]string, error) {
	rendered := RenderKnownHosts(peers)
	if len(rendered) == 0 {
		return nil, nil, nil
	}

	khPath := filepath.Join(scratchDir, "known_hosts")
	if err := os.WriteFile(khPath, rendered, 0o600); err != nil {
		return nil, nil, fmt.Errorf("ssh known_hosts: %w", err)
	}

	cfg := renderSSHConfig(containerPorts)
	cfgPath := filepath.Join(scratchDir, "strike_ssh_config")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		return nil, nil, fmt.Errorf("ssh config: %w", err)
	}

	mounts := []container.Mount{
		{Source: khPath, Target: "/etc/ssh/ssh_known_hosts", ReadOnly: true},
		{Source: cfgPath, Target: strikeSSHConfigPath, ReadOnly: true},
	}

	env := map[string]string{
		"GIT_SSH_COMMAND": gitSSHBase + " -F " + strikeSSHConfigPath,
	}

	return mounts, env, nil
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
