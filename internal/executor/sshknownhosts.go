package executor

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
		host := formatHost(sp.Host)
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

// ConfigureSSHPeers renders the SSH known_hosts file and returns a mount
// and env map for injecting it into a container. If no SSH peers are
// present, all return values are nil.
func ConfigureSSHPeers(peers []lane.Peer, scratchDir string) (*container.Mount, map[string]string, error) {
	rendered := RenderKnownHosts(peers)
	if len(rendered) == 0 {
		return nil, nil, nil
	}

	path := filepath.Join(scratchDir, "known_hosts")
	if err := os.WriteFile(path, rendered, 0o644); err != nil { //nolint:gosec // G306: file contains public host-key data only; bind-mounted read-only
		return nil, nil, fmt.Errorf("ssh known_hosts: %w", err)
	}

	mount := &container.Mount{
		Source:   path,
		Target:   "/etc/ssh/ssh_known_hosts",
		ReadOnly: true,
	}

	env := map[string]string{
		"GIT_SSH_COMMAND": "ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/ssh/ssh_known_hosts -o GlobalKnownHostsFile=/etc/ssh/ssh_known_hosts -o PasswordAuthentication=no",
	}

	return mount, env, nil
}
