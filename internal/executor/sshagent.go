package executor

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/copier"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/probe"
)

const containerAgentSocketPath = "/run/strike/ssh-agent.sock"

// StartAgentProxy creates a Unix-domain-socket proxy that forwards
// connections from the container to the host's ssh-agent. If no SSH
// peers are declared, all return values are nil. If SSH peers are
// declared but SSH_AUTH_SOCK is not set, returns an error.
func StartAgentProxy(ctx context.Context, peers []lane.Peer, scratchDir string) (*container.Mount, map[string]string, error) {
	var firstSSHHost string
	for _, p := range peers {
		if sp, ok := p.(lane.SSHPeer); ok {
			firstSSHHost = sp.Host
			break
		}
	}
	if firstSSHHost == "" {
		return nil, nil, nil
	}

	hostSock := os.Getenv("SSH_AUTH_SOCK")
	if hostSock == "" {
		return nil, nil, fmt.Errorf("ssh peer %q declared but SSH_AUTH_SOCK not set in strike process environment", firstSSHHost)
	}

	info, err := probe.Stat(hostSock)
	if err != nil {
		return nil, nil, fmt.Errorf("ssh agent socket %q: %w", hostSock, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return nil, nil, fmt.Errorf("ssh agent path %q is not a socket", hostSock)
	}

	proxyPath := filepath.Join(scratchDir, "agent.sock")
	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "unix", proxyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("ssh agent proxy listen: %w", err)
	}

	if chmodErr := chmodAgentSocket(proxyPath); chmodErr != nil {
		closer.Warn(listener, "ssh agent proxy listener")
		return nil, nil, fmt.Errorf("ssh agent proxy chmod: %w", chmodErr)
	}

	go func() {
		<-ctx.Done()
		closer.Warn(listener, "ssh agent proxy listener")
	}()

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go forwardAgent(conn, hostSock)
		}
	}()

	mount := &container.Mount{
		Source:   proxyPath,
		Target:   containerAgentSocketPath,
		ReadOnly: false,
	}

	env := map[string]string{
		"SSH_AUTH_SOCK": containerAgentSocketPath,
	}

	return mount, env, nil
}

func forwardAgent(client net.Conn, hostSock string) {
	defer closer.Warn(client, "ssh agent client")

	var d net.Dialer
	upstream, err := d.Dial("unix", hostSock)
	if err != nil {
		return
	}
	defer closer.Warn(upstream, "ssh agent upstream")

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		copier.Forward(upstream, client, "ssh agent forward up")
	}()

	go func() {
		defer wg.Done()
		copier.Forward(client, upstream, "ssh agent forward down")
	}()

	wg.Wait()
}
