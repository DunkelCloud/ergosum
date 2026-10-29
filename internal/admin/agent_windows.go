//go:build windows

package admin

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// openSSHAgentPipe is the pipe of the Windows OpenSSH agent service.
const openSSHAgentPipe = `\\.\pipe\openssh-ssh-agent`

// dialAgent connects to the SSH agent: the pipe or socket named by
// SSH_AUTH_SOCK, otherwise the OpenSSH agent service.
func dialAgent(ctx context.Context) (io.ReadWriteCloser, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		sock = openSSHAgentPipe
	}
	if !strings.HasPrefix(sock, `\\.\pipe\`) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock) //nolint:gosec // the administrator's own agent
	}
	f, err := os.OpenFile(sock, os.O_RDWR, 0) //nolint:gosec // the administrator's own agent
	if err != nil {
		return nil, fmt.Errorf("%w (is the ssh-agent service running? Get-Service ssh-agent)", err)
	}
	return f, nil
}
