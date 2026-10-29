//go:build !windows

package admin

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
)

// dialAgent connects to the SSH agent named by SSH_AUTH_SOCK.
func dialAgent(ctx context.Context) (io.ReadWriteCloser, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, errors.New("SSH_AUTH_SOCK is not set; start ssh-agent and add the key with ssh-add")
	}
	var d net.Dialer
	return d.DialContext(ctx, "unix", sock) //nolint:gosec // the administrator's own agent
}
