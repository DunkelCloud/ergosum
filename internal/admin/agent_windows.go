//go:build windows

package admin

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"golang.org/x/sys/windows"
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
	// Opened for overlapped I/O, as the OpenSSH tools do. Opened for
	// synchronous I/O (os.OpenFile), sign requests to the OpenSSH agent
	// service at times got no answer, while key listings always did.
	name, err := windows.UTF16PtrFromString(sock)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w (is the ssh-agent service running? Get-Service ssh-agent)", sock, err)
	}
	return os.NewFile(uintptr(h), sock), nil
}
