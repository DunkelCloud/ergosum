package authority

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// serveUnsealSocket listens on the local Unix socket for a passphrase. The
// socket is the only way to unseal: it is not reachable over the network,
// and its file mode (0600) limits it to the service user and root. The
// socket is created under a umask of 0177, so it never exists with wider
// permissions, whatever the directory allows.
func (a *Authority) serveUnsealSocket(ctx context.Context) (stop func(), err error) {
	path := a.cfg.UnsealSocket
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	_ = os.Remove(path) // stale socket from a previous run
	var ln net.Listener
	err = withUmask(0o177, func() error {
		var lerr error
		ln, lerr = a.listen("unix", path)
		return lerr
	})
	if err != nil {
		return nil, fmt.Errorf("unseal socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
				}
				if ctx.Err() != nil {
					return
				}
				time.Sleep(100 * time.Millisecond)
				continue
			}
			a.handleUnseal(conn)
		}
	}()
	return func() {
		select {
		case <-done:
		default:
			close(done)
		}
		_ = ln.Close()
		_ = os.Remove(path)
	}, nil
}

func (a *Authority) handleUnseal(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && line == "" {
		return
	}
	pass := []byte(strings.TrimRight(line, "\r\n"))
	err = a.Unseal(pass)
	for i := range pass {
		pass[i] = 0
	}
	if err != nil {
		a.log.Warn("unseal failed", "err", err)
		time.Sleep(time.Second) // slow down guessing
		_, _ = fmt.Fprintf(conn, "error: %v\n", err)
		return
	}
	_, _ = fmt.Fprintln(conn, "ok")
}

// ErrUnsealFailed is returned by UnsealVia when the instance refuses.
var ErrUnsealFailed = errors.New("unseal failed")

// UnsealVia sends a passphrase to a running instance's unseal socket.
func UnsealVia(ctx context.Context, socket string, passphrase []byte) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(time.Minute))
	if _, err := conn.Write(append(append([]byte{}, passphrase...), '\n')); err != nil {
		return err
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return err
	}
	reply = strings.TrimSpace(reply)
	if reply != "ok" {
		return fmt.Errorf("%w: %s", ErrUnsealFailed, strings.TrimPrefix(reply, "error: "))
	}
	return nil
}
