package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/DunkelCloud/ergosum/internal/secret"
)

// The local socket of "ergosumd secret": one JSON request and one JSON
// response per connection. The protocol belongs to this binary and is not
// part of ADR 0004.

// SecretRequest is what the CLI sends.
type SecretRequest struct {
	Op string `json:"op"` // "get" or "create"
	// get: part A as the caller read it.
	PartA []byte `json:"part_a,omitempty"`
	// create: name, threshold, the secret and the armored recovery copy.
	Name      string `json:"name,omitempty"`
	Threshold int    `json:"threshold,omitempty"`
	Secret    []byte `json:"secret,omitempty"`
	Recovery  string `json:"recovery,omitempty"`
}

// SecretResponse is what the daemon answers.
type SecretResponse struct {
	Secret []byte `json:"secret,omitempty"`
	// PartA: create: the new part A; get: a re-split part A to write in
	// place of the file, if any.
	PartA []byte `json:"part_a,omitempty"`
	Error string `json:"error,omitempty"`
}

// secretRequestLimit bounds a request: part A and the secret, in base64.
const secretRequestLimit = 2 << 20

// secretTimeout bounds one request on the socket: opening a secret may ask
// several instances one after another.
const secretTimeout = 5 * time.Minute

// serveSecrets serves the secret socket until stop is called. The socket
// is mode 0600, or 0660 with secret_socket_group.
func (d *Daemon) serveSecrets(ctx context.Context) (stop func(), err error) {
	path := d.cfg.SecretSocket
	if path == "-" {
		return func() {}, nil
	}
	gid := -1
	if d.cfg.SecretSocketGroup != "" && runtime.GOOS != "windows" {
		g, err := user.LookupGroup(d.cfg.SecretSocketGroup)
		if err != nil {
			return nil, fmt.Errorf("secret_socket_group: %w", err)
		}
		gid, _ = strconv.Atoi(g.Gid)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // as the token file's directory
		return nil, fmt.Errorf("secret socket: %w", err)
	}
	if fi, err := os.Lstat(path); err == nil && fi.Mode().Type() == os.ModeSocket {
		_ = os.Remove(path) // stale socket from a previous run
	}
	var ln net.Listener
	err = withUmask(0o177, func() error {
		var lerr error
		ln, lerr = new(net.ListenConfig).Listen(ctx, "unix", path)
		return lerr
	})
	if err != nil {
		return nil, fmt.Errorf("secret socket: %w", err)
	}
	mode := os.FileMode(0o600)
	if gid >= 0 {
		mode = 0o660
		err = os.Chown(path, -1, gid)
	}
	if err == nil {
		err = os.Chmod(path, mode)
	}
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("secret socket: %w", err)
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
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return
				}
				time.Sleep(100 * time.Millisecond)
				continue
			}
			go d.handleSecret(ctx, conn)
		}
	}()
	return func() {
		close(done)
		_ = ln.Close()
		_ = os.Remove(path)
	}, nil
}

func (d *Daemon) handleSecret(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(secretTimeout))
	ctx, cancel := context.WithTimeout(ctx, secretTimeout)
	defer cancel()
	uid := peerUID(conn)
	var req SecretRequest
	var resp SecretResponse
	if err := json.NewDecoder(io.LimitReader(conn, secretRequestLimit)).Decode(&req); err != nil {
		resp.Error = "malformed request"
		_ = json.NewEncoder(conn).Encode(resp) //nolint:gosec // the secret goes to the caller over the local socket
		return
	}
	var err error
	name := req.Name
	switch req.Op {
	case "get":
		if s, perr := secret.Parse(req.PartA); perr == nil {
			name = s.Name
		}
		resp.Secret, resp.PartA, err = d.GetSecret(ctx, req.PartA)
	case "create":
		resp.PartA, err = d.CreateSecret(ctx, req.Name, req.Threshold, req.Secret, req.Recovery)
	default:
		err = fmt.Errorf("unknown operation %q", req.Op)
	}
	if err != nil {
		resp.Error = err.Error()
		d.log.Warn("secret request failed", "op", req.Op, "name", name, "uid", uid, "err", err)
	} else {
		d.log.Info("secret request", "op", req.Op, "name", name, "uid", uid, "resplit", req.Op == "get" && resp.PartA != nil)
	}
	_ = json.NewEncoder(conn).Encode(resp) //nolint:gosec // the secret goes to the caller over the local socket
}

// CallSecret sends one request to the daemon's secret socket.
func CallSecret(ctx context.Context, socket string, req SecretRequest) (*SecretResponse, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, fmt.Errorf("cannot reach ergosumd at %s: %w", socket, err)
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil { //nolint:gosec // the secret goes to the daemon over the local socket
		return nil, err
	}
	var resp SecretResponse
	if err := json.NewDecoder(io.LimitReader(conn, secretRequestLimit)).Decode(&resp); err != nil {
		return nil, fmt.Errorf("no answer from ergosumd: %w", err)
	}
	if resp.Error != "" {
		return nil, errors.New(resp.Error)
	}
	return &resp, nil
}

// SecretSocketDefault is the socket the CLI uses when it cannot read the
// configuration.
func SecretSocketDefault() string {
	_, tokenFile := defaultPaths(runtime.GOOS)
	return filepath.Join(filepath.Dir(tokenFile), "secret.sock")
}
