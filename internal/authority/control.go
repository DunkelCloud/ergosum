package authority

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DunkelCloud/ergosum/internal/journal"
	"github.com/DunkelCloud/ergosum/internal/replication"
)

// Control commands on the local socket.
const (
	CmdUnseal     = "unseal"
	CmdCheckpoint = "checkpoint"
	CmdCompact    = "compact"
	CmdSync       = "sync"
	CmdExport     = "export"
	CmdState      = "state"
)

// ControlRequest is one command on the control socket, sent as a JSON
// line.
type ControlRequest struct {
	Cmd string `json:"cmd"`
	// Passphrase for unseal.
	Passphrase []byte `json:"passphrase,omitempty"`
	// From names the peers to pull from (sync).
	From []string `json:"from,omitempty"`
	// Archive exports the events not yet archived into the configured
	// archive directory instead of streaming the whole journal (export).
	Archive bool `json:"archive,omitempty"`
}

// controlReply is one JSON line of an answer: zero or more events (export),
// then a final line with either a result or an error.
type controlReply struct {
	Event  *journal.ArchiveLine `json:"event,omitempty"`
	Result any                  `json:"result,omitempty"`
	Error  string               `json:"error,omitempty"`
	Done   bool                 `json:"done,omitempty"`
}

// serveControlSocket listens on the local Unix socket for operator
// commands, the passphrase among them. The socket is not reachable over the
// network, and its file mode (0600) limits it to the service user and root.
// It is created under a umask of 0177, so it never exists with wider
// permissions, whatever the directory allows.
func (a *Authority) serveControlSocket(ctx context.Context) (stop func(), err error) {
	path := a.cfg.ControlSocket
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
		return nil, fmt.Errorf("control socket: %w", err)
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
			go a.handleControl(ctx, conn)
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

// controlTimeout bounds one command; a sync of a large journal from a slow
// peer is the longest.
const controlTimeout = 30 * time.Minute

func (a *Authority) handleControl(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	line, err := bufio.NewReaderSize(conn, 4096).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	var req ControlRequest
	err = json.Unmarshal(line, &req)
	wipe(line)
	defer wipe(req.Passphrase)
	enc := json.NewEncoder(conn)
	reply := func(r controlReply) error {
		_ = conn.SetWriteDeadline(time.Now().Add(time.Minute))
		return enc.Encode(r)
	}
	if err != nil {
		_ = reply(controlReply{Error: "malformed request"})
		return
	}
	ctx, cancel := context.WithTimeout(ctx, controlTimeout)
	defer cancel()
	result, err := a.control(ctx, req, func(l journal.ArchiveLine) error { return reply(controlReply{Event: &l}) })
	if err != nil {
		_ = reply(controlReply{Error: err.Error()})
		return
	}
	_ = reply(controlReply{Result: result, Done: true})
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ErrSealed is returned for commands that need the instance key.
var ErrSealed = errors.New("instance is sealed; run \"ergosum unseal\" first")

func (a *Authority) control(ctx context.Context, req ControlRequest, emit func(journal.ArchiveLine) error) (any, error) {
	switch req.Cmd {
	case CmdUnseal:
		err := a.Unseal(req.Passphrase)
		if err != nil {
			a.log.Warn("unseal failed", "err", err)
			time.Sleep(time.Second) // slow down guessing
			return nil, err
		}
		return "unsealed", nil
	case CmdState:
		return a.JournalState(ctx)
	case CmdExport:
		if req.Archive {
			if a.cfg.Compaction.Archive == "" {
				return nil, errors.New("no archive directory configured (compaction.archive)")
			}
			path, n, err := a.store.ExportArchive(ctx, a.cfg.Compaction.Archive)
			return map[string]any{"file": path, "events": n}, err
		}
		_, n, err := a.store.Export(ctx, emitWriter(emit), 0)
		return map[string]any{"events": n}, err
	}
	if a.Sealed() {
		return nil, ErrSealed
	}
	switch req.Cmd {
	case CmdCheckpoint:
		return a.Checkpoint(ctx)
	case CmdCompact:
		return a.Compact(ctx)
	case CmdSync:
		if len(req.From) == 0 {
			return nil, errors.New("sync needs at least one peer")
		}
		var out []replication.PullResult
		for _, p := range req.From {
			res, err := a.Sync(ctx, p)
			if err != nil {
				return out, fmt.Errorf("sync from %s: %w", p, err)
			}
			out = append(out, res)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unknown command %q", req.Cmd)
	}
}

// emitWriter turns the JSON lines of an export back into events for the
// control protocol.
type emitWriter func(journal.ArchiveLine) error

func (f emitWriter) Write(p []byte) (int, error) {
	var l journal.ArchiveLine
	if err := json.Unmarshal(p, &l); err != nil {
		return 0, err
	}
	return len(p), f(l)
}

// ErrControl is returned by Control when the instance refuses a command.
var ErrControl = errors.New("command failed")

// ErrUnsealFailed is returned by UnsealVia when the instance refuses.
var ErrUnsealFailed = errors.New("unseal failed")

// Control sends a command to a running instance's control socket. Events
// of an export go to onEvent; the result is returned raw.
func Control(ctx context.Context, socket string, req ControlRequest, onEvent func(journal.ArchiveLine) error) (json.RawMessage, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	_, err = conn.Write(append(data, '\n'))
	wipe(data)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bufio.NewReader(conn))
	for {
		var r struct {
			Event  *journal.ArchiveLine `json:"event"`
			Result json.RawMessage      `json:"result"`
			Error  string               `json:"error"`
			Done   bool                 `json:"done"`
		}
		if err := dec.Decode(&r); err != nil {
			return nil, fmt.Errorf("control socket: %w", err)
		}
		switch {
		case r.Error != "":
			return nil, fmt.Errorf("%w: %s", ErrControl, r.Error)
		case r.Event != nil:
			if onEvent != nil {
				if err := onEvent(*r.Event); err != nil {
					return nil, err
				}
			}
		case r.Done:
			return r.Result, nil
		}
	}
}

// UnsealVia sends a passphrase to a running instance's control socket.
func UnsealVia(ctx context.Context, socket string, passphrase []byte) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	_, err := Control(ctx, socket, ControlRequest{Cmd: CmdUnseal, Passphrase: passphrase}, nil)
	if errors.Is(err, ErrControl) {
		return fmt.Errorf("%w: %s", ErrUnsealFailed, strings.TrimPrefix(err.Error(), ErrControl.Error()+": "))
	}
	return err
}
