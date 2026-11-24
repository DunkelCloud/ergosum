package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/DunkelCloud/ergosum/internal/cli/clitest"
	"github.com/DunkelCloud/ergosum/internal/daemon"
	"github.com/DunkelCloud/ergosum/internal/exchange"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/protocol"
	"github.com/DunkelCloud/ergosum/internal/secret"
)

const (
	testDomain   = "example.com"
	testIdentity = "host1.example.com"
)

// fakeDaemon answers on a secret socket as "ergosumd run" does, without
// authorities: create seals to pins that no instance backs, get answers for
// every part A that create made, and forget drops one from what the daemon
// holds.
type fakeDaemon struct {
	socket string

	mu        sync.Mutex
	identity  string
	sealed    map[[32]byte][]byte // the secret of every part A it made
	held      map[[32]byte]bool   // those it holds in memory
	requests  []string            // the operations, in order
	createErr string              // create fails with it
	onCreate  func()              // runs before create answers
}

func newFakeDaemon(t *testing.T) *fakeDaemon {
	t.Helper()
	// A short path: a socket address has room for about 100 bytes.
	dir, err := os.MkdirTemp("", "es")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	d := &fakeDaemon{
		socket: filepath.Join(dir, "s"), identity: testIdentity,
		sealed: map[[32]byte][]byte{}, held: map[[32]byte]bool{},
	}
	ln, err := net.Listen("unix", d.socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go d.serve(conn)
		}
	}()
	return d
}

func (d *fakeDaemon) serve(conn net.Conn) {
	defer conn.Close()
	var req daemon.SecretRequest
	var resp daemon.SecretResponse
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return
	}
	d.mu.Lock()
	d.requests = append(d.requests, req.Op)
	createErr, onCreate := d.createErr, d.onCreate
	d.mu.Unlock()
	switch req.Op {
	case "create":
		if createErr != "" {
			resp.Error = createErr
			break
		}
		partA, err := d.seal(req.Name, req.Threshold, req.Secret, req.Recovery)
		if err != nil {
			resp.Error = err.Error()
			break
		}
		if onCreate != nil {
			onCreate()
		}
		resp.PartA = partA
	case "get":
		key := sha256.Sum256(req.PartA)
		d.mu.Lock()
		plain, ok := d.sealed[key]
		d.held[key] = d.held[key] || ok
		d.mu.Unlock()
		if !ok {
			resp.Error = "0 of the shares needed opened"
			break
		}
		resp.Secret = plain
	case "forget":
		d.mu.Lock()
		delete(d.held, sha256.Sum256(req.PartA))
		d.mu.Unlock()
	default:
		resp.Error = "unknown operation"
	}
	json.NewEncoder(conn).Encode(resp)
}

// seal makes a part A for the daemon's identity with three pins and holds
// its secret.
func (d *fakeDaemon) seal(name string, threshold int, plain []byte, recovery string) ([]byte, error) {
	d.mu.Lock()
	identity := d.identity
	d.mu.Unlock()
	var targets []secret.Target
	for range 3 {
		key, err := keys.GenerateExchangeKey()
		if err != nil {
			return nil, err
		}
		scalar, err := exchange.DeriveScalar(key, testDomain, identity)
		if err != nil {
			return nil, err
		}
		S := exchange.ReleaseKey(scalar)
		instance, err := keys.Generate()
		if err != nil {
			return nil, err
		}
		env, err := protocol.Seal(instance, protocol.ContextReleaseKey, protocol.ReleaseKey{
			V: 1, Type: protocol.TypeReleaseKey, TrustDomain: testDomain, Identity: identity,
			Authority: "kid", Key: exchange.EncodePoint(S),
		})
		if err != nil {
			return nil, err
		}
		targets = append(targets, secret.Target{Authority: keys.Fingerprint(&instance.PublicKey), ReleaseKey: env, Key: S})
	}
	s, _, err := secret.Seal(plain, name, testDomain, identity, threshold, targets, recovery)
	if err != nil {
		return nil, err
	}
	partA, err := s.Marshal()
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256(partA)
	d.mu.Lock()
	d.sealed[key], d.held[key] = bytes.Clone(plain), true
	d.mu.Unlock()
	return partA, nil
}

// partA is a part A as "secret create" would have left it, with a recovery
// copy for the recipients, if any.
func (d *fakeDaemon) partA(t *testing.T, name string, threshold int, plain string, recipients ...string) []byte {
	t.Helper()
	recovery, err := secret.Recovery([]byte(plain), recipients)
	if err != nil {
		t.Fatal(err)
	}
	partA, err := d.seal(name, threshold, []byte(plain), recovery)
	if err != nil {
		t.Fatal(err)
	}
	return partA
}

func (d *fakeDaemon) holds(partA []byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.held[sha256.Sum256(partA)]
}

// asked reports whether the daemon got a request for op, and forgets the
// requests so far.
func (d *fakeDaemon) asked(op string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	asked := slices.Contains(d.requests, op)
	d.requests = nil
	return asked
}

// outcome is what a command wrote and its exit code.
type outcome struct {
	stdout, stderr string
	code           int
}

// run runs "ergosumd args" against the fake daemon, with stdin and the
// environment variables env; no editor is set unless env names one.
func (d *fakeDaemon) run(t *testing.T, stdin string, env []string, args ...string) outcome {
	t.Helper()
	cmd := clitest.Command(t, append(args, "-socket", d.socket)...)
	cmd.Env = append(append(cmd.Env, "VISUAL=", "EDITOR="), env...)
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatal(err)
	}
	return outcome{stdout.String(), stderr.String(), cmd.ProcessState.ExitCode()}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// alone fails t unless path is the only entry of its directory: no
// temporary file is left next to part A.
func alone(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != filepath.Base(path) {
			t.Errorf("%s was left next to part A", e.Name())
		}
	}
}

// TestSecretReplace: replace puts a new part A with the same name and
// threshold in place of the file, with the file's mode; get then returns
// the new secret, with the newline rule of create; and the daemon no
// longer holds the old part A.
func TestSecretReplace(t *testing.T) {
	for _, tc := range []struct {
		name, stdin, want string
		args              []string
	}{
		{"newline removed", "new\n", "new", nil},
		{"CRLF removed", "new\r\n", "new", nil},
		{"without a newline", "new", "new", nil},
		{"only one newline removed", "new\n\n", "new\n", nil},
		{"raw", "new\n", "new\n", []string{"-raw"}},
		{"file only", "new\n", "new", []string{"-file"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newFakeDaemon(t)
			path := filepath.Join(t.TempDir(), "restic")
			old := d.partA(t, "restic", 2, "old")
			writeFile(t, path, old)
			if err := os.Chmod(path, 0o640); err != nil {
				t.Fatal(err)
			}
			args := []string{"secret", "replace", "restic", "-file", path}
			if slices.Equal(tc.args, []string{"-file"}) {
				args = []string{"secret", "replace", "-file", path}
			} else {
				args = append(args, tc.args...)
			}
			r := d.run(t, tc.stdin, nil, args...)
			if r.code != 0 || r.stdout != "" || !strings.Contains(r.stderr, "part A of restic replaced in "+path+": threshold 2 of 3") {
				t.Fatalf("replace: code %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
			}
			now := readFile(t, path)
			s, err := secret.Parse(now)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(now, old) || s.Name != "restic" || s.Threshold != 2 || len(s.Pins) < s.Threshold || s.Recovery != "" {
				t.Fatalf("part A after replace: name %s, threshold %d, %d pins, recovery %t", s.Name, s.Threshold, len(s.Pins), s.Recovery != "")
			}
			if fi, err := os.Stat(path); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o640) {
				t.Fatalf("part A after replace: %v, mode %v", err, fi.Mode())
			}
			alone(t, path)
			if d.holds(old) || !d.holds(now) {
				t.Fatalf("the daemon holds the old part A: %t, the new one: %t", d.holds(old), d.holds(now))
			}
			if g := d.run(t, "", nil, "secret", "get", "-file", path); g.code != 0 || g.stdout != tc.want {
				t.Fatalf("get after replace: %q, code %d, %s", g.stdout, g.code, g.stderr)
			}
		})
	}
}

// TestSecretReplaceRefused: what replace refuses, and what fails on the
// way, leaves part A byte for byte as it was and nothing next to it.
func TestSecretReplaceRefused(t *testing.T) {
	for _, tc := range []struct {
		name, stdin string
		args        []string
		prepare     func(d *fakeDaemon)
		create      bool // the daemon was asked to seal
		want        string
	}{
		{name: "empty input", want: "the new secret is empty"},
		{name: "only a newline", stdin: "\n", want: "the new secret is empty"},
		{name: "too long", stdin: strings.Repeat("x", secret.MaxSecret+1), want: "longer than"},
		{name: "another name", stdin: "new", args: []string{"secret", "replace", "borg"}, want: "holds the secret restic, not borg"},
		{name: "unknown recipient", stdin: "new", args: []string{"secret", "replace", "restic", "-recovery", "age1nope"}, want: "recovery recipient"},
		{
			name: "the daemon cannot seal", stdin: "new", create: true, want: "1 instances can be pinned",
			prepare: func(d *fakeDaemon) { d.createErr = "1 instances can be pinned, the threshold is 2" },
		},
		{
			name: "part A of another machine", stdin: "new", create: true, want: "is sealed for " + testIdentity,
			prepare: func(d *fakeDaemon) { d.identity = "host2.example.com" },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newFakeDaemon(t)
			path := filepath.Join(t.TempDir(), "restic")
			old := d.partA(t, "restic", 2, "old")
			writeFile(t, path, old)
			if tc.prepare != nil {
				d.mu.Lock()
				tc.prepare(d)
				d.mu.Unlock()
			}
			args := tc.args
			if args == nil {
				args = []string{"secret", "replace", "restic"}
			}
			r := d.run(t, tc.stdin, nil, append(args, "-file", path)...)
			if r.code != 1 || r.stdout != "" || !strings.Contains(r.stderr, tc.want) || !strings.Contains(r.stderr, "part A is as it was") {
				t.Fatalf("code %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
			}
			if !bytes.Equal(readFile(t, path), old) {
				t.Fatal("part A changed")
			}
			alone(t, path)
			if asked := d.asked("create"); asked != tc.create {
				t.Fatalf("the daemon was asked to seal: %t", asked)
			}
			d.mu.Lock()
			held := len(d.held)
			d.mu.Unlock()
			if !d.holds(old) || held != 1 {
				t.Fatalf("the daemon holds %d secrets, the old one: %t", held, d.holds(old))
			}
		})
	}
}

// TestSecretReplaceMissing: replace needs an existing part A and creates
// none.
func TestSecretReplaceMissing(t *testing.T) {
	d := newFakeDaemon(t)
	path := filepath.Join(t.TempDir(), "restic")
	r := d.run(t, "new", nil, "secret", "replace", "restic", "-file", path)
	if r.code != 1 || d.asked("create") {
		t.Fatalf("code %d, stderr %q", r.code, r.stderr)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("part A after a refused replace: %v", err)
	}
	writeFile(t, path, []byte("{}"))
	if r := d.run(t, "new", nil, "secret", "replace", "-file", path); r.code != 1 || d.asked("create") || string(readFile(t, path)) != "{}" {
		t.Fatalf("a file that is no part A: code %d, stderr %q", r.code, r.stderr)
	}
}

// TestSecretReplaceRecovery: a part A with a recovery copy is replaced
// only with -recovery, and the copy in the new part A opens the new secret
// with the recipient's key; -recovery adds a copy to a part A without one.
func TestSecretReplaceRecovery(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recipient := identity.Recipient().String()
	recovered := func(partA []byte) string {
		t.Helper()
		s, err := secret.Parse(partA)
		if err != nil {
			t.Fatal(err)
		}
		if s.Recovery == "" {
			t.Fatal("part A has no recovery copy")
		}
		r, err := age.Decrypt(armor.NewReader(strings.NewReader(s.Recovery)), identity)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		return string(plain)
	}

	d := newFakeDaemon(t)
	path := filepath.Join(t.TempDir(), "restic")
	old := d.partA(t, "restic", 2, "old", recipient)
	writeFile(t, path, old)
	if got := recovered(old); got != "old" {
		t.Fatalf("the recovery copy opens %q", got)
	}

	r := d.run(t, "new\n", nil, "secret", "replace", "restic", "-file", path)
	if r.code != 1 || !strings.Contains(r.stderr, "-recovery") || !strings.Contains(r.stderr, "part A is as it was") {
		t.Fatalf("without -recovery: code %d, stderr %q", r.code, r.stderr)
	}
	if !bytes.Equal(readFile(t, path), old) || d.asked("create") {
		t.Fatal("replace without -recovery changed part A or asked the daemon to seal")
	}

	r = d.run(t, "new\n", nil, "secret", "replace", "restic", "-file", path, "-recovery", recipient)
	if r.code != 0 || !strings.Contains(r.stderr, "with a recovery copy") {
		t.Fatalf("with -recovery: code %d, stderr %q", r.code, r.stderr)
	}
	if got := recovered(readFile(t, path)); got != "new" {
		t.Fatalf("the recovery copy after replace opens %q", got)
	}

	// A part A without a copy gains one.
	path = filepath.Join(t.TempDir(), "borg")
	writeFile(t, path, d.partA(t, "borg", 1, "old"))
	if r := d.run(t, "new\n", nil, "secret", "replace", "borg", "-file", path); r.code != 0 || !strings.Contains(r.stderr, "without a recovery copy") {
		t.Fatalf("no copy before, none asked for: code %d, stderr %q", r.code, r.stderr)
	}
	if r := d.run(t, "newer\n", nil, "secret", "replace", "borg", "-file", path, "-recovery", recipient); r.code != 0 {
		t.Fatalf("adding a copy: code %d, stderr %q", r.code, r.stderr)
	}
	if got := recovered(readFile(t, path)); got != "newer" {
		t.Fatalf("the added recovery copy opens %q", got)
	}
}

// TestSecretReplaceResplit: a get may put a re-split part A in place of
// the file while replace is at work. replace overwrites it, and the daemon
// forgets both the part A that replace read and the re-split one.
func TestSecretReplaceResplit(t *testing.T) {
	d := newFakeDaemon(t)
	path := filepath.Join(t.TempDir(), "restic")
	old := d.partA(t, "restic", 2, "old")
	resplit := d.partA(t, "restic", 2, "old")
	writeFile(t, path, old)
	d.mu.Lock()
	d.onCreate = func() { writeFile(t, path, resplit) }
	d.mu.Unlock()
	if r := d.run(t, "new\n", nil, "secret", "replace", "restic", "-file", path); r.code != 0 {
		t.Fatalf("code %d, stderr %q", r.code, r.stderr)
	}
	now := readFile(t, path)
	if bytes.Equal(now, old) || bytes.Equal(now, resplit) || d.holds(old) || d.holds(resplit) || !d.holds(now) {
		t.Fatalf("the daemon holds the old part A: %t, the re-split one: %t, the new one: %t", d.holds(old), d.holds(resplit), d.holds(now))
	}
	if g := d.run(t, "", nil, "secret", "get", "-file", path); g.stdout != "new" {
		t.Fatalf("get after replace: %q, %s", g.stdout, g.stderr)
	}
}
