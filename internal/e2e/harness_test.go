// Package e2e runs authority and daemons in one process. A simulated
// network maps callback targets ("host:port" as the authority dials them) to
// loopback listeners, so a machine's place is just the set of targets that
// reach its listener. A clone elsewhere is a daemon with the same key that
// is reachable under other targets, or under none.
package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/DunkelCloud/ergosum/internal/authority"
	"github.com/DunkelCloud/ergosum/internal/daemon"
	"github.com/DunkelCloud/ergosum/internal/journal"
	jt "github.com/DunkelCloud/ergosum/internal/journal/journaltest"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/protocol"
	"github.com/DunkelCloud/ergosum/internal/tlspin"
)

const trustDomain = "example.com"

// simNet is the simulated network between authority and machines.
type simNet struct {
	mu      sync.Mutex
	routes  map[string]string // target "host:port" -> loopback address
	gate    chan struct{}     // when set, dials wait for it
	dialed  chan string
	aborted chan string // receives dials canceled while waiting at the gate
	dials   []string
}

func newSimNet() *simNet { return &simNet{routes: map[string]string{}} }

func (n *simNet) Dial(ctx context.Context, route authority.Route, address string) (net.Conn, error) {
	n.mu.Lock()
	gate, dialed, aborted := n.gate, n.dialed, n.aborted
	n.dials = append(n.dials, route.Check+" "+address)
	n.mu.Unlock()
	if dialed != nil {
		select {
		case dialed <- address:
		default:
		}
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			if aborted != nil {
				select {
				case aborted <- address:
				default:
				}
			}
			return nil, ctx.Err()
		}
	}
	n.mu.Lock()
	real, ok := n.routes[address]
	n.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("simnet: %s unreachable", address)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", real)
}

// at returns a Listen function for a daemon reachable under the targets.
func (n *simNet) at(targets ...string) func(string, string) (net.Listener, error) {
	return func(string, string) (net.Listener, error) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		n.mu.Lock()
		for _, t := range targets {
			n.routes[t] = ln.Addr().String()
		}
		n.mu.Unlock()
		return ln, nil
	}
}

// env is one authority instance with its admins.
type env struct {
	t      *testing.T
	net    *simNet
	admins *jt.Admins
	auth   *authority.Authority
	key    *ecdsa.PrivateKey
	url    string
	socket string
	cfg    authority.Config
	opts   envOptions
	cancel context.CancelFunc
	// done receives what Run returns, once; whoever takes it calls exited.
	done chan error
	// running is set between start and stop.
	running bool
}

type envOptions struct {
	threshold  int
	passphrase string // non-empty: encrypted signing key, starts sealed
	networks   []string
	ttl        time.Duration
	instance   string
	net        *simNet
	admins     *jt.Admins

	// Replication: the instance key (generated if nil), the peers, the
	// replication listener ("" for none), the links that carry it, and
	// compaction.
	key        *ecdsa.PrivateKey
	peers      []authority.PeerConfig
	replListen string
	links      *links
	compaction authority.CompactionConfig
}

func quietLogger(t *testing.T) *slog.Logger {
	if testing.Verbose() {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func freePort(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func newEnv(t *testing.T, o envOptions) *env {
	t.Helper()
	e := prepareEnv(t, o)
	e.start()
	return e
}

// prepareEnv writes the key and builds the configuration of an instance
// without starting it.
func prepareEnv(t *testing.T, o envOptions) *env {
	t.Helper()
	if o.threshold == 0 {
		o.threshold = 1
	}
	if o.ttl == 0 {
		o.ttl = 30 * time.Minute
	}
	if o.instance == "" {
		o.instance = "authority-a"
	}
	if o.net == nil {
		o.net = newSimNet()
	}
	if o.admins == nil {
		o.admins = jt.NewAdmins(t, "alice", "bob", "carol")
	}
	dir := t.TempDir()
	key := o.key
	if key == nil {
		var err error
		if key, err = keys.Generate(); err != nil {
			t.Fatal(err)
		}
	}
	var pemBytes []byte
	var err error
	if o.passphrase != "" {
		pemBytes, err = keys.EncryptPEM(key, []byte(o.passphrase))
	} else {
		pemBytes, err = keys.MarshalPrivatePEM(key)
	}
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "signing.key")
	if err := os.WriteFile(keyPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	apiAddr := freePort(t)
	cfg := authority.Config{
		Instance:      o.instance,
		TrustDomain:   trustDomain,
		Issuer:        "https://ergosum.example.com",
		TokenTTL:      o.ttl,
		SigningKey:    keyPath,
		Journal:       filepath.Join(dir, "journal.db"),
		Listen:        apiAddr,
		OpsListen:     "127.0.0.1:0",
		ControlSocket: filepath.Join(dir, "control.sock"),
		Registry:      o.admins.Registry(o.threshold),
		Replication:   authority.ReplicationConfig{Listen: o.replListen, Peers: o.peers},
		Compaction:    o.compaction,
	}
	cfg.Callbacks.Timeout = 3 * time.Second
	for _, n := range o.networks {
		cfg.Callbacks.Networks = append(cfg.Callbacks.Networks, authority.NetworkRoute{CIDR: n})
	}
	e := &env{t: t, net: o.net, admins: o.admins, key: key, url: "https://" + apiAddr, socket: cfg.ControlSocket, cfg: cfg, opts: o}
	t.Cleanup(e.stop)
	return e
}

// start runs the instance; stop ends it. A stopped instance can be started
// again with its journal.
func (e *env) start() {
	e.t.Helper()
	opts := authority.Options{Logger: quietLogger(e.t), Network: e.net,
		RetryMin: 10 * time.Millisecond, RetryMax: 100 * time.Millisecond, ReplicationIdle: 50 * time.Millisecond}
	if e.opts.links != nil {
		opts.DialPeer = e.opts.links.dialer(e.cfg.Instance)
	}
	a, err := authority.New(e.cfg, opts)
	if err != nil {
		e.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.auth, e.cancel, e.done, e.running = a, cancel, make(chan error, 1), true
	go func() { e.done <- a.Run(ctx) }()
	if e.opts.passphrase == "" {
		e.waitReady()
	} else {
		e.waitOps()
	}
}

// stop ends the instance and fails the test if it had stopped on its own
// with an error.
func (e *env) stop() {
	if !e.running {
		return
	}
	e.cancel()
	err := <-e.done
	e.exited()
	if err != nil {
		e.t.Errorf("authority stopped: %v", err)
	}
}

// exited cleans up after Run has returned, so that stop does not wait for
// it again.
func (e *env) exited() {
	e.running = false
	e.cancel()
	e.auth.Close()
}

func (e *env) waitReady() {
	e.t.Helper()
	select {
	case <-e.auth.Ready():
	case err := <-e.done:
		e.exited()
		e.t.Fatalf("authority stopped: %v", err)
	case <-time.After(10 * time.Second):
		e.t.Fatal("authority not ready")
	}
}

func (e *env) waitOps() {
	e.t.Helper()
	deadline := time.After(2 * time.Second)
	for e.auth.OpsAddr() == "" {
		select {
		case err := <-e.done:
			e.exited()
			e.t.Fatalf("authority stopped: %v", err)
		case <-deadline:
			e.t.Fatal("ops listener not up")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (e *env) fingerprint() string { return keys.Fingerprint(&e.key.PublicKey) }

// apiClient talks to the authority API with its key pinned.
func (e *env) apiClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: tlspin.ClientConfig(nil, tlspin.Fingerprints(e.fingerprint())),
	}}
}

// writeBinding posts a binding event to the write API.
func (e *env) writeBinding(ev *journal.BindingEvent) (int, string) {
	e.t.Helper()
	body, _ := json.Marshal(ev)
	resp, err := e.apiClient().Post(e.url+protocol.PathBindings, "application/json", bytes.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data)
}

// bind writes an approved binding.set through the API.
func (e *env) bind(identity, fingerprint string, epoch uint64, checks ...journal.Check) {
	e.t.Helper()
	ev := e.admins.Sign(e.t, jt.Set(trustDomain, identity, epoch, fingerprint, checks...), "alice", "bob", "carol")
	if status, body := e.writeBinding(ev); status != http.StatusCreated {
		e.t.Fatalf("binding %s: %d %s", identity, status, body)
	}
}

func (e *env) revoke(identity string, epoch uint64) {
	e.t.Helper()
	ev := e.admins.Sign(e.t, jt.Revoke(trustDomain, identity, epoch), "alice", "bob", "carol")
	if status, body := e.writeBinding(ev); status != http.StatusCreated {
		e.t.Fatalf("revoke %s: %d %s", identity, status, body)
	}
}

type machine struct {
	d        *daemon.Daemon
	stateDir string
	tokenDir string
}

type machineOptions struct {
	stateDir    string // reuse a state dir (restart, or a clone's copied key)
	addresses   []string
	targets     []string
	authorities []*env
	tailnet     string // the overlay name a request proposes
}

// machine creates a daemon for identity, reachable under the given targets.
func (e *env) machine(identity string, o machineOptions) *machine {
	e.t.Helper()
	if o.stateDir == "" {
		o.stateDir = e.t.TempDir()
	}
	if len(o.authorities) == 0 {
		o.authorities = []*env{e}
	}
	if o.addresses == nil {
		o.addresses = []string{"192.0.2.250"}
	}
	tokenDir := e.t.TempDir()
	cfg := daemon.Config{
		Identity:       identity,
		StateDir:       o.stateDir,
		TokenFile:      filepath.Join(tokenDir, "token"),
		TokenGroup:     "-",
		MetricsFile:    filepath.Join(tokenDir, "ergosum.prom"),
		CallbackListen: "127.0.0.1:0",
		Addresses:      o.addresses,
		RequestTimeout: 20 * time.Second,
	}
	for _, a := range o.authorities {
		cfg.Authorities = append(cfg.Authorities, daemon.AuthorityConfig{URL: a.url, Key: a.fingerprint()})
	}
	tailnet := func(context.Context) (string, error) {
		if o.tailnet == "" {
			return "", errors.New("not on a tailnet")
		}
		return o.tailnet, nil
	}
	d, err := daemon.New(cfg, daemon.Options{Logger: quietLogger(e.t), Listen: e.net.at(o.targets...), TailnetName: tailnet})
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(d.Close)
	return &machine{d: d, stateDir: o.stateDir, tokenDir: tokenDir}
}

// cloneState copies a machine's state directory, as a disk image would.
func cloneState(t *testing.T, from string) string {
	t.Helper()
	to := t.TempDir()
	entries, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range entries {
		data, err := os.ReadFile(filepath.Join(from, en.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(to, en.Name()), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return to
}

func denied(err error) bool {
	var re *daemon.RequestError
	return errors.As(err, &re) && re.Code == protocol.ErrDenied
}

func requireCount(t *testing.T, a *authority.Authority, result string, want float64) {
	t.Helper()
	if got := a.RequestCount(result); got != want {
		t.Fatalf("machine_identity_requests_total{result=%q} = %v, want %v", result, got, want)
	}
}

func journalCount(t *testing.T, a *authority.Authority, kind string) int {
	t.Helper()
	n, err := a.Store().Count(context.Background(), kind)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
