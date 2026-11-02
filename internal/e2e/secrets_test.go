package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ergosum/internal/authority"
	"github.com/DunkelCloud/ergosum/internal/daemon"
	jt "github.com/DunkelCloud/ergosum/internal/journal/journaltest"
	"github.com/DunkelCloud/ergosum/internal/secret"
)

// newSecretCluster prepares n instances with exchange keys on one simulated
// network, named authority-a, authority-b, ...
func newSecretCluster(t *testing.T, n int) []*env {
	t.Helper()
	sim := newSimNet()
	admins := jt.NewAdmins(t, "alice", "bob", "carol")
	out := make([]*env, n)
	for i := range out {
		out[i] = prepareEnv(t, envOptions{instance: fmt.Sprintf("authority-%c", 'a'+i), net: sim, admins: admins, exchangeKey: newExchangeKey(t)})
	}
	return out
}

// restarted is the machine's daemon after a restart: same key and list,
// nothing in memory.
func restarted(m *machine, envs []*env) *machine {
	m.d.Close()
	return envs[0].machine(host1, machineOptions{stateDir: m.stateDir, targets: []string{at(host1Tailnet)}, authorities: envs})
}

func exchanges(envs ...*env) []float64 {
	out := make([]float64, len(envs))
	for i, e := range envs {
		if e.running {
			out[i] = e.auth.ExchangeCount(authority.ResultIssued)
		}
	}
	return out
}

// TestSecret: a secret sealed with a threshold of 2 of 3 opens after a
// restart at the first two listed instances, from memory while the daemon
// holds a token, with one instance down, and not with two down or for
// another machine.
func TestSecret(t *testing.T) {
	envs := newSecretCluster(t, 3)
	a, b, c := envs[0], envs[1], envs[2]
	for _, e := range envs {
		e.start()
	}
	m := a.machine(host1, machineOptions{targets: []string{at(host1Tailnet)}, authorities: envs})
	for _, e := range envs {
		e.bind(host1, m.d.Fingerprint(), 1, tailnetCheck(host1Tailnet))
	}
	ctx := context.Background()
	plain := []byte("correct horse battery staple")
	partA, err := m.d.CreateSecret(ctx, "restic", 2, plain, "")
	if err != nil {
		t.Fatal(err)
	}
	s, err := secret.Parse(partA)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Pins) != 3 || s.Threshold != 2 || s.Identity != host1 || s.TrustDomain != trustDomain {
		t.Fatalf("part A: %d pins, threshold %d, %s in %s", len(s.Pins), s.Threshold, s.Identity, s.TrustDomain)
	}
	if bytes.Contains(partA, plain) {
		t.Fatal("part A contains the secret")
	}

	m = restarted(m, envs)
	got, replace, err := m.d.GetSecret(ctx, partA)
	if err != nil || !bytes.Equal(got, plain) || replace != nil {
		t.Fatalf("get after a restart: %q, %v", got, err)
	}
	if n := exchanges(a, b, c); n[0] != 2 || n[1] != 2 || n[2] != 1 {
		t.Fatalf("exchanges per instance %v: create at all three, the get at the first two", n)
	}

	// With a token, from memory.
	if _, _, err := m.d.Obtain(ctx); err != nil {
		t.Fatal(err)
	}
	before := exchanges(a, b, c)
	if got, _, err := m.d.GetSecret(ctx, partA); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("get from memory: %v", err)
	}
	if after := exchanges(a, b, c); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("a get with a token asked the instances: %v -> %v", before, after)
	}

	a.stop()
	m = restarted(m, envs)
	if got, _, err := m.d.GetSecret(ctx, partA); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("one instance down: %v", err)
	}
	b.stop()
	m = restarted(m, envs)
	if _, _, err := m.d.GetSecret(ctx, partA); err == nil || !strings.Contains(err.Error(), "1 of the 2 shares") {
		t.Fatalf("two instances down: %v", err)
	}

	other := c.machine(host2, machineOptions{targets: []string{at(host2Tailnet)}, authorities: envs})
	c.bind(host2, other.d.Fingerprint(), 1, tailnetCheck(host2Tailnet))
	if _, _, err := other.d.GetSecret(ctx, partA); err == nil || !strings.Contains(err.Error(), "sealed for "+host1) {
		t.Fatalf("another machine: %v", err)
	}
}

// TestSecretCreateRefused: fewer reachable instances than the threshold
// write no part A, and the error names the one that did not answer.
func TestSecretCreateRefused(t *testing.T) {
	envs := newSecretCluster(t, 2)
	for _, e := range envs {
		e.start()
	}
	m := envs[0].machine(host1, machineOptions{targets: []string{at(host1Tailnet)}, authorities: envs})
	envs[0].bind(host1, m.d.Fingerprint(), 1, tailnetCheck(host1Tailnet))
	// envs[1] has no binding for host1.
	_, err := m.d.CreateSecret(context.Background(), "restic", 2, []byte("x"), "")
	if err == nil || !strings.Contains(err.Error(), "1 instances can be pinned") || !strings.Contains(err.Error(), envs[1].fingerprint()) {
		t.Fatalf("got %v", err)
	}
	if _, err := m.d.CreateSecret(context.Background(), "Bad_Name", 1, []byte("x"), ""); err == nil {
		t.Fatal("a bad name was taken")
	}
}

// TestSecretRevoked: once the pins deny the refresh after a token round,
// the daemon no longer answers from memory, and the secret does not open.
func TestSecretRevoked(t *testing.T) {
	envs := newSecretCluster(t, 2)
	for _, e := range envs {
		e.start()
	}
	m := envs[0].machine(host1, machineOptions{targets: []string{at(host1Tailnet)}, authorities: envs})
	for _, e := range envs {
		e.bind(host1, m.d.Fingerprint(), 1, tailnetCheck(host1Tailnet))
	}
	ctx := context.Background()
	partA, err := m.d.CreateSecret(ctx, "restic", 1, []byte("x"), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.d.Obtain(ctx); err != nil {
		t.Fatal(err)
	}
	m.d.RefreshSecrets(ctx)
	if _, _, err := m.d.GetSecret(ctx, partA); err != nil {
		t.Fatal(err)
	}
	for _, e := range envs {
		e.revoke(host1, 2)
	}
	m.d.RefreshSecrets(ctx)
	if _, _, err := m.d.GetSecret(ctx, partA); err == nil {
		t.Fatal("a revoked machine got its secret")
	}
}

// TestSecretReshare: a new instance in the list is pinned once the
// threshold of pinned instances serves that list; the next get hands the
// new part A over, which then opens with the new instance. A list that
// fewer pinned instances serve changes nothing.
func TestSecretReshare(t *testing.T) {
	envs := newSecretCluster(t, 3)
	a, b, c := envs[0], envs[1], envs[2]
	dir := t.TempDir()
	files := make([]string, 3)
	for i, e := range envs {
		files[i] = filepath.Join(dir, fmt.Sprintf("%d.yaml", i))
		writeList(t, files[i], 1, listed{e: a}, listed{e: b})
		e.cfg.AuthoritiesFile = files[i]
	}
	// c is not in list 1, and an instance starts only with a list that
	// names it.
	writeList(t, files[2], 1, listed{e: a}, listed{e: b}, listed{e: c})
	for _, e := range envs {
		e.start()
	}
	m := a.machine(host1, machineOptions{targets: []string{at(host1Tailnet)}, authorities: []*env{a}})
	for _, e := range envs {
		e.bind(host1, m.d.Fingerprint(), 1, tailnetCheck(host1Tailnet))
	}
	ctx := context.Background()
	if _, _, err := m.d.Obtain(ctx); err != nil {
		t.Fatal(err)
	}
	partA, err := m.d.CreateSecret(ctx, "restic", 2, []byte("x"), "")
	if err != nil {
		t.Fatal(err)
	}
	m.d.ReshareSecrets(ctx)
	if _, replace, err := m.d.GetSecret(ctx, partA); err != nil || replace != nil {
		t.Fatalf("re-split without a new list: %v", err)
	}

	// c joins: list 2 on all three.
	for _, f := range files {
		writeList(t, f, 2, listed{e: a}, listed{e: b}, listed{e: c})
	}
	if _, _, err := m.d.Obtain(ctx); err != nil {
		t.Fatal(err)
	}
	m.d.ReshareSecrets(ctx)
	_, replace, err := m.d.GetSecret(ctx, partA)
	if err != nil || replace == nil {
		t.Fatalf("no re-split for list 2: %v", err)
	}
	old, _ := secret.Parse(partA)
	n, err := secret.Parse(replace)
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Pins) != 3 || n.Threshold != 2 || n.Ciphertext != old.Ciphertext || n.Pins[2].Authority != c.fingerprint() {
		t.Fatalf("re-split part A: %d pins, threshold %d", len(n.Pins), n.Threshold)
	}
	// The caller wrote it; the old part A is done with.
	if _, again, err := m.d.GetSecret(ctx, replace); err != nil || again != nil {
		t.Fatalf("get with the new part A: %v", err)
	}

	// The new part A opens without a: at b and c.
	a.stop()
	m = restarted(m, envs)
	if got, _, err := m.d.GetSecret(ctx, replace); err != nil || string(got) != "x" {
		t.Fatalf("new part A without a: %v", err)
	}

	// Only c serves list 3, which drops a: one pinned instance is fewer
	// than the threshold, so nothing changes.
	b.stop()
	writeList(t, files[2], 3, listed{e: b}, listed{e: c})
	if _, _, err := m.d.Obtain(ctx); err != nil {
		t.Fatal(err)
	}
	m.d.ReshareSecrets(ctx)
	if _, again, err := m.d.GetSecret(ctx, replace); err != nil || again != nil {
		t.Fatalf("re-split on a list one pinned instance serves: %v", err)
	}
}

// TestSecretSocket: the CLI's way in, through the running daemon's socket.
func TestSecretSocket(t *testing.T) {
	envs := newSecretCluster(t, 1)
	e := envs[0]
	e.start()
	m := e.machine(host1, machineOptions{targets: []string{at(host1Tailnet)}})
	e.bind(host1, m.d.Fingerprint(), 1, tailnetCheck(host1Tailnet))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.d.Run(ctx) }()
	defer func() {
		cancel()
		<-done
	}()
	token := filepath.Join(m.tokenDir, "token")
	socket := filepath.Join(m.tokenDir, "secret.sock")
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(token); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no token")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(socket)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("socket: %v, mode %v", err, fi.Mode())
		}
	}
	created, err := daemon.CallSecret(ctx, socket, daemon.SecretRequest{Op: "create", Name: "restic", Threshold: 1, Secret: []byte("pw")})
	if err != nil {
		t.Fatal(err)
	}
	got, err := daemon.CallSecret(ctx, socket, daemon.SecretRequest{Op: "get", PartA: created.PartA})
	if err != nil || string(got.Secret) != "pw" {
		t.Fatalf("get: %v", err)
	}
	if _, err := daemon.CallSecret(ctx, socket, daemon.SecretRequest{Op: "get", PartA: []byte("{}")}); err == nil {
		t.Fatal("junk opened")
	}
}
