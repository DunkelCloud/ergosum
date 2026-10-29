package e2e

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/DunkelCloud/ergosum/internal/admin"
	"github.com/DunkelCloud/ergosum/internal/authority"
	"github.com/DunkelCloud/ergosum/internal/journal"
	"github.com/DunkelCloud/ergosum/internal/sshsig"
)

func adminSigner(s ssh.Signer) admin.Signer {
	return func(_ context.Context, canonical []byte) ([]byte, error) {
		return sshsig.Sign(s, journal.Namespace, canonical)
	}
}

// adminTool is one administrator's tool, against the given authorities.
type adminTool struct {
	*admin.Tool
	out bytes.Buffer
}

func newAdminTool(t *testing.T, c *cluster, name string, authorities ...admin.Authority) *adminTool {
	t.Helper()
	client, err := admin.NewClient(admin.Config{Authorities: authorities})
	if err != nil {
		t.Fatal(err)
	}
	s := c.admins.Signers[name]
	at := &adminTool{}
	at.Tool = &admin.Tool{Client: client, TrustDomain: trustDomain, Out: &at.out,
		Key: &admin.SignKey{Public: s.PublicKey(), Sign: adminSigner(s)}}
	return at
}

// said returns and forgets what the tool printed.
func (a *adminTool) said() string {
	s := a.out.String()
	a.out.Reset()
	return s
}

func requireSaid(t *testing.T, said string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(said, w) {
			t.Fatalf("output lacks %q:\n%s", w, said)
		}
	}
}

func writeText(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readText(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestAdminRoutineCases walks the routine cases with the administrator tool
// and approvals 2: a machine's request bound by two administrators, a look
// at the binding, a key change that the daemon carries out itself, a
// changed place, a file overtaken by another change, a text changed after
// a signature, a signature over CRLF text, a revocation and a binding again.
func TestAdminRoutineCases(t *testing.T) {
	c := newCluster(t, []string{instA, instB}, clusterOptions{threshold: 2})
	a, b := c.envs[instA], c.envs[instB]
	ctx := context.Background()
	// The first authority is down; the tool moves on to the next.
	down := admin.Authority{URL: "https://" + freePort(t), Key: a.fingerprint()}
	authA := admin.Authority{URL: a.url, Key: a.fingerprint()}
	alice := newAdminTool(t, c, "alice", down, authA)
	bob := newAdminTool(t, c, "bob", authA)
	carol := newAdminTool(t, c, "carol", authA)
	dir := t.TempDir()
	m := a.machine(host1, machineOptions{targets: []string{at(host1Tailnet), at(host1IP)}, authorities: []*env{a, b}, tailnet: host1Tailnet})

	// Enrollment: the machine writes the request, two administrators sign.
	req, err := m.d.Request(ctx, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	requireSaid(t, string(req), "identity "+host1, "key "+m.d.Fingerprint(), "check tailnet "+host1Tailnet, "check ip 192.0.2.250")
	enroll := filepath.Join(dir, "host1.txt")
	writeText(t, enroll, "identity "+host1, "key "+m.d.Fingerprint(), "check tailnet "+host1Tailnet)
	if err := alice.Bind(ctx, enroll); err != nil {
		t.Fatal(err)
	}
	requireSaid(t, alice.said(), "for the first time, at epoch 1", "1 of 2 approvals", "ergosum bind "+enroll)
	if a.binding(host1) != nil {
		t.Fatal("recorded with one approval of two")
	}
	if err := alice.Bind(ctx, enroll); err != nil {
		t.Fatal(err)
	}
	requireSaid(t, alice.said(), "have signed already")
	if err := bob.Bind(ctx, enroll); err != nil {
		t.Fatal(err)
	}
	requireSaid(t, bob.said(), "Approvals for binding.set: 1 of 2 (alice)", "Recorded by", "Start ergosumd on "+host1)
	requireSaid(t, readText(t, enroll), "kind binding.set", "epoch 1", "# signed by alice", "# signed by bob", "# recorded by")
	eventually(t, "binding at B", func() bool { return b.binding(host1) != nil })
	if _, _, err := m.d.Obtain(ctx); err != nil {
		t.Fatal(err)
	}
	if err := carol.Bind(ctx, enroll); err != nil {
		t.Fatal(err)
	}
	requireSaid(t, carol.said(), "recorded already at epoch 1")

	// A look at it: show and list.
	var shown, listed bytes.Buffer
	if err := carol.Show(ctx, host1, &shown); err != nil {
		t.Fatal(err)
	}
	requireSaid(t, shown.String(), "bound at epoch 1, approved by alice, bob", "key "+m.d.Fingerprint(), "check tailnet "+host1Tailnet)
	if err := carol.List(ctx, &listed); err != nil {
		t.Fatal(err)
	}
	requireSaid(t, listed.String(), host1, "bound", m.d.Fingerprint())
	requireSaid(t, carol.said(), "1 identity at", "binding.set needs 2 of alice, bob, carol")

	// Key change: "ergosumd request -new-key" runs next to the service. The
	// service picks the next key up, keeps its current key until the new
	// binding is recorded, then switches by itself, without a refused
	// request.
	oldKey := m.d.Fingerprint()
	cli := a.machine(host1, machineOptions{stateDir: m.stateDir, authorities: []*env{a, b}, tailnet: host1Tailnet})
	req, err = cli.d.Request(ctx, true, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	newKey := cli.d.PendingFingerprint()
	if newKey == "" || newKey == oldKey || !strings.Contains(string(req), "key "+newKey) {
		t.Fatalf("request for a new key:\n%s", req)
	}
	token := filepath.Join(m.tokenDir, "token")
	runOnce := func(what string, done func() bool) {
		t.Helper()
		_ = os.Remove(token)
		runCtx, stop := context.WithCancel(ctx)
		exited := make(chan error, 1)
		go func() { exited <- m.d.Run(runCtx) }()
		eventually(t, what, func() bool { _, err := os.Stat(token); return err == nil && done() })
		stop()
		<-exited
	}
	runOnce("token with the old key while the next one waits", func() bool {
		return m.d.Fingerprint() == oldKey && m.d.PendingFingerprint() == newKey
	})
	rekey := filepath.Join(dir, "host1-rekey.txt")
	writeText(t, rekey, "identity "+host1, "key "+newKey, "check tailnet "+host1Tailnet, "check ip "+host1IP)
	if err := carol.Bind(ctx, rekey); err != nil {
		t.Fatal(err)
	}
	requireSaid(t, carol.said(), "epoch 1 -> 2", "key "+oldKey+" -> "+newKey, "+ check ip "+host1IP, "  check tailnet "+host1Tailnet)
	if err := bob.Bind(ctx, rekey); err != nil {
		t.Fatal(err)
	}
	requireSaid(t, bob.said(), "switches to the new key itself")
	eventually(t, "new key at B", func() bool { return b.binding(host1).Key == newKey })
	runOnce("token with the new key", func() bool { return m.d.Fingerprint() == newKey && m.d.PendingFingerprint() == "" })
	if _, err := os.Stat(filepath.Join(m.stateDir, "identity.key.new")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the next key is still waiting: %v", err)
	}
	for _, e := range []*env{a, b} {
		requireCount(t, e.auth, authority.ResultForeignKey, 0)
	}

	// Another place: from "ergosum show", edited, at the next epoch. A file
	// made at the same time for another change is overtaken.
	var cur bytes.Buffer
	if err := bob.Show(ctx, host1, &cur); err != nil {
		t.Fatal(err)
	}
	move := filepath.Join(dir, "host1-move.txt")
	other := filepath.Join(dir, "host1-other.txt")
	writeText(t, move, strings.Replace(cur.String(), "check ip "+host1IP+"\n", "", 1))
	writeText(t, other, cur.String())
	if err := carol.Bind(ctx, other); err != nil {
		t.Fatal(err)
	}
	carol.said()
	for _, tool := range []*adminTool{alice, bob} {
		if err := tool.Bind(ctx, move); err != nil {
			t.Fatal(err)
		}
	}
	requireSaid(t, bob.said(), "- check ip "+host1IP, "The new checks apply")
	if err := alice.Bind(ctx, other); !errors.Is(err, admin.ErrEpochMoved) || !strings.Contains(err.Error(), "ergosum show "+host1) {
		t.Fatalf("overtaken file: %v", err)
	}

	// A text changed after a signature, and a signature over CRLF text.
	edited := filepath.Join(dir, "host1-edited.txt")
	cur.Reset()
	if err := bob.Show(ctx, host1, &cur); err != nil {
		t.Fatal(err)
	}
	writeText(t, edited, cur.String())
	if err := alice.Bind(ctx, edited); err != nil {
		t.Fatal(err)
	}
	writeText(t, edited, strings.Replace(readText(t, edited), "check tailnet "+host1Tailnet, "check tailnet "+host2Tailnet, 1))
	if err := bob.Bind(ctx, edited); err == nil || !strings.Contains(err.Error(), "changed after it was signed") {
		t.Fatalf("changed text: %v", err)
	}
	crlf := filepath.Join(dir, "host1-crlf.txt")
	if err := bob.Text(ctx, enrollAgain(t, cur.String(), crlf), filepath.Join(dir, "event.txt")); err != nil {
		t.Fatal(err)
	}
	text := readText(t, filepath.Join(dir, "event.txt"))
	sig, err := sshsig.Sign(c.admins.Signers["bob"], journal.Namespace, []byte(strings.ReplaceAll(text, "\n", "\r\n")))
	if err != nil {
		t.Fatal(err)
	}
	writeText(t, crlf, readText(t, crlf)+string(sig))
	if err := bob.Bind(ctx, crlf); err == nil || !strings.Contains(err.Error(), "CRLF") {
		t.Fatalf("CRLF signature: %v", err)
	}

	// Revocation: the tool writes the file; the second signature records it.
	revoke := filepath.Join(dir, "host1.revoke.txt")
	if err := alice.Revoke(ctx, host1, revoke); err != nil {
		t.Fatal(err)
	}
	requireSaid(t, alice.said(), "Revoke "+host1+" at epoch 4", "It ends the binding of epoch 3", "1 of 2 approvals")
	if err := alice.Revoke(ctx, host1, revoke); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("second revocation file: %v", err)
	}
	if err := bob.Bind(ctx, revoke); err != nil {
		t.Fatal(err)
	}
	requireSaid(t, bob.said(), "alias_name=spiffe://"+trustDomain+"/host/"+host1, "disabled=true")
	eventually(t, "revocation at B", func() bool { return !b.binding(host1).Active() })
	if _, _, err := m.d.Obtain(ctx); err == nil {
		t.Fatal("token after the revocation")
	}

	// Binding again under the old name, at the epoch after the revocation.
	again := filepath.Join(dir, "host1-again.txt")
	writeText(t, again, "identity "+host1, "key "+m.d.Fingerprint(), "check tailnet "+host1Tailnet)
	if err := carol.Bind(ctx, again); err != nil {
		t.Fatal(err)
	}
	requireSaid(t, carol.said(), "revoked in epoch 4, this binding takes epoch 5")
	if err := alice.Bind(ctx, again); err != nil {
		t.Fatal(err)
	}
	eventually(t, "binding again at B", func() bool { return b.binding(host1).Active() })
	if _, _, err := m.d.Obtain(ctx); err != nil {
		t.Fatal(err)
	}
}

// enrollAgain writes a file from the shown binding.
func enrollAgain(t *testing.T, shown, path string) string {
	t.Helper()
	writeText(t, path, shown)
	return path
}
