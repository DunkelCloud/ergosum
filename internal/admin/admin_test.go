package admin_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/DunkelCloud/ergosum/internal/admin"
	"github.com/DunkelCloud/ergosum/internal/journal"
	jt "github.com/DunkelCloud/ergosum/internal/journal/journaltest"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/sshsig"
)

func signerOf(s ssh.Signer) admin.Signer {
	return func(_ context.Context, canonical []byte) ([]byte, error) {
		return sshsig.Sign(s, journal.Namespace, canonical)
	}
}

func event(t *testing.T) *journal.BindingEvent {
	t.Helper()
	k, _ := keys.Generate()
	e, _, err := admin.NewEvent(context.Background(), nil, journal.KindBindingSet, "example.com", "host1.example.com", 3,
		keys.Fingerprint(&k.PublicKey), []journal.Check{{Type: "tailnet", Target: "host1.tailnet.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// Administrators sign copies of one event separately; merging keeps one
// signature per key and refuses a different event.
func TestSignSeparatelyAndMerge(t *testing.T) {
	ctx := context.Background()
	admins := jt.NewAdmins(t, "alice", "bob")
	e := event(t)
	alice, bob := *e, *e
	if _, err := admin.AddSignature(ctx, &alice, signerOf(admins.Signers["alice"])); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.AddSignature(ctx, &alice, signerOf(admins.Signers["alice"])); !errors.Is(err, admin.ErrAlreadySigned) {
		t.Fatalf("second signature by the same key: %v", err)
	}
	if _, err := admin.AddSignature(ctx, &bob, signerOf(admins.Signers["bob"])); err != nil {
		t.Fatal(err)
	}
	merged, err := admin.Merge(&alice, &bob, &alice)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged.Signatures) != 2 {
		t.Fatalf("%d signatures after merging", len(merged.Signatures))
	}
	reg, _ := journal.NewRegistry(admins.Registry(2))
	if _, err := reg.Verify(merged); err != nil {
		t.Fatalf("merged event does not meet the threshold: %v", err)
	}
	other := *e
	other.Epoch = 4
	other.Signatures = nil
	if _, err := admin.Merge(&alice, &other); err == nil {
		t.Fatal("merged two different events")
	}
	// A signer that signs something else is caught before the event changes.
	wrong := func(_ context.Context, _ []byte) ([]byte, error) {
		return sshsig.Sign(admins.Signers["bob"], journal.Namespace, []byte("something else"))
	}
	if _, err := admin.AddSignature(ctx, &alice, wrong); err == nil || len(alice.Signatures) != 1 {
		t.Fatalf("signature over other text accepted: %v", err)
	}
}

func TestEventFileRoundTrip(t *testing.T) {
	e := event(t)
	path := filepath.Join(t.TempDir(), "event.json")
	if err := admin.WriteEvent(path, e); err != nil {
		t.Fatal(err)
	}
	got, err := admin.ReadEvent(path)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := e.Canonical()
	b, _ := got.Canonical()
	if string(a) != string(b) {
		t.Fatalf("round trip changed the event:\n%s\n%s", a, b)
	}
	if err := os.WriteFile(path, []byte(`{"v":1,"extra":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ReadEvent(path); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestParseCheck(t *testing.T) {
	for in, want := range map[string]journal.Check{
		"tailnet:host1.tailnet.example.com": {Type: "tailnet", Target: "host1.tailnet.example.com"},
		"ip:[2001:db8::10]:7440":            {Type: "ip", Target: "[2001:db8::10]:7440"},
		"net:198.51.100.0/24":               {Type: "net", Target: "198.51.100.0/24"},
	} {
		got, err := admin.ParseCheck(in)
		if err != nil || got != want {
			t.Fatalf("%s: %+v, %v", in, got, err)
		}
	}
	if _, err := admin.ParseCheck("tailnet"); err == nil {
		t.Fatal("check without target accepted")
	}
}

// TestSSHKeygen signs with the real ssh-keygen, as administrators do.
func TestSSHKeygen(t *testing.T) {
	prog, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not installed")
	}
	key := filepath.Join(t.TempDir(), "admin")
	if out, err := exec.Command(prog, "-q", "-t", "ed25519", "-N", "", "-C", "admin@example.com", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v %s", err, out)
	}
	e := event(t)
	fp, err := admin.AddSignature(context.Background(), e, admin.SSHKeygen(prog, key))
	if err != nil {
		t.Fatal(err)
	}
	pubLine, _ := os.ReadFile(key + ".pub")
	pub, err := sshsig.ParseAuthorizedKey(strings.TrimSpace(string(pubLine)))
	if err != nil {
		t.Fatal(err)
	}
	if fp != sshsig.Fingerprint(pub) {
		t.Fatalf("signed by %s, want %s", fp, sshsig.Fingerprint(pub))
	}
}
