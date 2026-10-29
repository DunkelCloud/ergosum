package admin_test

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

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

func fingerprint(t *testing.T) string {
	t.Helper()
	k, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return keys.Fingerprint(&k.PublicKey)
}

func event(t *testing.T) *journal.BindingEvent {
	t.Helper()
	return jt.Set("example.com", "host1.example.com", 3, fingerprint(t), journal.Check{Type: "tailnet", Target: "host1.tailnet.example.com"})
}

// A signature is checked against the text before it joins the event, and
// a key signs once.
func TestAddSignature(t *testing.T) {
	ctx := context.Background()
	admins := jt.NewAdmins(t, "alice", "bob")
	e := event(t)
	if _, err := admin.AddSignature(ctx, e, signerOf(admins.Signers["alice"])); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.AddSignature(ctx, e, signerOf(admins.Signers["alice"])); !errors.Is(err, admin.ErrAlreadySigned) {
		t.Fatalf("second signature by the same key: %v", err)
	}
	wrong := func(_ context.Context, _ []byte) ([]byte, error) {
		return sshsig.Sign(admins.Signers["bob"], journal.Namespace, []byte("something else"))
	}
	if _, err := admin.AddSignature(ctx, e, wrong); err == nil || len(e.Signatures) != 1 {
		t.Fatalf("signature over other text accepted: %v", err)
	}
}

func utf16LE(s string) []byte {
	out := []byte{0xFF, 0xFE}
	for _, u := range utf16.Encode([]rune(s)) {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

// The file takes the fields in any order, with comments, CRLF line
// endings, a byte order mark or UTF-16, and the signature blocks.
func TestParseFile(t *testing.T) {
	admins := jt.NewAdmins(t, "alice")
	e := admins.Sign(t, event(t), "alice")
	canonical, _ := e.Canonical()
	text := "# written by ergosumd request\n" +
		"check tailnet host1.tailnet.example.com\n" +
		"  identity host1.example.com  \n" +
		"key " + e.Key + "\n\n" +
		"# added by ergosum bind\nepoch 3\ntrust-domain example.com\nkind binding.set\n" +
		"# signed by alice\n" + e.Signatures[0]
	for name, data := range map[string][]byte{
		"LF":        []byte(text),
		"CRLF":      []byte(strings.ReplaceAll(text, "\n", "\r\n")),
		"BOM":       append([]byte("\xEF\xBB\xBF"), text...),
		"UTF-16":    utf16LE(strings.ReplaceAll(text, "\n", "\r\n")),
		"canonical": append(canonical, e.Signatures[0]...),
	} {
		f, err := admin.ParseFile(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := f.Event().Canonical()
		if err != nil || string(got) != string(canonical) {
			t.Fatalf("%s: %s %v", name, got, err)
		}
		if len(f.Signatures) != 1 {
			t.Fatalf("%s: %d signatures", name, len(f.Signatures))
		}
		if _, err := sshsig.Verify([]byte(f.Signatures[0]), journal.Namespace, canonical); err != nil {
			t.Fatalf("%s: signature: %v", name, err)
		}
	}
	for text, want := range map[string]string{
		"identity a.example.com\nidentity b.example.com\n":             `a second "identity" line`,
		"identity a.example.com\nhost a\n":                             `unknown field "host"`,
		"identity a.example.com\ncheck tailnet\n":                      `want "check TYPE TARGET"`,
		"identity a.example.com\nepoch zero\n":                         "epoch must be a positive number",
		"identity a.example.com\nkey 1234\n":                           "not a key fingerprint",
		"key " + e.Key + "\n":                                          "no identity line",
		"identity a.example.com\n-----BEGIN SSH SIGNATURE-----\nAAA\n": "no -----END SSH SIGNATURE----- line",
	} {
		if _, err := admin.ParseFile([]byte(text)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", text, err, want)
		}
	}
}

// Appended lines keep the file's line ending.
func TestFileAppend(t *testing.T) {
	f, err := admin.ParseFile([]byte("identity host1.example.com\r\nkey " + fingerprint(t)))
	if err != nil {
		t.Fatal(err)
	}
	f.Append("epoch 1", "kind binding.set")
	if got := string(f.Bytes()); !strings.HasSuffix(got, "\r\nepoch 1\r\nkind binding.set\r\n") {
		t.Fatalf("%q", got)
	}
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The administrator key may be given as a key line, an OpenSSH or SSH2
// public key file, or a private key file; a PuTTY key file is explained.
func TestLoadSignKey(t *testing.T) {
	admins := jt.NewAdmins(t, "alice")
	pub := admins.Signers["alice"].PublicKey()
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " alice@example.com"
	b64 := base64.StdEncoding.EncodeToString(pub.Marshal())
	ssh2 := "---- BEGIN SSH2 PUBLIC KEY ----\r\nComment: \"alice@example.com\"\r\n" + b64[:40] + "\r\n" + b64[40:] + "\r\n---- END SSH2 PUBLIC KEY ----\r\n"
	for name, spec := range map[string]string{
		"line": line,
		"file": writeFile(t, "alice.pub", line+"\n"),
		"SSH2": writeFile(t, "alice-ssh2.pub", ssh2),
	} {
		k, err := admin.LoadSignKey(spec, "")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if k.Fingerprint() != sshsig.Fingerprint(pub) {
			t.Fatalf("%s: %s", name, k.Fingerprint())
		}
	}
	if _, err := admin.LoadSignKey(writeFile(t, "alice.ppk", "PuTTY-User-Key-File-3: ssh-ed25519\n"), ""); err == nil || !strings.Contains(err.Error(), "Pageant") {
		t.Fatalf("PuTTY key: %v", err)
	}
	if _, err := admin.LoadSignKey(filepath.Join(t.TempDir(), "missing"), ""); err == nil {
		t.Fatal("missing file accepted")
	}
}

// TestSSHKeygen signs with the real ssh-keygen and a private key file.
func TestSSHKeygen(t *testing.T) {
	prog, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not installed")
	}
	key := filepath.Join(t.TempDir(), "admin")
	if out, err := exec.Command(prog, "-q", "-t", "ed25519", "-N", "", "-C", "admin@example.com", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v %s", err, out)
	}
	k, err := admin.LoadSignKey(key, prog)
	if err != nil {
		t.Fatal(err)
	}
	pubLine, _ := os.ReadFile(key + ".pub")
	pub, err := sshsig.ParseAuthorizedKey(strings.TrimSpace(string(pubLine)))
	if err != nil {
		t.Fatal(err)
	}
	if k.Fingerprint() != sshsig.Fingerprint(pub) {
		t.Fatalf("key %s, want %s", k.Fingerprint(), sshsig.Fingerprint(pub))
	}
	fp, err := admin.AddSignature(context.Background(), event(t), k.Sign)
	if err != nil {
		t.Fatal(err)
	}
	if fp != sshsig.Fingerprint(pub) {
		t.Fatalf("signed by %s, want %s", fp, sshsig.Fingerprint(pub))
	}
}
