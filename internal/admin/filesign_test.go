package admin

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/DunkelCloud/ergosum/internal/sshsig"
)

// An encrypted key file as a Windows editor leaves it, with CRLF and no
// line end after the last line, signs; ssh-keygen refuses such a file.
func TestFileSign(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "release", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.TrimSuffix(strings.ReplaceAll(string(pem.EncodeToMemory(block)), "\n", "\r\n"), "\r\n")
	file := filepath.Join(t.TempDir(), "release-key")
	if err := os.WriteFile(file, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	msg := []byte("checksums\n")
	asked := 0
	pass := func(p string) func() ([]byte, error) {
		return func() ([]byte, error) { asked++; return []byte(p), nil }
	}
	pub, sig, err := FileSign(file, pass("secret"), "ergosum-release", msg)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := sshsig.Verify(sig, "ergosum-release", msg)
	if err != nil || sshsig.Fingerprint(signed) != sshsig.Fingerprint(pub) || asked != 1 {
		t.Fatalf("signature: %v, asked %d times", err, asked)
	}
	if _, _, err := FileSign(file, pass("wrong"), "ergosum-release", msg); err == nil {
		t.Error("signed with a wrong passphrase")
	}
	refuse := func() ([]byte, error) { return nil, errors.New("no terminal") }
	if _, _, err := FileSign(file, refuse, "ergosum-release", msg); err == nil {
		t.Error("signed without a passphrase")
	}

	plain, err := ssh.MarshalPrivateKey(priv, "release")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, pem.EncodeToMemory(plain), 0o600); err != nil {
		t.Fatal(err)
	}
	asked = 0
	if _, _, err := FileSign(file, pass("unused"), "ergosum-release", msg); err != nil || asked != 0 {
		t.Errorf("unencrypted key: %v, asked %d times", err, asked)
	}
}
