package sshsig

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func signers(t *testing.T) map[string]ssh.Signer {
	t.Helper()
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	out := map[string]ssh.Signer{}
	for name, k := range map[string]any{"ed25519": edKey, "ecdsa": ecKey, "rsa": rsaKey} {
		s, err := ssh.NewSignerFromKey(k)
		if err != nil {
			t.Fatal(err)
		}
		out[name] = s
	}
	return out
}

func TestSignVerify(t *testing.T) {
	msg := []byte("ergosum binding v1\nkind binding.set\n")
	for name, s := range signers(t) {
		t.Run(name, func(t *testing.T) {
			sig, err := Sign(s, "ergosum-binding", msg)
			if err != nil {
				t.Fatal(err)
			}
			pub, err := Verify(sig, "ergosum-binding", msg)
			if err != nil {
				t.Fatal(err)
			}
			if Fingerprint(pub) != Fingerprint(s.PublicKey()) {
				t.Fatal("returned key differs from signer")
			}
			if _, err := Verify(sig, "file", msg); !errors.Is(err, ErrNamespace) {
				t.Fatalf("other namespace: %v", err)
			}
			if _, err := Verify(sig, "ergosum-binding", append(msg, 'x')); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("modified message: %v", err)
			}
		})
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	for _, in := range []string{
		"",
		"not a signature",
		"-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n",
	} {
		if _, err := Verify([]byte(in), "n", []byte("m")); err == nil {
			t.Fatalf("accepted %q", in)
		}
	}
}

func TestVerifyRejectsTrailingData(t *testing.T) {
	s := signers(t)["ed25519"]
	sig, _ := Sign(s, "n", []byte("m"))
	block, _ := pem.Decode(sig)
	block.Bytes = append(block.Bytes, 0)
	if _, err := Verify(pem.EncodeToMemory(block), "n", []byte("m")); err == nil {
		t.Fatal("accepted signature with trailing bytes")
	}
}

// TestOpenSSHInterop checks both directions against ssh-keygen -Y, when
// ssh-keygen is available.
func TestOpenSSHInterop(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not installed")
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "admin")
	out, err := exec.Command(keygen, "-q", "-t", "ed25519", "-N", "", "-C", "admin@example.com", "-f", keyPath).CombinedOutput()
	if err != nil {
		t.Skipf("ssh-keygen cannot create keys here: %v %s", err, out)
	}
	msgPath := filepath.Join(dir, "event.txt")
	msg := []byte("ergosum binding v1\nkind binding.set\nidentity host1.example.com\n")
	if err := os.WriteFile(msgPath, msg, 0o600); err != nil {
		t.Fatal(err)
	}

	// ssh-keygen signs, we verify.
	out, err = exec.Command(keygen, "-Y", "sign", "-f", keyPath, "-n", "ergosum-binding", msgPath).CombinedOutput()
	if err != nil {
		t.Skipf("ssh-keygen -Y sign unavailable: %v %s", err, out)
	}
	sig, err := os.ReadFile(msgPath + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := Verify(sig, "ergosum-binding", msg)
	if err != nil {
		t.Fatalf("verify ssh-keygen signature: %v", err)
	}
	pubLine, _ := os.ReadFile(keyPath + ".pub")
	want, err := ParseAuthorizedKey(string(pubLine))
	if err != nil {
		t.Fatal(err)
	}
	if Fingerprint(pub) != Fingerprint(want) {
		t.Fatal("key mismatch")
	}

	// We sign, ssh-keygen verifies.
	privPEM, _ := os.ReadFile(keyPath)
	signer, err := ssh.ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	ours, err := Sign(signer, "ergosum-binding", msg)
	if err != nil {
		t.Fatal(err)
	}
	oursPath := filepath.Join(dir, "ours.sig")
	_ = os.WriteFile(oursPath, ours, 0o600)
	allowed := filepath.Join(dir, "allowed_signers")
	_ = os.WriteFile(allowed, []byte("admin@example.com "+strings.TrimSpace(string(pubLine))+"\n"), 0o600)
	cmd := exec.Command(keygen, "-Y", "verify", "-f", allowed, "-I", "admin@example.com", "-n", "ergosum-binding", "-s", oursPath)
	cmd.Stdin = strings.NewReader(string(msg))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen rejected our signature: %v %s", err, out)
	}
}
