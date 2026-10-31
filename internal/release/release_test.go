package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/DunkelCloud/ergosum/internal/sshsig"
)

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func signersLine(principals, options string, k ssh.PublicKey) string {
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
	if options == "" {
		return principals + " " + key + " comment"
	}
	return principals + " " + options + " " + key + " comment"
}

// The repository's release-signers verifies the first signed release, a
// signature made with ssh-keygen on Windows.
func TestRepositorySigners(t *testing.T) {
	data, err := os.ReadFile("../../release-signers")
	if err != nil {
		t.Fatal(err)
	}
	signers, err := ParseSigners(data)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join("testdata", "v0.1.0-rc.1")
	sums, _ := os.ReadFile(filepath.Join(dir, SumsFile))
	sig, _ := os.ReadFile(filepath.Join(dir, SigFile))
	s, err := Verify(sums, sig, signers)
	if err != nil {
		t.Fatal(err)
	}
	if fp := sshsig.Fingerprint(s.Key); fp != "SHA256:xcJy5kiogfRmaX7n8ednlEIcxJUxQGiN1QJgXxhKeSc" {
		t.Errorf("signed by %s", fp)
	}
	entries, err := ParseSums(sums)
	if err != nil || len(entries) != 10 {
		t.Fatalf("%d entries, %v", len(entries), err)
	}
	if _, err := Verify(append(sums, '\n'), sig, signers); err == nil {
		t.Error("changed SHA256SUMS verified")
	}
}

func TestVerify(t *testing.T) {
	key, other := newSigner(t), newSigner(t)
	sums := []byte("0000000000000000000000000000000000000000000000000000000000000000  ergosumd-linux-amd64\n")
	sig, err := sshsig.Sign(key, Namespace, sums)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.PublicKey()
	for _, c := range []struct {
		name, signers string
		ok            bool
	}{
		{"listed", signersLine("release", `namespaces="ergosum-release"`, pub), true},
		{"no options", signersLine("release", "", pub), true},
		{"several principals and namespaces", signersLine("ops,release", `namespaces="ergosum-binding,ergosum-*"`, pub), true},
		{"other key", signersLine("release", "", other.PublicKey()), false},
		{"other principal", signersLine("ops", "", pub), false},
		{"other namespace", signersLine("release", `namespaces="ergosum-binding"`, pub), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			signers, err := ParseSigners([]byte("# keys\n\n" + c.signers + "\n"))
			if err != nil {
				t.Fatal(err)
			}
			_, err = Verify(sums, sig, signers)
			if (err == nil) != c.ok {
				t.Errorf("verified: %v, want %v (%v)", err == nil, c.ok, err)
			}
		})
	}
	binding, _ := sshsig.Sign(key, "ergosum-binding", sums)
	signers, _ := ParseSigners([]byte(signersLine("release", "", pub)))
	if _, err := Verify(sums, binding, signers); err == nil {
		t.Error("a signature in another namespace verified")
	}
}

func TestParseSigners(t *testing.T) {
	pub := newSigner(t).PublicKey()
	for _, bad := range []string{
		"",
		"# only a comment",
		signersLine("release", "cert-authority", pub),
		signersLine("release", `valid-before="20300101"`, pub),
		"release ssh-ed25519",
	} {
		if _, err := ParseSigners([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	crlf := "\xEF\xBB\xBF" + signersLine("release", `namespaces="ergosum-release"`, pub) + "\r\n"
	if _, err := ParseSigners([]byte(crlf)); err != nil {
		t.Errorf("BOM and CRLF: %v", err)
	}
}

func TestParseSums(t *testing.T) {
	h := strings.Repeat("ab", 32)
	good := fmt.Sprintf("%s  a\n%s *b.exe\r\n", h, h)
	entries, err := ParseSums([]byte(good))
	if err != nil || len(entries) != 2 || entries[1].Name != "b.exe" {
		t.Fatalf("%v %v", entries, err)
	}
	for _, bad := range []string{
		h + " a\n",
		strings.Repeat("AB", 32) + "  a\n",
		h + "  ../a\n",
		h + "  dir/a\n",
		h + `  dir\a` + "\n",
		h + "  ..\n",
		h + "  a\n" + h + "  a\n",
		h + "  a\n\n",
	} {
		if _, err := ParseSums([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestCheck(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hello := "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
	matched, missing, err := Check(dir, []Entry{{hello, "a"}, {hello, "b"}})
	if err != nil || len(matched) != 1 || len(missing) != 1 || missing[0] != "b" {
		t.Fatalf("matched %v, missing %v, %v", matched, missing, err)
	}
	if _, _, err := Check(dir, []Entry{{strings.Repeat("0", 64), "a"}}); err == nil {
		t.Error("a changed file matched")
	}
}
