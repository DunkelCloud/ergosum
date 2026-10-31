package keys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSignVerifyContextSeparation(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello")
	sig, err := Sign(k, "ctx-a", msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 64 {
		t.Fatalf("raw signature length %d", len(sig))
	}
	if !Verify(&k.PublicKey, "ctx-a", msg, sig) {
		t.Fatal("valid signature rejected")
	}
	if Verify(&k.PublicKey, "ctx-b", msg, sig) {
		t.Fatal("signature verified under a different context")
	}
	if Verify(&k.PublicKey, "ctx-a", []byte("hellO"), sig) {
		t.Fatal("signature verified for a different message")
	}
	other, _ := Generate()
	if Verify(&other.PublicKey, "ctx-a", msg, sig) {
		t.Fatal("signature verified with a different key")
	}
}

func TestRawSignatureIsPlainES256(t *testing.T) {
	// A context-free ES256 check: the raw signature must verify with the
	// standard library once converted, so that JWT consumers accept it.
	k, _ := Generate()
	sig, _ := Sign(k, "c", []byte("m"))
	der, err := RawToDER(sig)
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256([]byte("c\x00m"))
	if !ecdsa.VerifyASN1(&k.PublicKey, d[:], der) {
		t.Fatal("raw signature does not verify as ES256")
	}
}

func TestThumbprintAndFingerprintStable(t *testing.T) {
	k, _ := Generate()
	if Thumbprint(&k.PublicKey) != PublicJWK(&k.PublicKey).Kid {
		t.Fatal("kid differs from thumbprint")
	}
	fp := Fingerprint(&k.PublicKey)
	if !strings.HasPrefix(fp, "SHA256:") || len(fp) != len("SHA256:")+43 {
		t.Fatalf("unexpected fingerprint %q", fp)
	}
	pub, err := ParseSPKI(SPKI(&k.PublicKey))
	if err != nil || Fingerprint(pub) != fp {
		t.Fatal("SPKI round trip changed the fingerprint")
	}
}

func TestLoadOrCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.key")
	k1, created, err := LoadOrCreate(path)
	if err != nil || !created {
		t.Fatalf("create: %v %v", created, err)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(path)
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %o, want 0600", fi.Mode().Perm())
		}
	}
	k2, created, err := LoadOrCreate(path)
	if err != nil || created {
		t.Fatalf("load: %v %v", created, err)
	}
	if Fingerprint(&k1.PublicKey) != Fingerprint(&k2.PublicKey) {
		t.Fatal("reloaded key differs")
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(path, 0o644)
		if _, _, err := LoadOrCreate(path); err == nil {
			t.Fatal("world-readable key accepted")
		}
	}
}

func TestEncryptedKeyFile(t *testing.T) {
	k, _ := Generate()
	data, err := EncryptPEM(k, []byte("correct horse"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("BEGIN PRIVATE KEY")) {
		t.Fatal("plaintext key in encrypted file")
	}
	kf, err := ParseKeyFile(data)
	if err != nil {
		t.Fatal(err)
	}
	if !kf.Encrypted() {
		t.Fatal("file not recognized as encrypted")
	}
	if Thumbprint(kf.Public) != Thumbprint(&k.PublicKey) {
		t.Fatal("public key header mismatch")
	}
	if _, err := kf.Decrypt([]byte("wrong")); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	got, err := kf.Decrypt([]byte("correct horse"))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(k) {
		t.Fatal("decrypted key differs")
	}
}

func TestEncryptedKeyFileHeaderSwap(t *testing.T) {
	k, _ := Generate()
	other, _ := Generate()
	data, _ := EncryptPEM(k, []byte("pw"))
	otherSPKI := SPKI(&other.PublicKey)
	kf, _ := ParseKeyFile(data)
	// Replace the advertised public key: decryption must fail because the
	// header is bound to the ciphertext.
	kf.block.Headers["Public-Key"] = encodeStd(otherSPKI)
	kf.Public = &other.PublicKey
	if _, err := kf.Decrypt([]byte("pw")); err == nil {
		t.Fatal("swapped public key header accepted")
	}
}

// TestKeyFileBounds: only P-256 keys load, in either PEM form, and an
// encrypted file cannot ask scrypt for more than 256 MiB or p above 4.
func TestKeyFileBounds(t *testing.T) {
	k384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1, _ := x509.MarshalECPrivateKey(k384)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(k384)
	for typ, der := range map[string][]byte{"EC PRIVATE KEY": sec1, "PRIVATE KEY": pkcs8} {
		if _, err := ParseKeyFile(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})); err == nil {
			t.Errorf("%s on P-384 accepted", typ)
		}
	}

	for _, ok := range []string{"N=32768,r=8,p=1", "N=2097152,r=1,p=4", "N=262144,r=8,p=1"} {
		if _, _, _, err := parseScryptParams(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"N=1048576,r=32,p=1", // 4 GiB
		"N=262144,r=16,p=1",  // 512 MiB
		"N=32768,r=8,p=5",
		"N=30000,r=8,p=1",
		"N=1,r=8,p=1",
		"N=32768,r=0,p=1",
		"N=32768,r=8",
	} {
		if _, _, _, err := parseScryptParams(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func encodeStd(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
