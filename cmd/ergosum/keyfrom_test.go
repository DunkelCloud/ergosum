package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DunkelCloud/ergosum/internal/keys"
)

// TestEncryptExisting: an existing signing or exchange key comes back
// encrypted and unchanged; an encrypted one or the wrong kind is refused.
func TestEncryptExisting(t *testing.T) {
	dir := t.TempDir()
	pass := []byte("correct horse battery staple")

	sk, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := keys.MarshalPrivatePEM(sk)
	signing := filepath.Join(dir, "signing.key")
	if err := os.WriteFile(signing, plain, 0o600); err != nil {
		t.Fatal(err)
	}
	data, summary, err := encryptExisting(signing, false, pass)
	if err != nil {
		t.Fatal(err)
	}
	f, err := keys.ParseKeyFile(data)
	if err != nil || !f.Encrypted() {
		t.Fatalf("not an encrypted key file: %v", err)
	}
	k, err := f.Decrypt(pass)
	if err != nil || !k.Equal(sk) {
		t.Fatalf("decrypted key differs: %v", err)
	}
	if !strings.Contains(summary, keys.Fingerprint(&sk.PublicKey)) {
		t.Fatalf("summary without the fingerprint: %q", summary)
	}

	xk, _ := keys.GenerateExchangeKey()
	xplain, _ := keys.MarshalExchangeKeyPEM(xk)
	exchangeFile := filepath.Join(dir, "exchange.key")
	if err := os.WriteFile(exchangeFile, xplain, 0o600); err != nil {
		t.Fatal(err)
	}
	xdata, _, err := encryptExisting(exchangeFile, true, pass)
	if err != nil {
		t.Fatal(err)
	}
	xf, err := keys.ParseExchangeKeyFile(xdata)
	if err != nil || !xf.Encrypted() {
		t.Fatalf("not an encrypted exchange key file: %v", err)
	}
	if got, err := xf.Decrypt(pass); err != nil || !bytes.Equal(got, xk) {
		t.Fatalf("decrypted exchange key differs: %v", err)
	}

	encrypted := filepath.Join(dir, "signing.key.enc")
	if err := os.WriteFile(encrypted, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := encryptExisting(encrypted, false, pass); err == nil {
		t.Fatal("an encrypted key was encrypted again")
	}
	if _, _, err := encryptExisting(exchangeFile, false, pass); err == nil {
		t.Fatal("an exchange key was taken as a signing key")
	}
	if _, _, err := encryptExisting(signing, true, pass); err == nil {
		t.Fatal("a signing key was taken as an exchange key")
	}
}
