package keys

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestExchangeKeyFile(t *testing.T) {
	key, err := GenerateExchangeKey()
	if err != nil {
		t.Fatal(err)
	}
	plain, err := MarshalExchangeKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	f, err := ParseExchangeKeyFile(plain)
	if err != nil || f.Encrypted() || !bytes.Equal(f.Key, key) {
		t.Fatalf("plain file: %v, encrypted %v", err, f != nil && f.Encrypted())
	}

	enc, err := EncryptExchangeKeyPEM(key, []byte("correct horse"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(enc, plain) {
		t.Fatal("the encrypted file contains the key")
	}
	f, err = ParseExchangeKeyFile(enc)
	if err != nil || !f.Encrypted() {
		t.Fatalf("encrypted file: %v", err)
	}
	if _, err := f.Decrypt([]byte("wrong")); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	got, err := f.Decrypt([]byte("correct horse"))
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("decrypt: %v", err)
	}

	// The parameters are bound to the ciphertext.
	tampered := strings.Replace(string(enc), "N=32768", "N=16384", 1)
	if f, err := ParseExchangeKeyFile([]byte(tampered)); err == nil {
		if _, err := f.Decrypt([]byte("correct horse")); err == nil {
			t.Fatal("changed KDF parameters were accepted")
		}
	}

	// Neither kind of key file passes for the other.
	sk, _ := Generate()
	spem, _ := MarshalPrivatePEM(sk)
	if _, err := ParseExchangeKeyFile(spem); err == nil {
		t.Fatal("a signing key was taken as an exchange key")
	}
	if _, err := ParseKeyFile(plain); err == nil {
		t.Fatal("an exchange key was taken as a signing key")
	}
	if _, err := MarshalExchangeKeyPEM(key[:16]); err == nil {
		t.Fatal("a short key was written")
	}
}
