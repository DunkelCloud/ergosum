package main

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"

	"github.com/DunkelCloud/ergosum/internal/keys"
)

// encryptExisting returns the plain key in the file from encrypted with
// pass: a signing key, or with exchange an exchange key. The key stays the
// same, so that an instance changes to an encrypted key without changes to
// Vault or the authority lists. The result is decrypted again and compared
// before it is returned. summary is what keygen prints for the key.
func encryptExisting(from string, exchange bool, pass []byte) (data []byte, summary string, err error) {
	plain, err := os.ReadFile(from) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, "", err
	}
	if exchange {
		f, err := keys.ParseExchangeKeyFile(plain)
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", from, err)
		}
		if f.Encrypted() {
			return nil, "", fmt.Errorf("%s is encrypted already", from)
		}
		if data, err = keys.EncryptExchangeKeyPEM(f.Key, pass); err != nil {
			return nil, "", err
		}
		g, err := keys.ParseExchangeKeyFile(data)
		if err == nil {
			var k []byte
			if k, err = g.Decrypt(pass); err == nil && !bytes.Equal(k, f.Key) {
				err = errors.New("the encrypted key differs")
			}
		}
		if err != nil {
			return nil, "", fmt.Errorf("checking the encrypted key: %w", err)
		}
		return data, "the same exchange key, encrypted\n", nil
	}
	f, err := keys.ParseKeyFile(plain)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", from, err)
	}
	if f.Encrypted() {
		return nil, "", fmt.Errorf("%s is encrypted already", from)
	}
	if data, err = keys.EncryptPEM(f.Key, pass); err != nil {
		return nil, "", err
	}
	g, err := keys.ParseKeyFile(data)
	if err == nil {
		var k *ecdsa.PrivateKey
		if k, err = g.Decrypt(pass); err == nil && !k.Equal(f.Key) {
			err = errors.New("the encrypted key differs")
		}
	}
	if err != nil {
		return nil, "", fmt.Errorf("checking the encrypted key: %w", err)
	}
	pub := &f.Key.PublicKey
	return data, fmt.Sprintf("the same signing key, encrypted\nkid:         %s\nfingerprint: %s\n", keys.Thumbprint(pub), keys.Fingerprint(pub)), nil
}
