package keys

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// PEM block types of an instance's exchange key (ADR 0004), plain and
// passphrase-encrypted.
const (
	pemExchange          = "ERGOSUM EXCHANGE KEY"
	pemEncryptedExchange = "ERGOSUM ENCRYPTED EXCHANGE KEY"
)

// ExchangeKeySize is the size of an exchange key: 32 random bytes.
const ExchangeKeySize = 32

// ExchangeKeyFile is a parsed exchange key file. An encrypted file yields
// the key only after Decrypt.
type ExchangeKeyFile struct {
	Key   []byte
	block *pem.Block
}

// Encrypted reports whether the file holds a passphrase-encrypted key.
func (k *ExchangeKeyFile) Encrypted() bool { return k.Key == nil }

// GenerateExchangeKey returns a new exchange key.
func GenerateExchangeKey() ([]byte, error) {
	k := make([]byte, ExchangeKeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// MarshalExchangeKeyPEM encodes an exchange key as PEM.
func MarshalExchangeKeyPEM(key []byte) ([]byte, error) {
	if len(key) != ExchangeKeySize {
		return nil, errors.New("keys: an exchange key has 32 bytes")
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemExchange, Bytes: key}), nil
}

// EncryptExchangeKeyPEM encrypts an exchange key with a passphrase, as
// EncryptPEM does a signing key: one passphrase can unseal both.
func EncryptExchangeKeyPEM(key, passphrase []byte) ([]byte, error) {
	if len(key) != ExchangeKeySize {
		return nil, errors.New("keys: an exchange key has 32 bytes")
	}
	if len(passphrase) == 0 {
		return nil, errors.New("keys: empty passphrase")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	h := map[string]string{
		"KDF":        "scrypt",
		"KDF-Params": fmt.Sprintf("N=%d,r=%d,p=%d", scryptN, scryptR, scryptP),
		"Salt":       base64.StdEncoding.EncodeToString(salt),
		"Cipher":     "AES-256-GCM",
	}
	aead, err := deriveAEAD(passphrase, salt, scryptN, scryptR, scryptP)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	h["Nonce"] = base64.StdEncoding.EncodeToString(nonce)
	ct := aead.Seal(nil, nonce, key, exchangeAssociatedData(h))
	return pem.EncodeToMemory(&pem.Block{Type: pemEncryptedExchange, Headers: h, Bytes: ct}), nil
}

// ParseExchangeKeyFile parses a file written by MarshalExchangeKeyPEM or
// EncryptExchangeKeyPEM.
func ParseExchangeKeyFile(data []byte) (*ExchangeKeyFile, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("keys: no PEM block found")
	}
	switch block.Type {
	case pemExchange:
		if len(block.Bytes) != ExchangeKeySize {
			return nil, errors.New("keys: an exchange key has 32 bytes")
		}
		return &ExchangeKeyFile{Key: block.Bytes}, nil
	case pemEncryptedExchange:
		return &ExchangeKeyFile{block: block}, nil
	default:
		return nil, fmt.Errorf("keys: %q is not an exchange key", block.Type)
	}
}

// Decrypt unseals an encrypted exchange key file.
func (k *ExchangeKeyFile) Decrypt(passphrase []byte) ([]byte, error) {
	if !k.Encrypted() {
		return k.Key, nil
	}
	h := k.block.Headers
	if h["KDF"] != "scrypt" || h["Cipher"] != "AES-256-GCM" {
		return nil, fmt.Errorf("keys: unsupported KDF %q or cipher %q", h["KDF"], h["Cipher"])
	}
	n, r, p, err := parseScryptParams(h["KDF-Params"])
	if err != nil {
		return nil, err
	}
	salt, err := base64.StdEncoding.DecodeString(h["Salt"])
	if err != nil {
		return nil, fmt.Errorf("keys: bad Salt header: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(h["Nonce"])
	if err != nil {
		return nil, fmt.Errorf("keys: bad Nonce header: %w", err)
	}
	aead, err := deriveAEAD(passphrase, salt, n, r, p)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("keys: bad nonce length")
	}
	key, err := aead.Open(nil, nonce, k.block.Bytes, exchangeAssociatedData(h))
	if err != nil {
		return nil, ErrBadPassphrase
	}
	if len(key) != ExchangeKeySize {
		return nil, errors.New("keys: an exchange key has 32 bytes")
	}
	return key, nil
}

func exchangeAssociatedData(h map[string]string) []byte {
	return []byte(strings.Join([]string{
		"ergosum encrypted exchange key v1",
		h["KDF"], h["KDF-Params"], h["Salt"], h["Cipher"],
	}, "\x00"))
}
