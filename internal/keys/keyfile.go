package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// PEM block type of a passphrase-encrypted private key.
const pemEncrypted = "ERGOSUM ENCRYPTED PRIVATE KEY"

// Default scrypt cost. N=2^15, r=8 needs 32 MiB, which fits small VMs.
const (
	scryptN = 1 << 15
	scryptR = 8
	scryptP = 1
)

// Largest scrypt cost a key file may ask for.
const (
	maxScryptMemory = 256 << 20
	maxScryptP      = 4
)

// ErrBadPassphrase is returned when an encrypted key cannot be decrypted.
var ErrBadPassphrase = errors.New("keys: wrong passphrase or corrupted key file")

// KeyFile is a parsed private key file. Encrypted files expose only the
// public key until Decrypt succeeds.
type KeyFile struct {
	Key    *ecdsa.PrivateKey
	Public *ecdsa.PublicKey
	block  *pem.Block
}

// Encrypted reports whether the file holds a passphrase-encrypted key.
func (k *KeyFile) Encrypted() bool { return k.Key == nil }

// ParseKeyFile parses an unencrypted PKCS#8 or SEC 1 PEM key, or an
// encrypted key written by EncryptPEM.
func ParseKeyFile(data []byte) (*KeyFile, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("keys: no PEM block found")
	}
	switch block.Type {
	case pemPrivate:
		key, err := parsePKCS8(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &KeyFile{Key: key, Public: &key.PublicKey}, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		if key.Curve != elliptic.P256() {
			return nil, errNotP256
		}
		return &KeyFile{Key: key, Public: &key.PublicKey}, nil
	case pemEncrypted:
		spki, err := base64.StdEncoding.DecodeString(block.Headers["Public-Key"])
		if err != nil {
			return nil, fmt.Errorf("keys: bad Public-Key header: %w", err)
		}
		pub, err := ParseSPKI(spki)
		if err != nil {
			return nil, err
		}
		return &KeyFile{Public: pub, block: block}, nil
	default:
		return nil, fmt.Errorf("keys: unsupported PEM block %q", block.Type)
	}
}

// EncryptPEM encrypts key with a passphrase (scrypt, AES-256-GCM). The
// public key stays readable in a header so that the key ID is known while
// the key is still sealed; it is bound to the ciphertext as associated data.
func EncryptPEM(key *ecdsa.PrivateKey, passphrase []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("keys: empty passphrase")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	params := fmt.Sprintf("N=%d,r=%d,p=%d", scryptN, scryptR, scryptP)
	h := map[string]string{
		"KDF":        "scrypt",
		"KDF-Params": params,
		"Salt":       base64.StdEncoding.EncodeToString(salt),
		"Cipher":     "AES-256-GCM",
		"Public-Key": base64.StdEncoding.EncodeToString(SPKI(&key.PublicKey)),
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
	ct := aead.Seal(nil, nonce, der, associatedData(h))
	return pem.EncodeToMemory(&pem.Block{Type: pemEncrypted, Headers: h, Bytes: ct}), nil
}

// Decrypt unseals an encrypted key file.
func (k *KeyFile) Decrypt(passphrase []byte) (*ecdsa.PrivateKey, error) {
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
	der, err := aead.Open(nil, nonce, k.block.Bytes, associatedData(h))
	if err != nil {
		return nil, ErrBadPassphrase
	}
	key, err := parsePKCS8(der)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(SPKI(&key.PublicKey), SPKI(k.Public)) != 1 {
		return nil, errors.New("keys: decrypted key does not match the Public-Key header")
	}
	return key, nil
}

func deriveAEAD(passphrase, salt []byte, n, r, p int) (cipher.AEAD, error) {
	dk, err := scrypt.Key(passphrase, salt, n, r, p, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func associatedData(h map[string]string) []byte {
	return []byte(strings.Join([]string{
		"ergosum encrypted private key v1",
		h["KDF"], h["KDF-Params"], h["Salt"], h["Cipher"], h["Public-Key"],
	}, "\x00"))
}

func parseScryptParams(s string) (n, r, p int, err error) {
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return 0, 0, 0, fmt.Errorf("keys: bad KDF-Params %q", s)
		}
		x, convErr := strconv.Atoi(v)
		if convErr != nil {
			return 0, 0, 0, fmt.Errorf("keys: bad KDF-Params %q", s)
		}
		switch k {
		case "N":
			n = x
		case "r":
			r = x
		case "p":
			p = x
		}
	}
	// Bound the cost so that a crafted file cannot exhaust memory or CPU:
	// scrypt needs 128·N·r bytes and runs p times.
	if n < 2 || n&(n-1) != 0 || r < 1 || p < 1 || p > maxScryptP || 128*int64(n)*int64(r) > maxScryptMemory {
		return 0, 0, 0, fmt.Errorf("keys: KDF-Params out of range: %q", s)
	}
	return n, r, p, nil
}
