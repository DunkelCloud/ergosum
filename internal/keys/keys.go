// Package keys handles the ECDSA P-256 keys used by daemons and authority
// instances: generation, PEM files (optionally passphrase-encrypted),
// fingerprints, JWK thumbprints and context-separated raw signatures.
package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
)

// Generate creates a new ECDSA P-256 private key.
func Generate() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// SPKI returns the DER-encoded SubjectPublicKeyInfo of pub.
func SPKI(pub *ecdsa.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		// Cannot happen for a valid P-256 key.
		panic(fmt.Sprintf("keys: marshal public key: %v", err))
	}
	return der
}

// Fingerprint returns "SHA256:" followed by the unpadded standard base64
// encoding of the SHA-256 digest of the key's SubjectPublicKeyInfo.
func Fingerprint(pub *ecdsa.PublicKey) string {
	return FingerprintSPKI(SPKI(pub))
}

// FingerprintSPKI is Fingerprint for an already encoded SubjectPublicKeyInfo.
func FingerprintSPKI(spki []byte) string {
	sum := sha256.Sum256(spki)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// ParseSPKI parses a DER SubjectPublicKeyInfo and requires a P-256 key.
func ParseSPKI(der []byte) (*ecdsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("keys: not an ECDSA P-256 public key")
	}
	return pub, nil
}

// JWK is the public JSON Web Key representation of a P-256 key.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
}

// PublicJWK returns the JWK of pub with kid set to its thumbprint.
func PublicJWK(pub *ecdsa.PublicKey) JWK {
	x, y := coordinates(pub)
	j := JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(x),
		Y:   base64.RawURLEncoding.EncodeToString(y),
		Use: "sig",
		Alg: "ES256",
	}
	j.Kid = Thumbprint(pub)
	return j
}

// Thumbprint returns the RFC 7638 JWK thumbprint (SHA-256, base64url) of pub.
// It serves as the key ID ("kid") of an authority instance.
func Thumbprint(pub *ecdsa.PublicKey) string {
	x, y := coordinates(pub)
	// RFC 7638: required members in lexicographic order, no whitespace.
	canonical, _ := json.Marshal(struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}{"P-256", "EC", base64.RawURLEncoding.EncodeToString(x), base64.RawURLEncoding.EncodeToString(y)})
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func coordinates(pub *ecdsa.PublicKey) (x, y []byte) {
	b, err := pub.Bytes()
	if err != nil || len(b) != 65 {
		panic("keys: invalid P-256 public key")
	}
	return b[1:33], b[33:65]
}

// Sign signs msg under the given context string and returns the raw 64-byte
// R||S signature. The signed digest is SHA-256(context || 0x00 || msg).
func Sign(key *ecdsa.PrivateKey, context string, msg []byte) ([]byte, error) {
	digest := contextDigest(context, msg)
	der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	return derToRaw(der)
}

// Verify checks a raw R||S signature produced by Sign.
func Verify(pub *ecdsa.PublicKey, context string, msg, sig []byte) bool {
	der, err := RawToDER(sig)
	if err != nil {
		return false
	}
	digest := contextDigest(context, msg)
	return ecdsa.VerifyASN1(pub, digest[:], der)
}

func contextDigest(context string, msg []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(context))
	h.Write([]byte{0})
	h.Write(msg)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

type ecdsaSig struct {
	R, S *big.Int
}

func derToRaw(der []byte) ([]byte, error) {
	var s ecdsaSig
	rest, err := asn1.Unmarshal(der, &s)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("keys: malformed ECDSA signature")
	}
	out := make([]byte, 64)
	s.R.FillBytes(out[:32])
	s.S.FillBytes(out[32:])
	return out, nil
}

// RawToDER converts a raw 64-byte R||S signature into ASN.1 DER.
func RawToDER(raw []byte) ([]byte, error) {
	if len(raw) != 64 {
		return nil, errors.New("keys: raw signature must be 64 bytes")
	}
	return asn1.Marshal(ecdsaSig{
		R: new(big.Int).SetBytes(raw[:32]),
		S: new(big.Int).SetBytes(raw[32:]),
	})
}

// DERToRaw converts an ASN.1 DER ECDSA P-256 signature into raw R||S.
func DERToRaw(der []byte) ([]byte, error) { return derToRaw(der) }

const pemPrivate = "PRIVATE KEY"

// MarshalPrivatePEM encodes key as an unencrypted PKCS#8 PEM block.
func MarshalPrivatePEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemPrivate, Bytes: der}), nil
}

// MarshalPublicPEM encodes pub as a PEM "PUBLIC KEY" block, the form Vault
// expects in jwt_validation_pubkeys.
func MarshalPublicPEM(pub *ecdsa.PublicKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: SPKI(pub)})
}

func parsePKCS8(der []byte) (*ecdsa.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("keys: not an ECDSA P-256 private key")
	}
	return key, nil
}

// LoadOrCreate loads an unencrypted private key from path or, if the file
// does not exist, generates one and writes it with mode 0600. created
// reports whether a new key was generated.
func LoadOrCreate(path string) (key *ecdsa.PrivateKey, created bool, err error) {
	data, err := os.ReadFile(path) //nolint:gosec // path comes from operator configuration
	if err == nil {
		if err := checkPrivateMode(path); err != nil {
			return nil, false, err
		}
		kf, err := ParseKeyFile(data)
		if err != nil {
			return nil, false, fmt.Errorf("%s: %w", path, err)
		}
		if kf.Encrypted() {
			return nil, false, fmt.Errorf("%s: encrypted keys are not supported here", path)
		}
		return kf.Key, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	key, err = Generate()
	if err != nil {
		return nil, false, err
	}
	pemBytes, err := MarshalPrivatePEM(key)
	if err != nil {
		return nil, false, err
	}
	if err := WriteFileAtomic(path, pemBytes, 0o600); err != nil {
		return nil, false, err
	}
	return key, true, nil
}

func checkPrivateMode(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s: private key is accessible by group or others (mode %o), expected 0600", path, fi.Mode().Perm())
	}
	return nil
}

// WriteFileAtomic writes data to a temporary file next to path, syncs it
// and renames it over path.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // no-op after a successful rename
	if err := f.Chmod(mode); err != nil && runtime.GOOS != "windows" {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	syncDir(dir)
	return nil
}

func syncDir(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	if d, err := os.Open(dir); err == nil { //nolint:gosec // directory of a file we just wrote
		_ = d.Sync()
		_ = d.Close()
	}
}
