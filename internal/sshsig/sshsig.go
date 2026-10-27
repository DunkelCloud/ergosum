// Package sshsig signs and verifies OpenSSH signatures in the SSHSIG format
// (the format of "ssh-keygen -Y sign"), as specified in OpenSSH's
// PROTOCOL.sshsig. It is the signature adapter for admin approvals.
package sshsig

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
)

const (
	magic      = "SSHSIG"
	version    = 1
	pemType    = "SSH SIGNATURE"
	hashSHA512 = "sha512"
	hashSHA256 = "sha256"
)

// Errors returned by Verify.
var (
	ErrMalformed      = errors.New("sshsig: malformed signature")
	ErrNamespace      = errors.New("sshsig: wrong namespace")
	ErrBadSignature   = errors.New("sshsig: signature does not verify")
	ErrWeakAlgorithm  = errors.New("sshsig: signature algorithm not accepted")
	ErrNoUserPresence = errors.New("sshsig: security key signature without user presence")
)

// Sign creates an armored SSHSIG signature over message.
func Sign(signer ssh.Signer, namespace string, message []byte) ([]byte, error) {
	if namespace == "" {
		return nil, errors.New("sshsig: empty namespace")
	}
	signed := signedData(namespace, hashSHA512, digest(hashSHA512, message))
	var sig *ssh.Signature
	var err error
	if as, ok := signer.(ssh.AlgorithmSigner); ok && signer.PublicKey().Type() == ssh.KeyAlgoRSA {
		sig, err = as.SignWithAlgorithm(nil, signed, ssh.KeyAlgoRSASHA512)
	} else {
		sig, err = signer.Sign(nil, signed)
	}
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString(magic)
	_ = binary.Write(&b, binary.BigEndian, uint32(version))
	writeString(&b, signer.PublicKey().Marshal())
	writeString(&b, []byte(namespace))
	writeString(&b, nil) // reserved
	writeString(&b, []byte(hashSHA512))
	writeString(&b, ssh.Marshal(sig))
	return pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: b.Bytes()}), nil
}

// Verify checks an armored SSHSIG signature over message in the given
// namespace and returns the public key that made it. The caller decides
// whether that key is trusted.
func Verify(armored []byte, namespace string, message []byte) (ssh.PublicKey, error) {
	block, rest := pem.Decode(armored)
	if block == nil || block.Type != pemType || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrMalformed
	}
	r := bytes.NewReader(block.Bytes)
	m := make([]byte, len(magic))
	if _, err := io.ReadFull(r, m); err != nil || string(m) != magic {
		return nil, ErrMalformed
	}
	var v uint32
	if err := binary.Read(r, binary.BigEndian, &v); err != nil || v != version {
		return nil, ErrMalformed
	}
	pubBytes, err1 := readString(r)
	ns, err2 := readString(r)
	reserved, err3 := readString(r)
	hashAlg, err4 := readString(r)
	sigBytes, err5 := readString(r)
	if err := errors.Join(err1, err2, err3, err4, err5); err != nil || r.Len() != 0 {
		return nil, ErrMalformed
	}
	_ = reserved // ignored, as specified
	if string(ns) != namespace {
		return nil, fmt.Errorf("%w: %q", ErrNamespace, ns)
	}
	h := string(hashAlg)
	if h != hashSHA512 && h != hashSHA256 {
		return nil, fmt.Errorf("%w: hash %q", ErrWeakAlgorithm, h)
	}
	pub, err := ssh.ParsePublicKey(pubBytes)
	if err != nil {
		return nil, ErrMalformed
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(sigBytes, &sig); err != nil {
		return nil, ErrMalformed
	}
	if sig.Format == ssh.KeyAlgoRSA { // RSA with SHA-1
		return nil, fmt.Errorf("%w: %s", ErrWeakAlgorithm, sig.Format)
	}
	if err := pub.Verify(signedData(namespace, h, digest(h, message)), &sig); err != nil {
		return nil, ErrBadSignature
	}
	if isSecurityKey(pub.Type()) {
		// Security-key signatures carry flags; bit 0 is user presence.
		if len(sig.Rest) < 1 || sig.Rest[0]&0x01 == 0 {
			return nil, ErrNoUserPresence
		}
	}
	return pub, nil
}

func isSecurityKey(t string) bool {
	return t == ssh.KeyAlgoSKED25519 || t == ssh.KeyAlgoSKECDSA256
}

func digest(alg string, message []byte) []byte {
	if alg == hashSHA256 {
		s := sha256.Sum256(message)
		return s[:]
	}
	s := sha512.Sum512(message)
	return s[:]
}

func signedData(namespace, hashAlg string, hashed []byte) []byte {
	var b bytes.Buffer
	b.WriteString(magic)
	writeString(&b, []byte(namespace))
	writeString(&b, nil)
	writeString(&b, []byte(hashAlg))
	writeString(&b, hashed)
	return b.Bytes()
}

func writeString(b *bytes.Buffer, s []byte) {
	_ = binary.Write(b, binary.BigEndian, uint32(len(s))) //nolint:gosec // lengths are bounded by the inputs
	b.Write(s)
}

func readString(r *bytes.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	if int64(n) > int64(r.Len()) {
		return nil, ErrMalformed
	}
	s := make([]byte, n)
	if _, err := io.ReadFull(r, s); err != nil {
		return nil, err
	}
	return s, nil
}

// ParseAuthorizedKey parses one public key in authorized_keys format,
// for example "ssh-ed25519 AAAA... alice@example.com".
func ParseAuthorizedKey(line string) (ssh.PublicKey, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	return pub, err
}

// Fingerprint returns the OpenSSH SHA256 fingerprint of pub.
func Fingerprint(pub ssh.PublicKey) string { return ssh.FingerprintSHA256(pub) }
