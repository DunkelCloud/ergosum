// Package jwt issues and verifies the identity token: a JWT (RFC 7519)
// signed with ES256 in the JWT-SVID layout (see docs/adr/0002-token-format.md).
package jwt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/DunkelCloud/ergosum/internal/keys"
)

// Header is the JOSE header of an identity token.
type Header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// Claims are the claims of an identity token.
type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	Host      string   `json:"host"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf"`
	Expiry    int64    `json:"exp"`
	ID        string   `json:"jti"`
	Checks    []string `json:"checks"`
}

// Lifetime returns exp - iat.
func (c Claims) Lifetime() time.Duration {
	return time.Duration(c.Expiry-c.IssuedAt) * time.Second
}

// NewID returns a random token ID.
func NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Sign returns the compact serialization of a token signed with key.
func Sign(key *ecdsa.PrivateKey, kid string, c Claims) (string, error) {
	h, err := json.Marshal(Header{Alg: "ES256", Kid: kid, Typ: "JWT"})
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	digest := sha256.Sum256([]byte(input))
	der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	raw, err := keys.DERToRaw(der)
	if err != nil {
		return "", err
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(raw), nil
}

// Errors returned by Verify.
var (
	ErrMalformed = errors.New("jwt: malformed token")
	ErrSignature = errors.New("jwt: bad signature")
	ErrExpired   = errors.New("jwt: expired or not yet valid")
)

// ParseUnverified decodes header and claims without checking anything.
func ParseUnverified(token string) (Header, Claims, error) {
	var h Header
	var c Claims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return h, c, ErrMalformed
	}
	hb, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	pb, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	if err1 != nil || err2 != nil {
		return h, c, ErrMalformed
	}
	if json.Unmarshal(hb, &h) != nil || json.Unmarshal(pb, &c) != nil {
		return h, c, ErrMalformed
	}
	return h, c, nil
}

// Verify checks the ES256 signature with the key that keyFor returns for
// the token's kid, and the time window at now.
func Verify(token string, keyFor func(kid string) *ecdsa.PublicKey, now time.Time) (Header, Claims, error) {
	h, c, err := ParseUnverified(token)
	if err != nil {
		return h, c, err
	}
	if h.Alg != "ES256" {
		return h, c, fmt.Errorf("%w: alg %q", ErrSignature, h.Alg)
	}
	pub := keyFor(h.Kid)
	if pub == nil {
		return h, c, fmt.Errorf("%w: unknown kid %q", ErrSignature, h.Kid)
	}
	i := strings.LastIndexByte(token, '.')
	sig, err := base64.RawURLEncoding.DecodeString(token[i+1:])
	if err != nil {
		return h, c, ErrMalformed
	}
	der, err := keys.RawToDER(sig)
	if err != nil {
		return h, c, ErrSignature
	}
	digest := sha256.Sum256([]byte(token[:i]))
	if !ecdsa.VerifyASN1(pub, digest[:], der) {
		return h, c, ErrSignature
	}
	if t := now.Unix(); t < c.NotBefore || t >= c.Expiry {
		return h, c, ErrExpired
	}
	return h, c, nil
}
