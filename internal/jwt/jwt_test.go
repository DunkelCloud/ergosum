package jwt

import (
	"crypto/ecdsa"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ergosum/internal/keys"
)

func TestSignVerify(t *testing.T) {
	k, _ := keys.Generate()
	kid := keys.Thumbprint(&k.PublicKey)
	now := time.Unix(1_800_000_000, 0)
	c := Claims{
		Issuer:    "https://ergosum.example.com",
		Subject:   "spiffe://example.com/host/host1.example.com",
		Audience:  []string{"vault"},
		Host:      "host1.example.com",
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		Expiry:    now.Add(30 * time.Minute).Unix(),
		ID:        NewID(),
		Checks:    []string{"key", "tailnet", "ip"},
	}
	tok, err := Sign(k, kid, c)
	if err != nil {
		t.Fatal(err)
	}
	keyFor := func(id string) *ecdsa.PublicKey {
		if id == kid {
			return &k.PublicKey
		}
		return nil
	}
	h, got, err := Verify(tok, keyFor, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if h.Alg != "ES256" || h.Kid != kid || h.Typ != "JWT" {
		t.Fatalf("header %+v", h)
	}
	if got.Subject != c.Subject || got.Lifetime() != 30*time.Minute {
		t.Fatalf("claims %+v", got)
	}
	if _, _, err := Verify(tok, keyFor, now.Add(31*time.Minute)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired token: %v", err)
	}
	other, _ := keys.Generate()
	if _, _, err := Verify(tok, func(string) *ecdsa.PublicKey { return &other.PublicKey }, now); !errors.Is(err, ErrSignature) {
		t.Fatalf("other key: %v", err)
	}
	parts := strings.Split(tok, ".")
	forged := parts[0] + "." + parts[1] + "x." + parts[2]
	if _, _, err := Verify(forged, keyFor, now); err == nil {
		t.Fatal("modified token accepted")
	}
}
