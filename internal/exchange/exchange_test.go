package exchange

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
)

func testKey() []byte {
	k := make([]byte, KeySize)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func randomKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestVectors pins the derivation and the evaluation to values computed
// independently (RFC 5869 HKDF and affine P-256 arithmetic in Python).
func TestVectors(t *testing.T) {
	cases := []struct{ identity, s, S string }{
		{"host1.example.com",
			"379fce552fc9e07b86804f2aa3d712b40662a752f3119884d547bd514e132f26",
			"03ec796aa02f824b0a9131674d772de0d1878370f0ce9c78a84a94404dea6bd335"},
		{"host2.example.com",
			"27769cd4c4edaac04d79e903d60e69c19f729e69301c04072d350a216fb42f2c",
			"029211676f7953a7de4b2bce272c948719abcf6a4ed44fb1dde3a819e870912495"},
	}
	for _, c := range cases {
		s, err := DeriveScalar(testKey(), "example.com", c.identity)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(s[:]); got != c.s {
			t.Errorf("%s: s = %s, want %s", c.identity, got, c.s)
		}
		if got := hex.EncodeToString(ReleaseKey(s)); got != c.S {
			t.Errorf("%s: S = %s, want %s", c.identity, got, c.S)
		}
	}
	s, _ := DeriveScalar(testKey(), "example.com", "host1.example.com")
	// X = 7·G
	y, err := Evaluate(s, unhex(t, "028e533b6fa0bf7b4625bb30667c01fb607ef9f8b8a80fef5b300628703187b2a3"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(y), "0296a868bf0a02ed721454791bd8a43cae3bf3fbb54ededa9bac9fa994ff6c08cd"; got != want {
		t.Errorf("Y = %s, want %s", got, want)
	}
}

// TestRoundTrip: what the daemon pins it opens again through the instance,
// with a fresh blinding each time, and only with the scalar of its own
// identity.
func TestRoundTrip(t *testing.T) {
	key := randomKey(t)
	s, err := DeriveScalar(key, "example.com", "host1.example.com")
	if err != nil {
		t.Fatal(err)
	}
	S := ReleaseKey(s)
	C, K, err := Pin(S)
	if err != nil {
		t.Fatal(err)
	}
	var blinded [][]byte
	for range 2 {
		x, b, err := Blind(C, S)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(x, C) {
			t.Fatal("the blinded point is the client point")
		}
		blinded = append(blinded, x)
		y, err := Evaluate(s, x)
		if err != nil {
			t.Fatal(err)
		}
		k, err := b.Unblind(y)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(k, K) {
			t.Fatal("the opened key differs from the pinned one")
		}
	}
	if bytes.Equal(blinded[0], blinded[1]) {
		t.Fatal("two blindings of the same point are equal")
	}

	// Another machine that passes its own checks evaluates with its own
	// scalar and gets nothing out of this client point.
	other, _ := DeriveScalar(key, "example.com", "host2.example.com")
	x, b, _ := Blind(C, S)
	y, _ := Evaluate(other, x)
	k, err := b.Unblind(y)
	if err == nil && bytes.Equal(k, K) {
		t.Fatal("another identity's scalar opened the share")
	}
}

// TestNoRelationBetweenIdentities: for a scalar linear in the identity,
// s = x + H(id), the difference of two identities' scalars would be the
// same at every instance, and a machine could compute another machine's
// value from its own. With HKDF it differs from key to key.
func TestNoRelationBetweenIdentities(t *testing.T) {
	diff := func(key []byte) *big.Int {
		s1, _ := DeriveScalar(key, "example.com", "host1.example.com")
		s2, _ := DeriveScalar(key, "example.com", "host2.example.com")
		d := new(big.Int).Sub(new(big.Int).SetBytes(s2[:]), new(big.Int).SetBytes(s1[:]))
		return d.Mod(d, order)
	}
	if diff(randomKey(t)).Cmp(diff(randomKey(t))) == 0 {
		t.Fatal("the scalars of two identities differ by the same amount under two keys")
	}
	// The trust domain is part of the derivation too.
	a, _ := DeriveScalar(testKey(), "example.com", "host1.example.com")
	b, _ := DeriveScalar(testKey(), "example.org", "host1.example.com")
	if *a == *b {
		t.Fatal("the trust domain does not change the scalar")
	}
	// The separator keeps "a.b" + "c" apart from "a" + "b.c".
	c, _ := DeriveScalar(testKey(), "example.com", "x.example.com")
	d, _ := DeriveScalar(testKey(), "example.comx", "example.com")
	if *c == *d {
		t.Fatal("trust domain and identity run into each other")
	}
}

func TestBadPoints(t *testing.T) {
	s, _ := DeriveScalar(testKey(), "example.com", "host1.example.com")
	S := ReleaseKey(s)
	uncompressed := append([]byte{4}, make([]byte, 64)...)
	offCurve := append([]byte{2}, bytes.Repeat([]byte{0xff}, 32)...)
	for name, p := range map[string][]byte{
		"empty":        nil,
		"infinity":     {0},
		"short":        S[:32],
		"long":         append(append([]byte{}, S...), 0),
		"uncompressed": uncompressed,
		"off curve":    offCurve,
		"bad prefix":   append([]byte{5}, S[1:]...),
	} {
		if _, err := Evaluate(s, p); !errors.Is(err, ErrBadPoint) {
			t.Errorf("%s: Evaluate = %v, want ErrBadPoint", name, err)
		}
		if _, _, err := Pin(p); !errors.Is(err, ErrBadPoint) {
			t.Errorf("%s: Pin = %v, want ErrBadPoint", name, err)
		}
	}
	if _, err := DecodePoint("not base64!"); !errors.Is(err, ErrBadPoint) {
		t.Errorf("DecodePoint of junk: %v", err)
	}
	if b, err := DecodePoint(EncodePoint(S)); err != nil || !bytes.Equal(b, S) {
		t.Errorf("DecodePoint(EncodePoint(S)) = %x, %v", b, err)
	}
	if _, err := DeriveScalar(testKey()[:31], "example.com", "host1.example.com"); err == nil {
		t.Error("a short key was taken")
	}
}
