// Package exchange implements the McCallum-Relyea exchange of ADR 0004 on
// P-256: the scalar of an identity at an authority instance, its release
// key, the evaluation of blinded points at the instance, and the daemon's
// side of pinning a share to an instance and opening it again.
package exchange

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"

	"filippo.io/nistec"
)

// KeySize is the size of an instance's exchange key.
const KeySize = 32

// PointSize is the size of an encoded point: compressed SEC 1.
const PointSize = 33

// scalarSalt is the HKDF salt of the scalar derivation.
const scalarSalt = "ergosum/v1/exchange"

// order is n, the order of the P-256 group.
var order, _ = new(big.Int).SetString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)

// ErrBadPoint is returned for an encoding that is not a compressed point on
// P-256 other than the point at infinity.
var ErrBadPoint = errors.New("exchange: not a compressed point on P-256")

// Scalar is a scalar in [1, n-1], 32 bytes big endian.
type Scalar [32]byte

// DeriveScalar returns the scalar s of identity in trustDomain at the
// instance holding key:
//
//	OS2IP(HKDF-SHA256(ikm = key, salt = "ergosum/v1/exchange",
//	                  info = trustDomain || 0x00 || identity, L = 48)) mod n
//
// The 48 bytes make the bias of the reduction negligible. HKDF keeps the
// scalars of two identities unrelated: with a scalar linear in the identity,
// one machine could compute another machine's value from its own. The
// reduction is not constant-time; it runs only for an identity that has
// passed its checks, and could tell that identity only about its own scalar.
func DeriveScalar(key []byte, trustDomain, identity string) (*Scalar, error) {
	if len(key) != KeySize {
		return nil, errors.New("exchange: the key must be 32 bytes")
	}
	okm, err := hkdf.Key(sha256.New, key, []byte(scalarSalt), trustDomain+"\x00"+identity, 48)
	if err != nil {
		return nil, err
	}
	s, ok := reduce(okm)
	if !ok {
		return nil, errors.New("exchange: the derived scalar is zero")
	}
	return s, nil
}

// reduce returns b mod n as a Scalar; false if that is zero.
func reduce(b []byte) (*Scalar, bool) {
	x := new(big.Int).SetBytes(b)
	x.Mod(x, order)
	if x.Sign() == 0 {
		return nil, false
	}
	var s Scalar
	x.FillBytes(s[:])
	return &s, true
}

// randomScalar returns a uniformly random scalar.
func randomScalar() (*Scalar, error) {
	b := make([]byte, 48)
	for {
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		if s, ok := reduce(b); ok {
			return s, nil
		}
	}
}

// ReleaseKey returns S = s·G, encoded.
func ReleaseKey(s *Scalar) []byte {
	p, err := nistec.NewP256Point().ScalarBaseMult(s[:])
	if err != nil {
		panic(err) // a Scalar has the length ScalarBaseMult takes
	}
	return p.BytesCompressed()
}

// ParsePoint decodes a compressed point. Uncompressed encodings, points
// off the curve and the point at infinity are refused.
func ParsePoint(b []byte) (*nistec.P256Point, error) {
	if len(b) != PointSize {
		return nil, ErrBadPoint
	}
	p, err := nistec.NewP256Point().SetBytes(b)
	if err != nil || p.IsInfinity() == 1 {
		return nil, ErrBadPoint
	}
	return p, nil
}

// EncodePoint returns the wire form of an encoded point: unpadded
// base64url.
func EncodePoint(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// DecodePoint parses the wire form of a point and checks it with
// ParsePoint.
func DecodePoint(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, ErrBadPoint
	}
	if _, err := ParsePoint(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Evaluate returns Y = s·X for a blinded point X, as the instance answers
// an exchange request.
func Evaluate(s *Scalar, x []byte) ([]byte, error) {
	p, err := ParsePoint(x)
	if err != nil {
		return nil, err
	}
	y, err := nistec.NewP256Point().ScalarMult(p, s[:])
	if err != nil {
		return nil, err
	}
	return y.BytesCompressed(), nil
}

// Pin pins a share to the instance with release key S: it picks a random
// c and returns the client point C = c·G and the x-coordinate of K = c·S,
// the key material of the share. c is forgotten.
func Pin(releaseKey []byte) (clientPoint, keyX []byte, err error) {
	sp, err := ParsePoint(releaseKey)
	if err != nil {
		return nil, nil, err
	}
	c, err := randomScalar()
	if err != nil {
		return nil, nil, err
	}
	cp, err := nistec.NewP256Point().ScalarBaseMult(c[:])
	if err != nil {
		return nil, nil, err
	}
	k, err := nistec.NewP256Point().ScalarMult(sp, c[:])
	if err != nil {
		return nil, nil, err
	}
	keyX, err = k.BytesX()
	if err != nil {
		return nil, nil, err
	}
	return cp.BytesCompressed(), keyX, nil
}

// Blinding is the blinding of one client point for one exchange request.
type Blinding struct {
	e          Scalar
	releaseKey *nistec.P256Point
}

// Blind returns the blinded point X = C + e·G for a random e, which is
// uniformly random to the instance, and what Unblind needs.
func Blind(clientPoint, releaseKey []byte) (x []byte, b *Blinding, err error) {
	cp, err := ParsePoint(clientPoint)
	if err != nil {
		return nil, nil, err
	}
	sp, err := ParsePoint(releaseKey)
	if err != nil {
		return nil, nil, err
	}
	e, err := randomScalar()
	if err != nil {
		return nil, nil, err
	}
	eg, err := nistec.NewP256Point().ScalarBaseMult(e[:])
	if err != nil {
		return nil, nil, err
	}
	xp := nistec.NewP256Point().Add(cp, eg)
	if xp.IsInfinity() == 1 {
		return nil, nil, errors.New("exchange: blinded point at infinity")
	}
	return xp.BytesCompressed(), &Blinding{e: *e, releaseKey: sp}, nil
}

// Unblind returns the x-coordinate of K = Y − e·S from the instance's
// answer Y.
func (b *Blinding) Unblind(y []byte) ([]byte, error) {
	yp, err := ParsePoint(y)
	if err != nil {
		return nil, err
	}
	es, err := nistec.NewP256Point().ScalarMult(b.releaseKey, b.e[:])
	if err != nil {
		return nil, err
	}
	k := nistec.NewP256Point().Add(yp, nistec.NewP256Point().Negate(es))
	if k.IsInfinity() == 1 {
		return nil, ErrBadPoint
	}
	return k.BytesX()
}
