// Package secret implements part A of ADR 0004: a secret encrypted under a
// master key whose Shamir shares are pinned to authority instances, so
// that the machine opens it only after it has passed its checks at a
// threshold of them.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/DunkelCloud/ergosum/internal/exchange"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/protocol"
)

// Limits of part A.
const (
	MaxPins   = 16
	MaxSecret = 64 << 10
	MaxPartA  = 1 << 20
)

// Type is the "type" of part A.
const Type = "sealed_secret"

// Key derivation and associated data (ADR 0004, Part A).
const (
	secretSalt = "ergosum/v1/secret"        //nolint:gosec // an HKDF salt, not a credential
	shareSalt  = "ergosum/v1/share"         //nolint:gosec // an HKDF salt, not a credential
	secretAD   = "ergosum/v1/sealed-secret" //nolint:gosec // associated data, not a credential
	masterSize = 32
)

var nameRe = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)

// ValidName reports whether s can name a secret: lower-case letters,
// digits and hyphens, at most 63 characters.
func ValidName(s string) bool { return nameRe.MatchString(s) }

// Sealed is part A. Binary members are unpadded base64url.
type Sealed struct {
	V           int    `json:"v"`
	Type        string `json:"type"`
	Name        string `json:"name"`
	TrustDomain string `json:"trust_domain"`
	Identity    string `json:"identity"`
	Threshold   int    `json:"threshold"`
	Pins        []Pin  `json:"pins"`
	// Ciphertext is nonce || AES-256-GCM ciphertext of the secret.
	Ciphertext string `json:"ciphertext"`
	// Recovery is the secret encrypted with age to the recovery
	// recipients, ASCII-armored; empty without recipients.
	Recovery string `json:"recovery,omitempty"`
}

// Pin is one share, pinned to one instance.
type Pin struct {
	// Authority is the instance's key fingerprint.
	Authority string `json:"authority"`
	// ReleaseKey is the instance's signed release key for the identity.
	ReleaseKey protocol.Envelope `json:"release_key"`
	// ClientPoint is C = c·G.
	ClientPoint string `json:"client_point"`
	// Share is nonce || AES-256-GCM ciphertext of the share.
	Share string `json:"share"`
}

// Target is an instance to pin a share to.
type Target struct {
	Authority  string            // key fingerprint
	ReleaseKey protocol.Envelope // as the instance signed it
	Key        []byte            // S from the release key, verified by the caller
}

// Seal encrypts secret under a new master key and pins one share of it to
// each target; threshold of them open it. recovery is the armored age file
// for the way back, or empty.
func Seal(plain []byte, name, trustDomain, identity string, threshold int, targets []Target, recovery string) (*Sealed, []byte, error) {
	if len(plain) > MaxSecret {
		return nil, nil, fmt.Errorf("secret: more than %d bytes", MaxSecret)
	}
	master := make([]byte, masterSize)
	if _, err := rand.Read(master); err != nil {
		return nil, nil, err
	}
	s := &Sealed{V: 1, Type: Type, Name: name, TrustDomain: trustDomain, Identity: identity, Threshold: threshold, Recovery: recovery}
	key, err := s.secretKey(master)
	if err != nil {
		return nil, nil, err
	}
	ct, err := seal(key, plain, []byte(secretAD))
	if err != nil {
		return nil, nil, err
	}
	s.Ciphertext = encode(ct)
	if err := s.pin(master, targets); err != nil {
		return nil, nil, err
	}
	if err := s.validate(); err != nil {
		return nil, nil, err
	}
	return s, master, nil
}

// Reshare returns part A with new shares of master for the targets, with
// new client points, and the same threshold, ciphertext and recovery.
func (s *Sealed) Reshare(master []byte, targets []Target) (*Sealed, error) {
	n := *s
	n.Pins = nil
	if err := n.pin(master, targets); err != nil {
		return nil, err
	}
	if err := n.validate(); err != nil {
		return nil, err
	}
	return &n, nil
}

func (s *Sealed) pin(master []byte, targets []Target) error {
	if len(targets) < s.Threshold {
		return fmt.Errorf("secret: %d instances for a threshold of %d", len(targets), s.Threshold)
	}
	if len(targets) > MaxPins {
		return fmt.Errorf("secret: more than %d pins", MaxPins)
	}
	shares, err := split(master, len(targets), s.Threshold)
	if err != nil {
		return err
	}
	for i, t := range targets {
		c, kx, err := exchange.Pin(t.Key)
		if err != nil {
			return fmt.Errorf("secret: %s: %w", t.Authority, err)
		}
		key, err := s.shareKey(t.Authority, kx)
		if err != nil {
			return err
		}
		ct, err := seal(key, shares[i], c)
		if err != nil {
			return err
		}
		s.Pins = append(s.Pins, Pin{Authority: t.Authority, ReleaseKey: t.ReleaseKey, ClientPoint: exchange.EncodePoint(c), Share: encode(ct)})
	}
	return nil
}

// Parse decodes and checks part A.
func Parse(data []byte) (*Sealed, error) {
	if len(data) > MaxPartA {
		return nil, fmt.Errorf("secret: part A larger than %d bytes", MaxPartA)
	}
	var s Sealed
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("secret: not a part A: %w", err)
	}
	return &s, s.validate()
}

// Marshal encodes part A as written to its file.
func (s *Sealed) Marshal() ([]byte, error) {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func (s *Sealed) validate() error {
	switch {
	case s.V != 1 || s.Type != Type:
		return errors.New("secret: not a part A of version 1")
	case !ValidName(s.Name):
		return fmt.Errorf("secret: bad name %q", s.Name)
	case !protocol.ValidDNSName(s.TrustDomain) || !protocol.ValidDNSName(s.Identity):
		return errors.New("secret: bad trust domain or identity")
	case len(s.Pins) > MaxPins:
		return fmt.Errorf("secret: more than %d pins", MaxPins)
	case s.Threshold < 1 || s.Threshold > len(s.Pins):
		return fmt.Errorf("secret: threshold %d for %d pins", s.Threshold, len(s.Pins))
	}
	if _, err := decode(s.Ciphertext); err != nil {
		return errors.New("secret: bad ciphertext")
	}
	seen := map[string]bool{}
	for i, p := range s.Pins {
		if !keys.ValidFingerprint(p.Authority) || seen[p.Authority] {
			return fmt.Errorf("secret: pin %d: bad or repeated authority", i+1)
		}
		seen[p.Authority] = true
		if _, err := exchange.DecodePoint(p.ClientPoint); err != nil {
			return fmt.Errorf("secret: pin %d: %w", i+1, err)
		}
		if _, err := decode(p.Share); err != nil {
			return fmt.Errorf("secret: pin %d: bad share", i+1)
		}
	}
	return nil
}

// ReleaseKeyPayload returns the release key of a pin as it stands in part
// A, and S from it. The signature is not checked here; an exchange with
// the instance shows whether it still holds the same key.
func (p Pin) ReleaseKeyPayload() (protocol.ReleaseKey, []byte, error) {
	var rk protocol.ReleaseKey
	if err := p.ReleaseKey.Decode(&rk); err != nil {
		return rk, nil, err
	}
	key, err := exchange.DecodePoint(rk.Key)
	return rk, key, err
}

// Point returns the client point C of a pin.
func (p Pin) Point() []byte {
	c, _ := exchange.DecodePoint(p.ClientPoint) // checked by validate
	return c
}

// OpenShare decrypts the share of pin i (0-based) with the x-coordinate of
// K that the exchange with its instance yields.
func (s *Sealed) OpenShare(i int, keyX []byte) ([]byte, error) {
	p := s.Pins[i]
	key, err := s.shareKey(p.Authority, keyX)
	if err != nil {
		return nil, err
	}
	ct, _ := decode(p.Share) // checked by validate
	share, err := open(key, ct, p.Point())
	if err != nil || len(share) != masterSize {
		return nil, fmt.Errorf("secret: the share of %s does not open", p.Authority)
	}
	return share, nil
}

// Open recovers the master key from at least Threshold opened shares,
// keyed by pin index (0-based), and decrypts the secret.
func (s *Sealed) Open(shares map[int][]byte) (plain, master []byte, err error) {
	if len(shares) < s.Threshold {
		return nil, nil, fmt.Errorf("secret: %d of %d shares", len(shares), s.Threshold)
	}
	at := make(map[int][]byte, s.Threshold)
	for i, sh := range shares {
		if len(at) == s.Threshold {
			break
		}
		at[i+1] = sh
	}
	if master, err = combine(at); err != nil {
		return nil, nil, err
	}
	key, err := s.secretKey(master)
	if err != nil {
		return nil, nil, err
	}
	ct, _ := decode(s.Ciphertext) // checked by validate
	if plain, err = open(key, ct, []byte(secretAD)); err != nil {
		return nil, nil, errors.New("secret: the shares do not open the secret")
	}
	return plain, master, nil
}

func (s *Sealed) secretKey(master []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, master, []byte(secretSalt), s.TrustDomain+"\x00"+s.Identity+"\x00"+s.Name, 32)
}

func (s *Sealed) shareKey(authority string, keyX []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, keyX, []byte(shareSalt), authority+"\x00"+s.TrustDomain+"\x00"+s.Identity+"\x00"+s.Name, 32)
}

func seal(key, plain, ad []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plain, ad), nil
}

func open(key, ct, ad []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(ct) < aead.NonceSize() {
		return nil, errors.New("secret: ciphertext too short")
	}
	return aead.Open(nil, ct[:aead.NonceSize()], ct[aead.NonceSize():], ad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func decode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
