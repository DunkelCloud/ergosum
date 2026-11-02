package secret

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
	"golang.org/x/crypto/ssh"

	"github.com/DunkelCloud/ergosum/internal/exchange"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/protocol"
)

func TestGF(t *testing.T) {
	// FIPS-197, section 4.2, and the inverse pair of section 5.1.1.
	if got := gfMul(0x57, 0x83); got != 0xc1 {
		t.Fatalf("57·83 = %02x, want c1", got)
	}
	if got := gfMul(0x53, 0xca); got != 0x01 {
		t.Fatalf("53·ca = %02x, want 01", got)
	}
	for a := 1; a < 256; a++ {
		if gfMul(byte(a), gfInv(byte(a))) != 1 {
			t.Fatalf("%02x · %02x^-1 != 1", a, a)
		}
	}
}

func TestShamir(t *testing.T) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	const n, k = 5, 3
	shares, err := split(secret, n, k)
	if err != nil {
		t.Fatal(err)
	}
	for mask := 1; mask < 1<<n; mask++ {
		sub := map[int][]byte{}
		for i := range n {
			if mask&(1<<i) != 0 {
				sub[i+1] = shares[i]
			}
		}
		got, err := combine(sub)
		if err != nil {
			t.Fatal(err)
		}
		if ok := bytes.Equal(got, secret); ok != (len(sub) >= k) {
			t.Fatalf("%d shares (mask %05b): recovered %v", len(sub), mask, ok)
		}
	}
	// With a threshold of 1 every share is the secret.
	ones, _ := split(secret, 3, 1)
	for _, s := range ones {
		if !bytes.Equal(s, secret) {
			t.Fatal("a share of threshold 1 is not the secret")
		}
	}
}

// instance simulates an authority instance with its exchange key.
type instance struct {
	fp  string
	key []byte
}

func newInstances(t *testing.T, n int) []*instance {
	t.Helper()
	out := make([]*instance, n)
	for i := range out {
		k, _ := keys.GenerateExchangeKey()
		sig, _ := keys.Generate()
		out[i] = &instance{fp: keys.Fingerprint(&sig.PublicKey), key: k}
	}
	return out
}

func (in *instance) target(t *testing.T, td, id string) Target {
	t.Helper()
	s, err := exchange.DeriveScalar(in.key, td, id)
	if err != nil {
		t.Fatal(err)
	}
	S := exchange.ReleaseKey(s)
	sig, _ := keys.Generate()
	env, err := protocol.Seal(sig, protocol.ContextReleaseKey, protocol.ReleaseKey{
		V: 1, Type: protocol.TypeReleaseKey, TrustDomain: td, Identity: id, Authority: "kid", Key: exchange.EncodePoint(S),
	})
	if err != nil {
		t.Fatal(err)
	}
	return Target{Authority: in.fp, ReleaseKey: env, Key: S}
}

// openShare runs the exchange for pin i as the daemon and the instance do.
func openShare(t *testing.T, s *Sealed, i int, in *instance, identity string) ([]byte, error) {
	t.Helper()
	_, S, err := s.Pins[i].ReleaseKeyPayload()
	if err != nil {
		t.Fatal(err)
	}
	x, b, err := exchange.Blind(s.Pins[i].Point(), S)
	if err != nil {
		t.Fatal(err)
	}
	scalar, _ := exchange.DeriveScalar(in.key, s.TrustDomain, identity)
	y, err := exchange.Evaluate(scalar, x)
	if err != nil {
		t.Fatal(err)
	}
	kx, err := b.Unblind(y)
	if err != nil {
		return nil, err
	}
	return s.OpenShare(i, kx)
}

func TestSealOpen(t *testing.T) {
	const td, id = "example.com", "host1.example.com"
	ins := newInstances(t, 3)
	var targets []Target
	for _, in := range ins {
		targets = append(targets, in.target(t, td, id))
	}
	plain := []byte("it's a secret\n")
	s, master, err := Seal(plain, "restic", td, id, 2, targets, "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, plain[:12]) {
		t.Fatal("part A contains the secret")
	}
	s, err = Parse(data)
	if err != nil {
		t.Fatal(err)
	}

	for _, pair := range [][2]int{{0, 1}, {0, 2}, {1, 2}} {
		shares := map[int][]byte{}
		for _, i := range pair {
			sh, err := openShare(t, s, i, ins[i], id)
			if err != nil {
				t.Fatal(err)
			}
			shares[i] = sh
		}
		got, m, err := s.Open(shares)
		if err != nil || !bytes.Equal(got, plain) || !bytes.Equal(m, master) {
			t.Fatalf("pins %v: %q, %v", pair, got, err)
		}
	}
	one, _ := openShare(t, s, 0, ins[0], id)
	if _, _, err := s.Open(map[int][]byte{0: one}); err == nil {
		t.Fatal("opened with fewer shares than the threshold")
	}
	// Another identity, or another instance's key, opens no share.
	if _, err := openShare(t, s, 0, ins[0], "host2.example.com"); err == nil {
		t.Fatal("another identity opened a share")
	}
	if _, err := openShare(t, s, 0, ins[1], id); err == nil {
		t.Fatal("another instance opened a share")
	}

	// Re-splitting keeps the ciphertext and makes new client points.
	r, err := s.Reshare(master, targets[1:])
	if err != nil {
		t.Fatal(err)
	}
	if r.Ciphertext != s.Ciphertext || r.Threshold != 2 || len(r.Pins) != 2 || r.Pins[0].ClientPoint == s.Pins[1].ClientPoint {
		t.Fatalf("re-split: %+v", r)
	}
	a, _ := openShare(t, r, 0, ins[1], id)
	b, _ := openShare(t, r, 1, ins[2], id)
	if got, _, err := r.Open(map[int][]byte{0: a, 1: b}); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("re-split part A: %q, %v", got, err)
	}
	if _, err := s.Reshare(master, targets[:1]); err == nil {
		t.Fatal("re-split below the threshold")
	}
}

func TestParseRefuses(t *testing.T) {
	const td, id = "example.com", "host1.example.com"
	ins := newInstances(t, 2)
	targets := []Target{ins[0].target(t, td, id), ins[1].target(t, td, id)}
	good, _, err := Seal([]byte("x"), "restic", td, id, 1, targets, "")
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(s *Sealed){
		"version":           func(s *Sealed) { s.V = 2 },
		"type":              func(s *Sealed) { s.Type = "other" },
		"name":              func(s *Sealed) { s.Name = "Restic" },
		"long name":         func(s *Sealed) { s.Name = strings.Repeat("a", 64) },
		"identity":          func(s *Sealed) { s.Identity = "host1" },
		"threshold 0":       func(s *Sealed) { s.Threshold = 0 },
		"threshold > pins":  func(s *Sealed) { s.Threshold = 3 },
		"repeated instance": func(s *Sealed) { s.Pins[1].Authority = s.Pins[0].Authority },
		"bad point":         func(s *Sealed) { s.Pins[0].ClientPoint = "AA" },
		"bad share":         func(s *Sealed) { s.Pins[0].Share = "!" },
	} {
		c := *good
		c.Pins = append([]Pin(nil), good.Pins...)
		change(&c)
		data, _ := c.Marshal()
		if _, err := Parse(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, _, err := Seal(make([]byte, MaxSecret+1), "restic", td, id, 1, targets, ""); err == nil {
		t.Error("a secret over the limit was sealed")
	}
	many := make([]Target, MaxPins+1)
	for i := range many {
		many[i] = newInstances(t, 1)[0].target(t, td, id)
	}
	if _, _, err := Seal([]byte("x"), "restic", td, id, 1, many, ""); err == nil {
		t.Error("more pins than allowed")
	}
	if _, err := Parse(make([]byte, MaxPartA+1)); err == nil {
		t.Error("part A over the limit parsed")
	}
}

func TestRecovery(t *testing.T) {
	plain := []byte("repository password")
	x, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	sshLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " admin@example.com"
	armored, err := Recovery(plain, []string{x.Recipient().String(), sshLine})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(armored, armor.Header) {
		t.Fatalf("not armored: %q", armored[:30])
	}
	sshID, err := agessh.NewEd25519Identity(priv)
	if err != nil {
		t.Fatal(err)
	}
	for name, id := range map[string]age.Identity{"x25519": x, "ssh-ed25519": sshID} {
		r, err := age.Decrypt(armor.NewReader(strings.NewReader(armored)), id)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, _ := io.ReadAll(r)
		if !bytes.Equal(got, plain) {
			t.Fatalf("%s: %q", name, got)
		}
	}
	if s, err := Recovery(plain, nil); err != nil || s != "" {
		t.Fatalf("no recipients: %q, %v", s, err)
	}
	for _, bad := range []string{"ssh-rsa AAAAB3NzaC1yc2E", "age1notakey", "hello"} {
		if _, err := Recovery(plain, []string{bad}); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
}
