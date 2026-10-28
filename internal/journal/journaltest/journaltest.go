// Package journaltest provides admin keys and signed binding events for
// tests.
package journaltest

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/DunkelCloud/ergosum/internal/journal"
	"github.com/DunkelCloud/ergosum/internal/sshsig"
)

// Admins holds freshly generated admin SSH keys by name.
type Admins struct {
	Signers map[string]ssh.Signer
}

// NewAdmins generates one ed25519 key per name.
func NewAdmins(t testing.TB, names ...string) *Admins {
	t.Helper()
	a := &Admins{Signers: map[string]ssh.Signer{}}
	for _, n := range names {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		s, err := ssh.NewSignerFromKey(k)
		if err != nil {
			t.Fatal(err)
		}
		a.Signers[n] = s
	}
	return a
}

// Registry returns a registry configuration in which every admin is known
// and both kinds need threshold approvals from all admins.
func (a *Admins) Registry(threshold int) journal.RegistryConfig {
	cfg := journal.RegistryConfig{Admins: map[string]string{}, Approvals: map[string]journal.ApprovalConfig{}}
	names := make([]string, 0, len(a.Signers))
	for n, s := range a.Signers {
		cfg.Admins[n] = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey()))) + " " + n + "@example.com"
		names = append(names, n)
	}
	for _, kind := range []string{journal.KindBindingSet, journal.KindBindingRevoked} {
		cfg.Approvals[kind] = journal.ApprovalConfig{Threshold: threshold, Keys: names}
	}
	return cfg
}

// Sign appends a signature of each named admin to e.
func (a *Admins) Sign(t testing.TB, e *journal.BindingEvent, names ...string) *journal.BindingEvent {
	t.Helper()
	c, err := e.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		sig, err := sshsig.Sign(a.Signers[n], journal.Namespace, c)
		if err != nil {
			t.Fatal(err)
		}
		e.Signatures = append(e.Signatures, string(sig))
	}
	return e
}

// SignAs signs the canonical text of other (for example an older epoch)
// and attaches the signature to e.
func (a *Admins) SignAs(t testing.TB, e, other *journal.BindingEvent, name string) *journal.BindingEvent {
	t.Helper()
	c, err := other.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sshsig.Sign(a.Signers[name], journal.Namespace, c)
	if err != nil {
		t.Fatal(err)
	}
	e.Signatures = append(e.Signatures, string(sig))
	return e
}

// Set returns an unsigned binding.set event.
func Set(trustDomain, identity string, epoch uint64, key string, checks ...journal.Check) *journal.BindingEvent {
	return &journal.BindingEvent{V: 1, Kind: journal.KindBindingSet, TrustDomain: trustDomain, Identity: identity, Epoch: epoch, Key: key, Checks: checks}
}

// Revoke returns an unsigned binding.revoked event.
func Revoke(trustDomain, identity string, epoch uint64) *journal.BindingEvent {
	return &journal.BindingEvent{V: 1, Kind: journal.KindBindingRevoked, TrustDomain: trustDomain, Identity: identity, Epoch: epoch}
}
