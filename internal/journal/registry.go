package journal

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"
	"sort"

	"golang.org/x/crypto/ssh"

	"github.com/DunkelCloud/ergosum/internal/sshsig"
)

// RegistryConfig is the admin public key registry as configured on every
// instance. It is the trust root for binding events.
type RegistryConfig struct {
	// Admins maps a name to a public key in authorized_keys format.
	Admins map[string]string `yaml:"admins"`
	// Approvals maps an event kind to its threshold and allowed signers.
	Approvals map[string]ApprovalConfig `yaml:"approvals"`
}

// ApprovalConfig is the threshold and key set for one event kind.
type ApprovalConfig struct {
	Threshold int      `yaml:"threshold"`
	Keys      []string `yaml:"keys"`
}

// Registry verifies admin approvals of binding events.
type Registry struct {
	admins    map[string]ssh.PublicKey
	approvals map[string]ApprovalConfig
}

// Errors returned by Registry.Verify.
var (
	ErrInvalidSignature = errors.New("signature does not verify over this event")
	ErrUnknownSigner    = errors.New("signer is not in the key set for this kind")
	ErrDuplicateSigner  = errors.New("key signed more than once")
	ErrBelowThreshold   = errors.New("not enough approvals")
	// ErrTooManySignatures: more signatures than the kind has allowed keys.
	// Such an event cannot be valid and is refused before any signature is
	// verified.
	ErrTooManySignatures = errors.New("more signatures than allowed keys")
)

// NewRegistry validates and loads a registry configuration.
func NewRegistry(cfg RegistryConfig) (*Registry, error) {
	r := &Registry{admins: map[string]ssh.PublicKey{}, approvals: map[string]ApprovalConfig{}}
	fps := map[string]string{}
	for name, line := range cfg.Admins {
		pub, err := sshsig.ParseAuthorizedKey(line)
		if err != nil {
			return nil, fmt.Errorf("registry: admin %q: %w", name, err)
		}
		if err := checkAdminKey(pub); err != nil {
			return nil, fmt.Errorf("registry: admin %q: %w", name, err)
		}
		fp := sshsig.Fingerprint(pub)
		if other, dup := fps[fp]; dup {
			return nil, fmt.Errorf("registry: admins %q and %q share key %s", other, name, fp)
		}
		fps[fp] = name
		r.admins[name] = pub
	}
	for _, kind := range []string{KindBindingSet, KindBindingRevoked} {
		ap, ok := cfg.Approvals[kind]
		if !ok {
			return nil, fmt.Errorf("registry: no approvals for %s", kind)
		}
		if ap.Threshold < 1 || ap.Threshold > len(ap.Keys) {
			return nil, fmt.Errorf("registry: %s: threshold %d with %d keys", kind, ap.Threshold, len(ap.Keys))
		}
		seen := map[string]bool{}
		for _, k := range ap.Keys {
			if _, ok := r.admins[k]; !ok {
				return nil, fmt.Errorf("registry: %s: unknown admin %q", kind, k)
			}
			if seen[k] {
				return nil, fmt.Errorf("registry: %s: admin %q listed twice", kind, k)
			}
			seen[k] = true
		}
		r.approvals[kind] = ap
	}
	for kind := range cfg.Approvals {
		if _, ok := r.approvals[kind]; !ok {
			return nil, fmt.Errorf("registry: unknown event kind %q", kind)
		}
	}
	return r, nil
}

// minRSABits is the smallest RSA modulus accepted for an admin key.
const minRSABits = 2048

// checkAdminKey refuses keys that are too weak to serve as a trust root, and
// certificates, whose signatures would never match the plain key anyway.
func checkAdminKey(pub ssh.PublicKey) error {
	if _, ok := pub.(*ssh.Certificate); ok {
		return errors.New("certificates are not accepted; use the plain public key")
	}
	if pub.Type() == sshsig.KeyAlgoDSA {
		return errors.New("ssh-dss keys are not accepted")
	}
	if ck, ok := pub.(ssh.CryptoPublicKey); ok {
		if k, ok := ck.CryptoPublicKey().(*rsa.PublicKey); ok && k.N.BitLen() < minRSABits {
			return fmt.Errorf("RSA key has %d bits, at least %d are required", k.N.BitLen(), minRSABits)
		}
	}
	return nil
}

// Verify checks that the event carries at least the threshold of valid
// signatures from distinct keys of its kind's key set. Every signature must
// verify over the event's canonical text and come from an allowed key; a
// key may sign only once. An event with more signatures than the kind has
// keys is refused before any of them is verified. It returns the names of
// the signers.
func (r *Registry) Verify(e *BindingEvent) ([]string, error) {
	canonical, err := e.Canonical()
	if err != nil {
		return nil, err
	}
	ap, ok := r.approvals[e.Kind]
	if !ok {
		return nil, fmt.Errorf("%w: kind %s", ErrUnknownSigner, e.Kind)
	}
	if len(e.Signatures) > len(ap.Keys) {
		return nil, fmt.Errorf("%w: %d signatures for %d keys of %s", ErrTooManySignatures, len(e.Signatures), len(ap.Keys), e.Kind)
	}
	seen := map[string]bool{}
	var signers []string
	for i, sig := range e.Signatures {
		pub, err := sshsig.Verify([]byte(sig), Namespace, canonical)
		if err != nil {
			return nil, fmt.Errorf("%w: signature %d: %w", ErrInvalidSignature, i+1, err)
		}
		name := r.allowed(ap, pub)
		if name == "" {
			return nil, fmt.Errorf("%w: signature %d by %s", ErrUnknownSigner, i+1, sshsig.Fingerprint(pub))
		}
		if seen[name] {
			return nil, fmt.Errorf("%w: %s (%s)", ErrDuplicateSigner, name, sshsig.Fingerprint(pub))
		}
		seen[name] = true
		signers = append(signers, name)
	}
	if len(signers) < ap.Threshold {
		return nil, fmt.Errorf("%w: %d of %d for %s", ErrBelowThreshold, len(signers), ap.Threshold, e.Kind)
	}
	sort.Strings(signers)
	return signers, nil
}

func (r *Registry) allowed(ap ApprovalConfig, pub ssh.PublicKey) string {
	m := pub.Marshal()
	for _, name := range ap.Keys {
		if bytes.Equal(r.admins[name].Marshal(), m) {
			return name
		}
	}
	return ""
}
