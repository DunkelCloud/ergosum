// Package journal implements the binding journal: append-only events in
// SQLite, admin approval of binding events through SSH signatures with a
// per-kind threshold, the per-identity projection and its ordering rule
// (see docs/adr/0003-journal-format-and-replication.md).
package journal

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/protocol"
)

// Event kinds.
const (
	KindBindingSet     = "binding.set"
	KindBindingRevoked = "binding.revoked"
	KindObservation    = "observation" // prefix; full kinds are observation.<result>
	KindCheckpoint     = "checkpoint"
)

// Namespace is the SSHSIG namespace of admin signatures over binding events.
const Namespace = "ergosum-binding"

// MaxEpoch is the highest epoch of a binding event. Above it nothing could
// follow, so a binding at the very top of the range could never be revoked.
const MaxEpoch = 1 << 53

// CanonicalHeader is the first line of the canonical form.
const CanonicalHeader = "ergosum binding v1"

// Check is one callback check of a binding.
type Check struct {
	Type   string `json:"type"`
	Target string `json:"target"`
}

// BindingEvent is an admin-signed binding.set or binding.revoked event.
type BindingEvent struct {
	V           int      `json:"v"`
	Kind        string   `json:"kind"`
	TrustDomain string   `json:"trust_domain"`
	Identity    string   `json:"identity"`
	Epoch       uint64   `json:"epoch"`
	Key         string   `json:"key,omitempty"`
	Checks      []Check  `json:"checks,omitempty"`
	Signatures  []string `json:"signatures"`
}

// ErrInvalidEvent wraps all validation errors of the event content.
var ErrInvalidEvent = errors.New("invalid binding event")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidEvent, fmt.Sprintf(format, a...))
}

// Validate checks the event content (not its signatures).
func (e *BindingEvent) Validate() error {
	if e.V != 1 {
		return invalid("unsupported version %d", e.V)
	}
	if !protocol.ValidDNSName(e.TrustDomain) {
		return invalid("bad trust domain %q", e.TrustDomain)
	}
	if !protocol.ValidDNSName(e.Identity) {
		return invalid("bad identity %q", e.Identity)
	}
	if e.Epoch < 1 || e.Epoch > MaxEpoch {
		return invalid("epoch must be between 1 and 2^53")
	}
	switch e.Kind {
	case KindBindingSet:
		if !keys.ValidFingerprint(e.Key) {
			return invalid("bad key fingerprint %q", e.Key)
		}
		if len(e.Checks) == 0 {
			return invalid("binding.set needs at least one callback check")
		}
		seen := map[Check]bool{}
		for _, c := range e.Checks {
			if err := validateCheck(c); err != nil {
				return err
			}
			if seen[c] {
				return invalid("duplicate check %s %s", c.Type, c.Target)
			}
			seen[c] = true
		}
	case KindBindingRevoked:
		if e.Key != "" || len(e.Checks) != 0 {
			return invalid("binding.revoked carries no key and no checks")
		}
	default:
		return invalid("unknown kind %q", e.Kind)
	}
	return nil
}

func validateCheck(c Check) error {
	switch c.Type {
	case protocol.CheckTailnet:
		host, _, err := SplitTarget(c.Target)
		if err != nil || !protocol.ValidDNSName(host) {
			return invalid("bad tailnet target %q", c.Target)
		}
	case protocol.CheckIP:
		host, _, err := SplitTarget(c.Target)
		if err != nil {
			return invalid("bad ip target %q", c.Target)
		}
		a, err := netip.ParseAddr(host)
		if err != nil || a.Zone() != "" || a.Is4In6() || !a.IsGlobalUnicast() {
			return invalid("bad ip target %q", c.Target)
		}
		if a.String() != host {
			return invalid("ip target %q is not in canonical form (%s)", c.Target, a)
		}
	case protocol.CheckNet:
		p, err := netip.ParsePrefix(c.Target)
		if err != nil || p.Masked() != p || p.String() != c.Target {
			return invalid("bad net target %q (want a masked prefix such as 198.51.100.0/24)", c.Target)
		}
	default:
		return invalid("unknown check type %q", c.Type)
	}
	return nil
}

// SplitTarget splits "host" or "host:port" (IPv6 as "[addr]:port" or bare
// "addr") into host and port; port is 0 when absent. The host is returned as
// written, so that validation can insist on the canonical form. Every
// target has one spelling only: the port is plain decimal without sign or
// leading zeros, and brackets go around IPv6 addresses only.
func SplitTarget(t string) (host string, port int, err error) {
	if _, perr := netip.ParseAddr(t); perr == nil {
		return t, 0, nil
	}
	if !strings.Contains(t, ":") {
		return t, 0, nil
	}
	h, p, err := net.SplitHostPort(t)
	if err != nil {
		return "", 0, err
	}
	if strings.HasPrefix(t, "[") {
		if a, err := netip.ParseAddr(h); err != nil || !a.Is6() {
			return "", 0, fmt.Errorf("brackets around %q, which is no IPv6 address", h)
		}
	}
	if !portRe.MatchString(p) {
		return "", 0, fmt.Errorf("bad port in %q", t)
	}
	n, _ := strconv.Atoi(p)
	if n > 65535 {
		return "", 0, fmt.Errorf("bad port in %q", t)
	}
	return h, n, nil
}

var portRe = regexp.MustCompile(`^[1-9][0-9]{0,4}$`)

// SortedChecks returns the checks in canonical order (by type, then target).
func (e *BindingEvent) SortedChecks() []Check {
	cs := append([]Check(nil), e.Checks...)
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].Type != cs[j].Type {
			return cs[i].Type < cs[j].Type
		}
		return cs[i].Target < cs[j].Target
	})
	return cs
}

// Canonical returns the canonical text that admins sign: one "name value"
// line per field in fixed order, LF line endings, checks sorted.
func (e *BindingEvent) Canonical() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	var b strings.Builder
	line := func(k, v string) { b.WriteString(k + " " + v + "\n") }
	b.WriteString(CanonicalHeader + "\n")
	line("kind", e.Kind)
	line("trust-domain", e.TrustDomain)
	line("identity", e.Identity)
	line("epoch", strconv.FormatUint(e.Epoch, 10))
	if e.Kind == KindBindingSet {
		line("key", e.Key)
		for _, c := range e.SortedChecks() {
			line("check", c.Type+" "+c.Target)
		}
	}
	return []byte(b.String()), nil
}

// Hash returns the hex SHA-256 of the canonical text. Two events with the
// same content have the same hash regardless of their signatures.
func (e *BindingEvent) Hash() (string, error) {
	c, err := e.Canonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), nil
}
