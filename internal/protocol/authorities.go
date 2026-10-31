package protocol

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strconv"

	"github.com/DunkelCloud/ergosum/internal/keys"
)

// PathAuthorities serves the AuthorityList of an authority; one without a
// list answers 404.
const PathAuthorities = "/v1/authorities"

// Limits of an AuthorityList.
const (
	MaxListedAuthorities = 32
	MaxAuthorityURLs     = 8
	// MaxListSerial keeps serials exact in every JSON reader.
	MaxListSerial = 1<<53 - 1
)

// AuthorityList names every instance of a trust domain with the URLs it is
// reached on, in order of preference. Every authority serves the same
// list; Serial grows with each change, and a daemon takes a list only with
// a higher serial than the one it has, or from an authority that its
// configuration names and its list does not.
type AuthorityList struct {
	V           int               `json:"v"`
	TrustDomain string            `json:"trust_domain"`
	Serial      uint64            `json:"serial"`
	Authorities []ListedAuthority `json:"authorities"`
}

// ListedAuthority is one instance of an AuthorityList.
type ListedAuthority struct {
	// Key is the instance's key fingerprint ("SHA256:...").
	Key  string   `json:"key"`
	URLs []string `json:"urls"`
}

// Validate checks the list as a daemon receives it.
func (l *AuthorityList) Validate() error {
	if l.V != Version {
		return fmt.Errorf("authority list version %d", l.V)
	}
	if !ValidDNSName(l.TrustDomain) {
		return errors.New("authority list: bad trust domain")
	}
	if l.Serial < 1 || l.Serial > MaxListSerial {
		return errors.New("authority list: serial out of range")
	}
	return ValidateListedAuthorities(l.Authorities)
}

// ValidateListedAuthorities checks the instances of a list: at least one,
// each key once, each with one to MaxAuthorityURLs distinct URLs.
func ValidateListedAuthorities(as []ListedAuthority) error {
	if len(as) == 0 || len(as) > MaxListedAuthorities {
		return fmt.Errorf("authority list: %d instances (1 to %d)", len(as), MaxListedAuthorities)
	}
	seen := map[string]bool{}
	for i, a := range as {
		if !keys.ValidFingerprint(a.Key) {
			return fmt.Errorf("authority list: instance %d: key must be a SHA256 fingerprint", i+1)
		}
		if seen[a.Key] {
			return fmt.Errorf("authority list: %s listed twice", a.Key)
		}
		seen[a.Key] = true
		if err := ValidateAuthorityURLs(a.URLs); err != nil {
			return fmt.Errorf("authority list: %s: %w", a.Key, err)
		}
	}
	return nil
}

// ValidateAuthorityURLs checks the URLs of one instance.
func ValidateAuthorityURLs(urls []string) error {
	if len(urls) == 0 || len(urls) > MaxAuthorityURLs {
		return fmt.Errorf("%d URLs (1 to %d)", len(urls), MaxAuthorityURLs)
	}
	for i, u := range urls {
		if err := ValidAuthorityURL(u); err != nil {
			return err
		}
		if slices.Contains(urls[:i], u) {
			return fmt.Errorf("%s listed twice", u)
		}
	}
	return nil
}

// ValidAuthorityURL accepts https://HOST:PORT and nothing more: HOST an
// address (IPv6 in brackets) or a DNS name.
func ValidAuthorityURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Path != "" ||
		u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return fmt.Errorf("%q is not https://host:port", s)
	}
	if p, err := strconv.Atoi(u.Port()); err != nil || p < 1 || p > 65535 || u.Port() != strconv.Itoa(p) {
		return fmt.Errorf("%q needs a port", s)
	}
	host := u.Hostname()
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Zone() != "" || a.Is4In6() {
			return fmt.Errorf("%q: address with a zone or a mapped address", s)
		}
		return nil
	}
	if !ValidDNSName(host) {
		return fmt.Errorf("%q: host is neither an address nor a DNS name", s)
	}
	return nil
}

// Lists reports whether the list names the instance with key fingerprint fp.
func (l *AuthorityList) Lists(fp string) bool {
	return slices.ContainsFunc(l.Authorities, func(a ListedAuthority) bool { return a.Key == fp })
}

// Same reports whether two lists name the same instances with the same URLs
// in the same order, for the same trust domain.
func (l *AuthorityList) Same(o *AuthorityList) bool {
	return l.TrustDomain == o.TrustDomain && slices.EqualFunc(l.Authorities, o.Authorities, func(a, b ListedAuthority) bool {
		return a.Key == b.Key && slices.Equal(a.URLs, b.URLs)
	})
}
