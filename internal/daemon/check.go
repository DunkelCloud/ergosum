package daemon

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"sync"

	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/tlspin"
)

// KeyCheck is what one URL of a configured authority presents.
type KeyCheck struct {
	URL  string
	Want string // the configured key
	Got  string // the key the URL presented; empty if it was not reached
	Err  error  // why the URL was not reached
}

// CheckKeys connects to every URL of the configured authorities at once and
// returns the key each presents, in configuration order. Nothing is sent
// beyond the TLS handshake, which proves that the peer holds the key. It
// finds a key that names another instance, or no authority at all, before
// the daemon fails on it in its requests.
func CheckKeys(ctx context.Context, cfg Config) []KeyCheck {
	var checks []KeyCheck
	for _, a := range cfg.Authorities {
		for _, u := range a.urls() {
			checks = append(checks, KeyCheck{URL: u, Want: a.Key})
		}
	}
	var wg sync.WaitGroup
	for i := range checks {
		wg.Go(func() { checks[i].Got, checks[i].Err = presentedKey(ctx, checks[i].URL) })
	}
	wg.Wait()
	return checks
}

// presentedKey returns the fingerprint of the key that the TLS server at
// rawURL (https://host:port) presents.
func presentedKey(ctx context.Context, rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*dialTimeout)
	defer cancel()
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: dialTimeout},
		// Any key: the caller compares it with the configured one.
		Config: tlspin.ClientConfig(nil, func(string) bool { return true }),
	}
	conn, err := d.DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return "", errors.New("not a TLS connection")
	}
	cs := tc.ConnectionState()
	pub, err := tlspin.PeerKey(&cs)
	if err != nil {
		return "", err
	}
	return keys.Fingerprint(pub), nil
}
