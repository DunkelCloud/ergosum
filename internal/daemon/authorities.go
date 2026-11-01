package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/DunkelCloud/ergosum/internal/jwt"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/protocol"
	"github.com/DunkelCloud/ergosum/internal/tlspin"
)

// dialTimeout bounds one connection attempt, so that an address that
// drops packets costs seconds before the next URL is tried, not the
// whole request.
const dialTimeout = 5 * time.Second

// listFile is the daemon's copy of the authority list, in its state
// directory.
const listFile = "authorities.json"

// authorityClient reaches one instance, pinned by its key, on one of its
// URLs.
type authorityClient struct {
	pin    string
	urls   []string
	good   atomic.Int32 // index of the URL that answered last
	client *http.Client
}

func newAuthorityClient(pin string, urls []string, timeout time.Duration) *authorityClient {
	d := &net.Dialer{Timeout: dialTimeout}
	return &authorityClient{pin: pin, urls: urls, client: &http.Client{
		Timeout:       timeout,
		CheckRedirect: tlspin.NoRedirect,
		Transport: &http.Transport{
			DialContext:         d.DialContext,
			TLSHandshakeTimeout: dialTimeout,
			TLSClientConfig:     tlspin.ClientConfig(nil, tlspin.Fingerprints(pin)),
			Proxy:               nil,
		},
	}}
}

// name is how logs and errors call the instance: its key and the URL that
// answered last.
func (a *authorityClient) name() string { return a.urls[a.good.Load()] + " (" + a.pin + ")" }

// localPaths says from which kinds of address this machine reaches
// others; every kind if its addresses cannot be read.
func (d *Daemon) localPaths() protocol.Paths {
	addrs, err := d.interfaceAddrs()
	if err != nil {
		return protocol.AllPaths
	}
	return protocol.PathsFrom(addrs, d.overlay)
}

// do sends the request that build makes for a URL, trying the next URL
// while a request has not left this machine: the connection or the TLS
// handshake failed, so the instance cannot have seen it. Once a request
// was written, its answer or error is final, since a token request must
// never reach the same instance twice.
func (d *Daemon) do(ctx context.Context, a *authorityClient, build func(base string) (*http.Request, error)) (*http.Response, error) {
	var errs []error
	for _, i := range d.localPaths().Order(a.urls, int(a.good.Load()), d.overlay) {
		wrote := false
		trace := &httptrace.ClientTrace{WroteRequest: func(httptrace.WroteRequestInfo) { wrote = true }}
		req, err := build(a.urls[i])
		if err != nil {
			return nil, err
		}
		resp, err := a.client.Do(req.WithContext(httptrace.WithClientTrace(req.Context(), trace)))
		if err == nil {
			a.good.Store(int32(i)) //nolint:gosec // at most MaxAuthorityURLs
			return resp, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", a.urls[i], err))
		if wrote || ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}

// setAuthorities builds the clients: the instances of the list in its
// order, then the configured ones it does not name, as a way back. A
// client whose URLs stay the same is kept, with its connections.
func (d *Daemon) setAuthorities(list *protocol.AuthorityList) {
	type entry struct {
		pin  string
		urls []string
	}
	var es []entry
	if list != nil {
		for _, la := range list.Authorities {
			es = append(es, entry{la.Key, la.URLs})
		}
	}
	for _, c := range d.cfg.Authorities {
		if list == nil || !list.Lists(c.Key) {
			es = append(es, entry{c.Key, c.urls()})
		}
	}
	d.amu.Lock()
	defer d.amu.Unlock()
	old := map[string]*authorityClient{}
	for _, a := range d.authorities {
		old[a.pin] = a
	}
	prefer := ""
	if len(d.authorities) > 0 {
		prefer = d.authorities[d.preferred].pin
	}
	d.authorities, d.preferred, d.list = nil, 0, list
	for _, e := range es {
		a := old[e.pin]
		if a == nil || !slices.Equal(a.urls, e.urls) {
			a = newAuthorityClient(e.pin, e.urls, d.cfg.RequestTimeout)
		}
		if a.pin == prefer {
			d.preferred = len(d.authorities)
		}
		d.authorities = append(d.authorities, a)
	}
	serial := 0.0
	if list != nil {
		serial = float64(list.Serial)
	}
	d.mListSerial.Set("", serial)
}

// snapshot returns the clients and the index to start with.
func (d *Daemon) snapshot() (authorities []*authorityClient, preferred int) {
	d.amu.Lock()
	defer d.amu.Unlock()
	return slices.Clone(d.authorities), d.preferred
}

func (d *Daemon) setPreferred(a *authorityClient) {
	d.amu.Lock()
	defer d.amu.Unlock()
	if i := slices.Index(d.authorities, a); i >= 0 {
		d.preferred = i
	}
}

// loadList reads the daemon's copy of the authority list; a missing or
// unreadable copy means the configured authorities only.
func (d *Daemon) loadList() *protocol.AuthorityList {
	data, err := os.ReadFile(filepath.Join(d.cfg.StateDir, listFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	var l protocol.AuthorityList
	if err == nil {
		err = json.Unmarshal(data, &l)
	}
	if err == nil {
		err = l.Validate()
	}
	if err != nil {
		d.log.Warn("ignoring the stored authority list; using the configured authorities", "err", err)
		return nil
	}
	return &l
}

// refreshList asks an instance for its list: one that just issued a token
// for trustDomain, or, with trustDomain empty, one that is not responsible
// for a net check. A list replaces the one in use if its serial is higher,
// or if this instance was reached through the configuration and is missing
// from the list in use (the configuration names a new trust domain or new
// instances). It must name the instance that serves it, for the trust
// domain of the token. Without a token the list is taken only while none
// is in use: the first one of a new machine, whose anchor cannot run its
// net checks. The pinned connection vouches for it as much as after a
// token, and the next token checks its trust domain.
func (d *Daemon) refreshList(ctx context.Context, a *authorityClient, trustDomain string) {
	d.amu.Lock()
	cur := d.list
	d.amu.Unlock()
	if trustDomain == "" && cur != nil {
		return
	}
	resp, err := d.do(ctx, a, func(base string) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, base+protocol.PathAuthorities, http.NoBody)
	})
	if err != nil {
		d.log.Warn("cannot read the authority list", "authority", a.name(), "err", err)
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return // the instance serves no list
	}
	var l protocol.AuthorityList
	if err == nil && resp.StatusCode != http.StatusOK {
		err = errors.New(resp.Status)
	}
	if err == nil {
		err = json.Unmarshal(data, &l)
	}
	if err == nil {
		err = l.Validate()
	}
	if err == nil && trustDomain != "" && l.TrustDomain != trustDomain {
		err = fmt.Errorf("list for %s, token for %s", l.TrustDomain, trustDomain)
	}
	if err == nil && !l.Lists(a.pin) {
		err = errors.New("the list does not name the instance that serves it")
	}
	if err != nil {
		d.log.Warn("ignoring the authority list", "authority", a.name(), "err", err)
		return
	}
	d.amu.Lock()
	cur = d.list
	d.amu.Unlock()
	switch {
	case trustDomain == "" && cur != nil:
		return
	case cur == nil, !cur.Lists(a.pin), cur.TrustDomain != l.TrustDomain, l.Serial > cur.Serial:
	case l.Serial == cur.Serial && !l.Same(cur):
		d.log.Warn("authorities serve different lists with the same serial; keeping the one in use",
			"authority", a.name(), "serial", l.Serial)
		return
	default:
		return
	}
	stored, _ := json.Marshal(&l)
	if err := keys.WriteFileAtomic(filepath.Join(d.cfg.StateDir, listFile), stored, 0o600); err != nil {
		d.log.Warn("cannot store the authority list", "err", err)
	}
	d.setAuthorities(&l)
	d.log.Info("authority list taken", "authority", a.name(), "serial", l.Serial, "instances", len(l.Authorities))
}

// trustDomainOf returns the trust domain of a token's SPIFFE subject.
func trustDomainOf(c jwt.Claims) string {
	td, _, _ := strings.Cut(strings.TrimPrefix(c.Subject, "spiffe://"), "/")
	return td
}

// knownAuthority reports whether fp is the key of an authority in use, the
// configured ones and those of the list: callbacks come only from them.
func (d *Daemon) knownAuthority(fp string) bool {
	d.amu.Lock()
	defer d.amu.Unlock()
	return slices.ContainsFunc(d.authorities, func(a *authorityClient) bool { return a.pin == fp })
}
