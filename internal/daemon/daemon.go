// Package daemon implements ergosumd: it holds the machine's identity key,
// requests tokens, answers callbacks while a request is open and keeps the
// token file fresh.
package daemon

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DunkelCloud/ergosum/internal/jwt"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/metrics"
	"github.com/DunkelCloud/ergosum/internal/protocol"
	"github.com/DunkelCloud/ergosum/internal/tlspin"
	"github.com/DunkelCloud/ergosum/internal/version"
)

// Options carries dependencies that tests replace.
type Options struct {
	Logger *slog.Logger
	Now    func() time.Time
	// Listen creates the callback listener; default net.Listen.
	Listen func(network, address string) (net.Listener, error)
	// TailnetName returns the machine's overlay name for a request;
	// default: ask "tailscale status".
	TailnetName func(context.Context) (string, error)
	// InterfaceAddrs returns the machine's addresses, which decide the
	// URLs of an authority worth trying; default: all interfaces.
	InterfaceAddrs func() ([]netip.Addr, error)
}

// Daemon is one ergosumd instance.
type Daemon struct {
	cfg         Config
	log         *slog.Logger
	now         func() time.Time
	listen      func(network, address string) (net.Listener, error)
	tailnetName func(context.Context) (string, error)
	inflight    *inflight
	started     time.Time // reported in callback responses

	kmu      sync.RWMutex
	key      *ecdsa.PrivateKey
	cert     tls.Certificate
	pending  *ecdsa.PrivateKey // the next key, until a binding names it
	previous *ecdsa.PrivateKey // the old key, until a token for the new one

	holdPending time.Time // no switch before this, after going back

	interfaceAddrs func() ([]netip.Addr, error)

	amu         sync.Mutex
	authorities []*authorityClient
	preferred   int
	list        *protocol.AuthorityList // in use; nil: the configured authorities only

	tokenGID int
	overlay  []netip.Prefix
	addrWarn sync.Once // the address limit is reported once

	metrics     *metrics.Registry
	mExpiry     *metrics.Vec
	mSuccess    *metrics.Vec
	mError      *metrics.Vec
	mClockSkew  *metrics.Vec
	mCallbacks  *metrics.Vec
	mPending    *metrics.Vec
	mListSerial *metrics.Vec

	// rmu lets one token or exchange request out at a time: an instance
	// takes one request of an identity at a time and refuses the next.
	rmu      sync.Mutex
	tokenExp atomic.Int64 // expiry of the last token, Unix seconds

	secrets          *secretStore
	mSecretThreshold *metrics.Vec
	mSecretPins      *metrics.Vec
	mSecretReshare   *metrics.Vec

	lmu      sync.Mutex
	users    int
	listener net.Listener
	server   *http.Server
}

// New loads (or creates) the identity key.
func New(cfg Config, opts Options) (*Daemon, error) {
	cfg.SetDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	overlay, _ := protocol.ParsePrefixes(cfg.OverlayPrefixes) // checked by Validate
	d := &Daemon{cfg: cfg, log: opts.Logger, now: opts.Now, listen: opts.Listen, tailnetName: opts.TailnetName,
		interfaceAddrs: opts.InterfaceAddrs, tokenGID: -1, overlay: overlay}
	if d.interfaceAddrs == nil {
		d.interfaceAddrs = protocol.InterfaceAddrs
	}
	if d.tailnetName == nil {
		d.tailnetName = tailnetName
	}
	if d.log == nil {
		d.log = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	}
	if d.now == nil {
		d.now = time.Now
	}
	d.started = d.now().UTC()
	d.inflight = newInflight(d.now)
	if d.listen == nil {
		d.listen = net.Listen
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	key, created, err := keys.LoadOrCreate(d.keyPath())
	if err != nil {
		return nil, err
	}
	d.key = key
	if created {
		d.log.Info("generated identity key", "fingerprint", d.Fingerprint())
	}
	if d.cert, err = tlspin.Certificate(key); err != nil {
		return nil, err
	}
	if d.pending, err = keys.Load(d.keyPath() + pendingSuffix); err != nil && !errors.Is(err, os.ErrNotExist) {
		d.log.Warn("cannot read the next key; keeping the current key", "err", err)
	}
	if d.previous, err = keys.Load(d.keyPath() + previousSuffix); err != nil && !errors.Is(err, os.ErrNotExist) {
		d.log.Warn("cannot read the old key", "err", err)
	}
	if cfg.TokenGroup != "-" && runtime.GOOS != "windows" {
		if g, err := user.LookupGroup(cfg.TokenGroup); err == nil {
			d.tokenGID, _ = strconv.Atoi(g.Gid)
		} else {
			d.log.Warn("token group not found; token file keeps the default group", "group", cfg.TokenGroup)
		}
	}
	d.metrics = metrics.NewRegistry()
	d.metrics.Info("machine_identity_build_info", "Version and commit of the running binary.",
		"version", version.Version, "commit", version.Commit)
	d.mExpiry = d.metrics.Gauge("machine_identity_token_expiry_timestamp_seconds", "Expiry of the current identity token.")
	d.mSuccess = d.metrics.Gauge("machine_identity_last_success_timestamp_seconds", "Time of the last successful token request.")
	d.mError = d.metrics.Gauge("machine_identity_last_error_timestamp_seconds", "Time of the last failed token request.")
	d.mClockSkew = d.metrics.Gauge("machine_identity_clock_skew_seconds", "Authority clock minus local clock, estimated per request.")
	d.mCallbacks = d.metrics.Counter("machine_identity_callbacks_total", "Callbacks answered by status.", "status",
		protocol.StatusConfirmed, protocol.StatusNoOpenRequest, protocol.StatusEnded)
	d.mPending = d.metrics.Gauge("machine_identity_key_change_pending", "1 while a new key waits for its binding.")
	if d.pending != nil {
		d.mPending.Set("", 1)
	}
	d.mListSerial = d.metrics.Gauge("machine_identity_authorities_serial",
		"Serial of the authority list in use; 0 while only the configured authorities are known.")
	d.initSecrets()
	d.setAuthorities(d.loadList())
	return d, nil
}

// pendingSuffix names the next key next to the current one, previousSuffix
// the old key during a switch.
const (
	pendingSuffix  = ".new"
	previousSuffix = ".old"
)

// holdAfterRevert is how long the daemon keeps its old key after going
// back from a refused new one, before it tries the new key again.
const holdAfterRevert = 10 * time.Minute

func (d *Daemon) keyPath() string { return filepath.Join(d.cfg.StateDir, "identity.key") }

// identity returns the current key and its TLS certificate.
func (d *Daemon) identity() (*ecdsa.PrivateKey, tls.Certificate) {
	d.kmu.RLock()
	defer d.kmu.RUnlock()
	return d.key, d.cert
}

// Fingerprint returns the identity key fingerprint to bind.
func (d *Daemon) Fingerprint() string {
	k, _ := d.identity()
	return keys.Fingerprint(&k.PublicKey)
}

// PendingFingerprint returns the fingerprint of the key that waits for its
// binding, or "".
func (d *Daemon) PendingFingerprint() string {
	d.kmu.RLock()
	defer d.kmu.RUnlock()
	if d.pending == nil {
		return ""
	}
	return keys.Fingerprint(&d.pending.PublicKey)
}

// NewKey creates the next identity key next to the current one, or keeps
// the one that waits already, and returns its fingerprint. The daemon
// switches to it once an authority shows a binding to it.
func (d *Daemon) NewKey() (string, error) {
	key, created, err := keys.LoadOrCreate(d.keyPath() + pendingSuffix)
	if err != nil {
		return "", err
	}
	d.kmu.Lock()
	d.pending = key
	d.kmu.Unlock()
	d.mPending.Set("", 1)
	fp := keys.Fingerprint(&key.PublicKey)
	if created {
		d.log.Info("generated the next identity key", "fingerprint", fp)
	}
	return fp, nil
}

// loadPendingKey picks up the next key from the state directory, where
// "ergosumd request -new-key" puts it while the service runs, and forgets it
// if the file is gone.
func (d *Daemon) loadPendingKey() *ecdsa.PrivateKey {
	d.kmu.Lock()
	defer d.kmu.Unlock()
	key, err := keys.Load(d.keyPath() + pendingSuffix)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if d.pending != nil {
			d.log.Info("the next key is gone; keeping the current key")
		}
		d.pending = nil
		d.mPending.Set("", 0)
		return nil
	case err != nil:
		d.log.Warn("cannot read the next key; keeping the current key", "err", err)
		return nil
	case d.pending != nil && d.pending.Equal(key):
		return d.pending
	}
	d.pending = key
	d.mPending.Set("", 1)
	d.log.Info("found the next key; it waits for its binding", "next", keys.Fingerprint(&key.PublicKey))
	return key
}

// adoptPendingKey switches to the next key once an authority shows a
// binding to it, and deletes the old key. Until then the daemon keeps its
// current key, so that it never sends a request that the authorities refuse
// as foreign_key.
func (d *Daemon) adoptPendingKey(ctx context.Context) {
	if d.now().Before(d.holdPending) {
		return // just went back from this key
	}
	next := d.loadPendingKey()
	if next == nil {
		return
	}
	want := keys.Fingerprint(&next.PublicKey)
	bound, err := d.boundKeys(ctx)
	if err != nil {
		d.log.Warn("cannot read the binding; keeping the current key", "err", err)
		return
	}
	for url, key := range bound {
		if key != want {
			d.log.Info("the next key waits for its binding", "next", want, "authority", url, "bound", key)
			return
		}
	}
	if err := d.switchToPending(next); err != nil {
		d.log.Error("switching keys failed", "err", err)
		return
	}
	d.log.Info("switched to the next key, which every reachable authority binds now", "fingerprint", want)
}

// switchToPending makes next the current key. The current key stays as
// identity.key.old until a token has been issued for the next one, so that
// the daemon can go back if every authority refuses it after all.
func (d *Daemon) switchToPending(next *ecdsa.PrivateKey) error {
	cert, err := tlspin.Certificate(next)
	if err != nil {
		return err
	}
	cur, _ := d.identity()
	old, err := keys.MarshalPrivatePEM(cur)
	if err != nil {
		return err
	}
	if err := keys.WriteFileAtomic(d.keyPath()+previousSuffix, old, 0o600); err != nil {
		return err
	}
	if err := os.Rename(d.keyPath()+pendingSuffix, d.keyPath()); err != nil {
		return err
	}
	d.kmu.Lock()
	d.key, d.cert, d.pending, d.previous = next, cert, nil, cur
	d.kmu.Unlock()
	d.mPending.Set("", 0)
	return nil
}

// settleKeySwitch ends a key switch after the first request with the next
// key: a token deletes the old key; a refusal by every authority, while the
// old key is still at hand, goes back to it and keeps the next key waiting.
func (d *Daemon) settleKeySwitch(err error) {
	d.kmu.RLock()
	prev := d.previous
	d.kmu.RUnlock()
	if prev == nil {
		return
	}
	if err == nil {
		if rerr := os.Remove(d.keyPath() + previousSuffix); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			d.log.Warn("deleting the old key failed", "err", rerr)
			return
		}
		d.kmu.Lock()
		d.previous = nil
		d.kmu.Unlock()
		d.log.Info("token issued for the new key; the old key is deleted")
		return
	}
	if !allRefused(err) {
		return // an outage proves nothing about the key
	}
	cur, _ := d.identity()
	next, perr := keys.MarshalPrivatePEM(cur)
	if perr == nil {
		perr = keys.WriteFileAtomic(d.keyPath()+pendingSuffix, next, 0o600)
	}
	if perr == nil {
		perr = os.Rename(d.keyPath()+previousSuffix, d.keyPath())
	}
	cert, cerr := tlspin.Certificate(prev)
	if perr != nil || cerr != nil {
		d.log.Error("going back to the old key failed", "err", errors.Join(perr, cerr))
		return
	}
	d.kmu.Lock()
	d.key, d.cert, d.pending, d.previous = prev, cert, cur, nil
	d.kmu.Unlock()
	d.mPending.Set("", 1)
	d.holdPending = d.now().Add(holdAfterRevert)
	d.log.Error("every authority refuses the new key; back to the old key, the new one waits again",
		"fingerprint", keys.Fingerprint(&prev.PublicKey), "next", keys.Fingerprint(&cur.PublicKey))
}

// allRefused reports whether every authority answered and refused (403).
func allRefused(err error) bool {
	var errs []error
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		errs = j.Unwrap()
	} else {
		errs = []error{err}
	}
	for _, e := range errs {
		var re *RequestError
		if !errors.As(e, &re) || re.Status != http.StatusForbidden {
			return false
		}
	}
	return len(errs) > 0
}

// boundKeys returns, per reachable authority, the key of the identity's
// active binding, "" for none. Unreachable authorities are left out; an
// error means that none answered.
func (d *Daemon) boundKeys(ctx context.Context) (map[string]string, error) {
	out := map[string]string{}
	var errs []error
	authorities, _ := d.snapshot()
	for _, a := range authorities {
		resp, err := d.do(ctx, a, func(base string) (*http.Request, error) {
			return http.NewRequestWithContext(ctx, http.MethodGet, base+protocol.PathBindings+"/"+d.cfg.Identity, http.NoBody)
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", a.pin, err))
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: %w", a.name(), err))
		case resp.StatusCode == http.StatusNotFound:
			out[a.name()] = ""
		case resp.StatusCode != http.StatusOK:
			errs = append(errs, fmt.Errorf("%s: %s", a.name(), resp.Status))
		default:
			var b struct{ Kind, Key string }
			if err := json.Unmarshal(data, &b); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", a.name(), err))
				continue
			}
			if b.Kind != "binding.set" {
				b.Key = ""
			}
			out[a.name()] = b.Key
		}
	}
	if len(out) == 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}

// CallbackCount returns how many callbacks were answered with status.
func (d *Daemon) CallbackCount(status string) float64 { return d.mCallbacks.Get(status) }

// Run obtains a token, writes it and renews it from half its lifetime on,
// until ctx ends.
func (d *Daemon) Run(ctx context.Context) error {
	d.log.Info("starting", "identity", d.cfg.Identity, "fingerprint", d.Fingerprint(), "next_key", d.PendingFingerprint())
	// Without the socket the daemon still keeps its token fresh.
	if stop, err := d.serveSecrets(ctx); err != nil {
		d.log.Error("no secret socket; ergosumd secret is not available", "err", err)
	} else {
		defer stop()
	}
	bo := backoff{base: 5 * time.Second, max: 5 * time.Minute}
	for {
		d.adoptPendingKey(ctx)
		token, claims, err := d.Obtain(ctx)
		if ctx.Err() == nil {
			d.settleKeySwitch(err)
		}
		var wait time.Duration
		if err == nil {
			if werr := d.writeToken(token); werr != nil {
				d.log.Error("writing token failed", "err", werr)
				err = werr
			}
		}
		if err == nil {
			bo.reset()
			d.mExpiry.Set("", float64(claims.Expiry))
			d.mSuccess.Set("", float64(d.now().Unix()))
			// Secrets are released per round (ADR 0004).
			d.RefreshSecrets(ctx)
			d.ReshareSecrets(ctx)
			wait = renewDelay(claims, d.now())
			d.log.Info("token issued", "expires", time.Unix(claims.Expiry, 0).UTC(), "renew_in", wait.Round(time.Second).String())
		} else {
			if ctx.Err() != nil {
				return nil
			}
			d.mError.Set("", float64(d.now().Unix()))
			wait = bo.next()
			d.log.Warn("token request failed", "err", err, "retry_in", wait.Round(time.Second).String())
		}
		d.writeMetrics()
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// renewDelay schedules the renewal at half the lifetime, spread by up to a
// tenth of the lifetime in either direction.
func renewDelay(c jwt.Claims, now time.Time) time.Duration {
	life := c.Lifetime()
	jitter := time.Duration((rand.Float64()*2 - 1) * float64(life) / 10) //nolint:gosec // jitter, not a secret
	at := time.Unix(c.IssuedAt, 0).Add(life/2 + jitter)
	if d := at.Sub(now); d > time.Second {
		return d
	}
	return time.Second
}

// backoff is exponential with full jitter.
type backoff struct {
	base, max time.Duration
	n         int
}

func (b *backoff) next() time.Duration {
	ceil := b.base << b.n
	if ceil > b.max || ceil <= 0 {
		ceil = b.max
	} else {
		b.n++
	}
	d := time.Duration(rand.Int64N(int64(ceil))) //nolint:gosec // jitter, not a secret
	if d < time.Second {
		d = time.Second
	}
	return d
}

func (b *backoff) reset() { b.n = 0 }

// Obtain performs one request round: it keeps the callback listener open,
// tries the authorities one after another, each once and with a fresh
// request ID, and returns the first token.
func (d *Daemon) Obtain(ctx context.Context) (string, jwt.Claims, error) {
	if err := d.acquireListener(); err != nil {
		return "", jwt.Claims{}, err
	}
	defer d.releaseListener()

	var errs []error
	tried := map[string]bool{}
	for {
		authorities, preferred := d.snapshot()
		a := untried(authorities, preferred, tried)
		if a == nil {
			break
		}
		tried[a.pin] = true
		token, claims, err := d.request(ctx, a)
		if err == nil {
			d.tokenExp.Store(claims.Expiry)
			d.setPreferred(a)
			d.refreshList(ctx, a, trustDomainOf(claims))
			return token, claims, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", a.name(), err))
		if ctx.Err() != nil {
			break
		}
		// Until its first token a new machine knows only its anchor. An
		// anchor that cannot run a net check or an ip check on a private
		// address names the instances that can, and the round goes on with
		// them.
		var re *RequestError
		if errors.As(err, &re) && re.Code == protocol.ErrNotResponsible {
			d.refreshList(ctx, a, "")
		}
	}
	return "", jwt.Claims{}, errors.Join(errs...)
}

// untried returns the first authority from the preferred one on that the
// round has not tried yet; nil once it tried all. The authorities change
// when the round takes a list.
func untried(authorities []*authorityClient, preferred int, tried map[string]bool) *authorityClient {
	for i := range authorities {
		if a := authorities[(preferred+i)%len(authorities)]; !tried[a.pin] {
			return a
		}
	}
	return nil
}

// RequestError is a refusal by an authority.
type RequestError struct {
	Status int
	Code   string
	Detail string
}

func (e *RequestError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("%s (%d): %s", e.Code, e.Status, e.Detail)
	}
	return fmt.Sprintf("%s (%d)", e.Code, e.Status)
}

// request sends one token request. Its request ID is new, is never reused,
// and counts as in flight to this instance until the answer arrives.
func (d *Daemon) request(ctx context.Context, a *authorityClient) (string, jwt.Claims, error) {
	d.rmu.Lock()
	defer d.rmu.Unlock()
	id := protocol.NewRequestID()
	d.inflight.add(id, a.pin)
	defer d.inflight.remove(id)
	key, _ := d.identity()
	req := protocol.TokenRequest{
		V: protocol.Version, Type: protocol.TypeTokenRequest, Identity: d.cfg.Identity,
		RequestID: id, Timestamp: d.now().UTC(), Addresses: d.addresses(),
		Key: base64.StdEncoding.EncodeToString(keys.SPKI(&key.PublicKey)), To: a.pin,
	}
	env, err := protocol.Seal(key, protocol.ContextRequest, req)
	if err != nil {
		return "", jwt.Claims{}, err
	}
	body, _ := json.Marshal(env)
	sent := d.now()
	resp, err := d.do(ctx, a, func(base string) (*http.Request, error) {
		hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+protocol.PathToken, bytes.NewReader(body))
		if err == nil {
			hreq.Header.Set("Content-Type", "application/json")
		}
		return hreq, err
	})
	if err != nil {
		return "", jwt.Claims{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	received := d.now()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", jwt.Claims{}, err
	}
	if resp.StatusCode != http.StatusOK {
		var er protocol.ErrorResponse
		_ = json.Unmarshal(data, &er)
		d.observeSkew(er.ServerTime, sent, received)
		return "", jwt.Claims{}, &RequestError{Status: resp.StatusCode, Code: er.Error, Detail: er.Detail}
	}
	var tr protocol.TokenResponse
	if err := json.Unmarshal(data, &tr); err != nil {
		return "", jwt.Claims{}, fmt.Errorf("malformed token response: %w", err)
	}
	d.observeSkew(tr.ServerTime, sent, received)
	// The token must be signed by the instance we are talking to.
	peer, err := tlspin.PeerKey(resp.TLS)
	if err != nil {
		return "", jwt.Claims{}, err
	}
	kid := keys.Thumbprint(peer)
	_, claims, err := jwt.Verify(tr.Token, func(k string) *ecdsa.PublicKey {
		if k == kid {
			return peer
		}
		return nil
	}, tr.ServerTime)
	if err != nil {
		return "", jwt.Claims{}, fmt.Errorf("token rejected: %w", err)
	}
	if claims.Host != d.cfg.Identity {
		return "", jwt.Claims{}, fmt.Errorf("token for %q, expected %q", claims.Host, d.cfg.Identity)
	}
	return tr.Token, claims, nil
}

// maxSkewRound is the longest request round whose answer still yields a
// clock skew estimate. The estimate assumes the authority answered in the
// middle of the round; a long round (callbacks that time out, a refused
// request) can be off by half its length.
const maxSkewRound = 10 * time.Second

func (d *Daemon) observeSkew(server, sent, received time.Time) {
	if server.IsZero() || received.Sub(sent) > maxSkewRound {
		return
	}
	mid := sent.Add(received.Sub(sent) / 2)
	d.mClockSkew.Set("", server.Sub(mid).Seconds())
}

// addresses returns the configured or detected underlay addresses: global
// unicast addresses outside the overlay, at most protocol.MaxAddresses.
func (d *Daemon) addresses() []string {
	if len(d.cfg.Addresses) > 0 {
		return d.cfg.Addresses
	}
	cands := d.detectAddresses()
	out, truncated := pickAddresses(cands)
	if truncated {
		d.addrWarn.Do(func() {
			d.log.Warn("more underlay addresses than a request can carry; set addresses: in the configuration if the bound network is missing",
				"detected", len(cands), "reported", len(out))
		})
	}
	return out
}

// ifaceAddr is a detected address with the interface it belongs to.
type ifaceAddr struct {
	addr   string
	iface  string
	index  int
	prefix netip.Prefix // the network of the address on that interface
}

// detectAddresses lists the global unicast addresses outside the overlay on
// the interfaces that are up.
func (d *Daemon) detectAddresses() []ifaceAddr {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var cands []ifaceAddr
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if !ip.IsGlobalUnicast() || protocol.InPrefixes(ip, d.overlay) {
				continue
			}
			ones, _ := ipn.Mask.Size()
			if ip.Is4() && ones > 32 {
				ones -= 96
			}
			cands = append(cands, ifaceAddr{addr: ip.String(), iface: ifc.Name, index: ifc.Index, prefix: netip.PrefixFrom(ip, ones).Masked()})
		}
	}
	return cands
}

// virtualInterfacePrefixes name interfaces of containers, hypervisor bridges
// and tunnels. Their addresses are reported after the others, so that a host
// full of bridges still names the address of its real network first. The
// second line is macOS: tunnels of Tailscale and other VPNs, the bridges of
// Internet Sharing and virtual machines, Apple's peer-to-peer Wi-Fi,
// VMware Fusion, VirtualBox and ZeroTier.
var virtualInterfacePrefixes = []string{"docker", "br-", "veth", "virbr", "podman", "cni", "flannel", "lxc", "lxd", "tailscale", "wg", "tun", "tap", "zt",
	"utun", "bridge", "awdl", "llw", "vmnet", "vboxnet", "feth"}

func virtualInterface(name string) bool {
	for _, p := range virtualInterfacePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// orderAddresses puts physical-looking interfaces first, then orders by
// interface index.
func orderAddresses(cands []ifaceAddr) {
	sort.SliceStable(cands, func(i, j int) bool {
		vi, vj := virtualInterface(cands[i].iface), virtualInterface(cands[j].iface)
		if vi != vj {
			return !vi
		}
		return cands[i].index < cands[j].index
	})
}

// pickAddresses orders the candidates (see orderAddresses), drops
// duplicates and cuts the list at the protocol's limit. truncated reports
// whether addresses were left out.
func pickAddresses(cands []ifaceAddr) (out []string, truncated bool) {
	orderAddresses(cands)
	out = make([]string, 0, min(len(cands), protocol.MaxAddresses))
	seen := map[string]bool{}
	for _, c := range cands {
		if seen[c.addr] {
			continue
		}
		seen[c.addr] = true
		if len(out) == protocol.MaxAddresses {
			return out, true
		}
		out = append(out, c.addr)
	}
	return out, false
}

// acquireListener opens the callback listener for the first user; it stays
// open only while a request is in flight.
func (d *Daemon) acquireListener() error {
	d.lmu.Lock()
	defer d.lmu.Unlock()
	d.users++
	if d.listener != nil {
		return nil
	}
	ln, err := d.listen("tcp", d.cfg.CallbackListen)
	if err != nil {
		d.users--
		return fmt.Errorf("callback listener: %w", err)
	}
	_, cert := d.identity()
	tcfg := tlspin.ServerConfig(cert, d.knownAuthority)
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+protocol.PathCallback, d.handleCallback)
	srv := &http.Server{Handler: mux, TLSConfig: tcfg, ReadHeaderTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second}
	d.listener, d.server = ln, srv
	go func() { _ = srv.Serve(tls.NewListener(ln, tcfg)) }()
	return nil
}

func (d *Daemon) releaseListener() {
	d.lmu.Lock()
	defer d.lmu.Unlock()
	d.users--
	if d.users > 0 || d.server == nil {
		return
	}
	_ = d.server.Close()
	d.listener, d.server = nil, nil
}

// handleCallback answers an authority's callback. It confirms only a request
// that is in flight to the calling instance; for anything else it signs "no
// open request", which proves that the identity key is being used somewhere
// else.
func (d *Daemon) handleCallback(w http.ResponseWriter, r *http.Request) {
	peer, err := tlspin.PeerKey(r.TLS)
	if err != nil {
		http.Error(w, "no client certificate", http.StatusUnauthorized)
		return
	}
	var cb protocol.Callback
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&cb); err != nil {
		http.Error(w, "malformed callback", http.StatusBadRequest)
		return
	}
	if cb.V != protocol.Version || cb.Type != protocol.TypeCallback || !protocol.ValidRequestID(cb.RequestID) ||
		cb.Nonce == "" || cb.Target == "" || cb.Authority != keys.Thumbprint(peer) {
		http.Error(w, "invalid callback", http.StatusBadRequest)
		return
	}
	status := d.inflight.status(cb.RequestID, keys.Fingerprint(peer))
	resp := protocol.CallbackResponse{
		V: protocol.Version, Type: protocol.TypeCallbackResponse, Status: status,
		RequestID: cb.RequestID, Nonce: cb.Nonce, Target: cb.Target, Authority: cb.Authority,
		Timestamp: d.now().UTC(), Started: d.started,
	}
	key, _ := d.identity()
	env, err := protocol.Seal(key, protocol.ContextCallbackResponse, resp)
	if err != nil {
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}
	d.mCallbacks.Inc(status)
	switch status {
	case protocol.StatusNoOpenRequest:
		d.log.Error("callback for a request this machine did not make: the identity key is in use elsewhere",
			"request_id", cb.RequestID, "target", cb.Target, "authority", cb.Authority)
	case protocol.StatusEnded:
		d.log.Info("late callback for a request this machine has given up", "request_id", cb.RequestID, "target", cb.Target)
	default:
		d.log.Info("callback confirmed", "request_id", cb.RequestID, "target", cb.Target)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(env)
}

// writeToken replaces the token file atomically (mode 0640, token group).
// The group is set before the rename, so a reader never sees the new token
// with the wrong group, and a failed chown leaves the old file in place.
func (d *Daemon) writeToken(token string) error {
	dir := filepath.Dir(d.cfg.TokenFile)
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		// Normally the service manager provides the directory (systemd
		// RuntimeDirectory, OpenRC checkpath). When the daemon has to create
		// it, the umask must not close it to the token group's members.
		if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // the token file itself is 0640
			return err
		}
		if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // traversal only; the token file is 0640
			return err
		}
	}
	return keys.WriteFileAtomicGroup(d.cfg.TokenFile, []byte(token), 0o640, d.tokenGID)
}

func (d *Daemon) writeMetrics() {
	if d.cfg.MetricsFile == "" {
		return
	}
	var b bytes.Buffer
	_ = d.metrics.Write(&b)
	if err := keys.WriteFileAtomic(d.cfg.MetricsFile, b.Bytes(), 0o644); err != nil { //nolint:gosec // read by node_exporter
		d.log.Warn("writing metrics file failed", "err", err)
	}
}

// HoldCallbackListener opens the callback listener as during a request and
// returns the function that releases it.
func (d *Daemon) HoldCallbackListener() (release func(), err error) {
	if err := d.acquireListener(); err != nil {
		return nil, err
	}
	return d.releaseListener, nil
}

// Close closes the callback listener if it is still open.
func (d *Daemon) Close() {
	d.lmu.Lock()
	defer d.lmu.Unlock()
	if d.server != nil {
		_ = d.server.Close()
		d.listener, d.server = nil, nil
	}
}
