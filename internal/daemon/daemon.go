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
	"strconv"
	"sync"
	"time"

	"github.com/DunkelCloud/ergosum/internal/jwt"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/metrics"
	"github.com/DunkelCloud/ergosum/internal/protocol"
	"github.com/DunkelCloud/ergosum/internal/tlspin"
)

// Options carries dependencies that tests replace.
type Options struct {
	Logger *slog.Logger
	Now    func() time.Time
	// Listen creates the callback listener; default net.Listen.
	Listen func(network, address string) (net.Listener, error)
}

// Daemon is one ergosumd instance.
type Daemon struct {
	cfg         Config
	log         *slog.Logger
	now         func() time.Time
	listen      func(network, address string) (net.Listener, error)
	key         *ecdsa.PrivateKey
	cert        tls.Certificate
	inflight    *inflight
	authorities []*authorityClient
	preferred   int
	tokenGID    int
	overlay     []netip.Prefix

	metrics    *metrics.Registry
	mExpiry    *metrics.Vec
	mSuccess   *metrics.Vec
	mError     *metrics.Vec
	mClockSkew *metrics.Vec
	mCallbacks *metrics.Vec

	lmu      sync.Mutex
	users    int
	listener net.Listener
	server   *http.Server
}

type authorityClient struct {
	url    string
	pin    string
	client *http.Client
}

// New loads (or creates) the identity key.
func New(cfg Config, opts Options) (*Daemon, error) {
	cfg.SetDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	overlay, _ := protocol.ParsePrefixes(cfg.OverlayPrefixes) // checked by Validate
	d := &Daemon{cfg: cfg, log: opts.Logger, now: opts.Now, listen: opts.Listen, tokenGID: -1,
		inflight: newInflight(), overlay: overlay}
	if d.log == nil {
		d.log = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	}
	if d.now == nil {
		d.now = time.Now
	}
	if d.listen == nil {
		d.listen = net.Listen
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	key, created, err := keys.LoadOrCreate(filepath.Join(cfg.StateDir, "identity.key"))
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
	for _, a := range cfg.Authorities {
		d.authorities = append(d.authorities, &authorityClient{
			url: a.URL,
			pin: a.Key,
			client: &http.Client{
				Timeout: cfg.RequestTimeout,
				Transport: &http.Transport{
					TLSClientConfig: tlspin.ClientConfig(nil, tlspin.Fingerprints(a.Key)),
					Proxy:           nil,
				},
			},
		})
	}
	if cfg.TokenGroup != "-" && runtime.GOOS != "windows" {
		if g, err := user.LookupGroup(cfg.TokenGroup); err == nil {
			d.tokenGID, _ = strconv.Atoi(g.Gid)
		} else {
			d.log.Warn("token group not found; token file keeps the default group", "group", cfg.TokenGroup)
		}
	}
	d.metrics = metrics.NewRegistry()
	d.mExpiry = d.metrics.Gauge("machine_identity_token_expiry_timestamp_seconds", "Expiry of the current identity token.")
	d.mSuccess = d.metrics.Gauge("machine_identity_last_success_timestamp_seconds", "Time of the last successful token request.")
	d.mError = d.metrics.Gauge("machine_identity_last_error_timestamp_seconds", "Time of the last failed token request.")
	d.mClockSkew = d.metrics.Gauge("machine_identity_clock_skew_seconds", "Authority clock minus local clock, estimated per request.")
	d.mCallbacks = d.metrics.Counter("machine_identity_callbacks_total", "Callbacks answered by status.", "status",
		protocol.StatusConfirmed, protocol.StatusNoOpenRequest)
	return d, nil
}

// Fingerprint returns the identity key fingerprint to bind.
func (d *Daemon) Fingerprint() string { return keys.Fingerprint(&d.key.PublicKey) }

// CallbackCount returns how many callbacks were answered with status.
func (d *Daemon) CallbackCount(status string) float64 { return d.mCallbacks.Get(status) }

// Run obtains a token, writes it and renews it from half its lifetime on,
// until ctx ends.
func (d *Daemon) Run(ctx context.Context) error {
	d.log.Info("starting", "identity", d.cfg.Identity, "fingerprint", d.Fingerprint())
	bo := backoff{base: 5 * time.Second, max: 5 * time.Minute}
	for {
		token, claims, err := d.Obtain(ctx)
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
// tries the authorities one after another, each with a fresh request ID,
// and returns the first token.
func (d *Daemon) Obtain(ctx context.Context) (string, jwt.Claims, error) {
	if err := d.acquireListener(); err != nil {
		return "", jwt.Claims{}, err
	}
	defer d.releaseListener()

	var errs []error
	n := len(d.authorities)
	for i := 0; i < n; i++ {
		idx := (d.preferred + i) % n
		a := d.authorities[idx]
		token, claims, err := d.request(ctx, a)
		if err == nil {
			d.preferred = idx
			return token, claims, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", a.url, err))
		if ctx.Err() != nil {
			break
		}
	}
	return "", jwt.Claims{}, errors.Join(errs...)
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
	id := protocol.NewRequestID()
	d.inflight.add(id, a.pin)
	defer d.inflight.remove(id)
	req := protocol.TokenRequest{
		V: protocol.Version, Type: protocol.TypeTokenRequest, Identity: d.cfg.Identity,
		RequestID: id, Timestamp: d.now().UTC(), Addresses: d.addresses(),
		Key: base64.StdEncoding.EncodeToString(keys.SPKI(&d.key.PublicKey)),
	}
	env, err := protocol.Seal(d.key, protocol.ContextRequest, req)
	if err != nil {
		return "", jwt.Claims{}, err
	}
	body, _ := json.Marshal(env)
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.url+protocol.PathToken, bytes.NewReader(body))
	if err != nil {
		return "", jwt.Claims{}, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	sent := d.now()
	resp, err := a.client.Do(hreq)
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

func (d *Daemon) observeSkew(server, sent, received time.Time) {
	if server.IsZero() {
		return
	}
	mid := sent.Add(received.Sub(sent) / 2)
	d.mClockSkew.Set("", server.Sub(mid).Seconds())
}

// addresses returns the configured or detected underlay addresses.
func (d *Daemon) addresses() []string {
	if len(d.cfg.Addresses) > 0 {
		return d.cfg.Addresses
	}
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
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
			out = append(out, ip.String())
			if len(out) == 16 {
				return out
			}
		}
	}
	return out
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
	pins := make([]string, 0, len(d.cfg.Authorities))
	for _, a := range d.cfg.Authorities {
		pins = append(pins, a.Key)
	}
	tcfg := tlspin.ServerConfig(d.cert, tlspin.Fingerprints(pins...))
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
	status := protocol.StatusNoOpenRequest
	if d.inflight.confirms(cb.RequestID, keys.Fingerprint(peer)) {
		status = protocol.StatusConfirmed
	}
	resp := protocol.CallbackResponse{
		V: protocol.Version, Type: protocol.TypeCallbackResponse, Status: status,
		RequestID: cb.RequestID, Nonce: cb.Nonce, Target: cb.Target, Authority: cb.Authority,
		Timestamp: d.now().UTC(),
	}
	env, err := protocol.Seal(d.key, protocol.ContextCallbackResponse, resp)
	if err != nil {
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}
	d.mCallbacks.Inc(status)
	if status == protocol.StatusNoOpenRequest {
		d.log.Error("callback for a request this machine did not make: the identity key is in use elsewhere",
			"request_id", cb.RequestID, "target", cb.Target, "authority", cb.Authority)
	} else {
		d.log.Info("callback confirmed", "request_id", cb.RequestID, "target", cb.Target)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(env)
}

// writeToken replaces the token file atomically (mode 0640, token group).
// The group is set before the rename, so a reader never sees the new token
// with the wrong group, and a failed chown leaves the old file in place.
func (d *Daemon) writeToken(token string) error {
	if err := os.MkdirAll(filepath.Dir(d.cfg.TokenFile), 0o755); err != nil { //nolint:gosec // the token file itself is 0640
		return err
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
