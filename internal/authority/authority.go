// Package authority implements "ergosum serve": it holds the binding
// journal, verifies token requests, calls the machine back at the places its
// binding names, and signs identity tokens.
package authority

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/DunkelCloud/ergosum/internal/journal"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/metrics"
	"github.com/DunkelCloud/ergosum/internal/protocol"
	"github.com/DunkelCloud/ergosum/internal/tlspin"
)

// Results of a token request, as exported in
// machine_identity_requests_total{result=...}.
const (
	ResultIssued          = "issued"
	ResultKeyDuplicate    = "key_duplicate"
	ResultWrongLocation   = "wrong_location"
	ResultForeignKey      = "foreign_key"
	ResultUnknownIdentity = "unknown_identity"
	ResultReplay          = "replay"
	// ResultMisdirected: a request signed by the bound key but addressed to
	// another instance arrived here. Whoever had it forwarded it.
	ResultMisdirected = "misdirected"
)

// Limits for what unverified requests may cost. unverifiedPerMinute bounds
// the audit lines of refusals that anyone can cause.
const unverifiedPerMinute = 60

// Options carries dependencies that tests replace.
type Options struct {
	Logger  *slog.Logger
	Network Network
	Now     func() time.Time
	// Listen creates listeners; default net.Listen.
	Listen func(network, address string) (net.Listener, error)
	// DialPeer connects to peers for replication; default net.Dialer.
	DialPeer func(ctx context.Context, network, address string) (net.Conn, error)
	// RetryMin, RetryMax and ReplicationIdle tune the pushers (see
	// replication.Config); zero takes the defaults.
	RetryMin, RetryMax, ReplicationIdle time.Duration
}

// Authority is one authority instance.
type Authority struct {
	cfg        Config
	opts       Options
	log        *slog.Logger
	audit      *slog.Logger
	store      *journal.Store
	net        Network
	routes     routes
	now        func() time.Time
	listen     func(network, address string) (net.Listener, error)
	limiter    *limiter     // per identity, for verified refusals
	unverified *window      // overall, for refusals anyone can cause
	seen       *replayCache // request IDs already processed

	metrics  *metrics.Registry
	requests *metrics.Vec
	sealedG  *metrics.Vec
	bindings *metrics.Vec
	jm       *journalMetrics

	repl *replicationState

	keyFile *keys.KeyFile
	public  *ecdsa.PublicKey
	kid     string

	mu       sync.RWMutex
	key      *ecdsa.PrivateKey // nil while sealed
	cert     tls.Certificate
	unsealed chan struct{}

	addrMu   sync.Mutex
	apiAddr  net.Addr
	opsAddr  net.Addr
	replAddr net.Addr
	ready    chan struct{}
}

// New loads the signing key and opens the journal. With an encrypted key the
// instance starts sealed.
func New(cfg Config, opts Options) (*Authority, error) {
	cfg.SetDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	rs, _ := cfg.routes()
	ps, _ := cfg.peers()
	a := &Authority{
		cfg:        cfg,
		opts:       opts,
		log:        opts.Logger,
		net:        opts.Network,
		routes:     rs,
		now:        opts.Now,
		listen:     opts.Listen,
		limiter:    newLimiter(time.Minute),
		unverified: &window{every: time.Minute, max: unverifiedPerMinute},
		// A daemon's request is in flight for far less than this; after
		// that, a replayed ID meets a daemon that no longer confirms it.
		seen:     newReplayCache(max(2*cfg.ClockSkew, protocol.EndedTTL+5*time.Minute)),
		unsealed: make(chan struct{}),
		ready:    make(chan struct{}),
	}
	if a.log == nil {
		a.log = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	}
	a.audit = a.log.With("log_type", "audit")
	if a.now == nil {
		a.now = time.Now
	}
	if a.listen == nil {
		a.listen = net.Listen
	}
	if a.net == nil {
		a.net = &SystemNetwork{TailnetPrefixes: rs.overlay, Timeout: cfg.Callbacks.Timeout}
	}

	if err := checkKeyMode(cfg.SigningKey); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(cfg.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	a.keyFile, err = keys.ParseKeyFile(data)
	if err != nil {
		return nil, fmt.Errorf("signing key %s: %w", cfg.SigningKey, err)
	}
	a.public = a.keyFile.Public
	a.kid = keys.Thumbprint(a.public)

	reg, err := journal.NewRegistry(cfg.Registry)
	if err != nil {
		return nil, err
	}
	a.store, err = journal.Open(cfg.Journal, cfg.Instance, cfg.TrustDomain, reg)
	if err != nil {
		return nil, err
	}

	a.metrics = metrics.NewRegistry()
	a.requests = a.metrics.Counter("machine_identity_requests_total",
		"Token requests by result.", "result",
		ResultIssued, ResultKeyDuplicate, ResultWrongLocation, ResultForeignKey, ResultUnknownIdentity, ResultReplay, ResultMisdirected)
	a.sealedG = a.metrics.Gauge("machine_identity_authority_sealed",
		"1 while the signing key is still encrypted and the instance issues nothing.")
	a.bindings = a.metrics.Counter("machine_identity_binding_events_total",
		"Binding events submitted to the write API by outcome.", "outcome", "accepted", "rejected")

	if err := a.setupReplication(ps); err != nil {
		_ = a.store.Close()
		return nil, err
	}

	if a.keyFile.Encrypted() {
		a.sealedG.Set("", 1)
	} else {
		if err := a.setKey(a.keyFile.Key); err != nil {
			_ = a.store.Close()
			return nil, err
		}
	}
	return a, nil
}

// Close releases the journal.
func (a *Authority) Close() error { return a.store.Close() }

// Kid returns the key ID of this instance.
func (a *Authority) Kid() string { return a.kid }

// PublicKey returns the instance's public key.
func (a *Authority) PublicKey() *ecdsa.PublicKey { return a.public }

// Sealed reports whether the signing key is still encrypted.
func (a *Authority) Sealed() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.key == nil
}

// Store gives tests and tooling access to the journal.
func (a *Authority) Store() *journal.Store { return a.store }

// Metrics returns the metrics registry.
func (a *Authority) Metrics() *metrics.Registry { return a.metrics }

// RequestCount returns machine_identity_requests_total for a result.
func (a *Authority) RequestCount(result string) float64 { return a.requests.Get(result) }

// EquivocationCount returns how many contradicting events of origin were
// skipped.
func (a *Authority) EquivocationCount(origin string) float64 { return a.jm.equivocations.Get(origin) }

func (a *Authority) setKey(k *ecdsa.PrivateKey) error {
	cert, err := tlspin.Certificate(k)
	if err != nil {
		return err
	}
	// The journal signs the position of every own event; it gets the key
	// before the instance counts as unsealed and starts writing.
	if err := a.store.SetSigner(context.Background(), k); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.key != nil {
		return nil
	}
	a.key, a.cert = k, cert
	a.sealedG.Set("", 0)
	close(a.unsealed)
	return nil
}

func (a *Authority) signingKey() (*ecdsa.PrivateKey, tls.Certificate) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.key, a.cert
}

// Unseal decrypts the signing key with a passphrase.
func (a *Authority) Unseal(passphrase []byte) error {
	if !a.Sealed() {
		return nil
	}
	k, err := a.keyFile.Decrypt(passphrase)
	if err != nil {
		return err
	}
	if err := a.setKey(k); err != nil {
		return err
	}
	a.log.Info("unsealed", "kid", a.kid)
	return nil
}

// Ready is closed once the API listener accepts connections.
func (a *Authority) Ready() <-chan struct{} { return a.ready }

// APIAddr returns the bound API address once Ready is closed.
func (a *Authority) APIAddr() string {
	a.addrMu.Lock()
	defer a.addrMu.Unlock()
	if a.apiAddr == nil {
		return ""
	}
	return a.apiAddr.String()
}

// OpsAddr returns the bound ops address, or "" if not (yet) listening.
func (a *Authority) OpsAddr() string {
	a.addrMu.Lock()
	defer a.addrMu.Unlock()
	if a.opsAddr == nil {
		return ""
	}
	return a.opsAddr.String()
}

// Run serves until ctx ends. A sealed instance serves only the ops endpoint
// and the control socket; the API and replication listeners, the pushers
// and journal maintenance start after unsealing.
func (a *Authority) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 4)
	var servers []*http.Server
	var bg sync.WaitGroup
	stopAll := func() {
		cancel()
		shutdown(servers)
		bg.Wait()
	}

	if a.cfg.OpsListen != "-" {
		ln, err := a.listen("tcp", a.cfg.OpsListen)
		if err != nil {
			return fmt.Errorf("ops listener: %w", err)
		}
		a.addrMu.Lock()
		a.opsAddr = ln.Addr()
		a.addrMu.Unlock()
		srv := &http.Server{Handler: a.opsHandler(), ReadHeaderTimeout: 10 * time.Second,
			WriteTimeout: time.Minute, IdleTimeout: time.Minute}
		servers = append(servers, srv)
		go func() { errc <- serve(srv, ln) }()
	}

	a.log.Info("starting", "instance", a.cfg.Instance, "kid", a.kid,
		"fingerprint", keys.Fingerprint(a.public), "sealed", a.Sealed())

	stopControl, err := a.serveControlSocket(ctx)
	if err != nil {
		shutdown(servers)
		return err
	}
	defer stopControl()

	if a.Sealed() {
		a.log.Warn("sealed: run \"ergosum unseal\" on this host to start issuing", "socket", a.cfg.ControlSocket)
		select {
		case <-a.unsealed:
		case <-ctx.Done():
			shutdown(servers)
			return nil
		case err := <-errc:
			shutdown(servers)
			return err
		}
	}

	_, cert := a.signingKey()
	ln, err := a.listen("tcp", a.cfg.Listen)
	if err != nil {
		shutdown(servers)
		return fmt.Errorf("api listener: %w", err)
	}
	a.addrMu.Lock()
	a.apiAddr = ln.Addr()
	a.addrMu.Unlock()
	api := &http.Server{
		Handler:           a.apiHandler(),
		TLSConfig:         tlspin.ServerConfig(cert, nil),
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       time.Minute,
	}
	servers = append(servers, api)
	go func() { errc <- serve(api, tls.NewListener(ln, api.TLSConfig)) }()

	if a.cfg.Replication.Listen != "" {
		srv, rln, err := a.serveReplication(ctx, cert)
		if err != nil {
			shutdown(servers)
			return err
		}
		servers = append(servers, srv)
		go func() { errc <- serve(srv, rln) }()
	}
	bg.Add(2)
	go func() {
		defer bg.Done()
		a.repl.rep.Run(ctx)
	}()
	go func() {
		defer bg.Done()
		a.maintain(ctx)
	}()

	close(a.ready)
	a.log.Info("issuing", "listen", ln.Addr().String(), "replication", a.ReplicationAddr())

	select {
	case <-ctx.Done():
		stopAll()
		return nil
	case err := <-errc:
		stopAll()
		return err
	}
}

func serve(srv *http.Server, ln net.Listener) error {
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func shutdown(servers []*http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(ctx)
	}
}

func (a *Authority) apiHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+protocol.PathToken, a.handleToken)
	mux.HandleFunc("POST "+protocol.PathBindings, a.handleBindingWrite)
	mux.HandleFunc("GET "+protocol.PathBindings, a.handleBindingList)
	mux.HandleFunc("GET "+protocol.PathBindings+"/{identity}", a.handleBindingRead)
	mux.HandleFunc("GET "+protocol.PathKeys, a.handleKeys)
	mux.HandleFunc("GET "+protocol.PathKeysPEM, a.handleKeysPEM)
	return a.bodyGuard(mux, maxAPIBody)
}

func (a *Authority) opsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", a.metrics.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		if a.Sealed() {
			http.Error(w, "sealed", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET "+protocol.PathKeys, a.handleKeys)
	mux.HandleFunc("GET "+protocol.PathKeysPEM, a.handleKeysPEM)
	mux.HandleFunc("GET "+protocol.PathJournalState, func(w http.ResponseWriter, r *http.Request) {
		st, err := a.JournalState(r.Context())
		if err != nil {
			a.writeError(w, http.StatusServiceUnavailable, protocol.ErrUnavailable, "")
			return
		}
		writeJSON(w, http.StatusOK, st)
	})
	return a.bodyGuard(mux, 0)
}

func (a *Authority) handleKeys(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"keys": []keys.JWK{keys.PublicJWK(a.public)}})
}

func (a *Authority) handleKeysPEM(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(keys.MarshalPublicPEM(a.public))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (a *Authority) writeError(w http.ResponseWriter, status int, code, detail string) {
	writeJSON(w, status, protocol.ErrorResponse{V: protocol.Version, Error: code, Detail: detail, ServerTime: a.now().UTC()})
}

// bodyReadTimeout bounds how long a client may take to deliver a request
// body, so that a trickled body cannot hold a connection for the whole
// WriteTimeout. The deadline is cleared afterwards: the server's background
// read must keep noticing a requester that goes away during the callbacks.
const bodyReadTimeout = 15 * time.Second

// maxAPIBody is the largest body the API listener takes (a binding event).
const maxAPIBody = 256 << 10

// bodyGuard bounds every request body before a handler sees it. A request
// that announces a body gets the read deadline at once: an unread body is
// otherwise drained after the handler without any deadline, so a client
// that announces a body and never sends it held a connection for good.
// GET and HEAD carry no body, larger ones are refused before reading, and
// the connection is closed after such a refusal.
func (a *Authority) bodyGuard(next http.Handler, limit int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength == 0 {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.ContentLength > limit {
			w.Header().Set("Connection", "close")
			a.writeError(w, http.StatusRequestEntityTooLarge, protocol.ErrBadRequest, "request body not accepted")
			return
		}
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(bodyReadTimeout))
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

// readBody reads at most limit bytes of the request body under bodyReadTimeout.
func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(bodyReadTimeout))
	data, err := io.ReadAll(io.LimitReader(r.Body, limit))
	_ = rc.SetReadDeadline(time.Time{})
	return data, err
}

// limiter allows one event per key and interval. Its keys come from
// verified requests only, so their number is bounded by the bindings.
type limiter struct {
	mu    sync.Mutex
	every time.Duration
	last  map[string]time.Time
	swept time.Time
}

func newLimiter(every time.Duration) *limiter {
	return &limiter{every: every, last: map[string]time.Time{}}
}

func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t, ok := l.last[key]; ok && now.Sub(t) < l.every {
		return false
	}
	if now.Sub(l.swept) >= l.every {
		for k, t := range l.last {
			if now.Sub(t) >= l.every {
				delete(l.last, k)
			}
		}
		l.swept = now
	}
	l.last[key] = now
	return true
}

// window allows at most max events per interval, whatever their origin.
type window struct {
	mu    sync.Mutex
	every time.Duration
	max   int
	start time.Time
	n     int
}

func (w *window) allow(now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if now.Sub(w.start) >= w.every {
		w.start, w.n = now, 0
	}
	if w.n >= w.max {
		return false
	}
	w.n++
	return true
}

// replayCache remembers keys for a while; first reports whether a key is
// new. Only verified requests add keys.
type replayCache struct {
	mu    sync.Mutex
	ttl   time.Duration
	seen  map[string]time.Time
	swept time.Time
}

func newReplayCache(ttl time.Duration) *replayCache {
	return &replayCache{ttl: ttl, seen: map[string]time.Time{}}
}

func (c *replayCache) first(key string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Sub(c.swept) >= c.ttl {
		for k, t := range c.seen {
			if now.Sub(t) >= c.ttl {
				delete(c.seen, k)
			}
		}
		c.swept = now
	}
	if t, ok := c.seen[key]; ok && now.Sub(t) < c.ttl {
		return false
	}
	c.seen[key] = now
	return true
}
