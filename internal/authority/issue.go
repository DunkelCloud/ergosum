package authority

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DunkelCloud/ergosum/internal/journal"
	"github.com/DunkelCloud/ergosum/internal/jwt"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/metrics"
	"github.com/DunkelCloud/ergosum/internal/protocol"
	"github.com/DunkelCloud/ergosum/internal/tlspin"
)

// Outcomes of a single callback (see journal.Outcome...).
const (
	OutcomeConfirmed       = journal.OutcomeConfirmed
	OutcomeNoOpenRequest   = journal.OutcomeNoOpenRequest
	OutcomeUnreachable     = journal.OutcomeUnreachable
	OutcomeOtherKey        = journal.OutcomeOtherKey
	OutcomeInvalidResponse = journal.OutcomeInvalidResponse
	OutcomeNoAddress       = journal.OutcomeNoAddress
	OutcomeEnded           = journal.OutcomeEnded
)

// CheckOutcome records one check of a request for audit and observations.
type CheckOutcome = journal.CheckOutcome

// Observation is the payload of an instance-signed journal observation.
type Observation = journal.Observation

type plannedCheck struct {
	check   string
	prefix  string // net checks only
	host    string
	port    int
	route   Route
	targets []string // net checks: candidate addresses
}

// requestKind sets token requests and exchange requests (ADR 0004) apart:
// they run the same procedure, but sign under their own context and count
// and log under their own names.
type requestKind struct {
	event   string // audit "event"; the message reads it with spaces
	context string // signature context of the request
	metric  *metrics.Vec
}

func (k requestKind) message(result string) string {
	return strings.ReplaceAll(k.event, "_", " ") + " " + result
}

// readEnvelope reads the request body as an envelope. Reading the body to
// its end lets the server notice when the requester goes away, which
// cancels r.Context() (see the end of the callbacks).
func (a *Authority) readEnvelope(w http.ResponseWriter, r *http.Request) (protocol.Envelope, bool) {
	data, err := readBody(w, r, 64<<10)
	var env protocol.Envelope
	if err != nil || json.Unmarshal(data, &env) != nil {
		a.writeError(w, http.StatusBadRequest, protocol.ErrBadRequest, "malformed envelope")
		return env, false
	}
	return env, true
}

func (a *Authority) handleToken(w http.ResponseWriter, r *http.Request) {
	key, _ := a.signingKey()
	if key == nil {
		a.writeError(w, http.StatusServiceUnavailable, protocol.ErrUnavailable, "sealed")
		return
	}
	env, ok := a.readEnvelope(w, r)
	if !ok {
		return
	}
	var req protocol.TokenRequest
	if err := env.Decode(&req); err != nil {
		a.writeError(w, http.StatusBadRequest, protocol.ErrBadRequest, "malformed payload")
		return
	}
	if req.V != protocol.Version {
		a.writeError(w, http.StatusBadRequest, protocol.ErrUnsupported, "")
		return
	}
	pub, addrs, err := validateRequest(&req, protocol.TypeTokenRequest)
	if err != nil {
		a.writeError(w, http.StatusBadRequest, protocol.ErrBadRequest, err.Error())
		return
	}
	p, ok := a.admit(w, r, a.tokenKind, env, &req, pub, addrs)
	if !ok {
		return
	}
	defer p.release()

	token, claims, err := a.issue(key, p.binding, p.obs.Checks)
	if err != nil {
		a.log.Error("signing token failed", "err", err)
		a.writeError(w, http.StatusServiceUnavailable, protocol.ErrUnavailable, "")
		return
	}
	p.obs.TokenID = claims.ID
	a.record(r.Context(), a.tokenKind, ResultIssued, p.obs)
	writeJSON(w, http.StatusOK, protocol.TokenResponse{
		V: protocol.Version, Token: token,
		ExpiresAt:  time.Unix(claims.Expiry, 0).UTC(),
		ServerTime: a.now().UTC(),
	})
}

// admitted is a request that passed every step before issuing.
type admitted struct {
	binding *journal.Binding
	obs     Observation // with the outcomes of the checks
	release func()      // ends the request for the identity's limit
}

// admit runs the procedure of ADR 0001 on a decoded and validated request,
// up to the point where a token would be issued: timestamp, binding, key,
// signature, addressee, rate limit, replay, checks. It answers every
// refusal itself.
func (a *Authority) admit(w http.ResponseWriter, r *http.Request, kind requestKind, env protocol.Envelope,
	req *protocol.TokenRequest, pub *ecdsa.PublicKey, addrs []netip.Addr) (admitted, bool) {
	now := a.now()
	if d := now.Sub(req.Timestamp); d > a.cfg.ClockSkew || d < -a.cfg.ClockSkew {
		// Not yet verified: anyone can send this, so the warning is limited.
		if a.unverified.allow(now) {
			a.log.Warn("request timestamp outside the accepted window", "identity", req.Identity, "skew", d.String())
		}
		a.writeError(w, http.StatusBadRequest, protocol.ErrClockSkew, "")
		return admitted{}, false
	}

	ctx := r.Context()
	obs := Observation{
		V: 1, Instance: a.cfg.Instance, Kid: a.kid, Identity: req.Identity,
		RequestID: req.RequestID, Key: keys.Fingerprint(pub), Remote: r.RemoteAddr, Time: now.UTC(),
	}
	b, err := a.store.Binding(ctx, req.Identity)
	if err != nil {
		a.log.Error("journal read failed", "err", err)
		a.writeError(w, http.StatusServiceUnavailable, protocol.ErrUnavailable, "")
		return admitted{}, false
	}
	switch {
	case b == nil:
		a.deny(ctx, w, kind, ResultUnknownIdentity, obs, "no binding")
		return admitted{}, false
	case !b.Active():
		obs.Epoch = b.Epoch
		a.deny(ctx, w, kind, ResultUnknownIdentity, obs, "binding revoked")
		return admitted{}, false
	}
	obs.Epoch = b.Epoch
	if keys.Fingerprint(pub) != b.Key {
		a.deny(ctx, w, kind, ResultForeignKey, obs, "key does not match the binding")
		return admitted{}, false
	}
	if !env.Verify(pub, kind.context) {
		a.deny(ctx, w, kind, ResultForeignKey, obs, "request signature does not verify")
		return admitted{}, false
	}
	// A request addressed to another instance gets no callback: the daemon
	// has it in flight to that instance and would answer "no open request",
	// which must remain proof of a second key.
	if req.To != keys.Fingerprint(a.public) {
		a.deny(ctx, w, kind, ResultMisdirected, obs, "request addressed to "+req.To)
		return admitted{}, false
	}
	// What a holder of the bound key can make the instance do is bounded:
	// callbacks, journal entries, audit lines and the replay cache. Token
	// and exchange requests share the limit.
	release, ok := a.perID.acquire(req.Identity, now)
	if !ok {
		kind.metric.Inc(ResultRateLimited)
		if a.limiter.allow(ResultRateLimited+" "+req.Identity, now) {
			a.audit.Warn(kind.message(ResultRateLimited), "event", kind.event, "result", ResultRateLimited,
				"identity", req.Identity, "key", obs.Key, "remote", obs.Remote)
		}
		a.writeError(w, http.StatusTooManyRequests, protocol.ErrRateLimited, "")
		return admitted{}, false
	}
	// The daemon never reuses a request ID. A repeat comes from a second
	// holder of the key replaying an ID it has seen; it gets no callbacks.
	if !a.seen.first(req.Identity+" "+req.RequestID, now) {
		release()
		a.deny(ctx, w, kind, ResultReplay, obs, "request ID already processed")
		return admitted{}, false
	}

	plan, notResponsible := a.plan(b, addrs)
	if notResponsible != "" {
		release()
		a.log.Info("net check needs another instance", "identity", req.Identity, "prefix", notResponsible)
		a.writeError(w, http.StatusMisdirectedRequest, protocol.ErrNotResponsible, notResponsible)
		return admitted{}, false
	}
	outcomes := a.runChecks(ctx, plan, req, pub)
	if ctx.Err() != nil {
		// The requester is gone (timeout, crash, restart). Nobody can receive
		// the answer, and a "no open request" from a daemon that has dropped
		// the request proves nothing: the request is discarded without a
		// trace in the journal.
		release()
		a.log.Info("request abandoned by the requester", "identity", req.Identity, "request_id", req.RequestID)
		return admitted{}, false
	}
	for _, o := range outcomes {
		if o.Outcome == OutcomeEnded {
			// The daemon says it gave up on this request, or a restarted
			// daemon cannot tell: discarded like an abandoned request.
			release()
			a.log.Info("request ended at the machine", "identity", req.Identity, "request_id", req.RequestID, "detail", o.Detail)
			a.writeError(w, http.StatusForbidden, protocol.ErrDenied, "")
			return admitted{}, false
		}
	}
	obs.Checks = outcomes

	result := ResultIssued
	for _, o := range outcomes {
		switch o.Outcome {
		case OutcomeConfirmed:
		case OutcomeNoOpenRequest:
			result = ResultKeyDuplicate
		default:
			if result == ResultIssued {
				result = ResultWrongLocation
			}
		}
	}
	if result != ResultIssued {
		release()
		a.deny(ctx, w, kind, result, obs, "")
		return admitted{}, false
	}
	return admitted{binding: b, obs: obs, release: release}, true
}

func validateRequest(req *protocol.TokenRequest, typ string) (*ecdsa.PublicKey, []netip.Addr, error) {
	if req.Type != typ {
		return nil, nil, errors.New("wrong message type")
	}
	if !protocol.ValidDNSName(req.Identity) {
		return nil, nil, errors.New("bad identity")
	}
	if !protocol.ValidRequestID(req.RequestID) {
		return nil, nil, errors.New("bad request_id")
	}
	if !keys.ValidFingerprint(req.To) {
		return nil, nil, errors.New("bad to")
	}
	spki, err := base64.StdEncoding.DecodeString(req.Key)
	if err != nil {
		return nil, nil, errors.New("bad key")
	}
	pub, err := keys.ParseSPKI(spki)
	if err != nil {
		return nil, nil, errors.New("bad key")
	}
	addrs, err := protocol.ParseAddresses(req.Addresses)
	if err != nil {
		return nil, nil, err
	}
	return pub, addrs, nil
}

// plan turns the binding's checks into callbacks. Callback targets come
// from the binding only; from the request it takes just the underlay
// addresses that lie inside a net check's prefix. A net check whose prefix
// is not attached to this instance makes the instance not responsible.
func (a *Authority) plan(b *journal.Binding, addrs []netip.Addr) (plan []plannedCheck, notResponsible string) {
	for _, c := range b.Checks {
		switch c.Type {
		case protocol.CheckTailnet, protocol.CheckIP:
			host, port, _ := journal.SplitTarget(c.Target)
			if port == 0 {
				port = a.cfg.Callbacks.Port
			}
			route := a.routes.tailnet
			if c.Type == protocol.CheckIP {
				route = a.routes.ip
			}
			plan = append(plan, plannedCheck{check: c.Type, host: host, port: port, route: route})
		case protocol.CheckNet:
			p := netip.MustParsePrefix(c.Target)
			n, ok := a.routes.network(p)
			if !ok {
				return nil, c.Target
			}
			pc := plannedCheck{check: c.Type, prefix: c.Target, port: a.cfg.Callbacks.Port, route: n.route}
			for _, ad := range addrs {
				if p.Contains(ad) && len(pc.targets) < 4 {
					pc.targets = append(pc.targets, ad.String())
				}
			}
			plan = append(plan, pc)
		}
	}
	return plan, ""
}

func (a *Authority) runChecks(ctx context.Context, plan []plannedCheck, req *protocol.TokenRequest, pub *ecdsa.PublicKey) []CheckOutcome {
	out := make([]CheckOutcome, len(plan))
	var wg sync.WaitGroup
	for i, pc := range plan {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if pc.check != protocol.CheckNet {
				out[i] = a.callback(ctx, pc, pc.host, req, pub)
				return
			}
			if len(pc.targets) == 0 {
				out[i] = CheckOutcome{Type: pc.check, Target: pc.prefix, Outcome: OutcomeNoAddress, Detail: "no reported address inside the network"}
				return
			}
			for _, host := range pc.targets {
				out[i] = a.callback(ctx, pc, host, req, pub)
				if out[i].Outcome == OutcomeConfirmed || out[i].Outcome == OutcomeNoOpenRequest {
					return
				}
			}
		}()
	}
	wg.Wait()
	return out
}

// callback performs one callback over mutual TLS: the authority presents its
// instance key, the daemon must present the bound key, and the daemon's
// answer must be signed with that key over this request ID, nonce and
// target.
func (a *Authority) callback(ctx context.Context, pc plannedCheck, host string, req *protocol.TokenRequest, pub *ecdsa.PublicKey) CheckOutcome {
	target := protocol.Target(pc.check, pc.prefix, host, pc.port)
	res := CheckOutcome{Type: pc.check, Target: target}
	_, cert := a.signingKey()
	address := net.JoinHostPort(host, strconv.Itoa(pc.port))
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return a.net.Dial(ctx, pc.route, address)
		},
		TLSClientConfig:        tlspin.ClientConfig(&cert, tlspin.Fingerprints(keys.Fingerprint(pub))),
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 16 << 10,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: a.cfg.Callbacks.Timeout, CheckRedirect: tlspin.NoRedirect}

	cb := protocol.Callback{
		V: protocol.Version, Type: protocol.TypeCallback, RequestID: req.RequestID,
		Nonce: protocol.NewNonce(), Target: target, Authority: a.kid,
	}
	body, _ := json.Marshal(cb)
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+address+protocol.PathCallback, bytes.NewReader(body))
	if err != nil {
		res.Outcome, res.Detail = OutcomeUnreachable, err.Error()
		return res
	}
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(hreq)
	if err != nil {
		res.Outcome, res.Detail = OutcomeUnreachable, err.Error()
		if errors.Is(err, tlspin.ErrNotPinned) {
			res.Outcome = OutcomeOtherKey
		}
		return res
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		res.Outcome, res.Detail = OutcomeInvalidResponse, "status "+resp.Status
		return res
	}
	var env protocol.Envelope
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&env); err != nil {
		res.Outcome, res.Detail = OutcomeInvalidResponse, "malformed envelope"
		return res
	}
	if !env.Verify(pub, protocol.ContextCallbackResponse) {
		res.Outcome, res.Detail = OutcomeInvalidResponse, "signature does not verify"
		return res
	}
	var cr protocol.CallbackResponse
	if err := env.Decode(&cr); err != nil {
		res.Outcome, res.Detail = OutcomeInvalidResponse, "malformed payload"
		return res
	}
	if cr.V != protocol.Version || cr.Type != protocol.TypeCallbackResponse || cr.RequestID != cb.RequestID ||
		cr.Nonce != cb.Nonce || cr.Target != cb.Target || cr.Authority != cb.Authority {
		res.Outcome, res.Detail = OutcomeInvalidResponse, "response does not match the callback"
		return res
	}
	res.Outcome, res.Detail = classify(cr, req.Timestamp)
	if res.Outcome == OutcomeNoOpenRequest {
		res.Evidence = &env
	}
	return res
}

// classify turns a verified callback response into an outcome. "No open
// request" is proof of a second key only from a daemon process that already
// ran when the request was made: a process started later knows nothing of
// requests its predecessor made. Both times come from the machine's clock;
// a second key holder can choose the request's timestamp, but gains only
// within the clock-skew window after a restart of the real machine, and
// even then gets no token.
func classify(cr protocol.CallbackResponse, requested time.Time) (outcome, detail string) {
	switch cr.Status {
	case protocol.StatusConfirmed:
		return OutcomeConfirmed, ""
	case protocol.StatusEnded:
		return OutcomeEnded, "the daemon gave up on the request"
	case protocol.StatusNoOpenRequest:
		if cr.Started.IsZero() || cr.Started.After(requested) {
			return OutcomeEnded, "the daemon started after the request; no proof"
		}
		return OutcomeNoOpenRequest, ""
	default:
		return OutcomeInvalidResponse, "unknown status"
	}
}

func (a *Authority) issue(key *ecdsa.PrivateKey, b *journal.Binding, outcomes []CheckOutcome) (string, jwt.Claims, error) {
	now := a.now()
	seen := map[string]bool{protocol.CheckKey: true}
	for _, o := range outcomes {
		seen[o.Type] = true
	}
	checks := make([]string, 0, len(seen))
	for c := range seen {
		checks = append(checks, c)
	}
	sort.Strings(checks)
	c := jwt.Claims{
		Issuer:    a.cfg.Issuer,
		Subject:   "spiffe://" + a.cfg.TrustDomain + "/host/" + b.Identity,
		Audience:  []string{a.cfg.Audience},
		Host:      b.Identity,
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		Expiry:    now.Add(a.cfg.TokenTTL).Unix(),
		ID:        jwt.NewID(),
		Checks:    checks,
	}
	tok, err := jwt.Sign(key, a.kid, c)
	return tok, c, err
}

// deny answers a failed request with a uniform "denied"; the reason goes to
// the audit log and the journal only.
func (a *Authority) deny(ctx context.Context, w http.ResponseWriter, kind requestKind, result string, obs Observation, reason string) {
	obs.Reason = reason
	a.record(ctx, kind, result, obs)
	a.writeError(w, http.StatusForbidden, protocol.ErrDenied, "")
}

// record updates the metric, writes the audit entry and appends the signed
// observation. Only requests that verify against a bound key reach the
// journal. Foreign keys and unknown identities can be sent by anyone: they
// count in the metric and reach the audit log within an overall limit, but
// never the journal. Refusals that a key holder can repeat at will (wrong
// location, replay) are journaled once per identity and minute. Proven key
// duplicates and replays are logged as alerts. Exchange requests leave the
// same observations as token requests.
func (a *Authority) record(ctx context.Context, kind requestKind, result string, obs Observation) {
	kind.metric.Inc(result)
	obs.Kind = journal.KindObservation + "." + result
	now := a.now()
	verified := result != ResultForeignKey && result != ResultUnknownIdentity
	switch {
	case !verified:
		if a.unverified.allow(now) {
			a.audit.Warn(kind.message(result), "event", kind.event, "result", result,
				"identity", obs.Identity, "key", obs.Key, "remote", obs.Remote, "reason", obs.Reason)
		}
		return
	case result == ResultWrongLocation || result == ResultReplay || result == ResultMisdirected:
		if !a.limiter.allow(result+" "+obs.Identity, now) {
			return
		}
	}
	attrs := []any{
		"event", kind.event, "result", result, "identity", obs.Identity,
		"request_id", obs.RequestID, "key", obs.Key, "remote", obs.Remote, "epoch", obs.Epoch,
	}
	if obs.Reason != "" {
		attrs = append(attrs, "reason", obs.Reason)
	}
	if len(obs.Checks) > 0 {
		attrs = append(attrs, "checks", checkSummary(obs.Checks))
	}
	if obs.TokenID != "" {
		attrs = append(attrs, "jti", obs.TokenID, "kid", a.kid)
	}
	level := slog.LevelInfo
	switch result {
	case ResultKeyDuplicate:
		level = slog.LevelError
		attrs = append(attrs, "alert", "key duplicate proven: the bound key answered that it has no open request")
	case ResultReplay:
		// A replayed ID comes from a second holder of the key, typically a
		// copy of a disk image: as serious as a proven duplicate.
		level = slog.LevelError
		attrs = append(attrs, "alert", "request ID replayed: a second holder of the bound key reused an ID the machine had sent")
	case ResultMisdirected:
		level = slog.LevelError
		attrs = append(attrs, "alert", "request addressed to another instance: an instance or a relay forwarded a signed request")
	case ResultWrongLocation:
		level = slog.LevelWarn
	}
	a.audit.Log(ctx, level, kind.message(result), attrs...)

	// Peers accept only observations of a bounded shape; free texts are
	// clipped to it, and anything else would stop replication there.
	obs.Remote = journal.Clip(obs.Remote, journal.MaxRemote)
	obs.Reason = journal.Clip(obs.Reason, journal.MaxReason)
	for i := range obs.Checks {
		obs.Checks[i].Detail = journal.Clip(obs.Checks[i].Detail, journal.MaxDetail)
	}
	if err := obs.Validate(); err != nil {
		a.log.Error("observation not journaled", "err", err, "identity", obs.Identity, "request_id", obs.RequestID)
		return
	}
	key, _ := a.signingKey()
	env, err := protocol.Seal(key, protocol.ContextObservation, obs)
	if err != nil {
		a.log.Error("signing observation failed", "err", err)
		return
	}
	body, _ := json.Marshal(env)
	payload, _ := base64.RawURLEncoding.DecodeString(env.Payload)
	sum := sha256.Sum256(payload)
	if _, err := a.store.AppendObservation(context.WithoutCancel(ctx), obs.Kind, obs.Identity, hex.EncodeToString(sum[:]), body); err != nil {
		a.log.Error("journal write failed", "err", err)
		return
	}
	a.repl.rep.Notify()
}

func checkSummary(cs []CheckOutcome) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = fmt.Sprintf("%s=%s", c.Target, c.Outcome)
	}
	return out
}
