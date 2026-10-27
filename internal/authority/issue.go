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
	"sync"
	"time"

	"github.com/DunkelCloud/ergosum/internal/journal"
	"github.com/DunkelCloud/ergosum/internal/jwt"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/protocol"
	"github.com/DunkelCloud/ergosum/internal/tlspin"
)

// Outcomes of a single callback.
const (
	OutcomeConfirmed       = "confirmed"
	OutcomeNoOpenRequest   = "no_open_request"
	OutcomeUnreachable     = "unreachable"
	OutcomeOtherKey        = "other_key"
	OutcomeInvalidResponse = "invalid_response"
	OutcomeNoAddress       = "no_address"
)

// CheckOutcome records one check of a request for audit and observations.
type CheckOutcome struct {
	Type     string             `json:"type"`
	Target   string             `json:"target"`
	Outcome  string             `json:"outcome"`
	Detail   string             `json:"detail,omitempty"`
	Evidence *protocol.Envelope `json:"evidence,omitempty"` // signed no_open_request
}

// Observation is the payload of an instance-signed journal observation.
type Observation struct {
	V         int            `json:"v"`
	Kind      string         `json:"kind"`
	Instance  string         `json:"instance"`
	Kid       string         `json:"kid"`
	Identity  string         `json:"identity"`
	Epoch     uint64         `json:"epoch,omitempty"`
	RequestID string         `json:"request_id"`
	Key       string         `json:"key,omitempty"`
	Remote    string         `json:"remote,omitempty"`
	Checks    []CheckOutcome `json:"checks,omitempty"`
	TokenID   string         `json:"jti,omitempty"`
	Reason    string         `json:"reason,omitempty"`
	Time      time.Time      `json:"time"`
}

type plannedCheck struct {
	check   string
	prefix  string // net checks only
	host    string
	port    int
	route   Route
	targets []string // net checks: candidate addresses
}

func (a *Authority) handleToken(w http.ResponseWriter, r *http.Request) {
	key, _ := a.signingKey()
	if key == nil {
		a.writeError(w, http.StatusServiceUnavailable, protocol.ErrUnavailable, "sealed")
		return
	}
	var env protocol.Envelope
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&env); err != nil {
		a.writeError(w, http.StatusBadRequest, protocol.ErrBadRequest, "malformed envelope")
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
	pub, addrs, err := validateRequest(&req)
	if err != nil {
		a.writeError(w, http.StatusBadRequest, protocol.ErrBadRequest, err.Error())
		return
	}
	now := a.now()
	if d := now.Sub(req.Timestamp); d > a.cfg.ClockSkew || d < -a.cfg.ClockSkew {
		a.log.Warn("request timestamp outside the accepted window", "identity", req.Identity, "skew", d.String())
		a.writeError(w, http.StatusBadRequest, protocol.ErrClockSkew, "")
		return
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
		return
	}
	switch {
	case b == nil:
		a.deny(ctx, w, ResultUnknownIdentity, obs, "no binding")
		return
	case !b.Active():
		obs.Epoch = b.Epoch
		a.deny(ctx, w, ResultUnknownIdentity, obs, "binding revoked")
		return
	}
	obs.Epoch = b.Epoch
	if keys.Fingerprint(pub) != b.Key {
		a.deny(ctx, w, ResultForeignKey, obs, "key does not match the binding")
		return
	}
	if !env.Verify(pub, protocol.ContextRequest) {
		a.deny(ctx, w, ResultForeignKey, obs, "request signature does not verify")
		return
	}

	plan, notResponsible := a.plan(b, addrs)
	if notResponsible != "" {
		a.log.Info("net check needs another instance", "identity", req.Identity, "prefix", notResponsible)
		a.writeError(w, http.StatusMisdirectedRequest, protocol.ErrNotResponsible, notResponsible)
		return
	}
	outcomes := a.runChecks(ctx, plan, &req, pub)
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
		a.deny(ctx, w, result, obs, "")
		return
	}

	token, claims, err := a.issue(key, b, outcomes)
	if err != nil {
		a.log.Error("signing token failed", "err", err)
		a.writeError(w, http.StatusInternalServerError, protocol.ErrUnavailable, "")
		return
	}
	obs.TokenID = claims.ID
	a.record(ctx, ResultIssued, obs)
	writeJSON(w, http.StatusOK, protocol.TokenResponse{
		V: protocol.Version, Token: token,
		ExpiresAt:  time.Unix(claims.Expiry, 0).UTC(),
		ServerTime: a.now().UTC(),
	})
}

func validateRequest(req *protocol.TokenRequest) (*ecdsa.PublicKey, []netip.Addr, error) {
	if req.Type != protocol.TypeTokenRequest {
		return nil, nil, errors.New("wrong message type")
	}
	if !protocol.ValidDNSName(req.Identity) {
		return nil, nil, errors.New("bad identity")
	}
	if !protocol.ValidRequestID(req.RequestID) {
		return nil, nil, errors.New("bad request_id")
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
		TLSClientConfig:   tlspin.ClientConfig(&cert, tlspin.Fingerprints(keys.Fingerprint(pub))),
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: a.cfg.Callbacks.Timeout}

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
	switch cr.Status {
	case protocol.StatusConfirmed:
		res.Outcome = OutcomeConfirmed
	case protocol.StatusNoOpenRequest:
		res.Outcome = OutcomeNoOpenRequest
		res.Evidence = &env
	default:
		res.Outcome, res.Detail = OutcomeInvalidResponse, "unknown status"
	}
	return res
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
func (a *Authority) deny(ctx context.Context, w http.ResponseWriter, result string, obs Observation, reason string) {
	obs.Reason = reason
	a.record(ctx, result, obs)
	a.writeError(w, http.StatusForbidden, protocol.ErrDenied, "")
}

// record updates the metric, writes the audit entry and appends the signed
// observation. Requests without a valid binding key (foreign key, unknown
// identity) are rate-limited per identity, as they can be sent by anyone.
func (a *Authority) record(ctx context.Context, result string, obs Observation) {
	a.requests.Inc(result)
	obs.Kind = journal.KindObservation + "." + result
	limited := result == ResultForeignKey || result == ResultUnknownIdentity
	if limited && !a.limiter.allow(result+"|"+obs.Identity, a.now()) {
		return
	}
	attrs := []any{
		"event", "token_request", "result", result, "identity", obs.Identity,
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
	case ResultWrongLocation, ResultForeignKey, ResultUnknownIdentity:
		level = slog.LevelWarn
	}
	a.audit.Log(ctx, level, "token request "+result, attrs...)

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
	}
}

func checkSummary(cs []CheckOutcome) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = fmt.Sprintf("%s=%s", c.Target, c.Outcome)
	}
	return out
}
