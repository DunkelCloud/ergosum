package authority

import (
	"fmt"
	"net/http"
	"os"

	"github.com/DunkelCloud/ergosum/internal/exchange"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/protocol"
)

// loadExchangeKey reads Config.ExchangeKeyFile. An encrypted exchange key
// needs an encrypted signing key: both open with one passphrase at unseal.
func (a *Authority) loadExchangeKey() error {
	if a.cfg.ExchangeKeyFile == "" {
		return nil
	}
	if err := checkKeyMode("exchange key", a.cfg.ExchangeKeyFile); err != nil {
		return err
	}
	data, err := os.ReadFile(a.cfg.ExchangeKeyFile)
	if err != nil {
		return fmt.Errorf("exchange key: %w", err)
	}
	if a.exchangeFile, err = keys.ParseExchangeKeyFile(data); err != nil {
		return fmt.Errorf("exchange key %s: %w", a.cfg.ExchangeKeyFile, err)
	}
	if a.exchangeFile.Encrypted() && !a.keyFile.Encrypted() {
		return fmt.Errorf("exchange key %s is encrypted, the signing key is not: encrypt both with one passphrase, or neither", a.cfg.ExchangeKeyFile)
	}
	return nil
}

// exchangeKey returns the exchange key; nil without one, or while it is
// still encrypted.
func (a *Authority) exchangeKey() []byte {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.xkey
}

// handleExchange answers an exchange request (ADR 0004): after the same
// procedure as a token request, it evaluates the blinded points with the
// identity's scalar and returns them with the identity's release key. A
// successful exchange writes nothing to the journal; the audit log records
// it.
func (a *Authority) handleExchange(w http.ResponseWriter, r *http.Request) {
	if a.cfg.ExchangeKeyFile == "" {
		a.writeError(w, http.StatusNotFound, protocol.ErrNoExchange, "")
		return
	}
	key, _ := a.signingKey()
	xkey := a.exchangeKey()
	if key == nil || xkey == nil {
		a.writeError(w, http.StatusServiceUnavailable, protocol.ErrUnavailable, "sealed")
		return
	}
	env, ok := a.readEnvelope(w, r)
	if !ok {
		return
	}
	var req protocol.ExchangeRequest
	if err := env.Decode(&req); err != nil {
		a.writeError(w, http.StatusBadRequest, protocol.ErrBadRequest, "malformed payload")
		return
	}
	if req.V != protocol.Version {
		a.writeError(w, http.StatusBadRequest, protocol.ErrUnsupported, "")
		return
	}
	pub, addrs, err := validateRequest(&req.TokenRequest, protocol.TypeExchangeRequest)
	if err != nil {
		a.writeError(w, http.StatusBadRequest, protocol.ErrBadRequest, err.Error())
		return
	}
	points, err := decodePoints(req.Points)
	if err != nil {
		a.writeError(w, http.StatusBadRequest, protocol.ErrBadRequest, err.Error())
		return
	}
	p, ok := a.admit(w, r, a.exchangeKind, env, &req.TokenRequest, pub, addrs)
	if !ok {
		return
	}
	defer p.release()

	s, err := exchange.DeriveScalar(xkey, a.cfg.TrustDomain, req.Identity)
	if err != nil {
		a.log.Error("deriving the release scalar failed", "err", err, "identity", req.Identity)
		a.writeError(w, http.StatusServiceUnavailable, protocol.ErrUnavailable, "")
		return
	}
	out := make([]string, len(points))
	for i, x := range points {
		y, err := exchange.Evaluate(s, x)
		if err != nil { // checked by decodePoints
			a.writeError(w, http.StatusBadRequest, protocol.ErrBadRequest, "bad point")
			return
		}
		out[i] = exchange.EncodePoint(y)
	}
	rk, err := protocol.Seal(key, protocol.ContextReleaseKey, protocol.ReleaseKey{
		V: protocol.Version, Type: protocol.TypeReleaseKey, TrustDomain: a.cfg.TrustDomain,
		Identity: req.Identity, Authority: a.kid, Key: exchange.EncodePoint(exchange.ReleaseKey(s)),
	})
	if err != nil {
		a.log.Error("signing the release key failed", "err", err)
		a.writeError(w, http.StatusServiceUnavailable, protocol.ErrUnavailable, "")
		return
	}
	a.exchanges.Inc(ResultIssued)
	a.audit.Info(a.exchangeKind.message(ResultIssued), "event", a.exchangeKind.event, "result", ResultIssued,
		"identity", req.Identity, "request_id", req.RequestID, "key", p.obs.Key, "remote", p.obs.Remote,
		"epoch", p.obs.Epoch, "checks", checkSummary(p.obs.Checks), "points", len(points))
	writeJSON(w, http.StatusOK, protocol.ExchangeResponse{
		V: protocol.Version, ReleaseKey: rk, Points: out, ServerTime: a.now().UTC(),
	})
}

// decodePoints checks the points of an exchange request, as part of
// validating its envelope.
func decodePoints(in []string) ([][]byte, error) {
	if len(in) > protocol.MaxExchangePoints {
		return nil, fmt.Errorf("more than %d points", protocol.MaxExchangePoints)
	}
	out := make([][]byte, len(in))
	for i, s := range in {
		b, err := exchange.DecodePoint(s)
		if err != nil {
			return nil, fmt.Errorf("point %d: %w", i, err)
		}
		out[i] = b
	}
	return out, nil
}
