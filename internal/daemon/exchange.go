package daemon

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/DunkelCloud/ergosum/internal/exchange"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/protocol"
	"github.com/DunkelCloud/ergosum/internal/tlspin"
)

// ExchangeResult is an instance's answer to an exchange request (ADR 0004).
type ExchangeResult struct {
	// Authority is the key fingerprint of the instance, as pinned.
	Authority string
	// ReleaseKey is the signed release key, as part A keeps it.
	ReleaseKey protocol.Envelope
	// TrustDomain and Key come from the verified release key; Key is S,
	// a compressed point.
	TrustDomain string
	Key         []byte
	// Points are the evaluated points Y, in the order of the request.
	Points [][]byte
}

// Exchange sends one exchange request with the given blinded points to the
// instance whose key fingerprint is authority; with no points it only
// fetches the release key. The callback listener stays open and the
// request counts as in flight to this instance until the answer arrives,
// as for a token request.
func (d *Daemon) Exchange(ctx context.Context, authority string, points [][]byte) (*ExchangeResult, error) {
	if len(points) > protocol.MaxExchangePoints {
		return nil, fmt.Errorf("more than %d points in one request", protocol.MaxExchangePoints)
	}
	var a *authorityClient
	authorities, _ := d.snapshot()
	for _, c := range authorities {
		if c.pin == authority {
			a = c
		}
	}
	if a == nil {
		return nil, fmt.Errorf("%s is not an authority in use", authority)
	}
	if err := d.acquireListener(); err != nil {
		return nil, err
	}
	defer d.releaseListener()
	d.rmu.Lock()
	defer d.rmu.Unlock()

	id := protocol.NewRequestID()
	d.inflight.add(id, a.pin)
	defer d.inflight.remove(id)
	key, _ := d.identity()
	req := protocol.ExchangeRequest{
		TokenRequest: protocol.TokenRequest{
			V: protocol.Version, Type: protocol.TypeExchangeRequest, Identity: d.cfg.Identity,
			RequestID: id, Timestamp: d.now().UTC(), Addresses: d.addresses(),
			Key: base64.StdEncoding.EncodeToString(keys.SPKI(&key.PublicKey)), To: a.pin,
		},
		Points: make([]string, len(points)),
	}
	for i, p := range points {
		req.Points[i] = exchange.EncodePoint(p)
	}
	env, err := protocol.Seal(key, protocol.ContextExchangeRequest, req)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(env)
	sent := d.now()
	resp, err := d.do(ctx, a, func(base string) (*http.Request, error) {
		hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+protocol.PathExchange, bytes.NewReader(body))
		if err == nil {
			hreq.Header.Set("Content-Type", "application/json")
		}
		return hreq, err
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	received := d.now()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		// An instance of an earlier version answers a plain 404.
		var er protocol.ErrorResponse
		_ = json.Unmarshal(data, &er)
		d.observeSkew(er.ServerTime, sent, received)
		return nil, &RequestError{Status: resp.StatusCode, Code: er.Error, Detail: er.Detail}
	}
	var xr protocol.ExchangeResponse
	if err := json.Unmarshal(data, &xr); err != nil {
		return nil, fmt.Errorf("malformed exchange response: %w", err)
	}
	d.observeSkew(xr.ServerTime, sent, received)
	peer, err := tlspin.PeerKey(resp.TLS)
	if err != nil {
		return nil, err
	}
	res, err := d.checkReleaseKey(xr.ReleaseKey, peer)
	if err != nil {
		return nil, err
	}
	if xr.V != protocol.Version || len(xr.Points) != len(points) {
		return nil, errors.New("the exchange response does not match the request")
	}
	for _, s := range xr.Points {
		y, err := exchange.DecodePoint(s)
		if err != nil {
			return nil, fmt.Errorf("exchange response: %w", err)
		}
		res.Points = append(res.Points, y)
	}
	return res, nil
}

// checkReleaseKey verifies a release key with the key of the instance that
// sent it: signed by that instance, naming it, for this identity, in the
// trust domain of the authority list in use.
func (d *Daemon) checkReleaseKey(env protocol.Envelope, peer *ecdsa.PublicKey) (*ExchangeResult, error) {
	if !env.Verify(peer, protocol.ContextReleaseKey) {
		return nil, errors.New("the release key is not signed by the instance")
	}
	var rk protocol.ReleaseKey
	if err := env.Decode(&rk); err != nil {
		return nil, err
	}
	if rk.V != protocol.Version || rk.Type != protocol.TypeReleaseKey || rk.Identity != d.cfg.Identity ||
		rk.Authority != keys.Thumbprint(peer) || !protocol.ValidDNSName(rk.TrustDomain) {
		return nil, errors.New("the release key is not for this identity at this instance")
	}
	d.amu.Lock()
	list := d.list
	d.amu.Unlock()
	if list != nil && list.TrustDomain != rk.TrustDomain {
		return nil, fmt.Errorf("release key for trust domain %s, the authority list is for %s", rk.TrustDomain, list.TrustDomain)
	}
	s, err := exchange.DecodePoint(rk.Key)
	if err != nil {
		return nil, fmt.Errorf("release key: %w", err)
	}
	return &ExchangeResult{Authority: keys.Fingerprint(peer), ReleaseKey: env, TrustDomain: rk.TrustDomain, Key: s}, nil
}
