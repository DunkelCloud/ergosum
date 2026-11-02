package protocol

import "time"

// The exchange of ADR 0004: a daemon has the instances evaluate blinded
// points with its identity's scalar, after the same checks as for a token.
const (
	// ContextExchangeRequest signs an exchange request; it is the only
	// thing that sets it apart from a token request for the signature.
	ContextExchangeRequest = "ergosum/v1/exchange-request"
	// ContextReleaseKey signs the release key an instance hands out.
	ContextReleaseKey = "ergosum/v1/release-key"

	PathExchange = "/v1/exchange"

	TypeExchangeRequest = "exchange_request"
	TypeReleaseKey      = "release_key"

	// ErrNoExchange (404): the instance holds no exchange key.
	ErrNoExchange = "no_exchange"

	// MaxExchangePoints is the most points an exchange request may carry.
	MaxExchangePoints = 32
)

// ExchangeRequest is signed by the daemon with its identity key. Its
// members other than Type and Points mean what they mean in a token
// request, and the instance runs the same procedure on it.
type ExchangeRequest struct {
	TokenRequest
	// Points are the blinded points X to evaluate, compressed SEC 1 in
	// unpadded base64url; none only fetches the release key.
	Points []string `json:"points"`
}

// ExchangeResponse answers an exchange request that passed the checks.
type ExchangeResponse struct {
	V int `json:"v"`
	// ReleaseKey is a ReleaseKey signed by the instance key under
	// ContextReleaseKey.
	ReleaseKey Envelope `json:"release_key"`
	// Points are the evaluated points Y, in the order of the request.
	Points     []string  `json:"points"`
	ServerTime time.Time `json:"server_time"`
}

// ReleaseKey is the public key S = s·G of an identity at one instance.
type ReleaseKey struct {
	V           int    `json:"v"`
	Type        string `json:"type"` // "release_key"
	TrustDomain string `json:"trust_domain"`
	Identity    string `json:"identity"`
	Authority   string `json:"authority"` // kid of the instance
	Key         string `json:"key"`       // S, compressed SEC 1, unpadded base64url
}
