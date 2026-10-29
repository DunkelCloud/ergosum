// Package protocol defines the wire format between daemon and authority:
// token requests, callbacks and their signed responses (see
// docs/adr/0001-protocol.md).
package protocol

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/DunkelCloud/ergosum/internal/keys"
)

// Version is the protocol version carried in every message as "v" and in
// every URL path as "/v1/".
const Version = 1

// Signature contexts. Every signature covers SHA-256(context || 0x00 ||
// payload), so a signature made for one purpose never verifies for another.
const (
	ContextRequest          = "ergosum/v1/token-request"
	ContextCallbackResponse = "ergosum/v1/callback-response"
	ContextObservation      = "ergosum/v1/observation"
	ContextCheckpoint       = "ergosum/v1/checkpoint"
	// ContextEvent signs the position of a journal event: the JSON array
	// [origin, seq, kind, hash].
	ContextEvent = "ergosum/v1/event"
)

// HTTP paths.
const (
	PathToken    = "/v1/token"
	PathCallback = "/v1/callback"
	PathBindings = "/v1/bindings"
	PathKeys     = "/v1/keys"
	PathKeysPEM  = "/v1/keys.pem"
	// PathJournalState is served on the ops listener: state hash,
	// coverage, compaction frontier and outboxes.
	PathJournalState = "/v1/journal/state"
)

// Default ports. All of them are configurable.
const (
	DefaultAuthorityPort = 7432 // token requests and binding writes (TLS)
	DefaultCallbackPort  = 7433 // daemon callback listener (mutual TLS)
	DefaultOpsPort       = 7434 // authority metrics, health, public keys (HTTP)
	// DefaultReplicationPort is the authority's journal replication
	// listener (mutual TLS between instances).
	DefaultReplicationPort = 7435
)

// DefaultOverlayPrefixes are the address ranges Tailscale assigns. Daemon
// and authority use them unless configured otherwise.
var DefaultOverlayPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
}

// ParsePrefixes parses overlay prefixes from configuration; an empty list
// yields DefaultOverlayPrefixes.
func ParsePrefixes(in []string) ([]netip.Prefix, error) {
	if len(in) == 0 {
		return DefaultOverlayPrefixes, nil
	}
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("bad prefix %q", s)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// InPrefixes reports whether a lies in one of the prefixes.
func InPrefixes(a netip.Addr, prefixes []netip.Prefix) bool {
	a = a.Unmap()
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Envelope carries a signed payload. Payload is the base64url encoding of
// the exact JSON bytes that were signed; receivers verify those bytes and
// only then decode them, so no canonicalization of JSON is needed.
type Envelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// Seal marshals v as JSON and signs it under context.
func Seal(key *ecdsa.PrivateKey, context string, v any) (Envelope, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return Envelope{}, err
	}
	sig, err := keys.Sign(key, context, payload)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{
		Payload:   base64.RawURLEncoding.EncodeToString(payload),
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}, nil
}

// ErrBadEnvelope is returned for undecodable envelopes.
var ErrBadEnvelope = errors.New("protocol: malformed envelope")

// Decode decodes the payload without verifying the signature. Callers that
// need the payload to pick the verification key must call Verify before
// acting on anything else in it.
func (e Envelope) Decode(v any) error {
	payload, err := base64.RawURLEncoding.DecodeString(e.Payload)
	if err != nil {
		return ErrBadEnvelope
	}
	if err := json.Unmarshal(payload, v); err != nil {
		return fmt.Errorf("%w: %w", ErrBadEnvelope, err)
	}
	return nil
}

// Verify checks the envelope signature with pub under context.
func (e Envelope) Verify(pub *ecdsa.PublicKey, context string) bool {
	payload, err1 := base64.RawURLEncoding.DecodeString(e.Payload)
	sig, err2 := base64.RawURLEncoding.DecodeString(e.Signature)
	if err1 != nil || err2 != nil {
		return false
	}
	return keys.Verify(pub, context, payload, sig)
}

// TokenRequest is signed by the daemon with its identity key.
type TokenRequest struct {
	V         int       `json:"v"`
	Type      string    `json:"type"` // "token_request"
	Identity  string    `json:"identity"`
	RequestID string    `json:"request_id"`
	Timestamp time.Time `json:"timestamp"`
	Addresses []string  `json:"addresses"`
	Key       string    `json:"key"` // base64 (std) SubjectPublicKeyInfo DER
}

// Message types.
const (
	TypeTokenRequest     = "token_request"
	TypeCallback         = "callback"
	TypeCallbackResponse = "callback_response"
)

// TokenResponse is returned for a successful request.
type TokenResponse struct {
	V          int       `json:"v"`
	Token      string    `json:"token"`
	ExpiresAt  time.Time `json:"expires_at"`
	ServerTime time.Time `json:"server_time"`
}

// ErrorResponse is returned for every failed request.
type ErrorResponse struct {
	V          int       `json:"v"`
	Error      string    `json:"error"`
	Detail     string    `json:"detail,omitempty"`
	ServerTime time.Time `json:"server_time"`
}

// Error codes of ErrorResponse.
const (
	ErrDenied         = "denied"          // 403: a check failed; details only in the audit log
	ErrNotResponsible = "not_responsible" // 421: a net check needs another authority instance
	ErrBadRequest     = "bad_request"     // 400
	ErrClockSkew      = "clock_skew"      // 400: timestamp outside the accepted window
	ErrUnsupported    = "unsupported_version"
	ErrUnavailable    = "unavailable" // 503
	ErrRejected       = "rejected"    // 422: binding event rejected
	ErrConflict       = "conflict"    // 409: the binding event's epoch is not above the current one
)

// Callback is sent by the authority to the daemon over mutual TLS.
type Callback struct {
	V         int    `json:"v"`
	Type      string `json:"type"` // "callback"
	RequestID string `json:"request_id"`
	Nonce     string `json:"nonce"`
	Target    string `json:"target"`
	Authority string `json:"authority"` // kid of the calling instance
}

// CallbackResponse is signed by the daemon with its identity key.
type CallbackResponse struct {
	V         int       `json:"v"`
	Type      string    `json:"type"` // "callback_response"
	Status    string    `json:"status"`
	RequestID string    `json:"request_id"`
	Nonce     string    `json:"nonce"`
	Target    string    `json:"target"`
	Authority string    `json:"authority"`
	Timestamp time.Time `json:"timestamp"`
}

// Callback response status values.
const (
	StatusConfirmed     = "confirmed"
	StatusNoOpenRequest = "no_open_request"
)

// NewRequestID returns a fresh random request ID (128 bit, base64url).
func NewRequestID() string { return randomToken(16) }

// NewNonce returns a fresh random callback nonce (256 bit, base64url).
func NewNonce() string { return randomToken(32) }

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

var (
	requestIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
	labelRe     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// ValidRequestID reports whether s has the shape of a request ID.
func ValidRequestID(s string) bool { return requestIDRe.MatchString(s) }

// ValidDNSName reports whether s is a lower-case DNS name with at least two
// labels, as used for identities and tailnet callback targets. The last
// label is never all-numeric (RFC 3696), which also keeps address literals
// out: a name is resolved, an address is not.
func ValidDNSName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if !labelRe.MatchString(p) {
			return false
		}
	}
	return strings.ContainsFunc(parts[len(parts)-1], func(r rune) bool { return r < '0' || r > '9' })
}

// Check kinds.
const (
	CheckTailnet = "tailnet"
	CheckIP      = "ip"
	CheckNet     = "net"
	CheckKey     = "key"
)

// Target formats a callback target as it appears in Callback and
// CallbackResponse: "<check>:<host>:<port>", or for net checks
// "net:<prefix>:<host>:<port>". IPv6 hosts are bracketed.
func Target(check, prefix, host string, port int) string {
	hp := net.JoinHostPort(host, strconv.Itoa(port))
	if check == CheckNet {
		return check + ":" + prefix + ":" + hp
	}
	return check + ":" + hp
}

// MaxAddresses is the most underlay addresses a request may carry.
const MaxAddresses = 16

// ParseAddresses validates the underlay addresses of a request.
func ParseAddresses(in []string) ([]netip.Addr, error) {
	if len(in) > MaxAddresses {
		return nil, errors.New("too many addresses")
	}
	out := make([]netip.Addr, 0, len(in))
	for _, s := range in {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return nil, fmt.Errorf("bad address %q", s)
		}
		out = append(out, a.Unmap())
	}
	return out, nil
}
