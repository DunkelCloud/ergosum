package journal

import (
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/protocol"
)

// Observation is the payload of an instance-signed observation (ADR 0003,
// Observations). Ingest decodes it strictly and validates it, so that what
// an instance stores of another one has a known shape and a bounded size.
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

// CheckOutcome records one check of a request for audit and observations.
type CheckOutcome struct {
	Type     string             `json:"type"`
	Target   string             `json:"target"`
	Outcome  string             `json:"outcome"`
	Detail   string             `json:"detail,omitempty"`
	Evidence *protocol.Envelope `json:"evidence,omitempty"` // signed no_open_request
}

// Outcomes of a single callback.
const (
	OutcomeConfirmed       = "confirmed"
	OutcomeNoOpenRequest   = "no_open_request"
	OutcomeUnreachable     = "unreachable"
	OutcomeOtherKey        = "other_key"
	OutcomeInvalidResponse = "invalid_response"
	OutcomeNoAddress       = "no_address"
	// OutcomeEnded: the daemon gave up on the request, or restarted after
	// it was made. The instance discards the request like one whose
	// requester went away.
	OutcomeEnded = "ended"
)

var outcomes = map[string]bool{
	OutcomeConfirmed: true, OutcomeNoOpenRequest: true, OutcomeUnreachable: true, OutcomeOtherKey: true,
	OutcomeInvalidResponse: true, OutcomeNoAddress: true, OutcomeEnded: true,
}

// Limits of an observation. An observation has one outcome per check of
// the binding, so MaxChecks bounds both; the free texts are clipped by the
// writer (Clip).
const (
	MaxDetail = 512
	MaxReason = 256
	MaxRemote = 64
	maxTarget = 300

	// maxObservationBody and maxBindingBody bound the stored body of an
	// event; checkpoints are bounded by the page size.
	maxObservationBody = 64 << 10
	maxBindingBody     = 256 << 10
)

var (
	kidRe     = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	tokenIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
)

// Validate checks an observation as ingest accepts it.
func (o *Observation) Validate() error {
	switch {
	case o.V != 1:
		return unverified("observation version %d", o.V)
	case !observationKinds[o.Kind]:
		return unverified("observation kind %q", o.Kind)
	case !ValidInstanceName(o.Instance):
		return unverified("observation instance %q", o.Instance)
	case !kidRe.MatchString(o.Kid):
		return unverified("observation kid %q", o.Kid)
	case !protocol.ValidDNSName(o.Identity):
		return unverified("observation identity %q", o.Identity)
	case o.Epoch < 1 || o.Epoch > MaxEpoch:
		return unverified("observation epoch %d", o.Epoch)
	case !protocol.ValidRequestID(o.RequestID):
		return unverified("observation request ID %q", o.RequestID)
	case !keys.ValidFingerprint(o.Key):
		return unverified("observation key %q", o.Key)
	case !plain(o.Remote, MaxRemote) || !plain(o.Reason, MaxReason):
		return unverified("observation remote or reason")
	case len(o.Checks) > MaxChecks:
		return unverified("observation with %d checks", len(o.Checks))
	case (o.Kind == KindObservation+".issued") != (o.TokenID != ""):
		return unverified("token ID %q in a %s observation", o.TokenID, o.Kind)
	case o.TokenID != "" && !tokenIDRe.MatchString(o.TokenID):
		return unverified("observation token ID %q", o.TokenID)
	case o.Time.IsZero():
		return unverified("observation without time")
	}
	for _, c := range o.Checks {
		switch {
		case c.Type != protocol.CheckTailnet && c.Type != protocol.CheckIP && c.Type != protocol.CheckNet:
			return unverified("observation check type %q", c.Type)
		case !outcomes[c.Outcome]:
			return unverified("observation outcome %q", c.Outcome)
		case !plain(c.Target, maxTarget) || !plain(c.Detail, MaxDetail):
			return unverified("observation check target or detail")
		case (c.Evidence != nil) != (c.Outcome == OutcomeNoOpenRequest):
			return unverified("evidence with outcome %s", c.Outcome)
		}
	}
	return nil
}

// plain reports whether s is valid UTF-8 without control characters and
// at most n bytes long.
func plain(s string, n int) bool {
	return len(s) <= n && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
}

// Clip turns s into a text that Validate accepts in a field of n bytes:
// control characters and invalid UTF-8 become U+FFFD, and the text is cut
// at a character boundary.
func Clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return utf8.RuneError
		}
		return r
	}, strings.ToValidUTF8(s, string(utf8.RuneError)))
	for len(s) > n {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}
