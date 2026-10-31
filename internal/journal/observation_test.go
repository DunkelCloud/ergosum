package journal_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/DunkelCloud/ergosum/internal/journal"
	jt "github.com/DunkelCloud/ergosum/internal/journal/journaltest"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/protocol"
	"github.com/DunkelCloud/ergosum/internal/replication"
)

// observationAt seals payload as an observation of origin at seq.
func observationAt(t *testing.T, key *ecdsa.PrivateKey, origin, kind string, seq int64, payload any) replication.Event {
	t.Helper()
	env, err := protocol.Seal(key, protocol.ContextObservation, payload)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(env)
	raw, _ := base64.RawURLEncoding.DecodeString(env.Payload)
	sum := sha256.Sum256(raw)
	e := replication.Event{Origin: origin, Seq: seq, Kind: kind, Hash: hex.EncodeToString(sum[:]), Body: body}
	if e.Sig, err = keys.Sign(key, protocol.ContextEvent, e.SigningInput()); err != nil {
		t.Fatal(err)
	}
	return e
}

// TestObservationShape: ingest stores an observation only in its known
// shape and size, so that a peer cannot put anything else under one.
func TestObservationShape(t *testing.T) {
	ctx := context.Background()
	ka, kb := newKey(t), newKey(t)
	admins := jt.NewAdmins(t, "alice")
	b := openInstance(t, admins, 1, "instance-b", kb)
	b.SetInstanceKeys(map[string]*ecdsa.PublicKey{"instance-a": &ka.PublicKey, "instance-b": &kb.PublicKey})
	good := func() journal.Observation {
		return journal.Observation{
			V: 1, Kind: "observation.issued", Instance: "instance-a", Kid: keys.Thumbprint(&ka.PublicKey),
			Identity: "host1.example.com", Epoch: 1, RequestID: protocol.NewRequestID(), Key: fingerprint(t),
			Remote: "192.0.2.7:51000", TokenID: protocol.NewRequestID(), Time: time.Now().UTC(),
			Checks: []journal.CheckOutcome{{Type: protocol.CheckTailnet, Target: "tailnet:host1.tailnet.example.com:7433", Outcome: journal.OutcomeConfirmed}},
		}
	}
	o := good()
	if err := b.Verify(ctx, observationAt(t, ka, "instance-a", o.Kind, 1, o)); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*journal.Observation){
		"version":           func(o *journal.Observation) { o.V = 2 },
		"no epoch":          func(o *journal.Observation) { o.Epoch = 0 },
		"bad request ID":    func(o *journal.Observation) { o.RequestID = "x" },
		"bad key":           func(o *journal.Observation) { o.Key = "SHA256:x" },
		"no token ID":       func(o *journal.Observation) { o.TokenID = "" },
		"control character": func(o *journal.Observation) { o.Reason = "a\x1b[2Jb" },
		"long detail":       func(o *journal.Observation) { o.Checks[0].Detail = strings.Repeat("x", journal.MaxDetail+1) },
		"unknown outcome":   func(o *journal.Observation) { o.Checks[0].Outcome = "maybe" },
		"unknown check":     func(o *journal.Observation) { o.Checks[0].Type = "dns" },
		"evidence":          func(o *journal.Observation) { o.Checks[0].Evidence = &protocol.Envelope{} },
		"too many checks": func(o *journal.Observation) {
			for range journal.MaxChecks {
				o.Checks = append(o.Checks, o.Checks[0])
			}
		},
		"over 64 KiB": func(o *journal.Observation) {
			o.Checks[0].Outcome = journal.OutcomeNoOpenRequest
			o.Checks[0].Evidence = &protocol.Envelope{Payload: strings.Repeat("A", 64<<10)}
		},
	} {
		o := good()
		change(&o)
		err := b.Verify(ctx, observationAt(t, ka, "instance-a", o.Kind, 2, o))
		if !errors.Is(err, journal.ErrUnverified) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// An unknown field is refused, whatever it holds.
	var m map[string]any
	data, _ := json.Marshal(good())
	_ = json.Unmarshal(data, &m)
	m["note"] = "anything"
	if err := b.Verify(ctx, observationAt(t, ka, "instance-a", "observation.issued", 2, m)); !errors.Is(err, journal.ErrUnverified) {
		t.Errorf("unknown field: %v", err)
	}
}

// TestClip: clipped texts pass validation and keep whole characters.
func TestClip(t *testing.T) {
	for in, want := range map[string]string{
		"plain":           "plain",
		"a\x1b[2Jb":       "a�[2Jb",
		"ok\xffno":        "ok�no",
		"line\nbreak":     "line�bre",
		"äöüäöüäöüäöüxyz": "äöüäö",
	} {
		got := journal.Clip(in, 10)
		if got != want || len(got) > 10 || !utf8.ValidString(got) {
			t.Errorf("Clip(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestMaxChecks: a binding has at most MaxChecks checks, so that the
// observation of a request to it stays within its size.
func TestMaxChecks(t *testing.T) {
	var checks []journal.Check
	for i := range journal.MaxChecks + 1 {
		checks = append(checks, journal.Check{Type: protocol.CheckIP, Target: "192.0.2." + strconv.Itoa(i+1)})
	}
	if err := jt.Set(td, "host1.example.com", 1, fingerprint(t), checks[:journal.MaxChecks]...).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := jt.Set(td, "host1.example.com", 1, fingerprint(t), checks...).Validate(); err == nil {
		t.Fatalf("%d checks accepted", len(checks))
	}
}
