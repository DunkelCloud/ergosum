// Package replication copies an append-only event journal between
// instances without a leader and without a quorum. Every instance pushes the
// events it stores, its own and those it received, to its peers from an
// outbox kept as a cursor per peer over its local insertion order. Peers
// verify every event before they store it, and a new or rebuilt instance
// pulls a peer's journal page by page.
//
// The package knows events only as (origin, seq, kind, hash, body, sig).
// Storage is the caller's Store; verifying an event, telling which kinds
// are always ingested and reading the coverage of a checkpoint are
// callbacks. It depends on the standard library only, so that it can move
// to a library of its own.
package replication

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"regexp"
	"sync"
	"time"
)

// Version is carried in every page and acknowledgment as "v".
const Version = 1

// HTTP paths on the replication listener.
const (
	PathIngest = "/v1/journal/ingest"
	PathEvents = "/v1/journal/events"
)

// ownReserve is how far below MaxSeq a sync may raise the coverage of the
// syncing instance's own origin, so that it can always go on writing.
const ownReserve = 1 << 32

// MaxSeq is the highest sequence number and coverage that ingest accepts,
// so that no counter derived from a peer's numbers can overflow.
const MaxSeq = 1 << 53

// Event is one journal event. (Origin, Seq) identifies it across instances:
// Origin is the instance that first recorded it and Seq that instance's
// sequence number. Hash identifies the content.
type Event struct {
	Origin string `json:"origin"`
	Seq    int64  `json:"seq"`
	Kind   string `json:"kind"`
	Hash   string `json:"hash"`
	Body   []byte `json:"body"`
	// Sig is the origin's signature over SigningInput. The package carries
	// it; Verify must check it, or any peer could put an event under
	// another origin's (origin, seq) and make the genuine one conflict.
	Sig []byte `json:"sig,omitempty"`
}

// SigningInput returns the bytes an origin signs for an event: the JSON
// array [origin, seq, kind, hash]. The hash covers the body.
func (e Event) SigningInput() []byte {
	b, _ := json.Marshal([]any{e.Origin, e.Seq, e.Kind, e.Hash}) // cannot fail
	return b
}

// size estimates the encoded size of an event in a page.
func (e *Event) size() int64 {
	enc := base64.StdEncoding
	return int64(enc.EncodedLen(len(e.Body)) + enc.EncodedLen(len(e.Sig)) + len(e.Origin) + len(e.Kind) + len(e.Hash) + 128)
}

// Stored is an event with its position in the local insertion order of the
// instance that holds it. Positions are never reused.
type Stored struct {
	Pos int64 `json:"pos"`
	Event
}

// Page is a run of a journal in insertion order, as pushed to a peer and as
// pulled from it.
type Page struct {
	V int `json:"v"`
	// Instance is the sender.
	Instance string `json:"instance"`
	// Start is the sender's checkpoint that its compaction relied on. It is
	// present when events above the requested position have been deleted;
	// the receiver ingests it first. Only a pull, which an operator starts
	// against a peer of their choice, raises the receiver's coverage to the
	// checkpoint's: a pushed claim could otherwise make the receiver skip
	// events or raise its own sequence counter.
	Start *Stored `json:"start,omitempty"`
	// Events above the requested position, in the sender's insertion order.
	Events []Stored `json:"events"`
	// Last is the position the page reaches; a receiver that ingested the
	// whole page has seen everything up to it.
	Last int64 `json:"last"`
	// More reports that events may follow Last.
	More bool `json:"more,omitempty"`
}

// Ack answers a push: the last position the receiver accepted, and why it
// stopped if it did not accept the whole page.
type Ack struct {
	V        int    `json:"v"`
	Accepted int64  `json:"accepted"`
	Error    string `json:"error,omitempty"`
}

// Store is the journal as the package needs it. Implementations serialize
// writes themselves; the package calls Append and RaiseCoverage from one
// goroutine at a time.
type Store interface {
	// Read returns up to limit events above position after, in insertion
	// order, and the position the result reaches. If compaction has deleted
	// events above after, start is the checkpoint it relied on; last is
	// then the highest deleted position unless the result is full, in
	// which case it is the position of the last event returned.
	Read(ctx context.Context, after int64, limit int) (start *Stored, events []Stored, last int64, err error)
	// Lookup returns the hash stored under (origin, seq).
	Lookup(ctx context.Context, origin string, seq int64) (hash string, found bool, err error)
	// Contains reports whether an event of this kind and hash is stored
	// under any origin.
	Contains(ctx context.Context, kind, hash string) (bool, error)
	// Coverage returns the highest sequence number up to which every event
	// of origin has been ingested, stored or acknowledged as a duplicate.
	Coverage(ctx context.Context, origin string) (int64, error)
	// Append stores and applies a verified event whose (origin, seq) is
	// new, and advances the coverage of its origin.
	Append(ctx context.Context, e Event) error
	// RaiseCoverage raises the coverage of each origin to at least the
	// given sequence number, and on past events already stored above it.
	RaiseCoverage(ctx context.Context, coverage map[string]int64) error
	// Cursor returns the last position a peer has acknowledged.
	Cursor(ctx context.Context, peer string) (int64, error)
	// SetCursor records a peer's acknowledgment.
	SetCursor(ctx context.Context, peer string, pos int64) error
	// Outbox counts the events above position after and returns the time
	// the oldest of them was stored.
	Outbox(ctx context.Context, after int64) (n int64, oldest time.Time, err error)
	// Latest returns the stored events of one origin and kind, newest first.
	Latest(ctx context.Context, origin, kind string) ([]Stored, error)
	// SetFrontier raises the compaction frontier to a checkpoint's coverage.
	// The checkpoint becomes the Start of pages that reach below it.
	SetFrontier(ctx context.Context, checkpoint Stored, frontier map[string]int64) error
}

// Peer is another instance.
type Peer struct {
	Name string
	// URL is the base URL of the peer's replication listener. A peer
	// without URL is known, so that its events are accepted when others
	// forward them, but it receives no pushes and compaction does not wait
	// for it.
	URL string
}

// Config configures a Replicator.
type Config struct {
	// Self names this instance, the origin of its own events.
	Self  string
	Peers []Peer
	Store Store
	// Verify checks an event before it is stored, its Sig included. An
	// error that wraps ErrInvalid rejects the event; any other error is
	// temporary: nothing is stored or acknowledged, and the sender retries.
	Verify func(ctx context.Context, e Event) error
	// AlwaysIngest reports kinds that are ingested even at or below the
	// coverage of their origin, unless their hash is already stored. Other
	// kinds are acknowledged there without being stored, so that a peer
	// cannot push back what compaction deleted.
	AlwaysIngest func(kind string) bool
	// CheckpointKind is the kind of checkpoint events.
	CheckpointKind string
	// CheckpointCoverage returns the coverage recorded in a verified
	// checkpoint.
	CheckpointCoverage func(e Event) (map[string]int64, error)
	// Client returns the HTTP client for a peer. It authenticates both
	// sides, for example with mutual TLS.
	Client func(peer string) *http.Client
	// Authenticate names the peer behind an incoming request.
	Authenticate func(r *http.Request) (peer string, ok bool)
	// OnReject is called for every rejected event, for alarms.
	OnReject func(peer string, e Event, err error)
	// OnEquivocation is called when an origin signed two different events
	// for one position, or Verify reports ErrEquivocation; stored is the
	// hash already stored at that position, if any. The event is skipped.
	OnEquivocation func(peer string, e Event, stored string, err error)
	Logger         *slog.Logger

	// BatchSize is the most events per page. Default 256.
	BatchSize int
	// MaxBody limits the size of a page a peer accepts. Pages are cut to
	// fit; a single event larger than that cannot be sent. Default 32 MiB.
	MaxBody int64
	// RetryMin and RetryMax bound the backoff after a failed push. Defaults
	// 1s and 1m.
	RetryMin, RetryMax time.Duration
	// Idle is how long a pusher with nothing to send waits before it looks
	// again without being notified. Default 30s.
	Idle time.Duration
}

// Errors of ingest. ErrConflict wraps ErrRejected. Verify wraps ErrInvalid
// for events that do not verify, and ErrEquivocation for an event that
// verifies but contradicts one its origin signed before.
var (
	ErrRejected     = errors.New("event rejected")
	ErrConflict     = fmt.Errorf("%w: same origin and sequence number with another hash", ErrRejected)
	ErrInvalid      = errors.New("invalid event")
	ErrEquivocation = errors.New("origin signed contradicting events")
)

// Replicator pushes, ingests and pulls events.
type Replicator struct {
	cfg   Config
	peers map[string]Peer
	log   *slog.Logger
	mu    sync.Mutex // one ingest at a time
	wake  map[string]chan struct{}
}

// New validates the configuration.
func New(cfg Config) (*Replicator, error) {
	if cfg.Self == "" || cfg.Store == nil || cfg.Verify == nil || cfg.CheckpointKind == "" || cfg.CheckpointCoverage == nil {
		return nil, errors.New("replication: Self, Store, Verify, CheckpointKind and CheckpointCoverage are required")
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 256
	}
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = 32 << 20
	}
	if cfg.RetryMin <= 0 {
		cfg.RetryMin = time.Second
	}
	if cfg.RetryMax < cfg.RetryMin {
		cfg.RetryMax = max(time.Minute, cfg.RetryMin)
	}
	if cfg.Idle <= 0 {
		cfg.Idle = 30 * time.Second
	}
	r := &Replicator{cfg: cfg, peers: map[string]Peer{}, log: cfg.Logger, wake: map[string]chan struct{}{}}
	if r.log == nil {
		r.log = slog.New(slog.DiscardHandler)
	}
	for _, p := range cfg.Peers {
		if p.Name == "" || p.Name == cfg.Self {
			return nil, fmt.Errorf("replication: bad peer name %q", p.Name)
		}
		if _, dup := r.peers[p.Name]; dup {
			return nil, fmt.Errorf("replication: peer %q listed twice", p.Name)
		}
		r.peers[p.Name] = p
		if p.URL != "" {
			if cfg.Client == nil {
				return nil, errors.New("replication: Client is required for peers with a URL")
			}
			r.wake[p.Name] = make(chan struct{}, 1)
		}
	}
	return r, nil
}

// Notify tells the pushers that new events are stored.
func (r *Replicator) Notify() {
	for _, c := range r.wake {
		select {
		case c <- struct{}{}:
		default:
		}
	}
}

var hashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (r *Replicator) checkShape(e Event) error {
	switch {
	case e.Origin != r.cfg.Self && r.peers[e.Origin].Name == "":
		return fmt.Errorf("unknown origin %q", e.Origin)
	case e.Seq < 1 || e.Seq > MaxSeq:
		return fmt.Errorf("sequence number %d", e.Seq)
	case e.Kind == "" || len(e.Kind) > 64:
		return fmt.Errorf("bad kind %q", e.Kind)
	case !hashRe.MatchString(e.Hash):
		return errors.New("bad hash")
	case len(e.Body) == 0:
		return errors.New("empty body")
	}
	return nil
}

func (r *Replicator) reject(peer string, e Event, err error) error {
	if !errors.Is(err, ErrRejected) {
		err = fmt.Errorf("%w: %w", ErrRejected, err)
	}
	err = fmt.Errorf("%s/%d (%s) from %s: %w", e.Origin, e.Seq, e.Kind, peer, err)
	if r.cfg.OnReject != nil {
		r.cfg.OnReject(peer, e, err)
	}
	return err
}

// Ingest verifies and stores a page that peer pushed, in order. It stops at
// the first event it rejects and returns the last position it accepted;
// the coverage of that event's origin stops there, because nothing after
// it is stored from this page. A rejected event is never acknowledged, so
// the sender keeps it in its outbox and compaction keeps it on the sender.
// The checkpoint a page starts with is ingested like any event; its
// coverage counts only on a pull.
func (r *Replicator) Ingest(ctx context.Context, peer string, p Page) (accepted int64, err error) {
	return r.ingestPage(ctx, peer, p, false)
}

func (r *Replicator) ingestPage(ctx context.Context, peer string, p Page, pulled bool) (accepted int64, err error) {
	if p.V != Version {
		return 0, fmt.Errorf("%w: page version %d", ErrRejected, p.V)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if p.Start != nil {
		if err := r.ingestStart(ctx, peer, p.Start.Event, pulled); err != nil {
			return 0, err
		}
	}
	stored := 0
	// Whatever was stored is forwarded to the other peers, also when the
	// page stops early.
	defer func() {
		if stored > 0 {
			r.Notify()
		}
	}()
	for _, e := range p.Events {
		ok, err := r.ingest(ctx, peer, e.Event)
		if err != nil {
			return accepted, err
		}
		if ok {
			stored++
		}
		accepted = e.Pos
	}
	return max(accepted, p.Last), nil
}

// ingestStart ingests the checkpoint a page starts with and, on a pull,
// raises the coverage to the checkpoint's.
func (r *Replicator) ingestStart(ctx context.Context, peer string, s Event, pulled bool) error {
	if s.Origin != peer || s.Kind != r.cfg.CheckpointKind {
		return r.reject(peer, s, errors.New("a page may start only with a checkpoint of its sender"))
	}
	if _, err := r.ingest(ctx, peer, s); err != nil || !pulled {
		return err
	}
	// Ingest may acknowledge a checkpoint without verifying it (at or below
	// the coverage); its coverage counts only once it verifies.
	if err := r.verify(ctx, peer, s); err != nil {
		return err
	}
	cov, err := r.cfg.CheckpointCoverage(s)
	if err != nil {
		return r.reject(peer, s, err)
	}
	for o, n := range cov {
		if n < 0 || n > MaxSeq {
			return r.reject(peer, s, fmt.Errorf("coverage %d of %q", n, o))
		}
		// The own sequence counter follows the own coverage; a peer must
		// not push it so high that this instance can never write again.
		if o == r.cfg.Self && n > MaxSeq-ownReserve {
			return r.reject(peer, s, fmt.Errorf("coverage %d of this instance leaves no room to write", n))
		}
	}
	return r.cfg.Store.RaiseCoverage(ctx, cov)
}

// verify runs Verify; only an ErrInvalid rejects the event.
func (r *Replicator) verify(ctx context.Context, peer string, e Event) error {
	err := r.cfg.Verify(ctx, e)
	if err != nil && errors.Is(err, ErrInvalid) {
		return r.reject(peer, e, err)
	}
	return err
}

// ingest checks and stores one event; stored reports whether it was new.
func (r *Replicator) ingest(ctx context.Context, peer string, e Event) (stored bool, err error) {
	if err := r.checkShape(e); err != nil {
		return false, r.reject(peer, e, err)
	}
	st := r.cfg.Store
	hash, found, err := st.Lookup(ctx, e.Origin, e.Seq)
	if err != nil {
		return false, err
	}
	if found {
		if hash == e.Hash {
			return false, nil
		}
		// Same position, other content. If this event verifies too, its
		// origin signed two events for one position: proof against the
		// origin, not against the sender. It is reported and skipped;
		// stopping here would let one instance halt replication between
		// the honest ones, revocations included.
		if err := r.verify(ctx, peer, e); err != nil {
			return false, err
		}
		r.equivocation(peer, e, hash, fmt.Errorf("%w: %s/%d is stored with hash %s", ErrEquivocation, e.Origin, e.Seq, hash))
		return false, nil
	}
	cov, err := st.Coverage(ctx, e.Origin)
	if err != nil {
		return false, err
	}
	if e.Seq <= cov {
		if r.cfg.AlwaysIngest == nil || !r.cfg.AlwaysIngest(e.Kind) {
			return false, nil
		}
		dup, err := st.Contains(ctx, e.Kind, e.Hash)
		if err != nil || dup {
			return false, err
		}
	}
	if err := r.verify(ctx, peer, e); err != nil {
		if errors.Is(err, ErrEquivocation) {
			r.equivocation(peer, e, "", err)
			return false, nil
		}
		return false, err
	}
	if err := st.Append(ctx, e); err != nil {
		return false, err
	}
	return true, nil
}

// equivocation reports an event that contradicts one its origin signed
// before; the caller skips the event.
func (r *Replicator) equivocation(peer string, e Event, stored string, err error) {
	if r.cfg.OnEquivocation != nil {
		r.cfg.OnEquivocation(peer, e, stored, err)
	}
}

// Frontier raises the compaction frontier to the coverage of the newest own
// checkpoint that every peer with a URL has acknowledged. It returns that
// checkpoint, or nil if there is none yet.
func (r *Replicator) Frontier(ctx context.Context) (*Stored, error) {
	st := r.cfg.Store
	acked := int64(math.MaxInt64)
	for _, p := range r.cfg.Peers {
		if p.URL == "" {
			continue
		}
		c, err := st.Cursor(ctx, p.Name)
		if err != nil {
			return nil, err
		}
		acked = min(acked, c)
	}
	cps, err := st.Latest(ctx, r.cfg.Self, r.cfg.CheckpointKind)
	if err != nil {
		return nil, err
	}
	for _, cp := range cps {
		if cp.Pos > acked {
			continue
		}
		cov, err := r.cfg.CheckpointCoverage(cp.Event)
		if err != nil {
			return nil, err
		}
		if err := st.SetFrontier(ctx, cp, cov); err != nil {
			return nil, err
		}
		return &cp, nil
	}
	return nil, nil
}

// PeerStatus is the outbox of one peer.
type PeerStatus struct {
	Peer    string
	Cursor  int64
	Pending int64
	// Oldest is when the oldest unacknowledged event was stored; zero if
	// there is none.
	Oldest time.Time
}

// Status returns the outbox of every peer with a URL.
func (r *Replicator) Status(ctx context.Context) ([]PeerStatus, error) {
	var out []PeerStatus
	for _, p := range r.cfg.Peers {
		if p.URL == "" {
			continue
		}
		c, err := r.cfg.Store.Cursor(ctx, p.Name)
		if err != nil {
			return nil, err
		}
		n, oldest, err := r.cfg.Store.Outbox(ctx, c)
		if err != nil {
			return nil, err
		}
		out = append(out, PeerStatus{Peer: p.Name, Cursor: c, Pending: n, Oldest: oldest})
	}
	return out, nil
}
