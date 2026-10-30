package journal

import (
	"context"
	"crypto/ecdsa"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, no cgo

	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/protocol"
	"github.com/DunkelCloud/ergosum/internal/replication"
)

// schemaV1 is the schema of version 1, as written by the first release.
// New journals are created in it and migrated, so that every journal goes
// through the same migrations.
const schemaV1 = `
CREATE TABLE IF NOT EXISTS events (
	origin      TEXT    NOT NULL,
	seq         INTEGER NOT NULL,
	kind        TEXT    NOT NULL,
	identity    TEXT    NOT NULL,
	epoch       INTEGER NOT NULL DEFAULT 0,
	hash        TEXT    NOT NULL,
	body        BLOB    NOT NULL,
	recorded_at TEXT    NOT NULL,
	PRIMARY KEY (origin, seq)
);
CREATE INDEX IF NOT EXISTS events_identity ON events (identity, epoch);
CREATE UNIQUE INDEX IF NOT EXISTS events_binding_hash ON events (hash) WHERE kind LIKE 'binding.%';
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
	BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
	BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END;
CREATE TABLE IF NOT EXISTS bindings (
	identity TEXT PRIMARY KEY,
	kind     TEXT    NOT NULL,
	epoch    INTEGER NOT NULL,
	key      TEXT    NOT NULL,
	checks   TEXT    NOT NULL,
	hash     TEXT    NOT NULL,
	origin   TEXT    NOT NULL,
	seq      INTEGER NOT NULL
);
`

// migrateV2 adds what replication and compaction need (ADR 0003, Storage):
// the local insertion position and the origin's signature of every event,
// the sequence counter in meta, coverage, the compaction frontier with a
// delete trigger that refuses every event above it, the peers' cursors,
// and the body of the winning event in the projection. Existing events keep
// their content; in version 1 only the instance's own events exist, so
// their positions follow their row order, the coverage of the own origin is
// the highest sequence number, and SetSigner signs them once the key is
// available. The signature is the only column that may change, once.
const migrateV2 = `
ALTER TABLE events ADD COLUMN pos INTEGER;
ALTER TABLE events ADD COLUMN sig BLOB;
DROP TRIGGER events_no_update;
UPDATE events SET pos = rowid;
CREATE TRIGGER events_no_update BEFORE UPDATE OF origin, seq, kind, identity, epoch, hash, body, recorded_at, pos ON events
	BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END;
CREATE TRIGGER events_sig_once BEFORE UPDATE OF sig ON events WHEN OLD.sig IS NOT NULL
	BEGIN SELECT RAISE(ABORT, 'an event is signed once'); END;
CREATE UNIQUE INDEX events_pos ON events (pos);
CREATE INDEX events_kind ON events (kind, origin, seq);
DROP INDEX events_binding_hash;
CREATE UNIQUE INDEX events_binding_hash ON events (hash, origin) WHERE kind LIKE 'binding.%';
ALTER TABLE bindings ADD COLUMN body BLOB;
UPDATE bindings SET body = (SELECT e.body FROM events e WHERE e.origin = bindings.origin AND e.seq = bindings.seq);
CREATE TABLE coverage (origin TEXT PRIMARY KEY, seq INTEGER NOT NULL);
CREATE TABLE compaction (origin TEXT PRIMARY KEY, seq INTEGER NOT NULL);
CREATE TABLE peer_cursor (peer TEXT PRIMARY KEY, pos INTEGER NOT NULL);
CREATE TRIGGER compaction_only_rises BEFORE UPDATE ON compaction WHEN NEW.seq < OLD.seq
	BEGIN SELECT RAISE(ABORT, 'the compaction frontier only rises'); END;
DROP TRIGGER events_no_delete;
CREATE TRIGGER events_no_delete BEFORE DELETE ON events
	WHEN OLD.seq > COALESCE((SELECT seq FROM compaction WHERE origin = OLD.origin), 0)
	BEGIN SELECT RAISE(ABORT, 'event above the compaction frontier'); END;
INSERT INTO coverage (origin, seq) SELECT origin, MAX(seq) FROM events GROUP BY origin;
INSERT INTO meta (key, value) VALUES
	('next_seq', (SELECT COALESCE(MAX(seq), 0) + 1 FROM events WHERE origin = (SELECT value FROM meta WHERE key = 'instance'))),
	('next_pos', (SELECT COALESCE(MAX(pos), 0) + 1 FROM events)),
	('compacted_pos', 0),
	('frontier_pos', 0),
	('exported_pos', 0);
UPDATE meta SET value = '2' WHERE key = 'schema_version';
`

const schemaVersion = "2"

// Store is the SQLite-backed journal of one authority instance.
type Store struct {
	db          *sql.DB
	origin      string
	trustDomain string
	registry    *Registry
	mu          sync.Mutex // serializes writes
	now         func() time.Time

	keysMu sync.RWMutex
	keys   map[string]*ecdsa.PublicKey // instance keys by origin
	signer *ecdsa.PrivateKey           // own instance key, once unsealed
}

// timeFormat is RFC 3339 with a fixed number of fractional digits, so that
// stored times compare correctly as text.
const timeFormat = "2006-01-02T15:04:05.000000000Z07:00"

func formatTime(t time.Time) string { return t.UTC().Format(timeFormat) }

// Open opens (and creates) the journal at path. origin names this instance
// in the journal; trustDomain must match every binding event. Both are
// pinned on creation and must match on every later open. A journal of an
// older schema version is migrated.
func Open(path, origin, trustDomain string, registry *Registry) (*Store, error) {
	if origin == "" {
		return nil, errors.New("journal: empty origin")
	}
	q := url.Values{}
	for _, p := range []string{"busy_timeout(5000)", "journal_mode(WAL)", "synchronous(FULL)", "foreign_keys(1)"} {
		q.Add("_pragma", p)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // one writer; reads are cheap
	if err := prepare(context.Background(), db, origin, trustDomain); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db, origin: origin, trustDomain: trustDomain, registry: registry, now: time.Now, keys: map[string]*ecdsa.PublicKey{}}, nil
}

func prepare(ctx context.Context, db *sql.DB, origin, trustDomain string) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("journal: schema: %w", err)
	}
	var v string
	err := db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'schema_version'`).Scan(&v)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := db.ExecContext(ctx, schemaV1); err != nil {
			return fmt.Errorf("journal: schema: %w", err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO meta (key, value) VALUES ('schema_version', '1'), ('trust_domain', ?), ('instance', ?)`, trustDomain, origin); err != nil {
			return err
		}
		v = "1"
	case err != nil:
		return err
	}
	var td string
	if err := db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'trust_domain'`).Scan(&td); err != nil || td != trustDomain {
		return fmt.Errorf("journal: belongs to trust domain %q, configured %q", td, trustDomain)
	}
	if err := pinInstance(ctx, db, origin); err != nil {
		return err
	}
	switch v {
	case "1":
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback() //nolint:errcheck // no-op after commit
		if _, err := tx.ExecContext(ctx, migrateV2); err != nil {
			return fmt.Errorf("journal: migration to schema version 2: %w", err)
		}
		return tx.Commit()
	case schemaVersion:
		return nil
	default:
		return fmt.Errorf("journal: schema version %s, expected %s", v, schemaVersion)
	}
}

// pinInstance records the instance name on first use and refuses another
// one afterwards: (origin, seq) identifies events across instances, and a
// renamed instance would start a second sequence in the same journal.
func pinInstance(ctx context.Context, db *sql.DB, origin string) error {
	var inst string
	err := db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'instance'`).Scan(&inst)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// A journal written before the instance name was pinned.
		_, err = db.ExecContext(ctx, `INSERT INTO meta (key, value) VALUES ('instance', ?)`, origin)
		return err
	case err != nil:
		return err
	case inst != origin:
		return fmt.Errorf("journal: belongs to instance %q, configured %q", inst, origin)
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Origin returns the instance name the journal is pinned to.
func (s *Store) Origin() string { return s.origin }

// SetInstanceKeys sets the instance keys by origin, the own included, with
// which event positions, observations and checkpoints are verified.
func (s *Store) SetInstanceKeys(byOrigin map[string]*ecdsa.PublicKey) {
	s.keysMu.Lock()
	defer s.keysMu.Unlock()
	s.keys = byOrigin
}

func (s *Store) instanceKey(origin string) *ecdsa.PublicKey {
	s.keysMu.RLock()
	defer s.keysMu.RUnlock()
	return s.keys[origin]
}

// ErrNoSigner is returned for own events while the instance key is sealed.
var ErrNoSigner = errors.New("journal: own events need the unsealed instance key")

// SetSigner sets the instance key with which the instance signs the
// position of its own events (ADR 0003, Event signatures), and signs the
// own events that have no signature yet: those of a journal migrated from
// version 1.
func (s *Store) SetSigner(ctx context.Context, key *ecdsa.PrivateKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keysMu.Lock()
	s.signer = key
	s.keysMu.Unlock()
	rows, err := s.db.QueryContext(ctx, `SELECT seq, kind, hash FROM events WHERE origin = ? AND sig IS NULL`, s.origin)
	if err != nil {
		return err
	}
	var unsigned []replication.Event
	for rows.Next() {
		e := replication.Event{Origin: s.origin}
		if err := rows.Scan(&e.Seq, &e.Kind, &e.Hash); err != nil {
			_ = rows.Close()
			return err
		}
		unsigned = append(unsigned, e)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, e := range unsigned {
		sig, err := keys.Sign(key, protocol.ContextEvent, e.SigningInput())
		if err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE events SET sig = ? WHERE origin = ? AND seq = ?`, sig, e.Origin, e.Seq); err != nil {
			return err
		}
	}
	return nil
}

// signOwn signs the position of an own event.
func (s *Store) signOwn(seq int64, kind, hash string) ([]byte, error) {
	s.keysMu.RLock()
	key := s.signer
	s.keysMu.RUnlock()
	if key == nil {
		return nil, ErrNoSigner
	}
	e := replication.Event{Origin: s.origin, Seq: seq, Kind: kind, Hash: hash}
	return keys.Sign(key, protocol.ContextEvent, e.SigningInput())
}

// Binding is the projected current state of one identity.
type Binding struct {
	Identity string  `json:"identity"`
	Kind     string  `json:"kind"`
	Epoch    uint64  `json:"epoch"`
	Key      string  `json:"key,omitempty"`
	Checks   []Check `json:"checks,omitempty"`
	Hash     string  `json:"hash"`
	Origin   string  `json:"origin"`
	Seq      int64   `json:"seq"`
	// SignedBy names the administrators who approved the event, as the read
	// API reports them (see Registry.SignerNames); the journal never stores
	// it.
	SignedBy []string `json:"signed_by,omitempty"`
}

// Active reports whether the binding allows issuance.
func (b *Binding) Active() bool { return b != nil && b.Kind == KindBindingSet }

// Validate checks a binding as the read API reports it. Tools that show it
// or write it into a file rely on every field having its plain form, also
// when an authority answers otherwise.
func (b *Binding) Validate() error {
	if err := validateContent(b.Kind, b.Identity, b.Epoch, b.Key, b.Checks); err != nil {
		return err
	}
	switch {
	case !hashRe.MatchString(b.Hash):
		return invalid("bad hash %q", b.Hash)
	case !ValidInstanceName(b.Origin):
		return invalid("bad origin %q", b.Origin)
	case b.Seq < 1:
		return invalid("bad sequence number %d", b.Seq)
	}
	for _, name := range b.SignedBy {
		// A key the registry no longer knows is named by its fingerprint.
		if !ValidAdminName(name) && !keys.ValidFingerprint(name) {
			return invalid("bad administrator name %q", name)
		}
	}
	return nil
}

// Validate checks the answer of the list endpoint, like Binding.Validate.
func (l *BindingList) Validate() error {
	if l.V != 1 {
		return invalid("unsupported version %d", l.V)
	}
	if !protocol.ValidDNSName(l.TrustDomain) {
		return invalid("bad trust domain %q", l.TrustDomain)
	}
	for kind, ap := range l.Approvals {
		if kind != KindBindingSet && kind != KindBindingRevoked {
			return invalid("approvals for unknown kind %q", kind)
		}
		if ap.Threshold < 1 || ap.Threshold > len(ap.Admins) {
			return invalid("%s: threshold %d with %d administrators", kind, ap.Threshold, len(ap.Admins))
		}
		for name, fp := range ap.Admins {
			if !ValidAdminName(name) || !keys.ValidFingerprint(fp) {
				return invalid("%s: bad administrator %q with key %q", kind, name, fp)
			}
		}
	}
	seen := map[string]bool{}
	for _, b := range l.Bindings {
		if b == nil {
			return invalid("empty binding")
		}
		if err := b.Validate(); err != nil {
			return err
		}
		if seen[b.Identity] {
			return invalid("%s is listed twice", b.Identity)
		}
		seen[b.Identity] = true
	}
	return nil
}

// Validate checks a receipt, like Binding.Validate.
func (r *Receipt) Validate() error {
	switch {
	case !ValidInstanceName(r.Origin):
		return invalid("bad origin %q", r.Origin)
	case r.Seq < 1:
		return invalid("bad sequence number %d", r.Seq)
	case !hashRe.MatchString(r.Hash):
		return invalid("bad hash %q", r.Hash)
	}
	return nil
}

// ValidInstanceName reports whether s names an instance, the origin of
// journal events: lower-case letters, digits, hyphens and dots, such as
// authority-a or site-a.example.com.
func ValidInstanceName(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '.' {
			return false
		}
	}
	return true
}

// ValidAdminName reports whether s names an administrator in the registry:
// letters, digits, and . _ @ -, starting with a letter or digit, at most 64
// characters.
func ValidAdminName(s string) bool { return adminNameRe.MatchString(s) }

var (
	adminNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)
	hashRe      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// BindingList is the answer of the list endpoint: the projection of every
// identity, ordered by identity, and what an event needs to be accepted.
type BindingList struct {
	V           int                 `json:"v"`
	TrustDomain string              `json:"trust_domain"`
	Approvals   map[string]Approval `json:"approvals"`
	Bindings    []*Binding          `json:"bindings"`
}

// Receipt describes where an event was recorded.
type Receipt struct {
	Origin    string `json:"origin"`
	Seq       int64  `json:"seq"`
	Hash      string `json:"hash"`
	Duplicate bool   `json:"duplicate,omitempty"`
}

// Errors returned by AppendBinding besides the registry errors.
var (
	ErrTrustDomain = errors.New("event belongs to another trust domain")
	ErrLowerEpoch  = errors.New("epoch is lower than the current binding")
	ErrEpochTaken  = errors.New("another event holds this epoch")
)

// querier is what both *sql.DB and *sql.Tx offer.
type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// AppendBinding verifies an admin-signed binding event against the registry
// and appends it. It takes only an event above the current epoch, even one
// that would win at the same epoch: an administrator's change was made
// against the binding it saw, and must not replace another change unnoticed.
// Ingest still applies the ordering rule, so that events written at
// different instances converge. Re-submitting an accepted event is
// idempotent.
func (s *Store) AppendBinding(ctx context.Context, e *BindingEvent) (Receipt, error) {
	if err := e.Validate(); err != nil {
		return Receipt{}, err
	}
	if e.TrustDomain != s.trustDomain {
		return Receipt{}, fmt.Errorf("%w: %q", ErrTrustDomain, e.TrustDomain)
	}
	if _, err := s.registry.Verify(e); err != nil {
		return Receipt{}, err
	}
	hash, err := e.Hash()
	if err != nil {
		return Receipt{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var r Receipt
	err = s.db.QueryRowContext(ctx, `SELECT origin, seq, hash FROM events WHERE hash = ? AND kind LIKE 'binding.%' ORDER BY pos LIMIT 1`, hash).Scan(&r.Origin, &r.Seq, &r.Hash)
	if err == nil {
		r.Duplicate = true
		return r, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Receipt{}, err
	}

	cur, err := binding(ctx, s.db, e.Identity)
	if err != nil {
		return Receipt{}, err
	}
	cand := &Binding{Identity: e.Identity, Kind: e.Kind, Epoch: e.Epoch, Key: e.Key, Checks: e.SortedChecks(), Hash: hash}
	if cur != nil {
		if cur.Hash == hash {
			// Compaction removed the event; the projection still holds it.
			return Receipt{Origin: cur.Origin, Seq: cur.Seq, Hash: hash, Duplicate: true}, nil
		}
		if e.Epoch < cur.Epoch {
			return Receipt{}, fmt.Errorf("%w: %d < %d", ErrLowerEpoch, e.Epoch, cur.Epoch)
		}
		if e.Epoch == cur.Epoch {
			return Receipt{}, fmt.Errorf("%w: epoch %d", ErrEpochTaken, e.Epoch)
		}
	}
	body, err := json.Marshal(e)
	if err != nil {
		return Receipt{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Receipt{}, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit
	seq, err := s.insertOwn(ctx, tx, e.Kind, e.Identity, e.Epoch, hash, body)
	if err != nil {
		return Receipt{}, err
	}
	cand.Origin, cand.Seq = s.origin, seq
	if err := upsertBinding(ctx, tx, cand, body); err != nil {
		return Receipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return Receipt{}, err
	}
	return Receipt{Origin: s.origin, Seq: seq, Hash: hash}, nil
}

// Wins reports whether binding a takes precedence over b: the higher epoch
// wins; at equal epochs a revocation wins, otherwise the smaller hash.
func Wins(a, b *Binding) bool {
	if a.Epoch != b.Epoch {
		return a.Epoch > b.Epoch
	}
	ar, br := a.Kind == KindBindingRevoked, b.Kind == KindBindingRevoked
	if ar != br {
		return ar
	}
	return a.Hash < b.Hash
}

func metaInt(ctx context.Context, q querier, key string) (int64, error) {
	var v int64
	err := q.QueryRowContext(ctx, `SELECT CAST(value AS INTEGER) FROM meta WHERE key = ?`, key).Scan(&v)
	return v, err
}

func setMetaInt(ctx context.Context, q querier, key string, v int64) error {
	_, err := q.ExecContext(ctx, `UPDATE meta SET value = ? WHERE key = ?`, v, key)
	return err
}

// raiseMetaInt sets a counter in meta to at least v.
func raiseMetaInt(ctx context.Context, q querier, key string, v int64) error {
	_, err := q.ExecContext(ctx, `UPDATE meta SET value = MAX(CAST(value AS INTEGER), ?) WHERE key = ?`, v, key)
	return err
}

// insertOwn records an event of this instance under the next sequence
// number, signed with the instance key. Sequence numbers come from meta,
// never from the remaining rows, so compaction cannot cause one to be used
// twice.
func (s *Store) insertOwn(ctx context.Context, tx *sql.Tx, kind, identity string, epoch uint64, hash string, body []byte) (int64, error) {
	seq, err := metaInt(ctx, tx, "next_seq")
	if err != nil {
		return 0, err
	}
	if seq > replication.MaxSeq {
		return 0, fmt.Errorf("journal: sequence number %d above the limit", seq)
	}
	sig, err := s.signOwn(seq, kind, hash)
	if err != nil {
		return 0, err
	}
	return seq, s.insert(ctx, tx, s.origin, seq, kind, identity, epoch, hash, body, sig)
}

// insert records an event at the next position and advances the coverage
// of its origin over every event stored contiguously after it.
func (s *Store) insert(ctx context.Context, tx *sql.Tx, origin string, seq int64, kind, identity string, epoch uint64, hash string, body, sig []byte) error {
	pos, err := metaInt(ctx, tx, "next_pos")
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO events (origin, seq, kind, identity, epoch, hash, body, recorded_at, pos, sig) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		origin, seq, kind, identity, epoch, hash, body, formatTime(s.now()), pos, sig); err != nil {
		return err
	}
	if err := setMetaInt(ctx, tx, "next_pos", pos+1); err != nil {
		return err
	}
	if origin == s.origin {
		if err := raiseMetaInt(ctx, tx, "next_seq", seq+1); err != nil {
			return err
		}
	}
	return advanceCoverage(ctx, tx, origin, 0)
}

// advanceCoverage raises the coverage of origin to at least floor and then
// over every event stored contiguously above it.
func advanceCoverage(ctx context.Context, tx *sql.Tx, origin string, floor int64) error {
	var cov int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT seq FROM coverage WHERE origin = ?), 0)`, origin).Scan(&cov); err != nil {
		return err
	}
	next := max(cov, floor)
	for {
		var one int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM events WHERE origin = ? AND seq = ?`, origin, next+1).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return err
		}
		next++
	}
	if next == cov {
		return nil
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO coverage (origin, seq) VALUES (?, ?) ON CONFLICT (origin) DO UPDATE SET seq = excluded.seq`, origin, next)
	return err
}

func upsertBinding(ctx context.Context, q querier, b *Binding, body []byte) error {
	checks, err := json.Marshal(b.Checks)
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `
		INSERT INTO bindings (identity, kind, epoch, key, checks, hash, origin, seq, body)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (identity) DO UPDATE SET
			kind = excluded.kind, epoch = excluded.epoch, key = excluded.key,
			checks = excluded.checks, hash = excluded.hash,
			origin = excluded.origin, seq = excluded.seq, body = excluded.body`,
		b.Identity, b.Kind, b.Epoch, b.Key, string(checks), b.Hash, b.Origin, b.Seq, body)
	return err
}

// applyBinding makes b the projection of its identity if it wins against
// the current one (ADR 0003, ordering rule).
func applyBinding(ctx context.Context, q querier, b *Binding, body []byte) error {
	cur, err := binding(ctx, q, b.Identity)
	if err != nil {
		return err
	}
	if cur != nil && !Wins(b, cur) {
		return nil
	}
	return upsertBinding(ctx, q, b, body)
}

// Binding returns the projected binding of identity, or nil.
func (s *Store) Binding(ctx context.Context, identity string) (*Binding, error) {
	return binding(ctx, s.db, identity)
}

const bindingColumns = `identity, kind, epoch, key, checks, hash, origin, seq`

// rowScanner is what *sql.Row and *sql.Rows offer.
type rowScanner interface{ Scan(dest ...any) error }

func scanBinding(r rowScanner) (*Binding, error) {
	var b Binding
	var checks string
	if err := r.Scan(&b.Identity, &b.Kind, &b.Epoch, &b.Key, &checks, &b.Hash, &b.Origin, &b.Seq); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(checks), &b.Checks); err != nil {
		return nil, err
	}
	return &b, nil
}

func binding(ctx context.Context, q querier, identity string) (*Binding, error) {
	b, err := scanBinding(q.QueryRowContext(ctx, `SELECT `+bindingColumns+` FROM bindings WHERE identity = ?`, identity))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return b, err
}

// List returns the projection of every identity, ordered by identity.
func (s *Store) List(ctx context.Context) ([]*Binding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+bindingColumns+` FROM bindings ORDER BY identity`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []*Binding{}
	for rows.Next() {
		b, err := scanBinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// BindingEvent returns the event behind the projection of identity, with
// its signatures, or nil.
func (s *Store) BindingEvent(ctx context.Context, identity string) (*BindingEvent, error) {
	var body []byte
	err := s.db.QueryRowContext(ctx, `SELECT body FROM bindings WHERE identity = ?`, identity).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil || len(body) == 0 {
		return nil, err
	}
	var e BindingEvent
	if err := json.Unmarshal(body, &e); err != nil {
		return nil, fmt.Errorf("journal: binding of %s: %w", identity, err)
	}
	return &e, nil
}

// TrustDomain returns the trust domain the journal is pinned to.
func (s *Store) TrustDomain() string { return s.trustDomain }

// Registry returns the registry that binding events are verified against.
func (s *Store) Registry() *Registry { return s.registry }

// AppendObservation records an instance-signed observation. body is the
// JSON of a signed envelope.
func (s *Store) AppendObservation(ctx context.Context, kind, identity, hash string, body []byte) (Receipt, error) {
	if !strings.HasPrefix(kind, KindObservation+".") {
		return Receipt{}, fmt.Errorf("journal: %q is not an observation kind", kind)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Receipt{}, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit
	seq, err := s.insertOwn(ctx, tx, kind, identity, 0, hash, body)
	if err != nil {
		return Receipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return Receipt{}, err
	}
	return Receipt{Origin: s.origin, Seq: seq, Hash: hash}, nil
}

// Count returns the number of events of a kind (or of all kinds for "").
func (s *Store) Count(ctx context.Context, kind string) (int, error) {
	var n int
	var err error
	if kind == "" {
		err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`).Scan(&n)
	} else {
		err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE kind = ?`, kind).Scan(&n)
	}
	return n, err
}

// Project recomputes the projection from the binding events and the
// bindings inside the stored checkpoints, without touching the stored
// projection. It is the reference against which the incrementally
// maintained projection can be checked, also after compaction.
func (s *Store) Project(ctx context.Context) (map[string]*Binding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT origin, seq, kind, body FROM events WHERE kind LIKE 'binding.%' OR kind = ? ORDER BY pos`, KindCheckpoint)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]*Binding{}
	consider := func(e *BindingEvent, origin string, seq int64) error {
		h, err := e.Hash()
		if err != nil {
			return err
		}
		b := &Binding{Identity: e.Identity, Kind: e.Kind, Epoch: e.Epoch, Key: e.Key, Checks: e.SortedChecks(), Hash: h, Origin: origin, Seq: seq}
		if cur := out[e.Identity]; cur == nil || Wins(b, cur) {
			out[e.Identity] = b
		}
		return nil
	}
	for rows.Next() {
		var origin, kind string
		var seq int64
		var body []byte
		if err := rows.Scan(&origin, &seq, &kind, &body); err != nil {
			return nil, err
		}
		if kind != KindCheckpoint {
			var e BindingEvent
			if err := json.Unmarshal(body, &e); err != nil {
				return nil, fmt.Errorf("journal: event %s/%d: %w", origin, seq, err)
			}
			if err := consider(&e, origin, seq); err != nil {
				return nil, err
			}
			continue
		}
		cp, err := decodeCheckpoint(body)
		if err != nil {
			return nil, fmt.Errorf("journal: checkpoint %s/%d: %w", origin, seq, err)
		}
		for _, raw := range cp.Bindings {
			var e BindingEvent
			if err := json.Unmarshal(raw, &e); err != nil {
				return nil, fmt.Errorf("journal: checkpoint %s/%d: %w", origin, seq, err)
			}
			if err := consider(&e, origin, seq); err != nil {
				return nil, err
			}
		}
	}
	return out, rows.Err()
}

// Bindings returns the stored projection of all identities.
func (s *Store) Bindings(ctx context.Context) (map[string]*Binding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT identity FROM bindings`)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	_ = rows.Close()
	out := map[string]*Binding{}
	for _, id := range ids {
		b, err := s.Binding(ctx, id)
		if err != nil {
			return nil, err
		}
		out[id] = b
	}
	return out, nil
}

// EventBodies returns the stored bodies of all events of a kind, in journal
// order.
func (s *Store) EventBodies(ctx context.Context, kind string) ([][]byte, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT body FROM events WHERE kind = ? ORDER BY pos`, kind)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out [][]byte
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
