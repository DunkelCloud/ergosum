package journal

import (
	"context"
	"fmt"

	"github.com/DunkelCloud/ergosum/internal/replication"
)

// MaxUncovered is how many events of another origin an instance stores
// above that origin's coverage. Events arrive in their origin's order, so
// an honest origin has almost none there; an origin that never sends one
// of its sequence numbers would otherwise keep every later event out of
// compaction.
const MaxUncovered = 10000

// Reasons why Admit declines an event; both wrap replication.ErrSkipped.
var (
	ErrUncovered = fmt.Errorf("%w: too many events above the coverage of their origin", replication.ErrSkipped)
	ErrQuota     = fmt.Errorf("%w: the origin has used up its quota", replication.ErrSkipped)
)

// SetQuota sets how many bytes the observations and checkpoints of each
// other origin may take; 0 sets no limit.
func (s *Store) SetQuota(bytes int64) {
	s.quotaMu.Lock()
	defer s.quotaMu.Unlock()
	s.quota = bytes
}

// Admit implements replication.Config.Admit: it declines an observation or
// checkpoint of another origin that would exceed the quota of that origin,
// or that lies above its coverage while MaxUncovered events already do.
// What a compromised instance can make the others store is thereby bounded.
func (s *Store) Admit(ctx context.Context, e replication.Event, coverage int64) error {
	if e.Origin == s.origin || AlwaysIngest(e.Kind) {
		return nil
	}
	if e.Seq > coverage+1 {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT 1 FROM events WHERE origin = ? AND seq > ? LIMIT ?)`,
			e.Origin, coverage, s.maxUncovered).Scan(&n); err != nil {
			return err
		}
		if n >= s.maxUncovered {
			return fmt.Errorf("%w: %d events of %s above %d", ErrUncovered, n, e.Origin, coverage)
		}
	}
	s.quotaMu.Lock()
	quota := s.quota
	s.quotaMu.Unlock()
	if quota == 0 {
		return nil
	}
	used, err := s.originBytes(ctx, e.Origin)
	if err != nil {
		return err
	}
	if used+int64(len(e.Body)) > quota {
		return fmt.Errorf("%w: %s stores %d of %d bytes", ErrQuota, e.Origin, used, quota)
	}
	return nil
}

// OriginBytes returns the bytes that the observations and checkpoints of
// every other origin take, for the origins Admit has seen.
func (s *Store) OriginBytes() map[string]int64 {
	s.quotaMu.Lock()
	defer s.quotaMu.Unlock()
	out := make(map[string]int64, len(s.used))
	for o, n := range s.used {
		out[o] = n
	}
	return out
}

// originBytes returns what the observations and checkpoints of origin
// take, read from the journal the first time and then kept up to date.
func (s *Store) originBytes(ctx context.Context, origin string) (int64, error) {
	s.quotaMu.Lock()
	n, ok := s.used[origin]
	gen := s.usedGen
	s.quotaMu.Unlock()
	if ok {
		return n, nil
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(LENGTH(body)), 0) FROM events WHERE origin = ? AND kind NOT LIKE 'binding.%'`,
		origin).Scan(&n); err != nil {
		return 0, err
	}
	s.quotaMu.Lock()
	defer s.quotaMu.Unlock()
	if cur, ok := s.used[origin]; ok {
		return cur, nil
	}
	if gen == s.usedGen { // no compaction meanwhile
		if s.used == nil {
			s.used = map[string]int64{}
		}
		s.used[origin] = n
	}
	return n, nil
}

// stored counts a stored observation or checkpoint of another origin.
func (s *Store) stored(origin, kind string, size int) {
	if origin == s.origin || AlwaysIngest(kind) {
		return
	}
	s.quotaMu.Lock()
	defer s.quotaMu.Unlock()
	if _, ok := s.used[origin]; ok {
		s.used[origin] += int64(size)
	}
}

// forgetUsage drops what is known of the usage, after compaction deleted
// events; it is read from the journal again when needed.
func (s *Store) forgetUsage() {
	s.quotaMu.Lock()
	defer s.quotaMu.Unlock()
	s.used = nil
	s.usedGen++
}
