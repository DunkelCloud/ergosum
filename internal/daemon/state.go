package daemon

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/protocol"
)

// Request IDs stay known for this long after completion, and an open
// request is retried with the same ID for at most this long.
const (
	KnownAfterCompletion = 10 * time.Minute
	MaxOpen              = 10 * time.Minute
)

type requestState struct {
	ID        string     `json:"id"`
	Created   time.Time  `json:"created"`
	Completed *time.Time `json:"completed,omitempty"`
}

type stateFile struct {
	Requests []requestState `json:"requests"`
}

// requestBook persists request IDs so that a restart neither forgets an open
// request (which would turn a pending callback into a "no open request"
// answer) nor reuses a finished one.
type requestBook struct {
	mu   sync.Mutex
	path string
	now  func() time.Time
	reqs []requestState
}

func loadRequestBook(path string, now func() time.Time) (*requestBook, error) {
	b := &requestBook{path: path, now: now}
	data, err := os.ReadFile(path) //nolint:gosec // path from configuration
	if errors.Is(err, os.ErrNotExist) {
		return b, nil
	}
	if err != nil {
		return nil, err
	}
	var f stateFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	b.reqs = f.Requests
	return b, nil
}

func (b *requestBook) saveLocked() error {
	data, err := json.MarshalIndent(stateFile{Requests: b.reqs}, "", "  ")
	if err != nil {
		return err
	}
	return keys.WriteFileAtomic(b.path, data, 0o600)
}

func (b *requestBook) pruneLocked() {
	now := b.now()
	kept := b.reqs[:0]
	for _, r := range b.reqs {
		if r.Completed == nil && now.Sub(r.Created) > MaxOpen {
			t := now
			r.Completed = &t // abandon; still known for a while
		}
		if r.Completed != nil && now.Sub(*r.Completed) > KnownAfterCompletion {
			continue
		}
		kept = append(kept, r)
	}
	b.reqs = kept
}

// open returns the ID of the open request, creating and persisting a new
// one if there is none. The ID is on disk before any request leaves.
func (b *requestBook) open() (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneLocked()
	for _, r := range b.reqs {
		if r.Completed == nil {
			return r.ID, nil
		}
	}
	r := requestState{ID: protocol.NewRequestID(), Created: b.now()}
	b.reqs = append(b.reqs, r)
	if err := b.saveLocked(); err != nil {
		b.reqs = b.reqs[:len(b.reqs)-1]
		return "", err
	}
	return r.ID, nil
}

// complete marks a request as finished.
func (b *requestBook) complete(id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	for i := range b.reqs {
		if b.reqs[i].ID == id && b.reqs[i].Completed == nil {
			b.reqs[i].Completed = &now
		}
	}
	b.pruneLocked()
	return b.saveLocked()
}

// known reports whether id is open or was completed recently.
func (b *requestBook) known(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneLocked()
	for _, r := range b.reqs {
		if r.ID == id {
			return true
		}
	}
	return false
}
