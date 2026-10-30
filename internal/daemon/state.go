package daemon

import (
	"sync"
	"time"

	"github.com/DunkelCloud/ergosum/internal/protocol"
)

// inflight tracks the requests in flight: request ID to the key fingerprint
// of the authority instance the request went to. It lives in memory only.
// A callback is confirmed only for a request in flight to the calling
// instance, so a copied request ID is worthless once its request has ended,
// and worthless at every other instance even while it is in flight.
//
// A request the daemon gave up on (timeout, or it moved on to the next
// instance) is remembered as ended for protocol.EndedTTL. A late callback
// for it from the same instance is answered "ended", not "no open request":
// the instance may not have noticed yet that the daemon left.
type inflight struct {
	mu    sync.Mutex
	now   func() time.Time
	reqs  map[string]string
	ended map[string]endedRequest
}

type endedRequest struct {
	authority string
	until     time.Time
}

func newInflight(now func() time.Time) *inflight {
	if now == nil {
		now = time.Now
	}
	return &inflight{now: now, reqs: map[string]string{}, ended: map[string]endedRequest{}}
}

// add records a request to the instance with the given key fingerprint.
func (f *inflight) add(id, authority string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs[id] = authority
}

// remove ends a request; it is remembered as ended for a while.
func (f *inflight) remove(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	if a, ok := f.reqs[id]; ok {
		f.ended[id] = endedRequest{authority: a, until: now.Add(protocol.EndedTTL)}
	}
	delete(f.reqs, id)
	for k, e := range f.ended {
		if now.After(e.until) {
			delete(f.ended, k)
		}
	}
}

// status answers a callback for id from the instance with the given key
// fingerprint: confirmed while the request is in flight to that instance,
// ended for a while after this process gave it up, otherwise "no open
// request".
func (f *inflight) status(id, authority string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a, ok := f.reqs[id]; ok && a == authority {
		return protocol.StatusConfirmed
	}
	if e, ok := f.ended[id]; ok && e.authority == authority && !f.now().After(e.until) {
		return protocol.StatusEnded
	}
	return protocol.StatusNoOpenRequest
}
