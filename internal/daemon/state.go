package daemon

import "sync"

// inflight tracks the requests in flight: request ID to the key fingerprint
// of the authority instance the request went to. It lives in memory only.
// A callback is confirmed only for a request in flight to the calling
// instance, so a copied request ID is worthless once its request has ended,
// and worthless at every other instance even while it is in flight.
type inflight struct {
	mu   sync.Mutex
	reqs map[string]string
}

func newInflight() *inflight { return &inflight{reqs: map[string]string{}} }

// add records a request to the instance with the given key fingerprint.
func (f *inflight) add(id, authority string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs[id] = authority
}

// remove ends a request.
func (f *inflight) remove(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.reqs, id)
}

// confirms reports whether id is in flight to the instance with the given
// key fingerprint.
func (f *inflight) confirms(id, authority string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.reqs[id]
	return ok && a == authority
}
