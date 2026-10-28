package replication

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// Run pushes to every peer with a URL until ctx ends.
func (r *Replicator) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, p := range r.cfg.Peers {
		if p.URL == "" {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.pushLoop(ctx, p)
		}()
	}
	wg.Wait()
}

func (r *Replicator) pushLoop(ctx context.Context, p Peer) {
	delay := r.cfg.RetryMin
	failing := false
	for {
		n, err := r.Push(ctx, p.Name)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			// One line per attempt; the backoff bounds them to one per
			// RetryMax during a long outage.
			r.log.Warn("push failed", "peer", p.Name, "err", err, "retry_in", delay.String())
			failing = true
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
			delay = min(2*delay, r.cfg.RetryMax)
			continue
		}
		if failing {
			r.log.Info("push recovered", "peer", p.Name)
			failing = false
		}
		delay = r.cfg.RetryMin
		if n > 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-r.wake[p.Name]:
		case <-time.After(r.cfg.Idle):
		}
	}
}

// Push sends one page from a peer's outbox and advances its cursor by what
// the peer accepted. It returns the number of events sent.
func (r *Replicator) Push(ctx context.Context, peer string) (int, error) {
	p, ok := r.peers[peer]
	if !ok || p.URL == "" {
		return 0, fmt.Errorf("replication: no URL for peer %q", peer)
	}
	st := r.cfg.Store
	cursor, err := st.Cursor(ctx, peer)
	if err != nil {
		return 0, err
	}
	start, events, last, err := st.Read(ctx, cursor, r.cfg.BatchSize)
	if err != nil {
		return 0, err
	}
	if start == nil && len(events) == 0 {
		return 0, nil
	}
	events, last, _ = r.fit(start, events, last)
	page := Page{V: Version, Instance: r.cfg.Self, Start: start, Events: events, Last: last}
	ack, err := r.send(ctx, p, page)
	// A peer cannot acknowledge what it was not sent: an answer beyond the
	// page would skip events.
	if ack.Accepted > last {
		return 0, fmt.Errorf("peer %s acknowledged position %d beyond the page (%d)", peer, ack.Accepted, last)
	}
	if ack.Accepted > cursor {
		if serr := st.SetCursor(ctx, peer, ack.Accepted); serr != nil {
			return 0, serr
		}
	}
	if err != nil {
		return 0, err
	}
	// Success without the whole page would resend it at once, forever.
	if ack.Accepted < last {
		return 0, fmt.Errorf("peer %s accepted up to position %d of a page reaching %d", peer, ack.Accepted, last)
	}
	return len(events) + btoi(start != nil), nil
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// fit cuts events so that the page stays within the receiver's MaxBody,
// keeping at least one event so that the outbox moves. A page too large
// even with one event is logged; the receiver will refuse it.
func (r *Replicator) fit(start *Stored, events []Stored, last int64) (kept []Stored, reach int64, cut bool) {
	budget := r.cfg.MaxBody * 3 / 4 // room for the page's own fields
	if start != nil {
		budget -= start.size()
	}
	for i := range events {
		if budget -= events[i].size(); budget >= 0 {
			continue
		}
		if i > 0 {
			return events[:i], events[i-1].Pos, true
		}
		r.log.Error("page larger than max_body with a single event", "origin", events[0].Origin, "seq", events[0].Seq,
			"kind", events[0].Kind, "bytes", len(events[0].Body), "start", start != nil, "max_body", r.cfg.MaxBody)
		if len(events) > 1 {
			return events[:1], events[0].Pos, true
		}
		break
	}
	return events, last, false
}

func (r *Replicator) send(ctx context.Context, p Peer, page Page) (Ack, error) {
	body, err := json.Marshal(page)
	if err != nil {
		return Ack{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.URL+PathIngest, bytes.NewReader(body))
	if err != nil {
		return Ack{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.cfg.Client(p.Name).Do(req)
	if err != nil {
		return Ack{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return Ack{}, err
	}
	var ack Ack
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusUnprocessableEntity {
		return Ack{}, fmt.Errorf("peer %s answered %s", p.Name, resp.Status)
	}
	if err := json.Unmarshal(data, &ack); err != nil {
		return Ack{}, fmt.Errorf("peer %s: bad acknowledgment: %w", p.Name, err)
	}
	if resp.StatusCode != http.StatusOK || ack.Error != "" {
		return ack, fmt.Errorf("peer %s stopped at position %d: %s", p.Name, ack.Accepted, ack.Error)
	}
	return ack, nil
}

// PullResult summarizes a pull.
type PullResult struct {
	Peer   string `json:"peer"`
	Pages  int    `json:"pages"`
	Events int    `json:"events"`
	// Checkpoint reports that the peer had compacted and the pull started
	// with its checkpoint.
	Checkpoint bool  `json:"checkpoint,omitempty"`
	Last       int64 `json:"last"`
}

// Pull reads a peer's whole journal and ingests it with the same checks as
// a push. Unlike a push, it raises the coverage to the checkpoint a page
// starts with, since an operator chose the peer. Pulling from several peers
// gives the union of their journals.
func (r *Replicator) Pull(ctx context.Context, peer string) (PullResult, error) {
	res := PullResult{Peer: peer}
	p, ok := r.peers[peer]
	if !ok || p.URL == "" {
		return res, fmt.Errorf("replication: no URL for peer %q", peer)
	}
	var after int64
	for {
		page, err := r.fetch(ctx, p, after)
		if err != nil {
			return res, err
		}
		if page.Instance != peer {
			return res, fmt.Errorf("peer %s sent a page of %q", peer, page.Instance)
		}
		if _, err := r.ingestPage(ctx, peer, page, true); err != nil {
			return res, err
		}
		res.Pages++
		res.Events += len(page.Events)
		res.Checkpoint = res.Checkpoint || page.Start != nil
		if !page.More {
			res.Last = max(after, page.Last)
			return res, nil
		}
		if page.Last <= after {
			return res, fmt.Errorf("peer %s: page does not advance beyond position %d", peer, after)
		}
		after = page.Last
	}
}

func (r *Replicator) fetch(ctx context.Context, p Peer, after int64) (Page, error) {
	q := url.Values{"after": {strconv.FormatInt(after, 10)}, "limit": {strconv.Itoa(r.cfg.BatchSize)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL+PathEvents+"?"+q.Encode(), http.NoBody)
	if err != nil {
		return Page{}, err
	}
	resp, err := r.cfg.Client(p.Name).Do(req)
	if err != nil {
		return Page{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return Page{}, fmt.Errorf("peer %s answered %s", p.Name, resp.Status)
	}
	var page Page
	lr := &io.LimitedReader{R: resp.Body, N: r.cfg.MaxBody}
	if err := json.NewDecoder(lr).Decode(&page); err != nil {
		if lr.N <= 0 {
			return Page{}, fmt.Errorf("peer %s: page larger than %d bytes", p.Name, r.cfg.MaxBody)
		}
		return Page{}, fmt.Errorf("peer %s: bad page: %w", p.Name, err)
	}
	return page, nil
}

// Handler serves ingest and pull for authenticated peers.
func (r *Replicator) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+PathIngest, r.handleIngest)
	mux.HandleFunc("GET "+PathEvents, r.handleEvents)
	return mux
}

func (r *Replicator) peer(w http.ResponseWriter, req *http.Request) (string, bool) {
	if r.cfg.Authenticate == nil {
		http.Error(w, "no authentication configured", http.StatusForbidden)
		return "", false
	}
	name, ok := r.cfg.Authenticate(req)
	if !ok || r.peers[name].Name == "" {
		http.Error(w, "unknown peer", http.StatusForbidden)
		return "", false
	}
	return name, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (r *Replicator) handleIngest(w http.ResponseWriter, req *http.Request) {
	peer, ok := r.peer(w, req)
	if !ok {
		return
	}
	var page Page
	if err := json.NewDecoder(http.MaxBytesReader(w, req.Body, r.cfg.MaxBody)).Decode(&page); err != nil {
		if mbe := (*http.MaxBytesError)(nil); errors.As(err, &mbe) {
			writeJSON(w, http.StatusRequestEntityTooLarge, Ack{V: Version, Error: fmt.Sprintf("page larger than %d bytes", mbe.Limit)})
			return
		}
		writeJSON(w, http.StatusBadRequest, Ack{V: Version, Error: "malformed page"})
		return
	}
	if page.Instance != peer {
		writeJSON(w, http.StatusForbidden, Ack{V: Version, Error: "page sent on behalf of another instance"})
		return
	}
	accepted, err := r.Ingest(req.Context(), peer, page)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, Ack{V: Version, Accepted: accepted})
	case errors.Is(err, ErrRejected):
		writeJSON(w, http.StatusUnprocessableEntity, Ack{V: Version, Accepted: accepted, Error: err.Error()})
	default:
		r.log.Error("ingest failed", "peer", peer, "err", err)
		writeJSON(w, http.StatusServiceUnavailable, Ack{V: Version, Accepted: accepted, Error: "unavailable"})
	}
}

func (r *Replicator) handleEvents(w http.ResponseWriter, req *http.Request) {
	if _, ok := r.peer(w, req); !ok {
		return
	}
	after, err := strconv.ParseInt(req.URL.Query().Get("after"), 10, 64)
	if err != nil || after < 0 {
		http.Error(w, "bad after", http.StatusBadRequest)
		return
	}
	limit := r.cfg.BatchSize
	if s := req.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n < limit {
			limit = n
		}
	}
	start, events, last, err := r.cfg.Store.Read(req.Context(), after, limit)
	if err != nil {
		r.log.Error("reading journal failed", "err", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	more := len(events) == limit
	events, last, cut := r.fit(start, events, last)
	if events == nil {
		events = []Stored{}
	}
	writeJSON(w, http.StatusOK, Page{V: Version, Instance: r.cfg.Self, Start: start, Events: events, Last: last, More: more || cut})
}
