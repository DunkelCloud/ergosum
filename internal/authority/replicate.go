package authority

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/DunkelCloud/ergosum/internal/journal"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/metrics"
	"github.com/DunkelCloud/ergosum/internal/replication"
	"github.com/DunkelCloud/ergosum/internal/tlspin"
)

// replicationState is the journal replication of one instance: the peers,
// the replicator and its metrics.
type replicationState struct {
	peers  []peer
	byFP   map[string]string // peer key fingerprint -> name
	rep    *replication.Replicator
	dial   func(ctx context.Context, network, address string) (net.Conn, error)
	mu     sync.Mutex
	client map[string]*http.Client
}

// journalMetrics groups the metrics of journal replication and compaction.
type journalMetrics struct {
	rejected      *metrics.Vec
	equivocations *metrics.Vec
	skipped       *metrics.Vec
	originBytes   *metrics.Vec
	outboxEvents  *metrics.Vec
	outboxAge     *metrics.Vec
	coverage      *metrics.Vec
	frontier      *metrics.Vec
	checkpointAge *metrics.Vec
	compacted     *metrics.Vec
}

func (a *Authority) setupReplication(ps []peer) error {
	r := &replicationState{peers: ps, byFP: map[string]string{}, client: map[string]*http.Client{}, dial: a.opts.DialPeer}
	instanceKeys := map[string]*ecdsa.PublicKey{a.cfg.Instance: a.public}
	var rpeers []replication.Peer
	for _, p := range ps {
		if other, dup := r.byFP[p.fingerprint]; dup {
			return fmt.Errorf("replication.peers %q and %q share a key", other, p.name)
		}
		if p.fingerprint == keys.Fingerprint(a.public) {
			return fmt.Errorf("replication.peers %q has this instance's key", p.name)
		}
		instanceKeys[p.name] = p.key
		rpeers = append(rpeers, replication.Peer{Name: p.name, URL: p.url})
		if p.retired {
			continue // its key verifies history, but it may not connect
		}
		r.byFP[p.fingerprint] = p.name
	}
	a.store.SetInstanceKeys(instanceKeys)
	a.store.SetQuota(int64(a.cfg.Replication.OriginQuotaMiB) << 20)
	peerNames := make([]string, 0, len(rpeers))
	for _, p := range rpeers {
		peerNames = append(peerNames, p.Name)
	}
	m := a.metrics
	a.jm = &journalMetrics{
		rejected: m.Counter("machine_identity_journal_rejected_total",
			"Events that ingest rejected, by the peer that sent them. Each one stops replication from that peer.", "peer", peerNames...),
		equivocations: m.Counter("machine_identity_journal_equivocations_total",
			"Events whose origin signed a contradicting event before; they are skipped.", "origin", peerNames...),
		skipped: m.Counter("machine_identity_journal_skipped_total",
			"Observations and checkpoints of an origin skipped over its quota or too far above its coverage.", "origin", peerNames...),
		originBytes: m.GaugeVec("machine_identity_journal_origin_bytes",
			"Bytes that the observations and checkpoints of another origin take, against replication.origin_quota_mib.", "origin"),
		outboxEvents: m.GaugeVec("machine_identity_journal_outbox_events",
			"Events a peer has not acknowledged yet.", "peer"),
		outboxAge: m.GaugeVec("machine_identity_journal_outbox_oldest_age_seconds",
			"Age of the oldest event a peer has not acknowledged; 0 if there is none.", "peer"),
		coverage: m.GaugeVec("machine_identity_journal_coverage",
			"Sequence number up to which every event of an origin has been ingested.", "origin"),
		frontier: m.GaugeVec("machine_identity_journal_compaction_frontier",
			"Sequence number up to which events of an origin may be deleted.", "origin"),
		checkpointAge: m.Gauge("machine_identity_journal_checkpoint_age_seconds",
			"Age of the latest own checkpoint; -1 if there is none yet."),
		compacted: m.Counter("machine_identity_journal_compacted_events_total",
			"Events deleted by compaction.", ""),
	}
	for _, p := range ps {
		a.jm.rejected.Add(p.name, 0)
		if p.url != "" {
			a.jm.outboxEvents.Set(p.name, 0)
			a.jm.outboxAge.Set(p.name, 0)
		}
	}
	m.OnCollect(a.collectJournalMetrics)

	rep, err := replication.New(replication.Config{
		Self:               a.cfg.Instance,
		Peers:              rpeers,
		Store:              a.store,
		Verify:             a.store.Verify,
		AlwaysIngest:       journal.AlwaysIngest,
		CheckpointKind:     journal.KindCheckpoint,
		CheckpointCoverage: a.store.CheckpointCoverage,
		Client:             a.peerClient,
		Authenticate:       r.authenticate,
		OnReject:           a.onReject,
		OnEquivocation:     a.onEquivocation,
		Admit:              a.store.Admit,
		OnSkip:             a.onSkip,
		Logger:             a.log.With("component", "replication"),
		MaxBody:            int64(a.cfg.Replication.MaxPageMiB) << 20,
		RetryMin:           a.opts.RetryMin,
		RetryMax:           a.opts.RetryMax,
		Idle:               a.opts.ReplicationIdle,
	})
	if err != nil {
		return err
	}
	r.rep = rep
	a.repl = r
	return nil
}

// authenticate names the peer by the key of its TLS client certificate.
func (r *replicationState) authenticate(req *http.Request) (string, bool) {
	pub, err := tlspin.PeerKey(req.TLS)
	if err != nil {
		return "", false
	}
	name, ok := r.byFP[keys.Fingerprint(pub)]
	return name, ok
}

func (r *replicationState) pins() tlspin.Pins {
	fps := make([]string, 0, len(r.peers))
	for _, p := range r.peers {
		if !p.retired {
			fps = append(fps, p.fingerprint)
		}
	}
	return tlspin.Fingerprints(fps...)
}

// peerClient returns the mutual-TLS client for a peer: it presents the
// instance key and accepts only the peer's pinned key.
func (a *Authority) peerClient(name string) *http.Client {
	r := a.repl
	r.mu.Lock()
	defer r.mu.Unlock()
	if c := r.client[name]; c != nil {
		return c
	}
	var fp string
	for _, p := range r.peers {
		if p.name == name {
			fp = p.fingerprint
		}
	}
	_, cert := a.signingKey()
	tr := &http.Transport{
		TLSClientConfig:     tlspin.ClientConfig(&cert, tlspin.Fingerprints(fp)),
		DialContext:         r.dial,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     time.Minute,
	}
	c := &http.Client{Transport: tr, Timeout: 2 * time.Minute, CheckRedirect: tlspin.NoRedirect}
	if !a.Sealed() {
		r.client[name] = c // without a key the client cannot authenticate yet
	}
	return c
}

// onReject raises the alarm for an event that ingest refused: it stops
// replication from that peer until the cause is fixed, for example a stale
// registry here or a forged event there.
// onEquivocation reports an origin that signed contradicting events. The
// event is skipped and replication goes on; the origin's key is no longer
// trustworthy.
func (a *Authority) onEquivocation(peer string, e replication.Event, stored string, err error) {
	a.jm.equivocations.Inc(e.Origin)
	a.audit.Error("journal equivocation", "event", "journal_ingest", "peer", peer,
		"origin", e.Origin, "seq", e.Seq, "kind", e.Kind, "hash", e.Hash, "stored_hash", stored,
		"sig", e.Sig, "reason", err.Error(),
		"alert", "an instance signed two contradicting events; the event is skipped, take the instance out of service")
}

// onSkip reports an event over its origin's quota. Skipping goes on for
// every event beyond the quota, so the log line is limited per origin.
func (a *Authority) onSkip(peer string, e replication.Event, err error) {
	a.jm.skipped.Inc(e.Origin)
	if a.limiter.allow("skipped "+e.Origin, a.now()) {
		a.audit.Error("journal events skipped", "event", "journal_ingest", "peer", peer,
			"origin", e.Origin, "seq", e.Seq, "kind", e.Kind, "reason", err.Error(),
			"alert", "an instance wrote more than its quota or left gaps; its events are skipped, check that instance")
	}
}

func (a *Authority) onReject(peer string, e replication.Event, err error) {
	a.jm.rejected.Inc(peer)
	a.audit.Error("journal event rejected", "event", "journal_ingest", "peer", peer,
		"origin", e.Origin, "seq", e.Seq, "kind", e.Kind, "hash", e.Hash, "reason", err.Error(),
		"alert", "an event from a peer failed verification; replication from that peer stops here")
}

// serveReplication opens the mutual-TLS listener for peers.
func (a *Authority) serveReplication(ctx context.Context, cert tls.Certificate) (*http.Server, net.Listener, error) {
	ln, err := a.listen("tcp", a.cfg.Replication.Listen)
	if err != nil {
		return nil, nil, fmt.Errorf("replication listener: %w", err)
	}
	a.addrMu.Lock()
	a.replAddr = ln.Addr()
	a.addrMu.Unlock()
	srv := &http.Server{
		Handler:           a.repl.rep.Handler(),
		TLSConfig:         tlspin.ServerConfig(cert, a.repl.pins()),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       time.Minute,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	return srv, tls.NewListener(ln, srv.TLSConfig), nil
}

// ReplicationAddr returns the bound replication address, or "".
func (a *Authority) ReplicationAddr() string {
	a.addrMu.Lock()
	defer a.addrMu.Unlock()
	if a.replAddr == nil {
		return ""
	}
	return a.replAddr.String()
}

// Push sends one page to a peer now, for tests and tooling; the pushers do
// this on their own.
func (a *Authority) Push(ctx context.Context, peer string) (int, error) {
	return a.repl.rep.Push(ctx, peer)
}

// Sync pulls a peer's whole journal and ingests it with the same checks as
// a push (ergosum journal sync).
func (a *Authority) Sync(ctx context.Context, peer string) (replication.PullResult, error) {
	if a.Sealed() {
		return replication.PullResult{}, ErrSealed
	}
	res, err := a.repl.rep.Pull(ctx, peer)
	if err == nil {
		a.log.Info("journal synced", "peer", peer, "events", res.Events, "checkpoint", res.Checkpoint)
	}
	return res, err
}

// Checkpoint writes a checkpoint now (ergosum journal checkpoint).
func (a *Authority) Checkpoint(ctx context.Context) (journal.Receipt, error) {
	if a.Sealed() {
		return journal.Receipt{}, ErrSealed
	}
	rec, err := a.store.WriteCheckpoint(ctx)
	if err != nil {
		return rec, err
	}
	a.log.Info("checkpoint written", "seq", rec.Seq, "hash", rec.Hash)
	a.repl.rep.Notify()
	return rec, nil
}

// CompactResult reports a compaction.
type CompactResult struct {
	// Checkpoint is the sequence number of the own checkpoint the frontier
	// comes from; 0 if no checkpoint has been acknowledged by every peer.
	Checkpoint int64            `json:"checkpoint"`
	Frontier   map[string]int64 `json:"frontier"`
	Archive    string           `json:"archive,omitempty"`
	Deleted    int64            `json:"deleted"`
}

// Compact exports to the archive if one is configured, raises the
// compaction frontier to the newest own checkpoint every peer has
// acknowledged, and deletes what that frontier and the retention allow
// (ergosum journal compact).
func (a *Authority) Compact(ctx context.Context) (CompactResult, error) {
	var res CompactResult
	if dir := a.cfg.Compaction.Archive; dir != "" {
		path, _, err := a.store.ExportArchive(ctx, dir)
		if err != nil {
			return res, fmt.Errorf("archive: %w", err)
		}
		res.Archive = path
	}
	cp, err := a.repl.rep.Frontier(ctx)
	if err != nil {
		return res, err
	}
	if cp != nil {
		res.Checkpoint = cp.Seq
	}
	var pushed []string
	for _, p := range a.repl.peers {
		if p.url != "" {
			pushed = append(pushed, p.name)
		}
	}
	res.Deleted, err = a.store.Compact(ctx, journal.CompactOptions{
		Peers:     pushed,
		Retention: a.cfg.Compaction.Retention.retention(),
		Archived:  a.cfg.Compaction.Archive != "",
	})
	if err != nil {
		return res, err
	}
	if res.Frontier, err = a.store.Frontier(ctx); err != nil {
		return res, err
	}
	a.jm.compacted.Add("", float64(res.Deleted))
	if res.Deleted > 0 {
		a.log.Info("journal compacted", "deleted", res.Deleted, "checkpoint", res.Checkpoint)
	}
	return res, nil
}

// maintain writes a checkpoint when one is due and the journal changed
// since the last one, and compacts; at start and then every compaction
// interval.
func (a *Authority) maintain(ctx context.Context) {
	t := time.NewTicker(a.cfg.Compaction.Interval)
	defer t.Stop()
	for {
		last, err := a.store.LastCheckpoint(ctx)
		changed := false
		if err == nil {
			changed, err = a.store.ChangedSinceCheckpoint(ctx)
		}
		switch {
		case err != nil:
			if ctx.Err() == nil {
				a.log.Error("journal maintenance", "err", err)
			}
		case changed && a.now().Sub(last) >= a.cfg.Compaction.CheckpointInterval:
			if _, err := a.Checkpoint(ctx); err != nil && ctx.Err() == nil {
				a.log.Error("checkpoint failed", "err", err)
			}
		}
		if _, err := a.Compact(ctx); err != nil && ctx.Err() == nil {
			a.log.Error("compaction failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// JournalStatus is the journal state with the outbox of every peer.
type JournalStatus struct {
	journal.State
	Peers []PeerStatus `json:"peers,omitempty"`
}

// PeerStatus is one peer's outbox.
type PeerStatus struct {
	Peer    string     `json:"peer"`
	Cursor  int64      `json:"cursor"`
	Pending int64      `json:"pending"`
	Oldest  *time.Time `json:"oldest_pending,omitempty"`
}

// JournalState reports the journal and the outboxes, for the ops listener
// and "ergosum journal state".
func (a *Authority) JournalState(ctx context.Context) (JournalStatus, error) {
	st, err := a.store.State(ctx)
	if err != nil {
		return JournalStatus{}, err
	}
	out := JournalStatus{State: st}
	ps, err := a.repl.rep.Status(ctx)
	if err != nil {
		return out, err
	}
	for _, p := range ps {
		s := PeerStatus{Peer: p.Peer, Cursor: p.Cursor, Pending: p.Pending}
		if !p.Oldest.IsZero() {
			t := p.Oldest
			s.Oldest = &t
		}
		out.Peers = append(out.Peers, s)
	}
	return out, nil
}

func (a *Authority) collectJournalMetrics() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := a.JournalState(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		a.log.Error("journal metrics", "err", err)
		return
	}
	now := a.now()
	for _, p := range st.Peers {
		a.jm.outboxEvents.Set(p.Peer, float64(p.Pending))
		age := 0.0
		if p.Oldest != nil {
			age = now.Sub(*p.Oldest).Seconds()
		}
		a.jm.outboxAge.Set(p.Peer, age)
	}
	for o, n := range st.Coverage {
		a.jm.coverage.Set(o, float64(n))
	}
	for o, n := range st.Frontier {
		a.jm.frontier.Set(o, float64(n))
	}
	for o, n := range a.store.OriginBytes() {
		a.jm.originBytes.Set(o, float64(n))
	}
	age := -1.0
	if st.LastCheckpoint != nil {
		age = now.Sub(*st.LastCheckpoint).Seconds()
	}
	a.jm.checkpointAge.Set("", age)
}
