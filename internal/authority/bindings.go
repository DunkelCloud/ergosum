package authority

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/DunkelCloud/ergosum/internal/journal"
	"github.com/DunkelCloud/ergosum/internal/protocol"
)

// handleBindingWrite accepts an admin-signed binding event. The signatures
// and the threshold are the only authorization: the endpoint needs no
// credential of its own.
func (a *Authority) handleBindingWrite(w http.ResponseWriter, r *http.Request) {
	data, err := readBody(w, r, 256<<10)
	var e journal.BindingEvent
	if err == nil {
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		err = dec.Decode(&e)
	}
	if err != nil {
		a.writeError(w, http.StatusBadRequest, protocol.ErrBadRequest, "malformed binding event")
		return
	}
	rec, err := a.store.AppendBinding(r.Context(), &e)
	if err != nil {
		a.bindings.Inc("rejected")
		// Anyone who reaches the listener can cause a rejection, so its audit
		// line shares the overall limit of unverified requests; the metric
		// and the response carry the reason regardless.
		if a.unverified.allow(a.now()) {
			a.audit.Warn("binding event rejected", "event", "binding_write", "kind", e.Kind,
				"identity", e.Identity, "epoch", e.Epoch, "remote", r.RemoteAddr, "reason", err.Error())
		}
		status, code := http.StatusUnprocessableEntity, protocol.ErrRejected
		if errors.Is(err, journal.ErrLowerEpoch) || errors.Is(err, journal.ErrEpochTaken) {
			status, code = http.StatusConflict, protocol.ErrConflict
		}
		a.writeError(w, status, code, err.Error())
		return
	}
	a.bindings.Inc("accepted")
	a.audit.Info("binding event accepted", "event", "binding_write", "kind", e.Kind,
		"identity", e.Identity, "epoch", e.Epoch, "key", e.Key, "remote", r.RemoteAddr,
		"origin", rec.Origin, "seq", rec.Seq, "hash", rec.Hash, "duplicate", rec.Duplicate)
	status := http.StatusCreated
	if rec.Duplicate {
		status = http.StatusOK
	} else {
		a.repl.rep.Notify()
	}
	writeJSON(w, status, rec)
}

// handleBindingRead returns the current projection of one identity, for
// tooling that needs the current epoch, and for daemons that wait for the
// binding of a new key. It names the administrators who approved it.
func (a *Authority) handleBindingRead(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("identity")
	if !protocol.ValidDNSName(id) {
		a.writeError(w, http.StatusBadRequest, protocol.ErrBadRequest, "bad identity")
		return
	}
	b, err := a.store.Binding(r.Context(), id)
	if err != nil {
		a.writeError(w, http.StatusServiceUnavailable, protocol.ErrUnavailable, "")
		return
	}
	if b == nil {
		a.writeError(w, http.StatusNotFound, "not_found", "")
		return
	}
	e, err := a.store.BindingEvent(r.Context(), id)
	if err != nil {
		a.writeError(w, http.StatusServiceUnavailable, protocol.ErrUnavailable, "")
		return
	}
	if e != nil {
		b.SignedBy = a.store.Registry().SignerNames(e)
	}
	writeJSON(w, http.StatusOK, b)
}

// handleBindingList returns the projection of every identity and the
// approvals the registry demands, for administrator tooling. Bindings are
// no secret: the same is readable identity by identity.
func (a *Authority) handleBindingList(w http.ResponseWriter, r *http.Request) {
	body, err := a.bindingList(r.Context())
	if err != nil {
		a.writeError(w, http.StatusServiceUnavailable, protocol.ErrUnavailable, "")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// listCache keeps the answer of the list endpoint until the projection
// changes. Anyone who reaches the listener may ask for the list, and
// building it reads every binding over the journal's only connection: it
// is built once per change, by one request at a time.
type listCache struct {
	turn    chan struct{} // held by the request that looks at the cache
	version uint64
	body    []byte
	builds  int
}

func (a *Authority) bindingList(ctx context.Context) ([]byte, error) {
	c := &a.lists
	select {
	case c.turn <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-c.turn }()
	v := a.store.ProjectionVersion()
	if c.body != nil && c.version == v {
		return c.body, nil
	}
	bs, err := a.store.List(ctx)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(journal.BindingList{
		V: protocol.Version, TrustDomain: a.store.TrustDomain(),
		Approvals: a.store.Registry().Approvals(), Bindings: bs,
	})
	if err != nil {
		return nil, err
	}
	body = append(body, '\n')
	c.version, c.body = v, body
	c.builds++
	return c.body, nil
}
