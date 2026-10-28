package authority

import (
	"bytes"
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
		if errors.Is(err, journal.ErrLowerEpoch) || errors.Is(err, journal.ErrSuperseded) {
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
// tooling that needs the current epoch.
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
	writeJSON(w, http.StatusOK, b)
}
