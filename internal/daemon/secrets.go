package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/DunkelCloud/ergosum/internal/exchange"
	"github.com/DunkelCloud/ergosum/internal/protocol"
	"github.com/DunkelCloud/ergosum/internal/secret"
)

// The secrets of ADR 0004 that the daemon holds open, in memory only. A
// secret is keyed by the SHA-256 of its part A as a caller brought it: the
// daemon answers only for a part A it is given, so the file permissions of
// part A decide who may open a secret.

// reshareRetry is how often a listed instance that was unreachable is
// tried again for a re-split.
const reshareRetry = time.Hour

type heldSecret struct {
	sealed *secret.Sealed
	key    [32]byte // SHA-256 of part A
	plain  []byte
	master []byte
	// denied: a pin denied (403) the last refresh; the next get opens the
	// secret anew instead of answering from memory.
	denied bool
	// pending is a re-split part A for the next get to write, with its key.
	pending    []byte
	pendingKey [32]byte
	// Re-splitting: the list serial the pins were last checked against,
	// when to try unreachable instances again, and the instances that
	// refused (404, not_responsible) under that list.
	checked uint64
	retryAt time.Time
	refused map[string]bool
}

type secretStore struct {
	mu   sync.Mutex
	held map[[32]byte]*heldSecret
}

// all returns every held secret once.
func (s *secretStore) all() []*heldSecret {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*heldSecret
	for k, h := range s.held {
		if k == h.key {
			out = append(out, h)
		}
	}
	return out
}

func (d *Daemon) initSecrets() {
	d.secrets = &secretStore{held: map[[32]byte]*heldSecret{}}
	d.mSecretThreshold = d.metrics.GaugeVec("machine_identity_secret_threshold",
		"Threshold of each secret the daemon holds open.", "name")
	d.mSecretPins = d.metrics.GaugeVec("machine_identity_secret_pins",
		"Pinned instances of each held secret that answered its last refresh; below the threshold, the secret does not open once the daemon restarts.", "name")
	d.mSecretReshare = d.metrics.GaugeVec("machine_identity_secret_reshare_pending",
		"1 while a re-split part A waits for the next get to write it.", "name")
}

// tokenValid reports whether the daemon holds an unexpired token.
func (d *Daemon) tokenValid() bool { return d.now().Unix() < d.tokenExp.Load() }

// ownSecret checks that part A belongs to this machine.
func (d *Daemon) ownSecret(s *secret.Sealed) error {
	if s.Identity != d.cfg.Identity {
		return fmt.Errorf("part A is sealed for %s, this machine is %s", s.Identity, d.cfg.Identity)
	}
	d.amu.Lock()
	list := d.list
	d.amu.Unlock()
	if list != nil && list.TrustDomain != s.TrustDomain {
		return fmt.Errorf("part A is sealed in trust domain %s, the authorities are in %s", s.TrustDomain, list.TrustDomain)
	}
	return nil
}

// GetSecret returns the secret of part A. It answers from memory while the
// daemon holds an unexpired token and no pin denied the last refresh;
// otherwise it opens the secret anew at the listed pinned instances.
// replace is a re-split part A for the caller to write in place of its
// file, or nil.
func (d *Daemon) GetSecret(ctx context.Context, partA []byte) (plain, replace []byte, err error) {
	s, err := secret.Parse(partA)
	if err != nil {
		return nil, nil, err
	}
	if err := d.ownSecret(s); err != nil {
		return nil, nil, err
	}
	key := sha256.Sum256(partA)
	st := d.secrets
	st.mu.Lock()
	h := st.held[key]
	if h != nil && h.pending != nil && key == h.pendingKey {
		// The caller wrote the re-split part A: it is the one in use now.
		delete(st.held, h.key)
		h.sealed, h.key, h.pending = s, key, nil
		d.mSecretReshare.Set(s.Name, 0)
		d.log.Info("re-split part A in use", "name", s.Name)
	}
	if h != nil && !h.denied && d.tokenValid() {
		plain, replace = bytes.Clone(h.plain), h.pending
		st.mu.Unlock()
		return plain, replace, nil
	}
	st.mu.Unlock()

	plain, master, err := d.openSecret(ctx, s)
	if err != nil {
		return nil, nil, err
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if h == nil {
		h = &heldSecret{sealed: s, key: key, refused: map[string]bool{}}
		st.held[key] = h
	}
	h.plain, h.master, h.denied = plain, master, false
	d.mSecretThreshold.Set(s.Name, float64(s.Threshold))
	return bytes.Clone(plain), h.pending, nil
}

// openSecret asks the listed instances among the pins, in list order,
// until the threshold of them opened their shares.
func (d *Daemon) openSecret(ctx context.Context, s *secret.Sealed) (plain, master []byte, err error) {
	shares := map[int][]byte{}
	var failed []string
	authorities, _ := d.snapshot()
	for _, a := range authorities {
		if len(shares) == s.Threshold {
			break
		}
		i := slices.IndexFunc(s.Pins, func(p secret.Pin) bool { return p.Authority == a.pin })
		if i < 0 {
			continue
		}
		share, err := d.openPin(ctx, s, i)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", a.name(), err))
			continue
		}
		shares[i] = share
	}
	if len(shares) < s.Threshold {
		return nil, nil, fmt.Errorf("%d of the %d shares needed opened (%s)", len(shares), s.Threshold, strings.Join(failed, "; "))
	}
	return s.Open(shares)
}

// openPin opens the share of pin i through one exchange.
func (d *Daemon) openPin(ctx context.Context, s *secret.Sealed, i int) ([]byte, error) {
	_, S, err := s.Pins[i].ReleaseKeyPayload()
	if err != nil {
		return nil, err
	}
	x, b, err := exchange.Blind(s.Pins[i].Point(), S)
	if err != nil {
		return nil, err
	}
	r, err := d.Exchange(ctx, s.Pins[i].Authority, [][]byte{x})
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(r.Key, S) {
		return nil, errors.New("the instance has another release key now (a new exchange key)")
	}
	kx, err := b.Unblind(r.Points[0])
	if err != nil {
		return nil, err
	}
	return s.OpenShare(i, kx)
}

// CreateSecret seals plain under name: it fetches the release key of the
// identity from every instance in use and pins a share to each one that
// answers, at most secret.MaxPins in list order. With fewer than threshold
// answers it fails and names the instances that did not answer and why.
// The new secret is held open at once.
func (d *Daemon) CreateSecret(ctx context.Context, name string, threshold int, plain []byte, recovery string) ([]byte, error) {
	if !secret.ValidName(name) {
		return nil, fmt.Errorf("bad name %q: lower-case letters, digits and hyphens, at most 63 characters", name)
	}
	if threshold < 1 || threshold > secret.MaxPins {
		return nil, fmt.Errorf("threshold %d out of range (1 to %d)", threshold, secret.MaxPins)
	}
	var targets []secret.Target
	var failed []string
	trustDomain := ""
	authorities, _ := d.snapshot()
	for _, a := range authorities {
		if len(targets) == secret.MaxPins {
			break
		}
		r, err := d.Exchange(ctx, a.pin, nil)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", a.name(), err))
			continue
		}
		if trustDomain != "" && r.TrustDomain != trustDomain {
			failed = append(failed, fmt.Sprintf("%s: trust domain %s, not %s", a.name(), r.TrustDomain, trustDomain))
			continue
		}
		trustDomain = r.TrustDomain
		targets = append(targets, secret.Target{Authority: r.Authority, ReleaseKey: r.ReleaseKey, Key: r.Key})
	}
	if len(targets) < threshold {
		return nil, fmt.Errorf("%d instances can be pinned, the threshold is %d (%s)", len(targets), threshold, strings.Join(failed, "; "))
	}
	for _, f := range failed {
		d.log.Warn("instance not pinned", "name", name, "reason", f)
	}
	s, master, err := secret.Seal(plain, name, trustDomain, d.cfg.Identity, threshold, targets, recovery)
	if err != nil {
		return nil, err
	}
	data, err := s.Marshal()
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256(data)
	d.secrets.mu.Lock()
	d.secrets.held[key] = &heldSecret{sealed: s, key: key, plain: bytes.Clone(plain), master: master, refused: map[string]bool{}}
	d.secrets.mu.Unlock()
	d.mSecretThreshold.Set(name, float64(threshold))
	d.mSecretPins.Set(name, float64(len(targets)))
	return data, nil
}

// RefreshSecrets runs after each token round: one exchange request to
// every listed pinned instance, carrying the points of all held secrets
// pinned there. A pin that denies (403) makes the next get open its secret
// anew; the pins that answered are counted per secret.
func (d *Daemon) RefreshSecrets(ctx context.Context) {
	held := d.secrets.all()
	if len(held) == 0 {
		return
	}
	type item struct {
		h    *heldSecret
		i    int
		S, x []byte
		b    *exchange.Blinding
	}
	answered := map[*heldSecret]int{}
	denied := map[*heldSecret]bool{}
	authorities, _ := d.snapshot()
	for _, a := range authorities {
		var items []item
		for _, h := range held {
			i := slices.IndexFunc(h.sealed.Pins, func(p secret.Pin) bool { return p.Authority == a.pin })
			if i < 0 {
				continue
			}
			_, S, err := h.sealed.Pins[i].ReleaseKeyPayload()
			if err != nil {
				continue
			}
			x, b, err := exchange.Blind(h.sealed.Pins[i].Point(), S)
			if err != nil {
				continue
			}
			items = append(items, item{h: h, i: i, S: S, x: x, b: b})
		}
		for len(items) > 0 {
			chunk := items[:min(len(items), protocol.MaxExchangePoints)]
			items = items[len(chunk):]
			points := make([][]byte, len(chunk))
			for j, it := range chunk {
				points[j] = it.x
			}
			r, err := d.Exchange(ctx, a.pin, points)
			var re *RequestError
			switch {
			case errors.As(err, &re) && re.Status == http.StatusForbidden:
				for _, it := range chunk {
					denied[it.h] = true
				}
				d.log.Warn("an instance denied the refresh of held secrets", "authority", a.name())
				continue
			case err != nil:
				d.log.Warn("refreshing held secrets failed", "authority", a.name(), "err", err)
				continue
			}
			for j, it := range chunk {
				if !bytes.Equal(r.Key, it.S) {
					continue
				}
				kx, err := it.b.Unblind(r.Points[j])
				if err == nil {
					if _, err = it.h.sealed.OpenShare(it.i, kx); err == nil {
						answered[it.h]++
					}
				}
			}
		}
	}
	d.secrets.mu.Lock()
	defer d.secrets.mu.Unlock()
	for _, h := range held {
		h.denied = denied[h]
		d.mSecretPins.Set(h.sealed.Name, float64(answered[h]))
	}
}

// ReshareSecrets checks every held secret against the authority list in
// use. A pinned instance that is no longer listed drops out; a listed one
// that is not pinned is asked for its release key. The new part A, with
// new shares of the same master key, waits for the next get to write it.
// It is prepared only if at least the threshold of the secret's pinned
// instances serve the same list, and only with at least the threshold of
// pins; the threshold never goes down.
func (d *Daemon) ReshareSecrets(ctx context.Context) {
	d.amu.Lock()
	list := d.list
	d.amu.Unlock()
	if list == nil {
		return
	}
	now := d.now()
	for _, h := range d.secrets.all() {
		d.secrets.mu.Lock()
		due := h.checked != list.Serial || !now.Before(h.retryAt)
		if h.checked != list.Serial {
			h.checked, h.refused = list.Serial, map[string]bool{}
		}
		if due {
			h.retryAt = now.Add(reshareRetry)
		}
		s, master, refused := h.sealed, h.master, maps.Clone(h.refused)
		d.secrets.mu.Unlock()
		if !due || master == nil {
			continue
		}
		data, newRefused, err := d.reshare(ctx, s, master, list, refused)
		d.secrets.mu.Lock()
		for fp := range newRefused {
			h.refused[fp] = true
		}
		if err != nil {
			d.log.Warn("re-split not possible", "name", s.Name, "err", err)
		} else if data != nil && (h.pending == nil || !bytes.Equal(data, h.pending)) {
			delete(d.secrets.held, h.pendingKey)
			h.pending, h.pendingKey = data, sha256.Sum256(data)
			d.secrets.held[h.pendingKey] = h
			d.mSecretReshare.Set(s.Name, 1)
			d.log.Info("re-split part A prepared; the next get writes it", "name", s.Name, "serial", list.Serial)
		}
		d.secrets.mu.Unlock()
	}
}

// reshare returns the re-split part A of s for list, or nil if the pins
// need no change, and the instances that refused to be pinned.
func (d *Daemon) reshare(ctx context.Context, s *secret.Sealed, master []byte, list *protocol.AuthorityList, refused map[string]bool) (partA []byte, newRefused map[string]bool, err error) {
	pinned := map[string]int{}
	for i, p := range s.Pins {
		pinned[p.Authority] = i
	}
	kept, candidates := 0, 0
	for _, la := range list.Authorities {
		if _, ok := pinned[la.Key]; ok {
			kept++
		} else if !refused[la.Key] {
			candidates++
		}
	}
	if kept == len(s.Pins) && candidates == 0 {
		return nil, nil, nil
	}
	authorities, _ := d.snapshot()
	client := func(fp string) *authorityClient {
		i := slices.IndexFunc(authorities, func(a *authorityClient) bool { return a.pin == fp })
		if i < 0 {
			return nil
		}
		return authorities[i]
	}

	// The list is not signed by administrators: as many pinned instances
	// as open the secret must serve it.
	confirmed := 0
	for _, p := range s.Pins {
		if a := client(p.Authority); a != nil && list.Lists(p.Authority) {
			if l, err := d.readList(ctx, a); err == nil && l.Serial == list.Serial && l.Same(list) {
				confirmed++
			}
		}
	}
	if confirmed < s.Threshold {
		return nil, nil, fmt.Errorf("%d pinned instances serve list %d, %d needed", confirmed, list.Serial, s.Threshold)
	}

	newRefused = map[string]bool{}
	var targets []secret.Target
	added := 0
	for _, la := range list.Authorities {
		if len(targets) == secret.MaxPins {
			break
		}
		if i, ok := pinned[la.Key]; ok {
			_, S, err := s.Pins[i].ReleaseKeyPayload()
			if err == nil {
				targets = append(targets, secret.Target{Authority: la.Key, ReleaseKey: s.Pins[i].ReleaseKey, Key: S})
			}
			continue
		}
		if refused[la.Key] {
			continue
		}
		r, err := d.Exchange(ctx, la.Key, nil)
		var re *RequestError
		switch {
		case errors.As(err, &re) && (re.Status == http.StatusNotFound || re.Code == protocol.ErrNotResponsible):
			// Not again until the list changes.
			newRefused[la.Key] = true
			continue
		case err != nil:
			d.log.Info("instance not reached for a re-split; tried again in an hour", "name", s.Name, "authority", la.Key, "err", err)
			continue
		case r.TrustDomain != s.TrustDomain:
			newRefused[la.Key] = true
			continue
		}
		targets = append(targets, secret.Target{Authority: r.Authority, ReleaseKey: r.ReleaseKey, Key: r.Key})
		added++
	}
	if added == 0 && len(targets) == len(s.Pins) {
		return nil, newRefused, nil
	}
	if len(targets) < s.Threshold {
		return nil, newRefused, fmt.Errorf("%d instances can be pinned, the threshold is %d; keeping part A", len(targets), s.Threshold)
	}
	n, err := s.Reshare(master, targets)
	if err != nil {
		return nil, newRefused, err
	}
	data, err := n.Marshal()
	return data, newRefused, err
}
