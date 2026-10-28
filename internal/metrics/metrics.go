// Package metrics is a minimal Prometheus text exposition for a handful of
// counters and gauges, used for the authority's /metrics endpoint and the
// daemon's node_exporter textfile. It avoids a client library dependency in
// security-critical binaries.
package metrics

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"sync"
)

// Registry holds metric families in registration order.
type Registry struct {
	mu       sync.Mutex
	families []*Vec
	collect  []func()
}

// Vec is a metric family with at most one label.
type Vec struct {
	r      *Registry
	name   string
	help   string
	typ    string
	label  string
	values map[string]float64
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

func (r *Registry) add(name, help, typ, label string, preset []string) *Vec {
	v := &Vec{r: r, name: name, help: help, typ: typ, label: label, values: map[string]float64{}}
	for _, p := range preset {
		v.values[p] = 0
	}
	if label == "" {
		v.values[""] = 0
	}
	r.mu.Lock()
	r.families = append(r.families, v)
	r.mu.Unlock()
	return v
}

// Counter registers a counter. With a label, preset label values are
// exported as 0 from the start.
func (r *Registry) Counter(name, help, label string, preset ...string) *Vec {
	return r.add(name, help, "counter", label, preset)
}

// Gauge registers a gauge without labels.
func (r *Registry) Gauge(name, help string) *Vec {
	return r.add(name, help, "gauge", "", nil)
}

// GaugeVec registers a gauge with one label.
func (r *Registry) GaugeVec(name, help, label string) *Vec {
	return r.add(name, help, "gauge", label, nil)
}

// OnCollect registers a function that updates gauges before every
// exposition.
func (r *Registry) OnCollect(f func()) {
	r.mu.Lock()
	r.collect = append(r.collect, f)
	r.mu.Unlock()
}

// Inc adds 1 for the label value (use "" for unlabeled metrics).
func (v *Vec) Inc(label string) { v.Add(label, 1) }

// Add adds d for the label value.
func (v *Vec) Add(label string, d float64) {
	v.r.mu.Lock()
	v.values[label] += d
	v.r.mu.Unlock()
}

// Set sets the value for the label value.
func (v *Vec) Set(label string, x float64) {
	v.r.mu.Lock()
	v.values[label] = x
	v.r.mu.Unlock()
}

// Get returns the value for the label value.
func (v *Vec) Get(label string) float64 {
	v.r.mu.Lock()
	defer v.r.mu.Unlock()
	return v.values[label]
}

// Write writes the text exposition format.
func (r *Registry) Write(w io.Writer) error {
	r.mu.Lock()
	collect := append([]func(){}, r.collect...)
	r.mu.Unlock()
	for _, f := range collect {
		f()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var b bytes.Buffer
	for _, f := range r.families {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", f.name, f.help, f.name, f.typ)
		labels := make([]string, 0, len(f.values))
		for l := range f.values {
			labels = append(labels, l)
		}
		sort.Strings(labels)
		for _, l := range labels {
			if f.label == "" {
				fmt.Fprintf(&b, "%s %s\n", f.name, format(f.values[l]))
			} else {
				fmt.Fprintf(&b, "%s{%s=%q} %s\n", f.name, f.label, l, format(f.values[l]))
			}
		}
	}
	_, err := w.Write(b.Bytes())
	return err
}

func format(x float64) string {
	if x == math.Trunc(x) && math.Abs(x) < 1e15 {
		return strconv.FormatFloat(x, 'f', 0, 64)
	}
	return strconv.FormatFloat(x, 'g', -1, 64)
}

// Handler serves the registry in the text exposition format.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = r.Write(w)
	})
}
