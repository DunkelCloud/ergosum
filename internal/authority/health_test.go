package authority

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jt "github.com/DunkelCloud/ergosum/internal/journal/journaltest"
)

// TestHealthDegraded: an instance whose journal maintenance fails still
// answers /healthz with 200, but as degraded, with the step, the error and
// since when; the metric shows it until a maintenance run succeeds.
func TestHealthDegraded(t *testing.T) {
	a := newTestAuthority(t, jt.NewAdmins(t, "alice"))
	ops := a.opsHandler()
	get := func(path string) (int, string) {
		t.Helper()
		rec := httptest.NewRecorder()
		ops.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		body, _ := io.ReadAll(rec.Body)
		return rec.Code, string(body)
	}
	failing := func() string {
		t.Helper()
		_, m := get("/metrics")
		for _, l := range strings.Split(m, "\n") {
			if strings.HasPrefix(l, "machine_identity_journal_maintenance_failing ") {
				return strings.TrimPrefix(l, "machine_identity_journal_maintenance_failing ")
			}
		}
		t.Fatal("no machine_identity_journal_maintenance_failing in /metrics")
		return ""
	}

	if err := a.maintainOnce(context.Background()); err != nil {
		t.Fatalf("maintenance on a fresh journal: %v", err)
	}
	a.recordMaintenance(nil)
	if code, body := get("/healthz"); code != http.StatusOK || body != "ok\n" {
		t.Fatalf("healthy: %d %q", code, body)
	}
	if v := failing(); v != "0" {
		t.Fatalf("maintenance_failing %s while healthy", v)
	}

	first := time.Date(2026, 11, 6, 9, 39, 15, 0, time.UTC)
	a.now = func() time.Time { return first }
	_ = a.store.Close() // every journal access fails from here on
	err := a.maintainOnce(context.Background())
	if err == nil {
		t.Fatal("maintenance on a closed journal succeeded")
	}
	a.recordMaintenance(err)
	a.now = func() time.Time { return first.Add(time.Hour) }
	a.recordMaintenance(errors.New("compaction: disk I/O error (6410)"))
	code, body := get("/healthz")
	want := "degraded: journal maintenance failing since 2026-11-06T09:39:15Z: compaction: disk I/O error (6410)\n"
	if code != http.StatusOK || body != want {
		t.Fatalf("degraded: %d %q, want 200 %q", code, body, want)
	}
	if v := failing(); v != "1" {
		t.Fatalf("maintenance_failing %s while failing", v)
	}

	a.recordMaintenance(nil)
	if code, body := get("/healthz"); code != http.StatusOK || body != "ok\n" {
		t.Fatalf("recovered: %d %q", code, body)
	}
	if v := failing(); v != "0" {
		t.Fatalf("maintenance_failing %s after recovery", v)
	}
}

// TestMaintainOnceNamesTheStep: the error names the step that failed first.
func TestMaintainOnceNamesTheStep(t *testing.T) {
	a := newTestAuthority(t, jt.NewAdmins(t, "alice"))
	_ = a.store.Close()
	err := a.maintainOnce(context.Background())
	if err == nil || !strings.HasPrefix(err.Error(), "journal: ") {
		t.Fatalf("maintenance on a closed journal: %v, want the journal step first", err)
	}
}
