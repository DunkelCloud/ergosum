package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ergosum/internal/admin"
	"github.com/DunkelCloud/ergosum/internal/authority"
	jt "github.com/DunkelCloud/ergosum/internal/journal/journaltest"
	"github.com/DunkelCloud/ergosum/internal/protocol"
)

// listed is one instance in an authorities file.
type listed struct {
	e    *env
	urls []string // default: the instance's URL
}

// writeList writes an authorities file.
func writeList(t *testing.T, path string, serial uint64, instances ...listed) {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "serial: %d\nauthorities:\n", serial)
	for _, l := range instances {
		urls := l.urls
		if urls == nil {
			urls = []string{l.e.url}
		}
		fmt.Fprintf(&b, "  - key: %s\n    urls: [%s]\n", l.e.fingerprint(), strings.Join(urls, ", "))
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	// The authority notices a change by time and size; make the time differ.
	later := time.Now().Add(time.Duration(serial) * time.Second)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
}

func storedSerial(t *testing.T, m *machine) uint64 {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(m.stateDir, "authorities.json"))
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	var l protocol.AuthorityList
	if err := json.Unmarshal(data, &l); err != nil {
		t.Fatal(err)
	}
	return l.Serial
}

func getList(t *testing.T, e *env) (int, *protocol.AuthorityList) {
	t.Helper()
	resp, err := e.apiClient().Get(e.url + protocol.PathAuthorities)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var l protocol.AuthorityList
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&l); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode, &l
}

// TestAuthorityList: a daemon that knows one authority takes the list it
// serves, reaches the others through it, skips a URL that does not answer
// without sending its request twice, takes only higher serials from the
// instances of its list, and takes a list from an authority that its
// configuration names and its list does not.
func TestAuthorityList(t *testing.T) {
	sim := newSimNet()
	admins := jt.NewAdmins(t, "alice", "bob", "carol")
	a := prepareEnv(t, envOptions{instance: "authority-a", net: sim, admins: admins})
	b := prepareEnv(t, envOptions{instance: "authority-b", net: sim, admins: admins})
	c := prepareEnv(t, envOptions{instance: "authority-c", net: sim, admins: admins})
	dir := t.TempDir()
	fa, fb, fc := filepath.Join(dir, "a.yaml"), filepath.Join(dir, "b.yaml"), filepath.Join(dir, "c.yaml")
	dead := "https://" + freePort(t) // nothing listens there
	writeList(t, fa, 1, listed{e: a, urls: []string{dead, a.url}}, listed{e: b})
	writeList(t, fb, 1, listed{e: a, urls: []string{dead, a.url}}, listed{e: b})
	writeList(t, fc, 1, listed{e: c})
	a.cfg.AuthoritiesFile, b.cfg.AuthoritiesFile, c.cfg.AuthoritiesFile = fa, fb, fc
	for _, e := range []*env{a, b, c} {
		e.start()
	}

	// Configured: a and, as a way back, c.
	m := a.machine(host1, machineOptions{targets: []string{at(host1Tailnet)}, authorities: []*env{a, c}, tailnet: host1Tailnet})
	for _, e := range []*env{a, b, c} {
		e.bind(host1, m.d.Fingerprint(), 1, tailnetCheck(host1Tailnet))
	}
	c.stop() // until the configuration has to stand in for the list
	ctx := context.Background()
	if _, _, err := m.d.Obtain(ctx); err != nil {
		t.Fatal(err)
	}
	if got := storedSerial(t, m); got != 1 {
		t.Fatalf("stored serial %d after the first token", got)
	}
	// a is now tried on its first URL, which does not answer.
	if _, _, err := m.d.Obtain(ctx); err != nil {
		t.Fatalf("a on its second URL: %v", err)
	}
	requireCount(t, a.auth, "issued", 2)
	requireCount(t, a.auth, "replay", 0)

	// Through the list, b stands in for a.
	a.stop()
	if _, _, err := m.d.Obtain(ctx); err != nil {
		t.Fatalf("b through the list: %v", err)
	}
	requireCount(t, b.auth, "issued", 1)

	// b serves serial 2; a, back with serial 1, does not undo it.
	writeList(t, fb, 2, listed{e: a}, listed{e: b})
	if _, _, err := m.d.Obtain(ctx); err != nil {
		t.Fatal(err)
	}
	if got := storedSerial(t, m); got != 2 {
		t.Fatalf("stored serial %d, want 2", got)
	}
	b.stop()
	a.start()
	if _, _, err := m.d.Obtain(ctx); err != nil {
		t.Fatal(err)
	}
	if got := storedSerial(t, m); got != 2 {
		t.Fatalf("an instance of the list with a lower serial replaced it: %d", got)
	}

	// c is configured but not in the list: with a down, the daemon reaches
	// it and takes its list, despite the lower serial.
	a.stop()
	c.start()
	if _, _, err := m.d.Obtain(ctx); err != nil {
		t.Fatalf("c, configured: %v", err)
	}
	if got := storedSerial(t, m); got != 1 {
		t.Fatalf("stored serial %d, want c's 1", got)
	}

	// A restarted daemon starts from its stored list.
	m2 := c.machine(host1, machineOptions{stateDir: m.stateDir, targets: []string{at(host1Tailnet)}, authorities: []*env{a}, tailnet: host1Tailnet})
	if _, _, err := m2.d.Obtain(ctx); err != nil {
		t.Fatalf("from the stored list: %v", err)
	}
}

// TestAuthorityListFile: an instance serves its file, reads it again when
// it changes, keeps the last good list if the file turns invalid, refuses
// to start with a file that does not name it, and answers 404 without one.
func TestAuthorityListFile(t *testing.T) {
	sim := newSimNet()
	admins := jt.NewAdmins(t, "alice", "bob", "carol")
	a := prepareEnv(t, envOptions{instance: "authority-a", net: sim, admins: admins})
	b := prepareEnv(t, envOptions{instance: "authority-b", net: sim, admins: admins})
	path := filepath.Join(t.TempDir(), "authorities.yaml")
	writeList(t, path, 1, listed{e: a}, listed{e: b})
	a.cfg.AuthoritiesFile = path
	a.start()
	b.start()

	if code, l := getList(t, a); code != http.StatusOK || l.Serial != 1 || len(l.Authorities) != 2 || l.TrustDomain != trustDomain {
		t.Fatalf("%d %+v", code, l)
	}
	writeList(t, path, 2, listed{e: a})
	if _, l := getList(t, a); l.Serial != 2 || len(l.Authorities) != 1 {
		t.Fatalf("not read again: %+v", l)
	}
	if err := os.WriteFile(path, []byte("serial: 3\nauthorities: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Hour)
	_ = os.Chtimes(path, later, later)
	if _, l := getList(t, a); l.Serial != 2 {
		t.Fatalf("invalid file replaced the list: %+v", l)
	}
	if code, _ := getList(t, b); code != http.StatusNotFound {
		t.Fatalf("without a file: %d", code)
	}

	c := prepareEnv(t, envOptions{instance: "authority-c", net: sim, admins: admins})
	other := filepath.Join(t.TempDir(), "authorities.yaml")
	writeList(t, other, 1, listed{e: a})
	c.cfg.AuthoritiesFile = other
	if _, err := newAuthorityFromEnv(c); err == nil || !strings.Contains(err.Error(), "does not list this instance") {
		t.Fatalf("started with a list without itself: %v", err)
	}
}

// TestAdminExpand: an administrator's tool that knows one authority asks
// the others of its list too, and stops when the lists disagree.
func TestAdminExpand(t *testing.T) {
	sim := newSimNet()
	admins := jt.NewAdmins(t, "alice", "bob", "carol")
	a := prepareEnv(t, envOptions{instance: "authority-a", net: sim, admins: admins})
	b := prepareEnv(t, envOptions{instance: "authority-b", net: sim, admins: admins})
	dir := t.TempDir()
	fa, fb := filepath.Join(dir, "a.yaml"), filepath.Join(dir, "b.yaml")
	writeList(t, fa, 1, listed{e: a}, listed{e: b})
	writeList(t, fb, 1, listed{e: a}, listed{e: b})
	a.cfg.AuthoritiesFile, b.cfg.AuthoritiesFile = fa, fb
	a.start()
	b.start()

	client, err := admin.NewClient(admin.Config{TrustDomain: trustDomain, Authorities: []admin.Authority{{URL: a.url, Key: a.fingerprint()}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	list, added, err := client.Expand(ctx)
	if err != nil || list.Serial != 1 || len(added) != 1 || added[0].Key != b.fingerprint() || added[0].URL != b.url {
		t.Fatalf("list %+v, added %+v, %v", list, added, err)
	}
	if got := client.Authorities(); len(got) != 2 {
		t.Fatalf("authorities after expanding: %v", got)
	}

	writeList(t, fb, 2, listed{e: a}, listed{e: b})
	client, _ = admin.NewClient(admin.Config{TrustDomain: trustDomain, Authorities: []admin.Authority{
		{URL: a.url, Key: a.fingerprint()}, {URL: b.url, Key: b.fingerprint()}}})
	if _, _, err := client.Expand(ctx); !errors.Is(err, admin.ErrDisagree) {
		t.Fatalf("lists with serials 1 and 2: %v", err)
	}
}

// newAuthorityFromEnv creates an instance from an env's configuration
// without starting it.
func newAuthorityFromEnv(e *env) (*authority.Authority, error) {
	a, err := authority.New(e.cfg, authority.Options{Logger: quietLogger(e.t), Network: e.net})
	if err == nil {
		a.Close()
	}
	return a, err
}
