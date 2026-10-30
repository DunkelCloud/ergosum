package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/DunkelCloud/ergosum/internal/admin"
	"github.com/DunkelCloud/ergosum/internal/journal"
	jt "github.com/DunkelCloud/ergosum/internal/journal/journaltest"
	"github.com/DunkelCloud/ergosum/internal/protocol"
	"github.com/DunkelCloud/ergosum/internal/sshsig"
)

// fakeAuthority answers the read and write API with what the test sets. A
// recorded event becomes the binding at the authority and its replicas at
// once.
type fakeAuthority struct {
	list     *journal.BindingList
	binding  *journal.Binding // nil: not bound; the same as in list
	status   int              // of a submit
	answer   any              // of a submit; nil: the receipt of the event
	replicas []*fakeAuthority
}

func (f *fakeAuthority) RoundTrip(r *http.Request) (*http.Response, error) {
	status, body := http.StatusOK, any(nil)
	switch {
	case r.Method == http.MethodPost:
		var e journal.BindingEvent
		if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
			return nil, err
		}
		h, err := e.Hash()
		if err != nil {
			return nil, err
		}
		status, body = f.status, f.answer
		if body == nil {
			body = journal.Receipt{Origin: "authority-a", Seq: 8, Hash: h}
		}
		if status == http.StatusCreated {
			b := &journal.Binding{Identity: e.Identity, Kind: e.Kind, Epoch: e.Epoch, Key: e.Key, Checks: e.SortedChecks(), Hash: h, Origin: "authority-a", Seq: 8}
			for _, g := range f.replicas {
				g.set(b)
			}
		}
	case r.URL.Path == protocol.PathBindings:
		body = f.list
	case f.binding == nil:
		status, body = http.StatusNotFound, protocol.ErrorResponse{Error: "not_found"}
	default:
		body = f.binding
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(data)), Request: r}, nil
}

// set makes b the binding of its identity.
func (f *fakeAuthority) set(b *journal.Binding) {
	f.binding = b
	for i, old := range f.list.Bindings {
		if old.Identity == b.Identity {
			f.list.Bindings[i] = b
			return
		}
	}
	f.list.Bindings = append(f.list.Bindings, b)
}

// down is an authority that cannot be reached.
type down struct{}

func (down) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection refused")
}

const host1 = "host1.example.com"

func hash(t *testing.T, e *journal.BindingEvent) string {
	t.Helper()
	h, err := e.Hash()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// fakes is alice's tool against fake authorities.
type fakes struct {
	tool   *admin.Tool
	auth   []*fakeAuthority
	urls   []string
	routes map[string]http.RoundTripper
	out    *bytes.Buffer
}

// fakeCluster sets up n fake authorities that agree and replicate to each
// other: alice alone approves, host1 is bound at epoch 1, and a submit is
// recorded.
func fakeCluster(t *testing.T, n int) *fakes {
	t.Helper()
	admins := jt.NewAdmins(t, "alice")
	s := admins.Signers["alice"]
	e := event(t)
	e.Epoch = 1
	c := &fakes{routes: map[string]http.RoundTripper{}, out: &bytes.Buffer{}}
	cfg := admin.Config{TrustDomain: "example.com"}
	for i := range n {
		ap := journal.Approval{Threshold: 1, Admins: map[string]string{"alice": sshsig.Fingerprint(s.PublicKey())}}
		b := &journal.Binding{Identity: host1, Kind: e.Kind, Epoch: 1, Key: e.Key, Checks: e.Checks,
			Hash: hash(t, e), Origin: "authority-a", Seq: 7, SignedBy: []string{"alice"}}
		f := &fakeAuthority{
			list: &journal.BindingList{V: 1, TrustDomain: "example.com", Bindings: []*journal.Binding{b},
				Approvals: map[string]journal.Approval{journal.KindBindingSet: ap, journal.KindBindingRevoked: ap}},
			binding: b,
			status:  http.StatusCreated,
		}
		u := fmt.Sprintf("https://authority-%c.example.com:7432", 'a'+i)
		cfg.Authorities = append(cfg.Authorities, admin.Authority{URL: u, Key: fingerprint(t)})
		c.routes[u] = f
		c.auth = append(c.auth, f)
		c.urls = append(c.urls, u)
	}
	for _, f := range c.auth {
		f.replicas = c.auth
	}
	client, err := admin.NewClientRoutes(cfg, c.routes)
	if err != nil {
		t.Fatal(err)
	}
	c.tool = &admin.Tool{Client: client, Out: c.out, Key: &admin.SignKey{Public: s.PublicKey(), Sign: signerOf(s)}}
	return c
}

// fakeTool is alice's tool against one fake authority.
func fakeTool(t *testing.T) (*admin.Tool, *fakeAuthority, *bytes.Buffer) {
	t.Helper()
	c := fakeCluster(t, 1)
	return c.tool, c.auth[0], c.out
}

// requestFile writes a request for host1 with a new key.
func requestFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "host1.txt")
	if err := os.WriteFile(path, []byte("identity "+host1+"\nkey "+fingerprint(t)+"\ncheck tailnet host1.tailnet.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func requireNoControl(t *testing.T, s string) {
	t.Helper()
	for _, r := range s {
		if r != '\n' && (unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r)) {
			t.Fatalf("control character %U reaches the administrator: %q", r, s)
		}
	}
}

// Whatever an authority answers reaches the terminal and the files only in
// its plain form: a value with a line break, an escape sequence or a
// direction override is refused, and error texts are cleaned and cut.
func TestAnswersFromAuthorities(t *testing.T) {
	ctx := context.Background()
	bad := []struct {
		name  string
		spoil func(f *fakeAuthority)
	}{
		{"trust domain with a line", func(f *fakeAuthority) { f.list.TrustDomain = "example.com\ncheck ip 203.0.113.9" }},
		{"administrator with an escape", func(f *fakeAuthority) {
			f.list.Approvals[journal.KindBindingSet].Admins["\x1b[2Jmallory"] = fingerprint(t)
		}},
		{"origin with a line", func(f *fakeAuthority) { f.binding.Origin = "authority-a\ncheck ip 203.0.113.9" }},
		{"check with a line", func(f *fakeAuthority) {
			f.binding.Checks = []journal.Check{{Type: "tailnet", Target: "host1.tailnet.example.com\nkey " + fingerprint(t)}}
		}},
		{"signer with an override", func(f *fakeAuthority) { f.binding.SignedBy = []string{"‮alice"} }},
		{"key that is none", func(f *fakeAuthority) { f.binding.Key = "SHA256:x\x1b]0;owned\x07" }},
	}
	for _, c := range bad {
		tool, f, out := fakeTool(t)
		c.spoil(f)
		var w bytes.Buffer
		err := tool.List(ctx, &w)
		if err == nil || !strings.Contains(err.Error(), "unusable answer") {
			t.Fatalf("%s: list gave %v", c.name, err)
		}
		if c.name != "trust domain with a line" && c.name != "administrator with an escape" {
			if err := tool.Show(ctx, host1, &w); err == nil || !strings.Contains(err.Error(), "unusable answer") {
				t.Fatalf("%s: show gave %v", c.name, err)
			}
		}
		requireNoControl(t, err.Error())
		if w.Len() != 0 || out.Len() != 0 {
			t.Fatalf("%s: shown anyway:\n%s%s", c.name, &w, out)
		}
	}

	// Asked for one identity, answered with another.
	tool, f, _ := fakeTool(t)
	f.binding.Identity = "host2.example.com"
	if err := tool.Show(ctx, host1, io.Discard); err == nil || !strings.Contains(err.Error(), "asked for "+host1) {
		t.Fatalf("show of another identity: %v", err)
	}

	// A signer the registry no longer knows is named by its fingerprint.
	tool, f, _ = fakeTool(t)
	f.binding.SignedBy = append(f.binding.SignedBy, fingerprint(t))
	if err := tool.Show(ctx, host1, io.Discard); err != nil {
		t.Fatalf("signer by fingerprint: %v", err)
	}

	// A receipt with a line in it is refused and stays out of the file.
	tool, f, _ = fakeTool(t)
	f.answer = journal.Receipt{Origin: "authority-a\ncheck ip 203.0.113.9", Seq: 8, Hash: strings.Repeat("ab", 32)}
	path := requestFile(t)
	if err := tool.Bind(ctx, path); err == nil || !strings.Contains(err.Error(), "unusable receipt") {
		t.Fatalf("bad receipt: %v", err)
	}
	if data, _ := os.ReadFile(path); strings.Contains(string(data), "203.0.113.9") { //nolint:gosec // test file
		t.Fatalf("receipt written to the file:\n%s", data)
	}

	// A refusal's text is cleaned and cut.
	tool, f, _ = fakeTool(t)
	f.status = http.StatusForbidden
	f.answer = protocol.ErrorResponse{Error: "denied\x1b[2J", Detail: "\x1b]0;owned\x07\n" + strings.Repeat("x", 5000)}
	err := tool.Bind(ctx, path)
	if err == nil {
		t.Fatal("refusal not reported")
	}
	requireNoControl(t, err.Error())
	if len(err.Error()) > 600 {
		t.Fatalf("refusal of %d bytes shown", len(err.Error()))
	}
}

// The text to sign is the last thing shown before the question, so that
// nothing printed after it can stand in for it.
func TestTextToSignComesLast(t *testing.T) {
	ctx := context.Background()
	tool, _, out := fakeTool(t)
	path := requestFile(t)
	var before string
	tool.Confirm = func(string) error {
		before = out.String()
		return nil
	}
	if err := tool.Bind(ctx, path); err != nil {
		t.Fatal(err)
	}
	tail := "Text to sign:\n    " + journal.CanonicalHeader + "\n    kind binding.set\n    trust-domain example.com\n    identity " + host1 + "\n    epoch 2\n"
	if !strings.Contains(before, tail) || !strings.HasSuffix(before, "    check tailnet host1.tailnet.example.com\n") {
		t.Fatalf("the text to sign is not last:\n%s", before)
	}
	if !strings.Contains(out.String(), "Recorded by") {
		t.Fatalf("not recorded:\n%s", out)
	}
}

// Reads ask every authority, and those that answer must agree on the trust
// domain, the approvals and the binding; a change goes ahead with one
// authority down, with a warning, and the others are asked afterwards
// whether they have it.
func TestAuthoritiesMustAgree(t *testing.T) {
	ctx := context.Background()
	wait := *admin.ReadBackWait
	*admin.ReadBackWait = 300 * time.Millisecond
	t.Cleanup(func() { *admin.ReadBackWait = wait })
	said := func(c *fakes, want ...string) {
		t.Helper()
		for _, w := range want {
			if !strings.Contains(c.out.String(), w) {
				t.Fatalf("output lacks %q:\n%s", w, c.out)
			}
		}
	}

	if _, err := admin.NewClient(admin.Config{Authorities: []admin.Authority{{URL: "https://authority-a.example.com:7432", Key: fingerprint(t)}}}); err == nil {
		t.Fatal("configuration without a trust domain accepted")
	}

	c := fakeCluster(t, 2)
	if err := c.tool.Bind(ctx, requestFile(t)); err != nil {
		t.Fatal(err)
	}
	said(c, "Recorded by "+c.urls[0], c.urls[1]+" has it.")
	if strings.Contains(c.out.String(), "Warning") {
		t.Fatalf("warning with every authority reachable:\n%s", c.out)
	}

	// Another binding at B stops bind and show; list names the identity.
	c = fakeCluster(t, 2)
	other := *c.auth[1].binding
	other.Epoch, other.Hash = 2, strings.Repeat("cd", 32)
	c.auth[1].set(&other)
	if err := c.tool.Bind(ctx, requestFile(t)); !errors.Is(err, admin.ErrDisagree) || !strings.Contains(err.Error(), "epoch 2") {
		t.Fatalf("bind with another binding at B: %v", err)
	}
	if err := c.tool.Show(ctx, host1, io.Discard); !errors.Is(err, admin.ErrDisagree) {
		t.Fatalf("show with another binding at B: %v", err)
	}
	if err := c.tool.List(ctx, io.Discard); err != nil {
		t.Fatal(err)
	}
	said(c, "disagree on "+host1)

	// No binding at B.
	c = fakeCluster(t, 2)
	c.auth[1].binding, c.auth[1].list.Bindings = nil, nil
	if err := c.tool.Bind(ctx, requestFile(t)); !errors.Is(err, admin.ErrDisagree) || !strings.Contains(err.Error(), "no binding") {
		t.Fatalf("bind without a binding at B: %v", err)
	}

	// B serves another trust domain.
	c = fakeCluster(t, 2)
	c.auth[1].list.TrustDomain = "other.example"
	if err := c.tool.Bind(ctx, requestFile(t)); err == nil || !strings.Contains(err.Error(), "serves trust domain other.example") {
		t.Fatalf("bind with another trust domain at B: %v", err)
	}

	// B has other approvals.
	c = fakeCluster(t, 2)
	ap := c.auth[1].list.Approvals[journal.KindBindingSet]
	ap.Admins = map[string]string{"alice": ap.Admins["alice"], "mallory": fingerprint(t)}
	c.auth[1].list.Approvals[journal.KindBindingSet] = ap
	if err := c.tool.Bind(ctx, requestFile(t)); !errors.Is(err, admin.ErrDisagree) || !strings.Contains(err.Error(), "approvals") {
		t.Fatalf("bind with other approvals at B: %v", err)
	}

	// B is down: the change goes ahead with a warning.
	c = fakeCluster(t, 2)
	c.routes[c.urls[1]] = down{}
	if err := c.tool.Bind(ctx, requestFile(t)); err != nil {
		t.Fatal(err)
	}
	said(c, "Warning: only "+c.urls[0]+" answered", c.urls[1]+" does not have it yet: no answer")

	// B does not receive the event: the read-back says so.
	c = fakeCluster(t, 2)
	c.auth[0].replicas = c.auth[:1]
	if err := c.tool.Bind(ctx, requestFile(t)); err != nil {
		t.Fatal(err)
	}
	said(c, c.urls[1]+" does not have it yet: epoch 1 (bound")

	// A receipt for another event is no record.
	c = fakeCluster(t, 1)
	c.auth[0].answer = journal.Receipt{Origin: "authority-a", Seq: 8, Hash: strings.Repeat("ab", 32)}
	if err := c.tool.Bind(ctx, requestFile(t)); err == nil || !strings.Contains(err.Error(), "receipt for another event") {
		t.Fatalf("receipt for another event: %v", err)
	}
}
