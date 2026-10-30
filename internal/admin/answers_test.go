package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"github.com/DunkelCloud/ergosum/internal/admin"
	"github.com/DunkelCloud/ergosum/internal/journal"
	jt "github.com/DunkelCloud/ergosum/internal/journal/journaltest"
	"github.com/DunkelCloud/ergosum/internal/protocol"
	"github.com/DunkelCloud/ergosum/internal/sshsig"
)

// fakeAuthority answers the read and write API with what the test sets.
type fakeAuthority struct {
	list    *journal.BindingList
	binding *journal.Binding // nil: not bound
	status  int              // of a submit
	answer  any              // of a submit
}

func (f *fakeAuthority) RoundTrip(r *http.Request) (*http.Response, error) {
	status, body := http.StatusOK, any(nil)
	switch {
	case r.Method == http.MethodPost:
		status, body = f.status, f.answer
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

const host1 = "host1.example.com"

func hash(t *testing.T, e *journal.BindingEvent) string {
	t.Helper()
	h, err := e.Hash()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// fakeTool is alice's tool against one fake authority, where alice alone
// approves, host1 is bound at epoch 1 and a submit is recorded.
func fakeTool(t *testing.T) (*admin.Tool, *fakeAuthority, *bytes.Buffer) {
	t.Helper()
	admins := jt.NewAdmins(t, "alice")
	s := admins.Signers["alice"]
	ap := journal.Approval{Threshold: 1, Admins: map[string]string{"alice": sshsig.Fingerprint(s.PublicKey())}}
	e := event(t)
	e.Epoch = 1
	b := &journal.Binding{Identity: host1, Kind: e.Kind, Epoch: 1, Key: e.Key, Checks: e.Checks,
		Hash: hash(t, e), Origin: "authority-a", Seq: 7, SignedBy: []string{"alice"}}
	f := &fakeAuthority{
		list: &journal.BindingList{V: 1, TrustDomain: "example.com", Bindings: []*journal.Binding{b},
			Approvals: map[string]journal.Approval{journal.KindBindingSet: ap, journal.KindBindingRevoked: ap}},
		binding: b,
		status:  http.StatusCreated,
		answer:  journal.Receipt{Origin: "authority-a", Seq: 8, Hash: strings.Repeat("ab", 32)},
	}
	client, err := admin.NewClientWith(admin.Config{Authorities: []admin.Authority{{URL: "https://authority-a.example.com:7432", Key: fingerprint(t)}}}, f)
	if err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	return &admin.Tool{Client: client, Out: out, Key: &admin.SignKey{Public: s.PublicKey(), Sign: signerOf(s)}}, f, out
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
	path := filepath.Join(t.TempDir(), "host1.txt")
	if err := os.WriteFile(path, []byte("identity "+host1+"\nkey "+fingerprint(t)+"\ncheck tailnet host1.tailnet.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
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
	path := filepath.Join(t.TempDir(), "host1.txt")
	if err := os.WriteFile(path, []byte("identity "+host1+"\nkey "+fingerprint(t)+"\ncheck tailnet host1.tailnet.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
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
