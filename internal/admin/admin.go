// Package admin implements the administrator side of binding changes
// (ADR 0003): one text file per change that the administrators complete,
// sign with their SSH keys and record at a reachable authority, and the
// views of the current bindings.
package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"go.yaml.in/yaml/v3"

	"github.com/DunkelCloud/ergosum/internal/journal"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/protocol"
	"github.com/DunkelCloud/ergosum/internal/sshsig"
	"github.com/DunkelCloud/ergosum/internal/tlspin"
)

// Config is the configuration of the administrator tools.
type Config struct {
	// TrustDomain is the authorities' trust domain; an authority that
	// serves another one is not used.
	TrustDomain string `yaml:"trust_domain"`
	// SignKey is the administrator's key: a public key line or file whose
	// private key the SSH agent holds, or a private key file for
	// ssh-keygen.
	SignKey string `yaml:"sign_key"`
	// Authorities are instances of the trust domain; Expand adds those of
	// their authority list. Reads ask every one and insist that those that
	// answer agree; a change goes to the first reachable one, in order.
	Authorities []Authority `yaml:"authorities"`
	// ReleaseKey is the key "ergosum release sign" signs with, like
	// SignKey. Default: ~/.ssh/ergosum-release.pub.
	ReleaseKey string `yaml:"release_key"`
	// ReleaseSigners is the file of keys that may sign releases
	// (release-signers from the repository). Default on Linux:
	// /etc/ergosum/release-signers.
	ReleaseSigners string `yaml:"release_signers"`
}

// Authority names one authority instance and pins its key.
type Authority struct {
	URL string `yaml:"url"`
	// Key is the instance's key fingerprint, as printed by "ergosum keygen".
	Key string `yaml:"key"`
}

// LoadConfig reads a configuration file.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return Config{}, err
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Validate checks the trust domain and the authorities.
func (c Config) Validate() error {
	if !protocol.ValidDNSName(c.TrustDomain) {
		return fmt.Errorf("trust_domain %q: set the trust domain of the authorities", c.TrustDomain)
	}
	if len(c.Authorities) == 0 {
		return errors.New("no authority configured")
	}
	for _, a := range c.Authorities {
		u, err := url.Parse(a.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("authority url %q must be https://host:port", a.URL)
		}
		if !keys.ValidFingerprint(a.Key) {
			return fmt.Errorf("authority %s: bad key fingerprint %q", a.URL, a.Key)
		}
	}
	return nil
}

// Client talks to the authorities' API with their keys pinned.
type Client struct {
	cfg  Config
	http func(a Authority) *http.Client
}

// NewClient validates the configuration.
func NewClient(cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Client{cfg: cfg, http: func(a Authority) *http.Client {
		return &http.Client{Timeout: 30 * time.Second, CheckRedirect: tlspin.NoRedirect, Transport: &http.Transport{
			TLSClientConfig: tlspin.ClientConfig(nil, tlspin.Fingerprints(a.Key)),
		}}
	}}, nil
}

// errUnreachable marks a failure to talk to one authority; the client
// moves on to the next.
type errUnreachable struct {
	url string
	err error
}

func (e *errUnreachable) Error() string { return e.url + ": " + e.err.Error() }

// reply is one authority's answer.
type reply struct {
	from   string
	status int
	data   []byte
}

// ask sends one request to one authority; an error means that it is
// unreachable or unavailable.
func (c *Client) ask(ctx context.Context, a Authority, method, path string, body []byte) (reply, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(a.URL, "/")+path, rd)
	if err != nil {
		return reply{}, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http(a).Do(req)
	if err != nil {
		return reply{}, &errUnreachable{a.URL, err}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	_ = resp.Body.Close()
	if err != nil {
		return reply{}, &errUnreachable{a.URL, err}
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		return reply{}, &errUnreachable{a.URL, errors.New(http.StatusText(resp.StatusCode))}
	}
	return reply{from: a.URL, status: resp.StatusCode, data: data}, nil
}

// do sends a request to the first reachable authority.
func (c *Client) do(ctx context.Context, method, path string, body []byte) (status int, data []byte, from string, err error) {
	var errs []error
	for _, a := range c.cfg.Authorities {
		r, err := c.ask(ctx, a, method, path, body)
		var eu *errUnreachable
		if errors.As(err, &eu) {
			errs = append(errs, err)
			continue
		}
		if err != nil {
			return 0, nil, "", err
		}
		return r.status, r.data, r.from, nil
	}
	return 0, nil, "", fmt.Errorf("no authority reachable: %w", errors.Join(errs...))
}

// Reach tells which authorities answered a read.
type Reach struct {
	Asked       int
	Answered    []string
	Unreachable []error
}

// every reads path from every authority at once and returns the answers
// of the reachable ones in configuration order; an error means that none
// answered.
func (c *Client) every(ctx context.Context, path string) ([]reply, Reach, error) {
	replies := make([]reply, len(c.cfg.Authorities))
	errs := make([]error, len(c.cfg.Authorities))
	var wg sync.WaitGroup
	for i, a := range c.cfg.Authorities {
		wg.Go(func() { replies[i], errs[i] = c.ask(ctx, a, http.MethodGet, path, nil) })
	}
	wg.Wait()
	reach := Reach{Asked: len(c.cfg.Authorities)}
	var out []reply
	for i, r := range replies {
		var eu *errUnreachable
		switch {
		case errors.As(errs[i], &eu):
			reach.Unreachable = append(reach.Unreachable, errs[i])
		case errs[i] != nil:
			return nil, reach, errs[i]
		default:
			out = append(out, r)
			reach.Answered = append(reach.Answered, r.from)
		}
	}
	if len(out) == 0 {
		return nil, reach, fmt.Errorf("no authority reachable: %w", errors.Join(reach.Unreachable...))
	}
	return out, reach, nil
}

// maxResponse bounds an answer; the list of a few thousand bindings fits.
const maxResponse = 16 << 20

// ErrDisagree is returned when the reachable authorities answer a read
// differently.
var ErrDisagree = errors.New("the authorities disagree")

// lists reads the list from every reachable authority; each must serve the
// configured trust domain, and all must have the same approvals.
func (c *Client) lists(ctx context.Context) ([]*journal.BindingList, []string, Reach, error) {
	replies, reach, err := c.every(ctx, protocol.PathBindings)
	if err != nil {
		return nil, nil, reach, err
	}
	var ls []*journal.BindingList
	var from []string
	for _, r := range replies {
		if r.status != http.StatusOK {
			return nil, nil, reach, fmt.Errorf("%s: %d %s", r.from, r.status, errorDetail(r.data))
		}
		var l journal.BindingList
		if err := json.Unmarshal(r.data, &l); err != nil {
			return nil, nil, reach, fmt.Errorf("%s: %w", r.from, err)
		}
		if err := l.Validate(); err != nil {
			return nil, nil, reach, fmt.Errorf("%s: unusable answer: %w", r.from, err)
		}
		if l.TrustDomain != c.cfg.TrustDomain {
			return nil, nil, reach, fmt.Errorf("%s serves trust domain %s, the configuration names %s", r.from, l.TrustDomain, c.cfg.TrustDomain)
		}
		if len(ls) > 0 && !reflect.DeepEqual(l.Approvals, ls[0].Approvals) {
			return nil, nil, reach, fmt.Errorf("%w on the approvals (%s and %s): their registries differ", ErrDisagree, from[0], r.from)
		}
		ls = append(ls, &l)
		from = append(from, r.from)
	}
	return ls, from, reach, nil
}

// List returns the projection of every identity and the approvals the
// registry demands, as the first reachable authority has them, and the
// identities whose binding the reachable authorities disagree on, which
// happens while replication catches up.
func (c *Client) List(ctx context.Context) (l *journal.BindingList, from string, reach Reach, differ []string, err error) {
	ls, froms, reach, err := c.lists(ctx)
	if err != nil {
		return nil, "", reach, nil, err
	}
	seen := map[string]bool{}
	for _, l := range ls {
		for _, b := range l.Bindings {
			if seen[b.Identity] {
				continue
			}
			seen[b.Identity] = true
			for _, other := range ls {
				if !same(find(other, b.Identity), b) {
					differ = append(differ, b.Identity)
					break
				}
			}
		}
	}
	sort.Strings(differ)
	return ls[0], froms[0], reach, differ, nil
}

// State is what the reachable authorities agree on for one change: the
// list with the approvals and the current binding of the identity.
type State struct {
	List    *journal.BindingList
	From    string           // the first reachable authority
	Current *journal.Binding // nil if the identity has none
	Reach   Reach
}

// State reads the list from every authority and insists that the reachable
// ones agree on the identity's binding.
func (c *Client) State(ctx context.Context, identity string) (*State, error) {
	ls, from, reach, err := c.lists(ctx)
	if err != nil {
		return nil, err
	}
	bs := make([]*journal.Binding, len(ls))
	for i, l := range ls {
		bs[i] = find(l, identity)
	}
	if err := agree(identity, from, bs); err != nil {
		return nil, err
	}
	return &State{List: ls[0], From: from[0], Current: bs[0], Reach: reach}, nil
}

// Current returns the projection of identity, with the administrators who
// approved it, or nil if it has none, as every reachable authority has it.
func (c *Client) Current(ctx context.Context, identity string) (*journal.Binding, Reach, error) {
	replies, reach, err := c.every(ctx, protocol.PathBindings+"/"+identity)
	if err != nil {
		return nil, reach, err
	}
	var bs []*journal.Binding
	var from []string
	for _, r := range replies {
		b, err := binding(r, identity)
		if err != nil {
			return nil, reach, err
		}
		bs = append(bs, b)
		from = append(from, r.from)
	}
	if err := agree(identity, from, bs); err != nil {
		return nil, reach, err
	}
	return bs[0], reach, nil
}

// binding decodes and checks one authority's answer for identity.
func binding(r reply, identity string) (*journal.Binding, error) {
	switch r.status {
	case http.StatusOK:
		var b journal.Binding
		if err := json.Unmarshal(r.data, &b); err != nil {
			return nil, fmt.Errorf("%s: %w", r.from, err)
		}
		if err := b.Validate(); err != nil {
			return nil, fmt.Errorf("%s: unusable answer: %w", r.from, err)
		}
		if b.Identity != identity {
			return nil, fmt.Errorf("%s: unusable answer: asked for %s, got %s", r.from, identity, b.Identity)
		}
		return &b, nil
	case http.StatusNotFound:
		return nil, nil
	default:
		return nil, fmt.Errorf("%s: %d %s", r.from, r.status, errorDetail(r.data))
	}
}

// same reports whether two authorities have the same binding: the same
// event wins at both, or neither has one.
func same(a, b *journal.Binding) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Hash == b.Hash
}

// agree insists that every authority has the same binding.
func agree(identity string, from []string, bs []*journal.Binding) error {
	for i := 1; i < len(bs); i++ {
		if !same(bs[0], bs[i]) {
			return fmt.Errorf("%w on %s: %s has %s, %s has %s. Replication may be catching up: try again shortly. "+
				"If it persists, one of them is wrong; compare them with \"ergosum show -authority URL -authority-key KEY %s\"",
				ErrDisagree, identity, from[0], at(bs[0]), from[i], at(bs[i]), identity)
		}
	}
	return nil
}

// at describes a binding for a comparison.
func at(b *journal.Binding) string {
	if b == nil {
		return "no binding"
	}
	state := "bound"
	if !b.Active() {
		state = "revoked"
	}
	return fmt.Sprintf("epoch %d (%s, event %s/%d)", b.Epoch, state, b.Origin, b.Seq)
}

// Holds reports whether the authority at authority (its URL) has the event
// with hash as the binding of identity: "" if it does, otherwise what it
// has instead.
func (c *Client) Holds(ctx context.Context, authority, identity, hash string) (string, error) {
	for _, a := range c.cfg.Authorities {
		if a.URL != authority {
			continue
		}
		r, err := c.ask(ctx, a, http.MethodGet, protocol.PathBindings+"/"+identity, nil)
		if err != nil {
			return "", err
		}
		b, err := binding(r, identity)
		if err != nil {
			return "", err
		}
		if b != nil && b.Hash == hash {
			return "", nil
		}
		return at(b), nil
	}
	return "", fmt.Errorf("%s is not configured", authority)
}

// Authorities returns the URLs of the configured authorities.
func (c *Client) Authorities() []string {
	out := make([]string, 0, len(c.cfg.Authorities))
	for _, a := range c.cfg.Authorities {
		out = append(out, a.URL)
	}
	return out
}

// SubmitError is an authority's refusal of an event.
type SubmitError struct {
	Authority string
	Status    int
	Code      string
	Detail    string
}

func (e *SubmitError) Error() string {
	return fmt.Sprintf("%s refused the event (%d %s): %s", e.Authority, e.Status, e.Code, e.Detail)
}

// Submit writes an event to the first reachable authority.
func (c *Client) Submit(ctx context.Context, e *journal.BindingEvent) (journal.Receipt, string, error) {
	body, err := json.Marshal(e)
	if err != nil {
		return journal.Receipt{}, "", err
	}
	status, data, from, err := c.do(ctx, http.MethodPost, protocol.PathBindings, body)
	if err != nil {
		return journal.Receipt{}, "", err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		var er protocol.ErrorResponse
		_ = json.Unmarshal(data, &er)
		return journal.Receipt{}, from, &SubmitError{Authority: from, Status: status, Code: printable(er.Error, 64), Detail: printable(er.Detail, maxDetail)}
	}
	var r journal.Receipt
	if err := json.Unmarshal(data, &r); err != nil {
		return r, from, fmt.Errorf("%s: %w", from, err)
	}
	if err := r.Validate(); err != nil {
		return journal.Receipt{}, from, fmt.Errorf("%s: unusable receipt: %w", from, err)
	}
	return r, from, nil
}

func errorDetail(data []byte) string {
	var er protocol.ErrorResponse
	if json.Unmarshal(data, &er) == nil && er.Error != "" {
		return printable(er.Error+" "+er.Detail, maxDetail)
	}
	return printable(string(data), maxDetail)
}

// maxDetail bounds an authority's error text as shown.
const maxDetail = 300

// printable makes text from an authority safe to show on a terminal:
// control characters (escape sequences, line breaks) and bidirectional
// overrides become spaces, invalid UTF-8 the replacement character, and the
// text is cut after limit characters.
func printable(s string, limit int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == limit {
			b.WriteString("...")
			break
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			r = ' '
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// Signer signs canonical text. SSHKeygen is the implementation for
// administrators; tests use their own.
type Signer func(ctx context.Context, canonical []byte) ([]byte, error)

// SSHKeygen signs with "ssh-keygen -Y sign" in namespace ergosum-binding.
// keyFile is a private key, a security key handle (FIDO; ssh-keygen asks
// for the touch), or a public key whose private key is held by ssh-agent.
// The text goes through a temporary file, so that ssh-keygen keeps the
// terminal for passphrase and touch prompts.
func SSHKeygen(program, keyFile string) Signer {
	if program == "" {
		program = "ssh-keygen"
	}
	return func(ctx context.Context, canonical []byte) ([]byte, error) {
		dir, err := os.MkdirTemp("", "ergosum-sign-")
		if err != nil {
			return nil, err
		}
		defer func() { _ = os.RemoveAll(dir) }()
		msg := filepath.Join(dir, "event.txt")
		if err := os.WriteFile(msg, canonical, 0o600); err != nil { //nolint:gosec // our own temporary file
			return nil, err
		}
		cmd := exec.CommandContext(ctx, program, "-Y", "sign", "-f", keyFile, "-n", journal.Namespace, msg) //nolint:gosec // operator-supplied key path
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("%s -Y sign: %w", program, err)
		}
		return os.ReadFile(msg + ".sig") //nolint:gosec // our own temporary file
	}
}

// ErrAlreadySigned is returned by AddSignature when the key has signed the
// event already.
var ErrAlreadySigned = errors.New("this key has signed the event already")

// AddSignature signs the event's canonical text and appends the signature
// after checking it: it must verify over exactly this text, and its key
// must not have signed before.
func AddSignature(ctx context.Context, e *journal.BindingEvent, sign Signer) (string, error) {
	canonical, err := e.Canonical()
	if err != nil {
		return "", err
	}
	signers, err := Signers(e)
	if err != nil {
		return "", err
	}
	sig, err := sign(ctx, canonical)
	if err != nil {
		return "", err
	}
	pub, err := sshsig.Verify(sig, journal.Namespace, canonical)
	if err != nil {
		return "", fmt.Errorf("the new signature does not verify: %w", err)
	}
	fp := sshsig.Fingerprint(pub)
	for _, s := range signers {
		if s == fp {
			return fp, ErrAlreadySigned
		}
	}
	e.Signatures = append(e.Signatures, string(sig))
	return fp, nil
}

// Signers verifies every signature of the event over its canonical text
// and returns the key fingerprints. Whether a key is allowed and the
// threshold is met only the authorities can tell, from their registry.
func Signers(e *journal.BindingEvent) ([]string, error) {
	canonical, err := e.Canonical()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(e.Signatures))
	for i, s := range e.Signatures {
		pub, err := sshsig.Verify([]byte(s), journal.Namespace, canonical)
		if err != nil {
			return nil, fmt.Errorf("signature %d: %w", i+1, err)
		}
		out = append(out, sshsig.Fingerprint(pub))
	}
	return out, nil
}
