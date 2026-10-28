// Package admin implements the administrator side of binding changes:
// building a binding event from the current epoch, signing its canonical
// text with ssh-keygen, merging the signatures of several administrators
// and writing the event to a reachable authority (ADR 0003).
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
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/DunkelCloud/ergosum/internal/journal"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/protocol"
	"github.com/DunkelCloud/ergosum/internal/sshsig"
	"github.com/DunkelCloud/ergosum/internal/tlspin"
)

// Config is the configuration of the administrator tools.
type Config struct {
	// TrustDomain of new events.
	TrustDomain string `yaml:"trust_domain"`
	// Authorities are tried in order, as by the daemon.
	Authorities []Authority `yaml:"authorities"`
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

// Validate checks the authorities.
func (c Config) Validate() error {
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
		return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
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

func (c *Client) do(ctx context.Context, method, path string, body []byte) (status int, data []byte, from string, err error) {
	var errs []error
	for _, a := range c.cfg.Authorities {
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, rerr := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(a.URL, "/")+path, rd)
		if rerr != nil {
			return 0, nil, "", rerr
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, rerr := c.http(a).Do(req)
		if rerr != nil {
			errs = append(errs, &errUnreachable{a.URL, rerr})
			continue
		}
		data, rerr = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if rerr != nil {
			errs = append(errs, &errUnreachable{a.URL, rerr})
			continue
		}
		if resp.StatusCode == http.StatusServiceUnavailable {
			errs = append(errs, &errUnreachable{a.URL, errors.New(resp.Status)})
			continue
		}
		return resp.StatusCode, data, a.URL, nil
	}
	return 0, nil, "", fmt.Errorf("no authority reachable: %w", errors.Join(errs...))
}

// Current returns the projection of identity at the first reachable
// authority, or nil if it has none.
func (c *Client) Current(ctx context.Context, identity string) (*journal.Binding, error) {
	status, data, from, err := c.do(ctx, http.MethodGet, protocol.PathBindings+"/"+identity, nil)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusOK:
		var b journal.Binding
		if err := json.Unmarshal(data, &b); err != nil {
			return nil, fmt.Errorf("%s: %w", from, err)
		}
		return &b, nil
	case http.StatusNotFound:
		return nil, nil
	default:
		return nil, fmt.Errorf("%s: %d %s", from, status, errorDetail(data))
	}
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
		return journal.Receipt{}, from, &SubmitError{Authority: from, Status: status, Code: er.Error, Detail: er.Detail}
	}
	var r journal.Receipt
	if err := json.Unmarshal(data, &r); err != nil {
		return r, from, fmt.Errorf("%s: %w", from, err)
	}
	return r, from, nil
}

func errorDetail(data []byte) string {
	var er protocol.ErrorResponse
	if json.Unmarshal(data, &er) == nil && er.Error != "" {
		return strings.TrimSpace(er.Error + " " + er.Detail)
	}
	return strings.TrimSpace(string(data))
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
		if err := os.WriteFile(msg, canonical, 0o600); err != nil {
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

// Merge combines the signatures of copies of one event, signed separately.
// All copies must have the same canonical text; a key that signed several
// copies counts once.
func Merge(events ...*journal.BindingEvent) (*journal.BindingEvent, error) {
	if len(events) == 0 {
		return nil, errors.New("nothing to merge")
	}
	want, err := events[0].Canonical()
	if err != nil {
		return nil, err
	}
	out := *events[0]
	out.Signatures = nil
	seen := map[string]bool{}
	for i, e := range events {
		c, err := e.Canonical()
		if err != nil {
			return nil, fmt.Errorf("event %d: %w", i+1, err)
		}
		if !bytes.Equal(c, want) {
			return nil, fmt.Errorf("event %d is a different event:\n%s", i+1, c)
		}
		fps, err := Signers(e)
		if err != nil {
			return nil, fmt.Errorf("event %d: %w", i+1, err)
		}
		for j, fp := range fps {
			if !seen[fp] {
				seen[fp] = true
				out.Signatures = append(out.Signatures, e.Signatures[j])
			}
		}
	}
	return &out, nil
}

// ReadEvent reads an event file as written by bind, revoke or sign.
func ReadEvent(path string) (*journal.BindingEvent, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, err
	}
	var e journal.BindingEvent
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if e.Signatures == nil {
		e.Signatures = []string{}
	}
	return &e, nil
}

// WriteEvent writes an event file (indented JSON, mode 0644: it holds no
// secret).
func WriteEvent(path string, e *journal.BindingEvent) error {
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if path == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}
	return keys.WriteFileAtomic(path, data, 0o644)
}

// ParseCheck parses "type:target", e.g. "tailnet:host1.tailnet.example.com",
// "ip:192.0.2.10", "ip:[2001:db8::10]:7440" or "net:198.51.100.0/24".
func ParseCheck(s string) (journal.Check, error) {
	typ, target, ok := strings.Cut(s, ":")
	if !ok || typ == "" || target == "" {
		return journal.Check{}, fmt.Errorf("check %q: want type:target", s)
	}
	return journal.Check{Type: typ, Target: target}, nil
}

// NewEvent builds an unsigned event for identity at the epoch after the
// current one (1 if the identity is new), unless epoch is set.
func NewEvent(ctx context.Context, c *Client, kind, trustDomain, identity string, epoch uint64, key string, checks []journal.Check) (*journal.BindingEvent, *journal.Binding, error) {
	var cur *journal.Binding
	if epoch == 0 {
		if c == nil {
			return nil, nil, errors.New("no authority to read the current epoch from; configure one or give -epoch")
		}
		var err error
		if cur, err = c.Current(ctx, identity); err != nil {
			return nil, nil, err
		}
		epoch = 1
		if cur != nil {
			epoch = cur.Epoch + 1
		}
	}
	e := &journal.BindingEvent{V: 1, Kind: kind, TrustDomain: trustDomain, Identity: identity, Epoch: epoch, Key: key, Checks: checks, Signatures: []string{}}
	if err := e.Validate(); err != nil {
		return nil, cur, err
	}
	return e, cur, nil
}
