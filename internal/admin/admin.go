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
	"strings"
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
	// TrustDomain, if set, must be the authorities' trust domain; events
	// take it from the authority.
	TrustDomain string `yaml:"trust_domain"`
	// SignKey is the administrator's key: a public key line or file whose
	// private key the SSH agent holds, or a private key file for
	// ssh-keygen.
	SignKey string `yaml:"sign_key"`
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
		data, rerr = io.ReadAll(io.LimitReader(resp.Body, maxResponse))
		_ = resp.Body.Close()
		if rerr != nil {
			errs = append(errs, &errUnreachable{a.URL, rerr})
			continue
		}
		if resp.StatusCode == http.StatusServiceUnavailable {
			errs = append(errs, &errUnreachable{a.URL, errors.New(http.StatusText(resp.StatusCode))})
			continue
		}
		return resp.StatusCode, data, a.URL, nil
	}
	return 0, nil, "", fmt.Errorf("no authority reachable: %w", errors.Join(errs...))
}

// maxResponse bounds an answer; the list of a few thousand bindings fits.
const maxResponse = 16 << 20

// List returns the projection of every identity and the approvals the
// registry demands, from the first reachable authority.
func (c *Client) List(ctx context.Context) (*journal.BindingList, string, error) {
	status, data, from, err := c.do(ctx, http.MethodGet, protocol.PathBindings, nil)
	if err != nil {
		return nil, "", err
	}
	if status != http.StatusOK {
		return nil, from, fmt.Errorf("%s: %d %s", from, status, errorDetail(data))
	}
	var l journal.BindingList
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, from, fmt.Errorf("%s: %w", from, err)
	}
	if err := l.Validate(); err != nil {
		return nil, from, fmt.Errorf("%s: unusable answer: %w", from, err)
	}
	return &l, from, nil
}

// Current returns the projection of identity at the first reachable
// authority, with the administrators who approved it, or nil if it has
// none.
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
		if err := b.Validate(); err != nil {
			return nil, fmt.Errorf("%s: unusable answer: %w", from, err)
		}
		if b.Identity != identity {
			return nil, fmt.Errorf("%s: unusable answer: asked for %s, got %s", from, identity, b.Identity)
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
// text is cut after max characters.
func printable(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == max {
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
