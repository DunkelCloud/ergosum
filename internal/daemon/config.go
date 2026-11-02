package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/protocol"
)

// Config is the daemon configuration (ergosumd.yaml).
type Config struct {
	// Identity is the machine's name (FQDN), e.g. host1.example.com.
	Identity string `yaml:"identity"`
	// StateDir holds the identity key. Default: /var/lib/ergosum, on macOS
	// /var/db/ergosum/state.
	StateDir string `yaml:"state_dir"`
	// TokenFile is written atomically. Default: /run/ergosum/token, on
	// macOS /var/db/ergosum/token.
	TokenFile string `yaml:"token_file"`
	// TokenGroup owns the token file (mode 0640). Default: ergosum-token.
	// Set to "-" to leave the group unchanged.
	TokenGroup string `yaml:"token_group"`
	// MetricsFile is a node_exporter textfile; empty disables it.
	MetricsFile string `yaml:"metrics_file"`
	// CallbackListen is the callback listener address. Default: :7433.
	CallbackListen string `yaml:"callback_listen"`
	// Addresses are the underlay addresses reported in requests. Empty
	// means: all global unicast addresses outside the overlay.
	Addresses []string `yaml:"addresses"`
	// OverlayPrefixes are left out of the detected addresses, as the
	// authority's tailnet prefixes are. Default: 100.64.0.0/10,
	// fd7a:115c:a1e0::/48.
	OverlayPrefixes []string `yaml:"overlay_prefixes"`
	// Authorities are tried in order.
	Authorities []AuthorityConfig `yaml:"authorities"`
	// RequestTimeout bounds one request including its callbacks.
	// Default: 60s.
	RequestTimeout time.Duration `yaml:"request_timeout"`
	// SecretSocket is the local socket of "ergosumd secret" (ADR 0004),
	// mode 0600. Default: secret.sock next to the token file; "-"
	// disables it.
	SecretSocket string `yaml:"secret_socket"`
	// SecretSocketGroup, if set, opens the socket to one group (mode
	// 0660). Every opened secret costs exchanges at the authorities, out
	// of the identity's rate budget.
	SecretSocketGroup string `yaml:"secret_socket_group"`
}

// AuthorityConfig names one authority instance and pins its key.
type AuthorityConfig struct {
	// URL, or URLs in order of preference, reach the instance. The daemon
	// tries only those it can reach from its own addresses (see
	// docs/operations.md).
	URL  string   `yaml:"url"`
	URLs []string `yaml:"urls"`
	// Key is the instance's key fingerprint ("SHA256:...", as printed by
	// "ergosum keygen").
	Key string `yaml:"key"`
}

// LoadConfig reads and validates a YAML configuration file.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return Config{}, err
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	c.SetDefaults()
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// defaultPaths returns the default state directory and token file on goos.
// launchd creates no runtime directory as systemd and OpenRC do, and
// /var/run belongs to root, so on macOS the token stays in a directory of
// its own, next to the state.
func defaultPaths(goos string) (stateDir, tokenFile string) {
	if goos == "darwin" {
		return "/var/db/ergosum/state", "/var/db/ergosum/token"
	}
	return "/var/lib/ergosum", "/run/ergosum/token"
}

// SetDefaults fills unset fields.
func (c *Config) SetDefaults() {
	stateDir, tokenFile := defaultPaths(runtime.GOOS)
	if c.StateDir == "" {
		c.StateDir = stateDir
	}
	if c.TokenFile == "" {
		c.TokenFile = tokenFile
	}
	if c.TokenGroup == "" {
		c.TokenGroup = "ergosum-token"
	}
	if c.CallbackListen == "" {
		c.CallbackListen = fmt.Sprintf(":%d", protocol.DefaultCallbackPort)
	}
	if c.RequestTimeout == 0 {
		c.RequestTimeout = 60 * time.Second
	}
	if c.SecretSocket == "" {
		c.SecretSocket = filepath.Join(filepath.Dir(c.TokenFile), "secret.sock")
	}
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	var errs []error
	if !protocol.ValidDNSName(c.Identity) {
		errs = append(errs, fmt.Errorf("identity %q is not a lower-case FQDN", c.Identity))
	}
	if len(c.Authorities) == 0 {
		errs = append(errs, errors.New("at least one authority is required"))
	}
	for i, a := range c.Authorities {
		if err := protocol.ValidateAuthorityURLs(a.urls()); err != nil {
			errs = append(errs, fmt.Errorf("authorities[%d]: %w", i, err))
		}
		if !keys.ValidFingerprint(a.Key) {
			errs = append(errs, fmt.Errorf("authorities[%d]: key %q is no key fingerprint (SHA256: and 43 characters of base64, as ergosum keygen prints it)", i, a.Key))
		}
	}
	if _, err := protocol.ParseAddresses(c.Addresses); err != nil {
		errs = append(errs, err)
	}
	if _, err := protocol.ParsePrefixes(c.OverlayPrefixes); err != nil {
		errs = append(errs, fmt.Errorf("overlay_prefixes: %w", err))
	}
	return errors.Join(errs...)
}

// urls returns URL and URLs as one list.
func (a AuthorityConfig) urls() []string {
	if a.URL == "" {
		return a.URLs
	}
	return append([]string{a.URL}, a.URLs...)
}
