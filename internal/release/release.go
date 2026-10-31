// Package release checks signed releases: SHA256SUMS over the release
// files, and SHA256SUMS.sig, an SSH signature over it in the namespace
// ergosum-release by a key listed in release-signers (the ALLOWED SIGNERS
// format of ssh-keygen). deploy/install.sh checks the same with ssh-keygen.
package release

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/DunkelCloud/ergosum/internal/sshsig"
)

const (
	// Namespace of release signatures.
	Namespace = "ergosum-release"
	// Principal that release keys carry in release-signers.
	Principal = "release"
	// SumsFile is the file of checksums.
	SumsFile = "SHA256SUMS"
	// SigFile is the signature over SumsFile.
	SigFile = "SHA256SUMS.sig"
)

// Signer is one line of release-signers.
type Signer struct {
	Principals []string
	// Namespaces the key may sign in; empty means any.
	Namespaces []string
	Key        ssh.PublicKey
}

// Allows reports whether the line lets its key sign releases.
func (s *Signer) Allows(principal, namespace string) bool {
	match := false
	for _, p := range s.Principals {
		if ok, _ := path.Match(p, principal); ok {
			match = true
		}
	}
	if !match {
		return false
	}
	if len(s.Namespaces) == 0 {
		return true
	}
	for _, n := range s.Namespaces {
		if ok, _ := path.Match(n, namespace); ok {
			return true
		}
	}
	return false
}

// ParseSigners reads release-signers. Of the options it knows namespaces;
// a line with another option (cert-authority, valid-after, valid-before)
// is refused rather than read without it.
func ParseSigners(data []byte) ([]Signer, error) {
	var out []Signer
	for i, line := range strings.Split(strings.TrimPrefix(string(data), "\xEF\xBB\xBF"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return nil, fmt.Errorf("release signers line %d: want principals, options and a key", i+1)
		}
		s := Signer{Principals: strings.Split(fields[0], ",")}
		rest := fields[1:]
		if !isKeyType(rest[0]) {
			ns, err := parseOptions(rest[0])
			if err != nil {
				return nil, fmt.Errorf("release signers line %d: %w", i+1, err)
			}
			s.Namespaces = ns
			rest = rest[1:]
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.Join(rest, " ")))
		if err != nil {
			return nil, fmt.Errorf("release signers line %d: %w", i+1, err)
		}
		s.Key = key
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, errors.New("release signers: no key")
	}
	return out, nil
}

func isKeyType(s string) bool {
	return strings.HasPrefix(s, "ssh-") || strings.HasPrefix(s, "ecdsa-") || strings.HasPrefix(s, "sk-")
}

// parseOptions returns the namespaces of an options field such as
// namespaces="ergosum-release".
func parseOptions(field string) ([]string, error) {
	var ns []string
	for _, opt := range splitOptions(field) {
		name, value, _ := strings.Cut(opt, "=")
		if !strings.EqualFold(name, "namespaces") {
			return nil, fmt.Errorf("option %q is not supported", name)
		}
		value = strings.Trim(value, `"`)
		if value == "" {
			return nil, errors.New("empty namespaces option")
		}
		ns = append(ns, strings.Split(value, ",")...)
	}
	return ns, nil
}

// splitOptions splits at commas outside double quotes.
func splitOptions(s string) []string {
	var out []string
	quoted, start := false, 0
	for i, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
		case r == ',' && !quoted:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// Verify checks sig over sums and returns the release-signers line of the
// key that made it.
func Verify(sums, sig []byte, signers []Signer) (*Signer, error) {
	key, err := sshsig.Verify(sig, Namespace, sums)
	if err != nil {
		return nil, err
	}
	want := key.Marshal()
	for i := range signers {
		if bytes.Equal(signers[i].Key.Marshal(), want) && signers[i].Allows(Principal, Namespace) {
			return &signers[i], nil
		}
	}
	return nil, fmt.Errorf("signed by %s, which release signers do not list for %q in %s",
		sshsig.Fingerprint(key), Principal, Namespace)
}

// Entry is one line of SHA256SUMS.
type Entry struct {
	Hash string
	Name string
}

var sumLine = regexp.MustCompile(`^([0-9a-f]{64}) [ *]([^/\\]+)$`)

// ParseSums reads SHA256SUMS as sha256sum writes it. Names are plain file
// names; a path is refused, so that checking a directory stays inside it.
func ParseSums(data []byte) ([]Entry, error) {
	var out []Entry
	seen := map[string]bool{}
	for i, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		m := sumLine.FindStringSubmatch(strings.TrimSuffix(line, "\r"))
		if len(m) != 3 || m[2] == "." || m[2] == ".." {
			return nil, fmt.Errorf("%s line %d is not \"SHA256  NAME\"", SumsFile, i+1)
		}
		if seen[m[2]] {
			return nil, fmt.Errorf("%s lists %s twice", SumsFile, m[2])
		}
		seen[m[2]] = true
		out = append(out, Entry{Hash: m[1], Name: m[2]})
	}
	return out, nil
}

// Check compares the listed files present in dir with their checksums. It
// returns the files that match and the ones that are not there; a file
// that differs is an error.
func Check(dir string, entries []Entry) (matched, missing []string, err error) {
	for _, e := range entries {
		got, err := fileHash(filepath.Join(dir, e.Name))
		switch {
		case errors.Is(err, os.ErrNotExist):
			missing = append(missing, e.Name)
		case err != nil:
			return matched, missing, err
		case got != e.Hash:
			return matched, missing, fmt.Errorf("%s does not match %s", e.Name, SumsFile)
		default:
			matched = append(matched, e.Name)
		}
	}
	return matched, missing, nil
}

func fileHash(name string) (string, error) {
	f, err := os.Open(name) //nolint:gosec // a name from SHA256SUMS, without a path
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
