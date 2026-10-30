package admin

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/DunkelCloud/ergosum/internal/journal"
	"github.com/DunkelCloud/ergosum/internal/keys"
)

// File is a binding change as administrators handle it: one text file per
// change that grows from step to step. "ergosumd request" (or "ergosum
// show") writes identity, key and checks; "ergosum bind" adds kind, trust
// domain and epoch, then one signature per administrator, and records the
// event once the approvals suffice.
//
// The fields are the lines of the canonical text (ADR 0003), "name value",
// in any order. Lines starting with # are comments, line endings may be LF
// or CRLF, and the canonical header line may be present. Signatures are the
// armored blocks that "ssh-keygen -Y sign" writes. The JSON form of an event
// exists only on the wire.
type File struct {
	Kind        string
	TrustDomain string
	Identity    string
	Epoch       uint64
	Key         string
	Checks      []journal.Check
	Signatures  []string

	text string // the content as read, as UTF-8
	eol  string // the line ending of the file
}

const (
	sigBegin = "-----BEGIN SSH SIGNATURE-----"
	sigEnd   = "-----END SSH SIGNATURE-----"
)

// ParseFile parses a binding file. It accepts UTF-8 with or without a byte
// order mark and UTF-16 with one, which Windows PowerShell writes for "cmd >
// file".
func ParseFile(data []byte) (*File, error) {
	text, err := decodeText(data)
	if err != nil {
		return nil, err
	}
	f := &File{text: text, eol: "\n"}
	if strings.Contains(text, "\r\n") {
		f.eol = "\r\n"
	}
	var sig []string // lines of the signature being read
	seen := map[string]int{}
	for i, raw := range strings.Split(text, "\n") {
		n := i + 1
		line := strings.TrimSpace(raw)
		if sig != nil {
			sig = append(sig, line)
			if line == sigEnd {
				f.Signatures = append(f.Signatures, strings.Join(sig, "\n")+"\n")
				sig = nil
			}
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") || line == journal.CanonicalHeader {
			continue
		}
		if line == sigBegin {
			sig = []string{line}
			continue
		}
		fields := strings.Fields(line)
		name, args := fields[0], fields[1:]
		if _, known := fieldNames[name]; !known {
			return nil, fmt.Errorf("line %d: unknown field %q (want identity, key, check, kind, trust-domain or epoch)", n, name)
		}
		if prev, ok := seen[name]; ok && name != "check" {
			return nil, fmt.Errorf("line %d: a second %q line (the first is line %d)", n, name, prev)
		}
		seen[name] = n
		if name == "check" && len(args) != 2 {
			return nil, fmt.Errorf("line %d: want %q", n, "check TYPE TARGET")
		}
		if name != "check" && len(args) != 1 {
			return nil, fmt.Errorf("line %d: want %q", n, name+" VALUE")
		}
		switch name {
		case "kind":
			f.Kind = args[0]
		case "trust-domain":
			f.TrustDomain = args[0]
		case "identity":
			f.Identity = args[0]
		case "epoch":
			e, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil || e == 0 {
				return nil, fmt.Errorf("line %d: epoch must be a positive number", n)
			}
			f.Epoch = e
		case "key":
			if !keys.ValidFingerprint(args[0]) {
				return nil, fmt.Errorf("line %d: key %q is not a key fingerprint (SHA256:..., from ergosumd request)", n, args[0])
			}
			f.Key = args[0]
		case "check":
			f.Checks = append(f.Checks, journal.Check{Type: args[0], Target: args[1]})
		}
	}
	if sig != nil {
		return nil, errors.New("a signature has no " + sigEnd + " line")
	}
	if f.Identity == "" {
		return nil, errors.New("no identity line")
	}
	return f, nil
}

var fieldNames = map[string]struct{}{"kind": {}, "trust-domain": {}, "identity": {}, "epoch": {}, "key": {}, "check": {}}

func decodeText(data []byte) (string, error) {
	switch {
	case bytes.HasPrefix(data, []byte{0xFF, 0xFE}), bytes.HasPrefix(data, []byte{0xFE, 0xFF}):
		if len(data)%2 != 0 {
			return "", errors.New("truncated UTF-16 text")
		}
		big := data[0] == 0xFE
		u := make([]uint16, 0, len(data)/2-1)
		for i := 2; i < len(data); i += 2 {
			if big {
				u = append(u, uint16(data[i])<<8|uint16(data[i+1]))
			} else {
				u = append(u, uint16(data[i+1])<<8|uint16(data[i]))
			}
		}
		return string(utf16.Decode(u)), nil
	default:
		return string(bytes.TrimPrefix(data, []byte("\xEF\xBB\xBF"))), nil
	}
}

// Event returns the binding event the file describes.
func (f *File) Event() *journal.BindingEvent {
	return &journal.BindingEvent{
		V: 1, Kind: f.Kind, TrustDomain: f.TrustDomain, Identity: f.Identity, Epoch: f.Epoch,
		Key: f.Key, Checks: f.Checks, Signatures: append([]string{}, f.Signatures...),
	}
}

// Append adds lines at the end, in the file's line ending. Each argument is
// one line: control characters in it become spaces, so that no value can
// start a line of its own.
func (f *File) Append(lines ...string) {
	var b strings.Builder
	b.WriteString(f.text)
	if f.text != "" && !strings.HasSuffix(f.text, "\n") {
		b.WriteString(f.eol)
	}
	for _, l := range lines {
		b.WriteString(printable(l, len(l)))
		b.WriteString(f.eol)
	}
	f.text = b.String()
}

// Bytes returns the content as UTF-8.
func (f *File) Bytes() []byte { return []byte(f.text) }

// RequestText formats the lines of a request: identity, key and checks.
func RequestText(identity, key string, checks []journal.Check) []string {
	out := []string{"identity " + identity}
	if key != "" {
		out = append(out, "key "+key)
	}
	for _, c := range checks {
		out = append(out, CheckLine(c))
	}
	return out
}

// CheckLine formats a check as a file line.
func CheckLine(c journal.Check) string { return "check " + c.Type + " " + c.Target }
