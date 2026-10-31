package authority

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/DunkelCloud/ergosum/internal/protocol"
)

// listFile is the format of Config.AuthoritiesFile: the instances of the
// trust domain with the URLs daemons reach them on, the same on every
// instance. serial grows with each change.
type listFile struct {
	Serial      uint64       `yaml:"serial"`
	Authorities []listedFile `yaml:"authorities"`
}

type listedFile struct {
	Key  string   `yaml:"key"`
	URLs []string `yaml:"urls"`
}

// authorityList serves Config.AuthoritiesFile. It reads the file again when
// it changes, so that a change needs neither a restart nor an unseal; a
// file that turns invalid leaves the last good list in place.
type authorityList struct {
	path        string
	trustDomain string
	self        string // this instance's fingerprint, which the list must name
	log         *slog.Logger

	mu   sync.Mutex
	mod  time.Time
	size int64
	list *protocol.AuthorityList
}

func newAuthorityList(path, trustDomain, self string, log *slog.Logger) (*authorityList, error) {
	l := &authorityList{path: path, trustDomain: trustDomain, self: self, log: log}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("authorities file: %w", err)
	}
	if l.list, err = l.read(); err != nil {
		return nil, err
	}
	l.mod, l.size = fi.ModTime(), fi.Size()
	return l, nil
}

func (l *authorityList) read() (*protocol.AuthorityList, error) {
	data, err := os.ReadFile(l.path)
	if err != nil {
		return nil, fmt.Errorf("authorities file: %w", err)
	}
	var f listFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("authorities file %s: %w", l.path, err)
	}
	list := &protocol.AuthorityList{V: protocol.Version, TrustDomain: l.trustDomain, Serial: f.Serial}
	for _, a := range f.Authorities {
		list.Authorities = append(list.Authorities, protocol.ListedAuthority{Key: a.Key, URLs: a.URLs})
	}
	if err := list.Validate(); err != nil {
		return nil, fmt.Errorf("authorities file %s: %w", l.path, err)
	}
	if !list.Lists(l.self) {
		return nil, fmt.Errorf("authorities file %s does not list this instance (%s)", l.path, l.self)
	}
	return list, nil
}

// current returns the list, read again if the file changed.
func (l *authorityList) current() *protocol.AuthorityList {
	l.mu.Lock()
	defer l.mu.Unlock()
	fi, err := os.Stat(l.path)
	if err != nil || (fi.ModTime().Equal(l.mod) && fi.Size() == l.size) {
		if err != nil {
			l.log.Warn("authorities file unreadable; serving the last good list", "err", err, "serial", l.list.Serial)
		}
		return l.list
	}
	list, err := l.read()
	if err != nil {
		l.log.Error("authorities file invalid; serving the last good list", "err", err, "serial", l.list.Serial)
		return l.list
	}
	l.mod, l.size = fi.ModTime(), fi.Size()
	if list.Serial != l.list.Serial {
		l.log.Info("authorities file read", "serial", list.Serial, "instances", len(list.Authorities))
	}
	if list.Serial <= l.list.Serial && !list.Same(l.list) {
		l.log.Warn("authorities file changed without a higher serial; daemons keep the list they have",
			"serial", list.Serial, "previous", l.list.Serial)
	}
	l.list = list
	return list
}

func (a *Authority) handleAuthorities(w http.ResponseWriter, _ *http.Request) {
	if a.list == nil {
		a.writeError(w, http.StatusNotFound, "no_list", "this instance serves no authority list")
		return
	}
	writeJSON(w, http.StatusOK, a.list.current())
}
