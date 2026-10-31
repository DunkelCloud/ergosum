package authority

import (
	"bytes"
	"os"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/DunkelCloud/ergosum/internal/protocol"
)

// The example configuration and authority list load.
func TestExampleConfig(t *testing.T) {
	c, err := LoadConfig("../../examples/serve.yaml")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../examples/authorities.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var f listFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		t.Fatal(err)
	}
	l := protocol.AuthorityList{V: protocol.Version, TrustDomain: c.TrustDomain, Serial: f.Serial}
	for _, a := range f.Authorities {
		l.Authorities = append(l.Authorities, protocol.ListedAuthority{Key: a.Key, URLs: a.URLs})
	}
	if err := l.Validate(); err != nil {
		t.Fatal(err)
	}
}
