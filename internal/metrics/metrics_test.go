package metrics

import (
	"bytes"
	"strings"
	"testing"
)

func TestInfo(t *testing.T) {
	r := NewRegistry()
	r.Info("build_info", "Build.", "version", "v0.1.0", "commit", "abc")
	r.Gauge("up", "Up.").Set("", 1)
	var b bytes.Buffer
	if err := r.Write(&b); err != nil {
		t.Fatal(err)
	}
	want := `build_info{version="v0.1.0",commit="abc"} 1` + "\n"
	if !strings.Contains(b.String(), want) {
		t.Errorf("exposition lacks %q:\n%s", want, b.String())
	}
	if !strings.Contains(b.String(), "\nup 1\n") {
		t.Errorf("unlabeled gauge changed:\n%s", b.String())
	}
}
