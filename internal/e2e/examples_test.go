package e2e

import (
	"testing"

	"github.com/DunkelCloud/ergosum/internal/authority"
	"github.com/DunkelCloud/ergosum/internal/daemon"
)

// The shipped example configurations must stay loadable.
func TestExampleConfigs(t *testing.T) {
	if _, err := authority.LoadConfig("../../examples/serve.yaml"); err != nil {
		t.Errorf("serve.yaml: %v", err)
	}
	if _, err := daemon.LoadConfig("../../examples/ergosumd.yaml"); err != nil {
		t.Errorf("ergosumd.yaml: %v", err)
	}
}
