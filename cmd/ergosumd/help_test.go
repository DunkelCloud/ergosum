package main

import (
	"os"
	"strings"
	"testing"

	"github.com/DunkelCloud/ergosum/internal/cli/clitest"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && strings.HasPrefix(os.Args[1], fakeEditorFlag) {
		fakeEditor(strings.TrimPrefix(os.Args[1], fakeEditorFlag), os.Args[2:])
		os.Exit(0)
	}
	clitest.Main(m, main)
}

// TestHelp: every command explains its arguments and flags on -h.
func TestHelp(t *testing.T) {
	for _, c := range []string{"run", "request", "fingerprint", "check", "secret create", "secret get", "secret info", "secret replace", "secret edit"} {
		clitest.Help(t, c)
	}
}
