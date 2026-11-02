package e2e

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestFailedStart: an authority that stops while starting, here because its
// control socket path is longer than a Unix socket path can be anywhere,
// fails the test at once with its error instead of holding it until the test
// binary's timeout. The test that has to fail runs in a child process.
func TestFailedStart(t *testing.T) {
	if os.Getenv("ERGOSUM_E2E_FAILED_START") != "" {
		e := prepareEnv(t, envOptions{})
		e.cfg.ControlSocket = filepath.Join(t.TempDir(), strings.Repeat("s", 120))
		e.start()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFailedStart$", "-test.timeout=30s")
	cmd.Env = append(os.Environ(), "ERGOSUM_E2E_FAILED_START=1")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("child: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("authority stopped: control socket")) || bytes.Contains(out, []byte("test timed out")) {
		t.Fatalf("failed start not reported at once:\n%s", out)
	}
}
