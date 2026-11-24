// Package clitest checks the help that the commands print on -h.
package clitest

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// argsEnv carries the command line for a test binary that runs main, its
// arguments separated by spaces; argvEnv carries it as a JSON array, for
// arguments that contain spaces.
const (
	argsEnv = "ERGOSUM_CLITEST_ARGS"
	argvEnv = "ERGOSUM_CLITEST_ARGV"
)

// Main is TestMain for a command's package: it runs main instead of the
// tests when Help or Command started the test binary.
func Main(m *testing.M, main func()) {
	if args, ok := os.LookupEnv(argsEnv); ok {
		os.Args = append([]string{"cmd"}, strings.Fields(args)...)
		main()
		os.Exit(0)
	}
	if argv, ok := os.LookupEnv(argvEnv); ok {
		var args []string
		if err := json.Unmarshal([]byte(argv), &args); err != nil {
			fmt.Fprintln(os.Stderr, "clitest:", err)
			os.Exit(2)
		}
		os.Args = append([]string{"cmd"}, args...)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// Command returns the command args in the test binary, not yet started,
// for a test that feeds it, reads what it writes or sends it a signal. It
// runs main as the command itself would: with its exit code, and with the
// environment of the test unless the caller adds to cmd.Env.
func Command(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	argv, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0]) //nolint:gosec // the test binary itself
	cmd.Env = append(os.Environ(), argvEnv+"="+string(argv))
	return cmd
}

// Help runs the command args with -h in the test binary and fails t for
// each problem of its help.
func Help(t *testing.T, args string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), os.Args[0]) //nolint:gosec // the test binary itself
	cmd.Env = append(os.Environ(), argsEnv+"="+args+" -h")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("%s -h: %v\n%s", args, err, out)
		return
	}
	for _, p := range Problems(string(out)) {
		t.Errorf("%s -h: %s", args, p)
	}
}

// genericValues are the value names flag gives a flag whose usage names
// none.
var genericValues = []string{"string", "value", "int", "uint", "int64", "uint64", "float", "duration"}

// Problems returns what a help lacks: the usage line, an explanation under
// an argument or a flag, a named value of a flag; and its lines longer than
// 78 columns, apart from the usage line and the defaults.
func Problems(help string) []string {
	var problems []string
	lines := strings.Split(strings.TrimRight(help, "\n"), "\n")
	if !strings.HasPrefix(lines[0], "usage: ") {
		problems = append(problems, "no usage line")
	}
	items := false
	for i, l := range lines {
		if i > 0 && len(l) > 78 && !strings.HasPrefix(l, "      default: ") {
			problems = append(problems, "line longer than 78 columns: "+l)
		}
		switch {
		case l == "Arguments:" || l == "Flags:":
			items = true
			continue
		case l == "":
			items = false
			continue
		case !items || strings.HasPrefix(l, "      "):
			continue
		}
		head := strings.TrimSpace(l)
		if i+1 == len(lines) || !strings.HasPrefix(lines[i+1], "      ") || lines[i+1] == "      " {
			problems = append(problems, "nothing explains "+head)
		}
		for _, g := range genericValues {
			if strings.HasPrefix(head, "-") && strings.HasSuffix(head, " "+g) {
				problems = append(problems, head+": the value has no name")
			}
		}
	}
	return problems
}
