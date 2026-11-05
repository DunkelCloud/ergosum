package cli

import (
	"flag"
	"strings"
	"testing"

	"github.com/DunkelCloud/ergosum/internal/cli/clitest"
)

// TestUsage: the help names each flag's value, wraps the explanations of
// arguments and flags, and gives a default on its own line.
func TestUsage(t *testing.T) {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	fs.String("out", "-", "write to `FILE` instead of stdout")
	fs.Bool("raw", false, "keep the input as it is")
	fs.Int("threshold", 0, "the number `K` of instances that must answer: "+strings.Repeat("a long explanation ", 6))
	Usage(fs, "demo [-out FILE] NAME", "Does something.\n", Arg{Name: "NAME", Text: "the name"})
	var b strings.Builder
	fs.SetOutput(&b)
	fs.Usage()
	want := `usage: demo [-out FILE] NAME

Does something.

Arguments:
  NAME
      the name

Flags:
  -out FILE
      write to FILE instead of stdout
      default: -
  -raw
      keep the input as it is
  -threshold K
      the number K of instances that must answer: a long explanation a long
      explanation a long explanation a long explanation a long explanation a
      long explanation
`
	if b.String() != want {
		t.Errorf("help:\n%s\nwant:\n%s", b.String(), want)
	}
	if p := clitest.Problems(b.String()); len(p) > 0 {
		t.Errorf("problems: %q", p)
	}
}

// TestProblems: what the commands' tests catch.
func TestProblems(t *testing.T) {
	help := "usage: demo\n\nFlags:\n  -config string\n      a file\n  -yes\n  -x\n      " +
		strings.Repeat("x", 80) + "\n"
	got := strings.Join(clitest.Problems(help), "\n")
	for _, want := range []string{"-config string: the value has no name", "nothing explains -yes", "longer than 78"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q not found in:\n%s", want, got)
		}
	}
	if p := clitest.Problems("no usage\n"); len(p) != 1 {
		t.Errorf("without usage line: %q", p)
	}
}
