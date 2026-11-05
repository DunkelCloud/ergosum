// Package cli writes the help of the ergosum and ergosumd commands.
package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"
)

const (
	width  = 78       // line length the help is wrapped to
	indent = "      " // of the text under an argument or a flag
)

// Arg is a positional argument of a command and what it means.
type Arg struct {
	Name, Text string
}

// Usage makes fs answer -h, and a flag it does not know, with the synopsis,
// the text, the arguments and every flag: its value, what it means and its
// default. The value is the back-quoted word of the flag's usage, as with
// flag.PrintDefaults. text is wrapped by hand and ends with a newline; the
// texts of arguments and flags are wrapped here.
func Usage(fs *flag.FlagSet, synopsis, text string, args ...Arg) {
	fs.Usage = func() { write(fs.Output(), fs, synopsis, text, args) }
}

func write(w io.Writer, fs *flag.FlagSet, synopsis, text string, args []Arg) {
	var b strings.Builder
	fmt.Fprintf(&b, "usage: %s\n", synopsis)
	if text != "" {
		fmt.Fprintf(&b, "\n%s", text)
	}
	if len(args) > 0 {
		b.WriteString("\nArguments:\n")
		for _, a := range args {
			item(&b, a.Name, a.Text)
		}
	}
	first := true
	fs.VisitAll(func(f *flag.Flag) {
		if first {
			b.WriteString("\nFlags:\n")
			first = false
		}
		value, usage := flag.UnquoteUsage(f)
		head := "-" + f.Name
		if value != "" {
			head += " " + value
		}
		item(&b, head, usage)
		if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" {
			fmt.Fprintf(&b, "%sdefault: %s\n", indent, f.DefValue)
		}
	})
	_, _ = io.WriteString(w, b.String())
}

// item writes head and below it text, wrapped.
func item(b *strings.Builder, head, text string) {
	fmt.Fprintf(b, "  %s\n", head)
	line := ""
	for _, word := range strings.Fields(text) {
		switch {
		case line == "":
			line = word
		case len(indent)+len(line)+1+len(word) > width:
			fmt.Fprintf(b, "%s%s\n", indent, line)
			line = word
		default:
			line += " " + word
		}
	}
	if line != "" {
		fmt.Fprintf(b, "%s%s\n", indent, line)
	}
}
