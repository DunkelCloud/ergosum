package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/DunkelCloud/ergosum/internal/authority"
	"github.com/DunkelCloud/ergosum/internal/journal"
)

// journalCmd sends a journal command to the local instance's control
// socket and prints the result.
func journalCmd(args []string) error {
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	sub := args[0]
	fs := flag.NewFlagSet("journal "+sub, flag.ExitOnError)
	socket := fs.String("socket", defaultSocket, "control socket of the running instance")
	var from multiFlag
	var out string
	var archive bool
	req := authority.ControlRequest{Cmd: sub}
	switch sub {
	case authority.CmdState, authority.CmdCheckpoint, authority.CmdCompact:
	case authority.CmdSync:
		fs.Var(&from, "from", "peer to pull from, repeatable; several give the union")
	case authority.CmdExport:
		fs.StringVar(&out, "out", "-", "file for the JSON lines (\"-\" for stdout)")
		fs.BoolVar(&archive, "archive", false, "export what is not yet archived into the configured archive directory")
	default:
		usage()
		os.Exit(2)
	}
	_ = fs.Parse(args[1:])
	req.From, req.Archive = from, archive

	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Minute)
	defer cancel()
	var onEvent func(journal.ArchiveLine) error
	var buf *bufio.Writer
	var file *os.File
	if sub == authority.CmdExport && !archive {
		if out == "-" {
			buf = bufio.NewWriter(os.Stdout)
		} else {
			f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640) //nolint:gosec // operator-supplied path
			if err != nil {
				return fmt.Errorf("export (an existing file is never overwritten): %w", err)
			}
			file = f
			buf = bufio.NewWriter(f)
		}
		onEvent = func(l journal.ArchiveLine) error {
			data, err := json.Marshal(l)
			if err != nil {
				return err
			}
			_, err = buf.Write(append(data, '\n'))
			return err
		}
	}
	res, err := authority.Control(ctx, *socket, req, onEvent)
	if buf != nil {
		if ferr := buf.Flush(); err == nil {
			err = ferr
		}
	}
	if file != nil {
		if serr := file.Sync(); err == nil {
			err = serr
		}
		if cerr := file.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		return err
	}
	var pretty bytes.Buffer
	if json.Indent(&pretty, res, "", "  ") != nil {
		return errors.New("unreadable answer from the instance")
	}
	w := os.Stdout
	if sub == authority.CmdExport && !archive && out == "-" {
		w = os.Stderr // the events went to stdout
	}
	_, err = fmt.Fprintln(w, pretty.String())
	return err
}
