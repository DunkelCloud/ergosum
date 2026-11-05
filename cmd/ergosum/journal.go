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
	"github.com/DunkelCloud/ergosum/internal/cli"
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
	socket := socketFlag(fs)
	var from multiFlag
	var out string
	var archive bool
	req := authority.ControlRequest{Cmd: sub}
	switch sub {
	case authority.CmdState:
		cli.Usage(fs, "ergosum journal state [-socket PATH]", `Prints the journal state of the instance on this host: the state hash, the
coverage and the compaction frontier per origin, and the outbox of every
peer. Instances that hold the same binding events have the same state
hash; an outbox that does not drain points to a peer that is down or
refuses events.
`)
	case authority.CmdCheckpoint:
		cli.Usage(fs, "ergosum journal checkpoint [-socket PATH]", `Writes a checkpoint now: the projection of the journal (every winning
binding event with its administrators' signatures) and its coverage,
signed with the instance's key. The instance writes one on its own every
compaction.checkpoint_interval if the journal changed.
`)
	case authority.CmdCompact:
		cli.Usage(fs, "ergosum journal compact [-socket PATH]", `Runs compaction now: with compaction.archive it first writes the events not
yet archived to a new file there; then it raises the frontier and deletes
the events that the latest checkpoint acknowledged by every peer covers,
that every peer has acknowledged and whose retention has passed.
`)
	case authority.CmdSync:
		fs.Var(&from, "from", "pull from the peer named `PEER` in replication.peers (required); repeat it "+
			"for more peers, which give the union of what they hold")
		cli.Usage(fs, "ergosum journal sync -from PEER [-from PEER]... [-socket PATH]", `Pulls the journal from peers. A new or rebuilt instance does this before
anything is written to it: only a sync takes over the coverage of the
checkpoint that a peer's journal starts with, its own sequence counter
included. Several peers give the union, so that one peer cannot withhold
a binding event. Sync only from peers you trust.
`)
	case authority.CmdExport:
		fs.StringVar(&out, "out", "-", "write the JSON lines to `FILE`, with mode 0640, instead of stdout (\"-\"); "+
			"an existing file is never overwritten")
		fs.BoolVar(&archive, "archive", false, "export only what is not yet archived, into a new file in "+
			"compaction.archive, as compaction does; -out does not apply")
		cli.Usage(fs, "ergosum journal export [-out FILE] [-archive] [-socket PATH]", `Writes the whole journal as JSON lines, then a summary, which goes to
stderr when the events go to stdout. An export needs no trust in where it
is kept: observations and checkpoints are signed by their instance,
binding events by administrators, and gaps in an origin's sequence
numbers show. Keep a current one with the deployment's recovery material.
`)
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
