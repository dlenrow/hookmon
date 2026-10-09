//go:build ignore

// Built by naming this file explicitly (see test/canary/Makefile), which
// bypasses build constraints. The ignore tag keeps it out of ./... so the
// C canaries in this directory are not mistaken for cgo sources.

// bpf_tag_canary loads one program from a compiled eBPF object several times
// in one process and keeps every copy loaded, so each load's instructions
// carry different map fds. For each copy it prints the kernel's program ID
// and tag on stdout:
//
//	loaded id=<id> tag=<hex>
//
// With -raw-tp, each copy is also attached to that raw tracepoint, which goes
// through BPF_RAW_TRACEPOINT_OPEN. The canary then holds everything for
// -hold and exits.
//
// Usage: bpf_tag_canary [-copies N] [-hold DURATION] [-raw-tp NAME] <bpf.o> <program-name>
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	copies := flag.Int("copies", 1, "number of copies of the program to load")
	hold := flag.Duration("hold", 5*time.Second, "how long to keep the programs loaded")
	rawTP := flag.String("raw-tp", "", "raw tracepoint to attach each copy to")
	flag.Parse()
	if flag.NArg() != 2 || *copies < 1 {
		fmt.Fprintf(os.Stderr, "usage: %s [-copies N] [-hold DURATION] [-raw-tp NAME] <bpf.o> <program-name>\n", os.Args[0])
		os.Exit(1)
	}
	objPath, progName := flag.Arg(0), flag.Arg(1)

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load spec from %s: %v\n", objPath, err)
		os.Exit(1)
	}

	var held []func()
	defer func() {
		for i := len(held) - 1; i >= 0; i-- {
			held[i]()
		}
	}()

	for i := 0; i < *copies; i++ {
		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "copy %d: create collection: %v\n", i, err)
			os.Exit(1)
		}
		held = append(held, coll.Close)

		prog := coll.Programs[progName]
		if prog == nil {
			fmt.Fprintf(os.Stderr, "program %q not found in %s\n", progName, objPath)
			os.Exit(1)
		}
		info, err := prog.Info()
		if err != nil {
			fmt.Fprintf(os.Stderr, "copy %d: program info: %v\n", i, err)
			os.Exit(1)
		}
		id, ok := info.ID()
		if !ok {
			fmt.Fprintf(os.Stderr, "copy %d: kernel reported no program ID\n", i)
			os.Exit(1)
		}

		if *rawTP != "" {
			l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: *rawTP, Program: prog})
			if err != nil {
				fmt.Fprintf(os.Stderr, "copy %d: attach raw tracepoint %s: %v\n", i, *rawTP, err)
				os.Exit(1)
			}
			held = append(held, func() { l.Close() })
		}

		fmt.Printf("loaded id=%d tag=%s\n", id, info.Tag)
	}

	time.Sleep(*hold)
}
