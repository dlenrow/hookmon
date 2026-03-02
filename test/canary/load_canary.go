//go:build linux

// load_canary loads a compiled eBPF canary program (.o file), attaches it
// to its tracepoint, sleeps briefly, then detaches and exits.
// Usage: load_canary <path-to-bpf.o> <tracepoint-group> <tracepoint-name> <program-name>
//
// Examples:
//   load_canary hello_bpf.o    syscalls sys_enter_getpid  hello_count
//   load_canary net_monitor.o  syscalls sys_enter_connect net_count
//   load_canary hello_bpf_v2.o syscalls sys_enter_getpid  hello_count_v2
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintf(os.Stderr, "usage: %s <bpf.o> <tp-group> <tp-name> <prog-name>\n", os.Args[0])
		os.Exit(1)
	}

	objPath := os.Args[1]
	tpGroup := os.Args[2]
	tpName := os.Args[3]
	progName := os.Args[4]

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load spec from %s: %v\n", objPath, err)
		os.Exit(1)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create collection: %v\n", err)
		os.Exit(1)
	}
	defer coll.Close()

	prog := coll.Programs[progName]
	if prog == nil {
		fmt.Fprintf(os.Stderr, "program %q not found in %s\n", progName, objPath)
		fmt.Fprintf(os.Stderr, "available programs: ")
		for name := range coll.Programs {
			fmt.Fprintf(os.Stderr, "%s ", name)
		}
		fmt.Fprintf(os.Stderr, "\n")
		os.Exit(1)
	}

	tp, err := link.Tracepoint(tpGroup, tpName, prog, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "attach tracepoint %s/%s: %v\n", tpGroup, tpName, err)
		os.Exit(1)
	}
	defer tp.Close()

	fmt.Printf("canary loaded: %s (program: %s, tracepoint: %s/%s)\n", objPath, progName, tpGroup, tpName)
	fmt.Println("sleeping 5 seconds...")
	time.Sleep(5 * time.Second)
	fmt.Println("detaching and exiting")
}
