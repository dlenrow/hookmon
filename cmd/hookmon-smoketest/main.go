//go:build linux

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const workDir = "/tmp/hookmon-smoketest"

func main() {
	id := flag.String("id", "", "run identifier (logged, not used in keys)")
	variant := flag.Bool("variant", false, "change library content so hashes differ")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: hookmon-smoketest [--id ID] [--variant] run|cleanup")
		os.Exit(1)
	}

	switch args[0] {
	case "run":
		if os.Getuid() != 0 {
			fmt.Fprintln(os.Stderr, "error: hookmon-smoketest run requires root")
			os.Exit(1)
		}
		if err := run(*id, *variant); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "cleanup":
		cleanup()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", args[0])
		os.Exit(1)
	}
}

func run(id string, variant bool) error {
	self, _ := os.Executable()
	fmt.Printf("hookmon-smoketest run id=%q variant=%v exe=%s\n", id, variant, self)

	helperDir := filepath.Dir(self)

	if err := os.MkdirAll(workDir, 0755); err != nil {
		return fmt.Errorf("create %s: %w", workDir, err)
	}

	libSrc := filepath.Join(helperDir, "libhookmon_smoketest.so")
	helperSrc := filepath.Join(helperDir, "hookmon-smoketest-helper")

	if _, err := os.Stat(libSrc); err != nil {
		return fmt.Errorf("no-op library not found at %s: %w", libSrc, err)
	}
	if _, err := os.Stat(helperSrc); err != nil {
		return fmt.Errorf("helper binary not found at %s: %w", helperSrc, err)
	}

	libDst := filepath.Join(workDir, "libhookmon_smoketest.so")
	if err := copyFileVariant(libSrc, libDst, variant); err != nil {
		return fmt.Errorf("stage library: %w", err)
	}

	helperDst := filepath.Join(workDir, "hookmon-smoketest-helper")
	if err := copyFileVariant(helperSrc, helperDst, variant); err != nil {
		return fmt.Errorf("stage helper: %w", err)
	}
	os.Chmod(helperDst, 0755)

	type trigger struct {
		name string
		fn   func() error
	}

	triggers := []trigger{
		{"bpf_load", func() error { return triggerBPF(variant) }},
		{"exec_injection", func() error { return triggerExecInjection(libDst) }},
		{"shm_create", triggerSHM},
		{"dlopen", func() error { return triggerDlopen(helperDst, libDst) }},
		{"ptrace_inject", triggerPtrace},
		{"linker_config", triggerLinkerConfig},
		{"lib_integrity", func() error { return triggerLibIntegrity(libSrc) }},
		{"elf_rpath", func() error { return triggerElfRpath(helperDst) }},
	}

	var failed []string
	for _, t := range triggers {
		fmt.Printf("  %-18s ", t.name)
		if err := t.fn(); err != nil {
			fmt.Printf("FAIL: %v\n", err)
			failed = append(failed, t.name)
		} else {
			fmt.Println("ok")
		}
		time.Sleep(200 * time.Millisecond)
	}

	if len(failed) > 0 {
		return fmt.Errorf("%d triggers failed: %s", len(failed), strings.Join(failed, ", "))
	}
	fmt.Println("all 8 triggers fired")
	return nil
}

func cleanup() {
	for _, p := range []string{
		"/etc/ld.so.conf.d/hookmon-smoketest.conf",
		"/usr/lib/libhookmon_smoketest_canary.so",
		"/dev/shm/bpftime_hookmon_smoketest",
	} {
		os.Remove(p)
	}
	os.RemoveAll(workDir)
	fmt.Println("cleanup done")
}

func copyFileVariant(src, dst string, variant bool) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if variant {
		data = append(data, "\x00hookmon-variant"...)
	}
	return os.WriteFile(dst, data, 0644)
}
