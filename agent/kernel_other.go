//go:build !linux

package agent

func kernelRelease() string { return "" }
