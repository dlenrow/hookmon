package agent

import "golang.org/x/sys/unix"

func kernelRelease() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return ""
	}
	n := 0
	for n < len(u.Release) && u.Release[n] != 0 {
		n++
	}
	return string(u.Release[:n])
}
