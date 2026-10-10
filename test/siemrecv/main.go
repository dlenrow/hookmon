// Command siemrecv is a test SIEM receiver for the step 7d e2e test
// (test/e2e/siem_test.go). It runs in a container and prints what it
// receives to stdout, one line per message, so the test can read it with
// docker logs.
//
//	siemrecv syslog :5514    RFC 5424 syslog over TCP (octet-counted or
//	                          newline-framed) and UDP on the same port;
//	                          prints "SYSLOG <message>"
//	siemrecv webhook :8080   HTTP POSTs; prints "WEBHOOK <compact JSON body>"
//	                          and answers 204
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
)

var out sync.Mutex

func emit(kind, msg string) {
	out.Lock()
	defer out.Unlock()
	fmt.Printf("%s %s\n", kind, strings.ReplaceAll(msg, "\n", `\n`))
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: siemrecv syslog|webhook ADDR")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "syslog":
		err = serveSyslog(os.Args[2])
	case "webhook":
		err = serveWebhook(os.Args[2])
	default:
		err = fmt.Errorf("unknown mode %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "siemrecv:", err)
		os.Exit(1)
	}
}

func serveSyslog(addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			emit("SYSLOG", string(buf[:n]))
		}
	}()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "siemrecv: syslog on", addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go readSyslog(c)
	}
}

// readSyslog reads RFC 6587 frames: "<len> <msg>" when the frame starts
// with a digit, otherwise a line.
func readSyslog(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	for {
		b, err := r.Peek(1)
		if err != nil {
			return
		}
		if b[0] >= '0' && b[0] <= '9' {
			lenStr, err := r.ReadString(' ')
			if err != nil {
				return
			}
			n, err := strconv.Atoi(strings.TrimSpace(lenStr))
			if err != nil || n <= 0 {
				emit("SYSLOG-ERROR", "bad frame length "+strconv.Quote(lenStr))
				return
			}
			msg := make([]byte, n)
			if _, err := io.ReadFull(r, msg); err != nil {
				return
			}
			emit("SYSLOG", string(msg))
			continue
		}
		line, err := r.ReadString('\n')
		if line = strings.TrimRight(line, "\r\n"); line != "" {
			emit("SYSLOG", line)
		}
		if err != nil {
			return
		}
	}
}

func serveWebhook(addr string) error {
	fmt.Fprintln(os.Stderr, "siemrecv: webhook on", addr)
	return http.ListenAndServe(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		if err != nil || r.Method != http.MethodPost {
			http.Error(w, "POST a JSON body", http.StatusBadRequest)
			return
		}
		var buf bytes.Buffer
		if err := json.Compact(&buf, data); err != nil {
			emit("WEBHOOK-ERROR", err.Error())
			http.Error(w, "not JSON", http.StatusBadRequest)
			return
		}
		emit("WEBHOOK", buf.String())
		w.WriteHeader(http.StatusNoContent)
	}))
}
