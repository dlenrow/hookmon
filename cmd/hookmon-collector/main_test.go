package main

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// The SSH tests use host and client keys made by the real ssh-keygen, and
// known_hosts files in OpenSSH's format, against an SSH server in the test
// process that answers the collector's curl command with a /status body.

const robStatusBody = `{"overall":"alive","version":"test","sensors":[{"name":"bpf_syscall","status":"alive"}]}`

// robKeygen runs ssh-keygen to make a key pair of the given type in dir and
// returns the private key path. It skips the test without ssh-keygen.
func robKeygen(t *testing.T, dir, name, keyType string) string {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not found")
	}
	path := filepath.Join(dir, name)
	out, err := exec.Command("ssh-keygen", "-q", "-t", keyType, "-N", "", "-C", name, "-f", path).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen -t %s: %v: %s", keyType, err, out)
	}
	return path
}

func robSigner(t *testing.T, path string) ssh.Signer {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.ParsePrivateKey(data)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// robSSHServer is an SSH server on 127.0.0.1 that presents hostKeys,
// accepts clientPub, and answers any exec with robStatusBody. It records
// each command it ran.
type robSSHServer struct {
	addr string
	mu   sync.Mutex
	cmds []string
}

func (s *robSSHServer) commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.cmds...)
}

func robStartSSH(t *testing.T, hostKeys []ssh.Signer, clientPub ssh.PublicKey) *robSSHServer {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(clientPub.Marshal()) {
				return nil, nil
			}
			return nil, os.ErrPermission
		},
	}
	for _, k := range hostKeys {
		cfg.AddHostKey(k)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lis.Close() })
	srv := &robSSHServer{addr: lis.Addr().String()}
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			go srv.serve(conn, cfg)
		}
	}()
	return srv
}

func (s *robSSHServer) serve(conn net.Conn, cfg *ssh.ServerConfig) {
	defer conn.Close()
	_, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			defer ch.Close()
			for req := range chReqs {
				if req.Type != "exec" || len(req.Payload) < 4 {
					req.Reply(false, nil)
					continue
				}
				n := binary.BigEndian.Uint32(req.Payload)
				cmd := string(req.Payload[4 : 4+n])
				s.mu.Lock()
				s.cmds = append(s.cmds, cmd)
				s.mu.Unlock()
				req.Reply(true, nil)
				ch.Write([]byte(robStatusBody))
				ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
				return
			}
		}()
	}
}

// robKnownHosts writes a known_hosts file listing pubFiles (ssh-keygen .pub
// files) for addr, in OpenSSH's "[host]:port key" form. hashed runs
// ssh-keygen -H on it, as OpenSSH's HashKnownHosts does.
func robKnownHosts(t *testing.T, dir, name, addr string, hashed bool, pubFiles ...string) string {
	t.Helper()
	host, port, _ := net.SplitHostPort(addr)
	var b strings.Builder
	for _, f := range pubFiles {
		pub, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		fields := strings.Fields(string(pub))
		b.WriteString("[" + host + "]:" + port + " " + fields[0] + " " + fields[1] + "\n")
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if hashed {
		if out, err := exec.Command("ssh-keygen", "-H", "-f", path).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen -H: %v: %s", err, out)
		}
		data, _ := os.ReadFile(path)
		if strings.Contains(string(data), host) {
			t.Fatalf("hashed known_hosts still names the host: %s", data)
		}
	}
	return path
}

// robWriteConfig writes a collector config and loads it.
func robWriteConfig(t *testing.T, dir, body string) (*CollectorConfig, error) {
	t.Helper()
	path := filepath.Join(dir, "collector.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return loadConfig(path)
}

// TestSSH_HostKeyVerification: SSH mode accepts a host whose key is in
// known_hosts (plain or hashed, and when the host also has keys of types
// the file does not list), and refuses one whose key is unknown or has
// changed, without running anything on it. It fetches /status from the
// configured status port. Before step 7f it accepted any host key and
// always used port 2112.
func TestSSH_HostKeyVerification(t *testing.T) {
	dir := t.TempDir()
	hostEd := robKeygen(t, dir, "host_ed25519", "ed25519")
	hostEC := robKeygen(t, dir, "host_ecdsa", "ecdsa")
	impostor := robKeygen(t, dir, "impostor_ed25519", "ed25519")
	other := robKeygen(t, dir, "otherhost_ed25519", "ed25519")
	client := robKeygen(t, dir, "client", "ed25519")
	clientSigner := robSigner(t, client)

	// The host presents ECDSA and Ed25519 keys, as OpenSSH does.
	host := robStartSSH(t, []ssh.Signer{robSigner(t, hostEC), robSigner(t, hostEd)}, clientSigner.PublicKey())
	// Something else answering at the same address with another key.
	fake := robStartSSH(t, []ssh.Signer{robSigner(t, impostor)}, clientSigner.PublicKey())

	poll := func(addr, knownHosts string) (HostResult, *robSSHServer) {
		h := HostConfig{Hostname: "h", SSHHost: addr, SSHUser: "hookmon", SSHKey: client,
			SSHKnownHosts: knownHosts, StatusPort: 2156}
		srv := host
		if addr == fake.addr {
			srv = fake
		}
		return pollHost(context.Background(), h, zap.NewNop()), srv
	}

	accept := []struct {
		name  string
		known string
	}{
		{"ed25519 only (Go asks for ECDSA first)", robKnownHosts(t, dir, "kh_ed", host.addr, false, hostEd+".pub")},
		{"ecdsa only", robKnownHosts(t, dir, "kh_ec", host.addr, false, hostEC+".pub")},
		{"hashed", robKnownHosts(t, dir, "kh_hashed", host.addr, true, hostEd+".pub")},
	}
	for _, c := range accept {
		before := len(host.commands())
		res, _ := poll(host.addr, c.known)
		if !res.Reachable || res.Overall != "alive" || res.Error != "" {
			t.Errorf("%s: %+v, want reachable and alive", c.name, res)
			continue
		}
		cmds := host.commands()
		if len(cmds) != before+1 || cmds[len(cmds)-1] != "curl -s http://localhost:2156/status" {
			t.Errorf("%s: commands run %q, want one curl to port 2156", c.name, cmds[before:])
		}
	}

	refuse := []struct {
		name, addr, known, want string
	}{
		{"host not in known_hosts", host.addr, robKnownHosts(t, dir, "kh_other", "127.0.0.1:1", false, other+".pub"), "is not in"},
		{"empty known_hosts", host.addr, robKnownHosts(t, dir, "kh_empty", host.addr, false), "is not in"},
		{"key changed (impostor)", fake.addr, robKnownHosts(t, dir, "kh_fake", fake.addr, false, hostEd+".pub"), "does not match"},
		{"no known_hosts at all", host.addr, "", "refusing to connect without verifying"},
	}
	for _, c := range refuse {
		res, srv := poll(c.addr, c.known)
		if res.Reachable || !strings.Contains(res.Error, c.want) || !strings.Contains(res.Error, "refusing") {
			t.Errorf("%s: %+v, want unreachable with %q", c.name, res, c.want)
		}
		if c.addr == fake.addr && len(srv.commands()) != 0 {
			t.Errorf("%s: ran %q on a host with the wrong key", c.name, srv.commands())
		}
		t.Logf("%s: %s", c.name, res.Error)
	}
}

// TestLoadConfig_SSHNeedsKnownHosts: the collector refuses to start with a
// host in SSH mode and no usable known_hosts file. A top-level file applies
// to every SSH host unless the host names its own, and status_port
// defaults to 2112.
func TestLoadConfig_SSHNeedsKnownHosts(t *testing.T) {
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(kh, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	own := filepath.Join(dir, "own_known_hosts")
	if err := os.WriteFile(own, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := robWriteConfig(t, dir, "hosts:\n  - {hostname: a, ssh_host: 10.0.0.1, ssh_user: u, ssh_key: /k}\n"); err == nil ||
		!strings.Contains(err.Error(), "ssh_known_hosts") {
		t.Errorf("SSH host without known_hosts: %v, want an error naming ssh_known_hosts", err)
	}
	if _, err := robWriteConfig(t, dir, "ssh_known_hosts: "+filepath.Join(dir, "missing")+
		"\nhosts:\n  - {hostname: a, ssh_host: 10.0.0.1, ssh_user: u, ssh_key: /k}\n"); err == nil {
		t.Error("SSH host with an unreadable known_hosts file: loaded")
	}
	if _, err := robWriteConfig(t, dir, "hosts:\n  - {hostname: a, status_url: 'http://a:2112/status', status_port: 70000}\n"); err == nil {
		t.Error("status_port 70000: loaded")
	}

	cfg, err := robWriteConfig(t, dir, "ssh_known_hosts: "+kh+"\nhosts:\n"+
		"  - {hostname: a, ssh_host: 10.0.0.1, ssh_user: u, ssh_key: /k}\n"+
		"  - {hostname: b, ssh_host: 10.0.0.2, ssh_user: u, ssh_key: /k, ssh_known_hosts: "+own+", status_port: 2156}\n"+
		"  - {hostname: c, status_url: 'http://c:2112/status'}\n")
	if err != nil {
		t.Fatal(err)
	}
	a, b, c := cfg.Hosts[0], cfg.Hosts[1], cfg.Hosts[2]
	if a.SSHKnownHosts != kh || a.StatusPort != 2112 || b.SSHKnownHosts != own || b.StatusPort != 2156 || c.SSHKnownHosts != "" {
		t.Errorf("hosts: %+v %+v %+v", a, b, c)
	}
	if cfg.PollInterval != 30*time.Second {
		t.Errorf("poll interval default: %v", cfg.PollInterval)
	}
}
