package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolveEnrollToken: the token comes from --enroll-token-file, then
// --enroll-token, then $HOOKMON_ENROLL_TOKEN. The flag gets a warning that
// it is visible in the process list; a token file other users can read
// gets one too. Both flags at once, an empty file and a missing file are
// errors.
func TestResolveEnrollToken(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	private := write("token", "  s3cret-from-file\n", 0o600)
	open := write("token-open", "s3cret-open\n", 0o644)
	empty := write("token-empty", "\n\n", 0o600)
	twoLines := write("token-two", "a\nb\n", 0o600)
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == EnrollTokenEnv {
				return v
			}
			return ""
		}
	}

	cases := []struct {
		name, flag, file, env       string
		token, source, warnContains string
		errContains                 string
	}{
		{name: "file", file: private, env: "from-env", token: "s3cret-from-file", source: TokenFromFile},
		{name: "flag", flag: "from-flag", env: "from-env", token: "from-flag", source: TokenFromFlag, warnContains: "process list"},
		{name: "env", env: " from-env\n", token: "from-env", source: TokenFromEnv},
		{name: "none"},
		{name: "readable file", file: open, token: "s3cret-open", source: TokenFromFile, warnContains: "0644"},
		{name: "both flags", flag: "x", file: private, errContains: "not both"},
		{name: "empty file", file: empty, errContains: "empty"},
		{name: "two lines", file: twoLines, errContains: "more than one line"},
		{name: "missing file", file: filepath.Join(dir, "missing"), errContains: "no such file"},
	}
	for _, c := range cases {
		token, source, warning, err := ResolveEnrollToken(c.flag, c.file, env(c.env))
		if c.errContains != "" {
			if err == nil || !strings.Contains(err.Error(), c.errContains) {
				t.Errorf("%s: err %v, want one containing %q", c.name, err, c.errContains)
			}
			if token != "" {
				t.Errorf("%s: token %q returned with an error", c.name, token)
			}
			continue
		}
		if err != nil || token != c.token || source != c.source {
			t.Errorf("%s: (%q, %q, %v), want (%q, %q)", c.name, token, source, err, c.token, c.source)
		}
		if (c.warnContains == "") != (warning == "") || !strings.Contains(warning, c.warnContains) {
			t.Errorf("%s: warning %q, want one containing %q", c.name, warning, c.warnContains)
		}
	}
}
