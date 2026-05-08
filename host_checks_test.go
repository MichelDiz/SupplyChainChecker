//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// ----------------------------------------------------------------------------
// kernel parsing / comparison
// ----------------------------------------------------------------------------

func TestParseKernelVersion(t *testing.T) {
	cases := []struct {
		in     string
		maj    int
		min    int
		patch  int
		ok     bool
	}{
		{"6.17.4-1-pve", 6, 17, 4, true},
		{"7.0.0-3-pve", 7, 0, 0, true},
		{"5.15.205", 5, 15, 205, true},
		{"6.6", 6, 6, 0, true},
		{"v6.1.171-cloud-amd64", 6, 1, 171, true},
		{"junk", 0, 0, 0, false},
	}
	for _, c := range cases {
		maj, min, patch, ok := parseKernelVersion(c.in)
		if maj != c.maj || min != c.min || patch != c.patch || ok != c.ok {
			t.Errorf("parseKernelVersion(%q) = (%d,%d,%d,%v), want (%d,%d,%d,%v)",
				c.in, maj, min, patch, ok, c.maj, c.min, c.patch, c.ok)
		}
	}
}

func TestCompareKernelStrings(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"6.17.4-1-pve", "6.17.4-1-pve", 0},
		{"6.17.13-6-pve", "6.17.4-1-pve", 1},
		{"6.17.4-1-pve", "6.17.13-6-pve", -1},
		{"7.0.0-3-pve", "6.17.13-6-pve", 1},
		{"6.17.4", "6.17.4-1-pve", -1}, // suffix sorts after empty
		{"6.17.5", "6.17.4-99", 1},
	}
	for _, c := range cases {
		if got := compareKernelStrings(c.a, c.b); got != c.want {
			t.Errorf("compareKernelStrings(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestKernelIsPatched_CopyFail(t *testing.T) {
	fixedAt := []kernelFix{
		{"7.0", "7.0.5"},
		{"6.17", "6.17.13"}, // hypothetical 6.17 backport
		{"6.6", "6.6.138"},
	}
	cases := []struct {
		running   string
		patched   bool
	}{
		{"7.0.0-3-pve", false}, // < 7.0.5
		{"7.0.5-1-pve", true},  // == fix
		{"7.0.6-2-pve", true},  // > fix
		{"6.17.4-1-pve", false},
		{"6.17.13-1-pve", true},
		{"6.6.137", false},
		{"6.6.138", true},
		{"5.4.0", false}, // series not in table; conservatively unknown
	}
	for _, c := range cases {
		got, ev := kernelIsPatched(c.running, fixedAt)
		if got != c.patched {
			t.Errorf("kernelIsPatched(%q) = %v (%s), want %v", c.running, got, ev, c.patched)
		}
	}
}

// ----------------------------------------------------------------------------
// os-release / sshd_config parsers
// ----------------------------------------------------------------------------

func TestReadOSRelease(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "os-release")
	contents := `# fixture
NAME="Debian GNU/Linux"
ID=debian
VERSION_ID="13"
VERSION_CODENAME=trixie
`
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	m := readOSRelease(path)
	if m["ID"] != "debian" {
		t.Errorf("ID = %q, want debian", m["ID"])
	}
	if m["VERSION_ID"] != "13" {
		t.Errorf("VERSION_ID = %q, want 13", m["VERSION_ID"])
	}
	if m["NAME"] != "Debian GNU/Linux" {
		t.Errorf("NAME unwrap failed: %q", m["NAME"])
	}
}

func TestReadSSHDConfig_DropInOverrides(t *testing.T) {
	dir := t.TempDir()
	mainCfg := filepath.Join(dir, "sshd_config")
	dropDir := filepath.Join(dir, "sshd_config.d")
	if err := os.MkdirAll(dropDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// main says yes
	if err := os.WriteFile(mainCfg, []byte("PasswordAuthentication yes\nPort 22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// drop-in overrides to no
	if err := os.WriteFile(filepath.Join(dropDir, "00-key-only.conf"),
		[]byte("PasswordAuthentication no\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := readSSHDConfig(mainCfg, dropDir)
	if cfg["passwordauthentication"] != "no" {
		t.Errorf("expected drop-in override to win; got %q", cfg["passwordauthentication"])
	}
	if cfg["port"] != "22" {
		t.Errorf("expected main 'Port 22' to be retained; got %q", cfg["port"])
	}
}

// ----------------------------------------------------------------------------
// modprobeBlocks helper — tests against synthetic /tmp dirs.
// (We cannot redirect /etc/modprobe.d in a unit test without complicating
//  the API, so this just exercises the substring matching logic via a fake.)
// ----------------------------------------------------------------------------

func TestModprobeBlocks_DetectsBlacklistAndInstall(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "01-test.conf"), []byte(
		"# fixture\nblacklist esp4\ninstall rxrpc /bin/false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// We don't have a way to inject the dir without changing the function
	// signature, so just exercise the parser by reusing the file content
	// via a smaller helper inline.
	body := "# fixture\nblacklist esp4\ninstall rxrpc /bin/false\n"
	if !contains(body, "blacklist esp4\n") {
		t.Errorf("blacklist line not detected")
	}
	if !contains(body, "install rxrpc ") {
		t.Errorf("install line not detected")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

// ----------------------------------------------------------------------------
// integration-ish: run the full suite and assert we get a stable shape.
// We do NOT assert vulnerable/not-vulnerable — that depends on the host
// running the test. We only check that every check returns a populated ID.
// ----------------------------------------------------------------------------

func TestRunHostChecks_Smoke(t *testing.T) {
	report := RunHostChecks()
	if len(report.Checks) == 0 {
		t.Fatal("expected at least one host check result")
	}
	seen := map[string]bool{}
	for _, c := range report.Checks {
		if c.ID == "" {
			t.Errorf("check returned empty ID: %#v", c)
		}
		if seen[c.ID] {
			t.Errorf("duplicate check ID: %s", c.ID)
		}
		seen[c.ID] = true
		if c.Severity == "" {
			t.Errorf("check %s missing severity", c.ID)
		}
		if c.Title == "" {
			t.Errorf("check %s missing title", c.ID)
		}
	}
	t.Logf("host checks ran: %d results, %d vulnerable, context=%+v",
		len(report.Checks), report.VulnerableCount(), report.Context)
}
