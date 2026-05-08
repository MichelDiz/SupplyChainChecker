//go:build linux

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// detectHost reads /etc/os-release, /proc/sys/kernel/osrelease, etc. to fill
// in everything the Linux checks need. All reads are best-effort.
func detectHost() HostContext {
	ctx := HostContext{
		OS:   "linux",
		Arch: runtime.GOARCH,
	}
	if h, err := os.Hostname(); err == nil {
		ctx.Hostname = h
	}
	if k, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		ctx.Kernel = strings.TrimSpace(string(k))
	}
	osRelease := readOSRelease("/etc/os-release")
	ctx.Distro = osRelease["ID"]
	ctx.DistroVer = osRelease["VERSION_ID"]
	return ctx
}

// runHostChecks invokes every check in a fixed order so the JSON output is
// stable across runs (good for diffing reports between scans).
func runHostChecks(ctx HostContext) []HostCheckResult {
	return []HostCheckResult{
		checkKernelCopyFail(ctx),
		checkKernelDirtyFrag(ctx),
		checkPendingReboot(ctx),
		checkSSHPasswordAuth(ctx),
		checkUnattendedUpgrades(ctx),
		checkSudoersIntegrity(ctx),
	}
}

// ============================================================================
// CVE-2026-31431 (Copy Fail)
// algif_aead in-place crypto bug. LPE via AF_ALG sockets.
// Fixed in: 7.0.5+, 6.18.28+, 6.12.87+, 6.6.138+, 6.1.171+, 5.15.205+, 5.10.255+
// (per upstream advisory; per-distro kernel naming may differ).
// ============================================================================

func checkKernelCopyFail(ctx HostContext) HostCheckResult {
	r := HostCheckResult{
		ID:          "linux-kernel-copy-fail-CVE-2026-31431",
		Severity:    SeverityCritical,
		Title:       "Kernel vulnerable to CVE-2026-31431 (Copy Fail / algif_aead LPE)",
		Description: "Local privilege escalation via algif_aead AF_ALG socket in-place crypto bug. Active exploitation observed; CISA KEV.",
		References: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2026-31431",
			"https://www.cyber.gc.ca/en/alerts-advisories/al26-009-vulnerability-affecting-linux-cve-2026-31431",
		},
	}
	if ctx.Kernel == "" {
		r.NotApplicable = true
		r.Evidence = "could not read /proc/sys/kernel/osrelease"
		return r
	}

	// Mainline cutoffs published by upstream. Per-distro kernels may carry
	// the fix in earlier point releases; this is conservative.
	fixedAt := []kernelFix{
		{series: "7.0", minVer: "7.0.5"},
		{series: "6.18", minVer: "6.18.28"},
		{series: "6.12", minVer: "6.12.87"},
		{series: "6.6", minVer: "6.6.138"},
		{series: "6.1", minVer: "6.1.171"},
		{series: "5.15", minVer: "5.15.205"},
		{series: "5.10", minVer: "5.10.255"},
	}
	patched, evidence := kernelIsPatched(ctx.Kernel, fixedAt)
	r.Evidence = evidence
	if !patched {
		r.Vulnerable = true
		r.Remediation = []string{
			"Update the kernel to a patched version (e.g. proxmox-kernel >= 7.0.5).",
			"OR mitigate by blacklisting algif_aead/algif_hash/algif_skcipher/algif_rng if you don't use AF_ALG: " +
				"echo 'install algif_aead /bin/false' > /etc/modprobe.d/copyfail.conf && update-initramfs -u",
		}
	}
	return r
}

// ============================================================================
// CVE-2026-43284 / CVE-2026-43500 (DirtyFrag)
// xfrm-ESP page-cache write + RxRPC page-cache write.
// Fixed in: 7.0.5+, 6.18.28+, 6.12.87+, 6.6.138+, 6.1.171+, 5.15.205+, 5.10.255+
// ============================================================================

func checkKernelDirtyFrag(ctx HostContext) HostCheckResult {
	r := HostCheckResult{
		ID:          "linux-kernel-dirty-frag-CVE-2026-43284-43500",
		Severity:    SeverityCritical,
		Title:       "Kernel vulnerable to DirtyFrag (CVE-2026-43284 + CVE-2026-43500)",
		Description: "Universal Linux LPE chaining xfrm-ESP and RxRPC page-cache write bugs. Public PoC after embargo break.",
		References: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2026-43284",
			"https://www.openwall.com/lists/oss-security/2026/05/07/8",
		},
	}
	if ctx.Kernel == "" {
		r.NotApplicable = true
		r.Evidence = "could not read /proc/sys/kernel/osrelease"
		return r
	}

	fixedAt := []kernelFix{
		{series: "7.0", minVer: "7.0.5"},
		{series: "6.18", minVer: "6.18.28"},
		{series: "6.12", minVer: "6.12.87"},
		{series: "6.6", minVer: "6.6.138"},
		{series: "6.1", minVer: "6.1.171"},
		{series: "5.15", minVer: "5.15.205"},
		{series: "5.10", minVer: "5.10.255"},
	}
	patched, kernelEv := kernelIsPatched(ctx.Kernel, fixedAt)

	// Mitigation present? blacklist of esp4/esp6/rxrpc anywhere in modprobe.d.
	mitigated := modprobeBlocks([]string{"esp4", "esp6", "rxrpc"})
	mitEv := "blacklist not detected"
	if mitigated {
		mitEv = "modprobe blacklist for esp4/esp6/rxrpc detected"
	}

	r.Evidence = kernelEv + "; " + mitEv

	if patched {
		return r
	}
	if mitigated {
		r.Severity = SeverityMedium
		r.Title = "Kernel still vulnerable to DirtyFrag, but mitigated by modprobe blacklist"
		r.Vulnerable = true // still not patched at the source, surface it
		r.Remediation = []string{
			"Apply the kernel patch as soon as the distribution releases it; mitigation is defense-in-depth, not a fix.",
		}
		return r
	}

	r.Vulnerable = true
	r.Remediation = []string{
		"Update kernel to a fixed point release (>= 7.0.5 / 6.18.28 / 6.12.87 / 6.6.138 / 6.1.171 / 5.15.205 / 5.10.255).",
		"OR (defense-in-depth, not a fix) blacklist the affected modules if you don't use IPsec or AFS:" +
			" printf 'install esp4 /bin/false\\ninstall esp6 /bin/false\\ninstall rxrpc /bin/false\\n' > /etc/modprobe.d/dirtyfrag.conf && update-initramfs -u",
		"After applying mitigation, drop the page cache once: echo 3 > /proc/sys/vm/drop_caches",
	}
	return r
}

// ============================================================================
// Pending reboot — running kernel != latest installed
// ============================================================================

func checkPendingReboot(ctx HostContext) HostCheckResult {
	r := HostCheckResult{
		ID:          "linux-pending-reboot",
		Severity:    SeverityMedium,
		Title:       "Reboot pending to activate updated kernel",
		Description: "An updated kernel is installed but the running kernel is older. Until reboot, the older kernel's vulnerabilities still apply.",
	}
	if ctx.Kernel == "" {
		r.NotApplicable = true
		return r
	}
	entries, err := os.ReadDir("/lib/modules")
	if err != nil {
		r.NotApplicable = true
		r.Evidence = "could not read /lib/modules: " + err.Error()
		return r
	}
	latest := ""
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if compareKernelStrings(e.Name(), latest) > 0 {
			latest = e.Name()
		}
	}
	if latest == "" {
		r.NotApplicable = true
		return r
	}
	r.Evidence = fmt.Sprintf("running=%s, latest_installed=%s", ctx.Kernel, latest)
	if compareKernelStrings(latest, ctx.Kernel) > 0 {
		r.Vulnerable = true
		r.Remediation = []string{
			"Schedule a reboot to activate the newer kernel: `systemctl reboot` (or planned downtime if VMs/CTs depend on this host).",
		}
	}
	return r
}

// ============================================================================
// SSH password authentication enabled
// ============================================================================

func checkSSHPasswordAuth(ctx HostContext) HostCheckResult {
	r := HostCheckResult{
		ID:          "linux-ssh-password-auth-enabled",
		Severity:    SeverityMedium,
		Title:       "OpenSSH server allows password authentication",
		Description: "Password auth turns SSH into a brute-force surface. With key-based auth available, password auth should be disabled on internet-exposed hosts.",
	}
	cfg := readSSHDConfig("/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d")
	if cfg == nil {
		r.NotApplicable = true
		r.Evidence = "no sshd config readable"
		return r
	}
	val, ok := cfg["passwordauthentication"]
	if !ok {
		// OpenSSH default for "PasswordAuthentication" is "yes" (still true
		// across mainstream distros at the time of writing).
		val = "yes"
	}
	r.Evidence = "PasswordAuthentication=" + val
	if strings.EqualFold(val, "yes") {
		r.Vulnerable = true
		r.Remediation = []string{
			"Add `PasswordAuthentication no` to /etc/ssh/sshd_config.d/00-key-only.conf and run `systemctl reload ssh`.",
			"Verify your SSH keys are set up first: `ssh-add -L` on the client should list a key the server accepts.",
		}
	}
	return r
}

// ============================================================================
// unattended-upgrades enabled (Debian/Ubuntu only)
// ============================================================================

func checkUnattendedUpgrades(ctx HostContext) HostCheckResult {
	r := HostCheckResult{
		ID:          "linux-unattended-upgrades-disabled",
		Severity:    SeverityMedium,
		Title:       "Automated security updates not enabled",
		Description: "Without unattended-upgrades (Debian/Ubuntu) or dnf-automatic (RHEL family), security patches drift. Long drift windows turn known CVEs into trivial-to-exploit conditions.",
	}
	switch ctx.Distro {
	case "debian", "ubuntu", "raspbian":
		// Heuristic: check for the package and the periodic config.
		if !fileExists("/usr/bin/unattended-upgrade") && !fileExists("/usr/bin/unattended-upgrades") {
			r.Vulnerable = true
			r.Evidence = "unattended-upgrades binary not present"
			r.Remediation = []string{
				"apt install unattended-upgrades apt-listchanges",
				"Enable: dpkg-reconfigure -plow unattended-upgrades",
			}
			return r
		}
		// Periodic config? check key APT periodic vars.
		periodicEnabled := aptPeriodicEnabled()
		r.Evidence = fmt.Sprintf("unattended-upgrades installed; APT::Periodic::Unattended-Upgrade=%v", periodicEnabled)
		if !periodicEnabled {
			r.Vulnerable = true
			r.Remediation = []string{
				"Enable the periodic timer: write APT::Periodic::Unattended-Upgrade \"1\" to /etc/apt/apt.conf.d/20auto-upgrades.",
			}
		}
		return r
	default:
		return notApplicable(r.ID, r.Title, "non-Debian-family distro: distro="+ctx.Distro)
	}
}

// ============================================================================
// /etc/sudoers integrity (sanity: no NOPASSWD wildcards / world-writable)
// ============================================================================

func checkSudoersIntegrity(_ HostContext) HostCheckResult {
	r := HostCheckResult{
		ID:          "linux-sudoers-integrity",
		Severity:    SeverityHigh,
		Title:       "/etc/sudoers content sanity",
		Description: "Surfaces obvious sudoers misconfigurations: world-writable files, NOPASSWD: ALL on regular users, etc. Not a substitute for visudo audits.",
	}
	if !fileExists("/etc/sudoers") {
		return notApplicable(r.ID, r.Title, "/etc/sudoers not present")
	}
	files := []string{"/etc/sudoers"}
	if entries, err := os.ReadDir("/etc/sudoers.d"); err == nil {
		for _, e := range entries {
			if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			files = append(files, filepath.Join("/etc/sudoers.d", e.Name()))
		}
	}
	var issues []string
	for _, p := range files {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		// World-writable would be a real problem.
		if info.Mode().Perm()&0o002 != 0 {
			issues = append(issues, p+" is world-writable")
		}
		// Look for NOPASSWD on regular users (not %sudo, not root).
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		s := bufio.NewScanner(f)
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			low := strings.ToLower(line)
			if strings.Contains(low, "nopasswd:") &&
				!strings.HasPrefix(line, "%") &&
				!strings.HasPrefix(line, "root") &&
				!strings.HasPrefix(line, "Defaults") {
				issues = append(issues, p+": "+line)
			}
		}
		_ = f.Close()
	}
	if len(issues) > 0 {
		r.Vulnerable = true
		r.Evidence = strings.Join(issues, " | ")
		r.Remediation = []string{
			"Run `visudo -c` to validate sudoers.",
			"Remove or scope down NOPASSWD entries on regular users.",
			"Ensure sudoers files are mode 0440 (or stricter) and owned by root:root.",
		}
		return r
	}
	r.Evidence = fmt.Sprintf("checked %d sudoers file(s); no obvious issues", len(files))
	return r
}

// ============================================================================
// helpers (parsers and utilities)
// ============================================================================

func readOSRelease(path string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.Trim(strings.TrimSpace(line[eq+1:]), `"'`)
		out[key] = val
	}
	return out
}

// readSSHDConfig parses sshd_config and any *.conf in sshd_config.d. Later
// files in sshd_config.d override earlier ones, mimicking sshd's own load
// order. Returns lowercased keys.
func readSSHDConfig(main, dropdir string) map[string]string {
	out := map[string]string{}
	loadOne := func(path string) {
		f, err := os.Open(path)
		if err != nil {
			return
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			out[strings.ToLower(fields[0])] = fields[1]
		}
	}
	loadOne(main)
	if entries, err := os.ReadDir(dropdir); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			loadOne(filepath.Join(dropdir, e.Name()))
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// modprobeBlocks returns true if any of /etc/modprobe.d/* or
// /usr/lib/modprobe.d/* blacklists or `install`s any of the given module
// names to /bin/false (or similar).
func modprobeBlocks(modules []string) bool {
	dirs := []string{"/etc/modprobe.d", "/usr/lib/modprobe.d"}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			text := string(data)
			for _, m := range modules {
				// Matches both `blacklist <m>` and `install <m> /bin/false`.
				if strings.Contains(text, "blacklist "+m+"\n") ||
					strings.Contains(text, "blacklist "+m+" ") ||
					strings.Contains(text, "install "+m+" ") {
					return true
				}
			}
		}
	}
	return false
}

func aptPeriodicEnabled() bool {
	dirs := []string{"/etc/apt/apt.conf.d"}
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			data, err := os.ReadFile(filepath.Join(d, e.Name()))
			if err != nil {
				continue
			}
			if strings.Contains(string(data), `APT::Periodic::Unattended-Upgrade "1"`) {
				return true
			}
		}
	}
	return false
}

// ----------------------------------------------------------------------------
// Kernel version comparison (pure, easy to test)
// ----------------------------------------------------------------------------

type kernelFix struct {
	series string // e.g. "6.17"
	minVer string // e.g. "6.17.13"
}

// kernelIsPatched returns (true, evidence) if `running` is at or above the
// minVer for its series, or the series is newer than any in fixedAt.
func kernelIsPatched(running string, fixedAt []kernelFix) (bool, string) {
	maj, min, _, ok := parseKernelVersion(running)
	if !ok {
		return false, "could not parse kernel version " + running
	}
	series := fmt.Sprintf("%d.%d", maj, min)
	for _, f := range fixedAt {
		if f.series != series {
			continue
		}
		cmp := compareKernelStrings(running, f.minVer)
		if cmp >= 0 {
			return true, fmt.Sprintf("running=%s >= fixed=%s", running, f.minVer)
		}
		return false, fmt.Sprintf("running=%s < fixed=%s (series %s)", running, f.minVer, series)
	}
	// Series not in the table — assume newer than anything covered.
	if isSeriesNewerThanAny(maj, min, fixedAt) {
		return true, fmt.Sprintf("running=%s, series %s newer than known affected series", running, series)
	}
	return false, fmt.Sprintf("running=%s, series %s not in fix table (treat as unknown)", running, series)
}

func isSeriesNewerThanAny(maj, min int, fixedAt []kernelFix) bool {
	for _, f := range fixedAt {
		fm, fn, _, ok := parseKernelVersion(f.series + ".0")
		if !ok {
			continue
		}
		if maj > fm || (maj == fm && min > fn) {
			return true
		}
	}
	return false
}

// parseKernelVersion extracts the leading semver-like prefix from a kernel
// release string like "6.17.4-1-pve" → (6, 17, 4, true).
func parseKernelVersion(s string) (int, int, int, bool) {
	// trim a leading "v" if present.
	s = strings.TrimPrefix(s, "v")
	parts := strings.SplitN(s, "-", 2)
	core := parts[0]
	dot := strings.Split(core, ".")
	if len(dot) < 2 {
		return 0, 0, 0, false
	}
	maj, e1 := strconv.Atoi(dot[0])
	min, e2 := strconv.Atoi(dot[1])
	patch := 0
	if len(dot) >= 3 {
		patch, _ = strconv.Atoi(dot[2])
	}
	if e1 != nil || e2 != nil {
		return 0, 0, 0, false
	}
	return maj, min, patch, true
}

// compareKernelStrings returns -1/0/+1 for a<b / a==b / a>b. Compares the
// first three numeric components and falls back to lexical for the rest
// (so 6.17.4-1-pve > 6.17.4 because the suffix sorts after empty).
func compareKernelStrings(a, b string) int {
	if a == b {
		return 0
	}
	am1, am2, am3, aok := parseKernelVersion(a)
	bm1, bm2, bm3, bok := parseKernelVersion(b)
	if !aok && !bok {
		return strings.Compare(a, b)
	}
	if !aok {
		return -1
	}
	if !bok {
		return 1
	}
	switch {
	case am1 != bm1:
		if am1 > bm1 {
			return 1
		}
		return -1
	case am2 != bm2:
		if am2 > bm2 {
			return 1
		}
		return -1
	case am3 != bm3:
		if am3 > bm3 {
			return 1
		}
		return -1
	}
	// Compare suffix lexically.
	getSuffix := func(s string) string {
		if i := strings.Index(s, "-"); i >= 0 {
			return s[i:]
		}
		return ""
	}
	return strings.Compare(getSuffix(a), getSuffix(b))
}
