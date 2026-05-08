package main

import "runtime"

// HostCheckSeverity classifies how urgent a host check finding is.
// Strings are stable on the wire (JSON output) and intentionally lowercased.
type HostCheckSeverity string

const (
	SeverityCritical HostCheckSeverity = "critical"
	SeverityHigh     HostCheckSeverity = "high"
	SeverityMedium   HostCheckSeverity = "medium"
	SeverityLow      HostCheckSeverity = "low"
	SeverityInfo     HostCheckSeverity = "info"
)

// HostCheckResult is the outcome of a single check on the host.
//
// Vulnerable=true means "we positively detected the unsafe condition".
// NotApplicable=true means "we deliberately skipped this check on this host"
// (e.g. a Debian-only check on Alpine). Either flag implies the other is
// false. When both are false, the host passed the check.
type HostCheckResult struct {
	ID            string            `json:"id"`
	Severity      HostCheckSeverity `json:"severity"`
	Title         string            `json:"title"`
	Description   string            `json:"description,omitempty"`
	Vulnerable    bool              `json:"vulnerable"`
	NotApplicable bool              `json:"not_applicable,omitempty"`
	Evidence      string            `json:"evidence,omitempty"`
	Remediation   []string          `json:"remediation,omitempty"`
	References    []string          `json:"references,omitempty"`
}

// HostContext is everything the checks need to know about the host.
// Detected once per run.
type HostContext struct {
	OS        string `json:"os"`
	Distro    string `json:"distro,omitempty"`
	DistroVer string `json:"distro_version,omitempty"`
	Kernel    string `json:"kernel,omitempty"`
	Arch      string `json:"arch,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
}

// HostChecksReport is the JSON-friendly report returned by RunHostChecks.
type HostChecksReport struct {
	Context HostContext       `json:"context"`
	Checks  []HostCheckResult `json:"checks"`
}

// RunHostChecks detects the host context and runs every available check.
//
// On non-Linux hosts, only a stub set runs — the bulk of coverage is Linux
// posture (kernel CVEs, sshd policy, package versions). The function never
// shells out to anything beyond the standard library helpers each check uses.
func RunHostChecks() HostChecksReport {
	ctx := detectHost()
	if ctx.Arch == "" {
		ctx.Arch = runtime.GOARCH
	}
	if ctx.OS == "" {
		ctx.OS = runtime.GOOS
	}
	return HostChecksReport{
		Context: ctx,
		Checks:  runHostChecks(ctx),
	}
}

// VulnerableCount returns the number of checks that flagged the host.
// Useful for exit-code logic in main.
func (r HostChecksReport) VulnerableCount() int {
	n := 0
	for _, c := range r.Checks {
		if c.Vulnerable {
			n++
		}
	}
	return n
}

// notApplicable is a small helper for checks that bail out cleanly.
func notApplicable(id, title, reason string) HostCheckResult {
	return HostCheckResult{
		ID:            id,
		Severity:      SeverityInfo,
		Title:         title,
		NotApplicable: true,
		Evidence:      reason,
	}
}
