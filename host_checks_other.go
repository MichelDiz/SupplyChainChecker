//go:build !linux

package main

import (
	"os"
	"runtime"
)

// detectHost returns a minimal HostContext on non-Linux platforms.
// The Linux-only checks below short-circuit to "not applicable" via
// runHostChecks's empty list on these platforms.
func detectHost() HostContext {
	host, _ := os.Hostname()
	return HostContext{
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Hostname: host,
	}
}

// runHostChecks on non-Linux returns a single info entry indicating the host
// posture suite is Linux-only today, so users on macOS/Windows get a clear
// "scanned, but nothing applicable" instead of silent emptiness.
func runHostChecks(ctx HostContext) []HostCheckResult {
	return []HostCheckResult{
		{
			ID:            "host-checks-platform-unsupported",
			Severity:      SeverityInfo,
			Title:         "Host checks not implemented for this platform",
			Description:   "Linux is the only platform with concrete host security checks today. macOS and Windows coverage is on the roadmap.",
			NotApplicable: true,
			Evidence:      "GOOS=" + ctx.OS,
		},
	}
}
