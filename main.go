package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

type multiFlag []string

func (m *multiFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func main() {
	var roots multiFlag
	var skips multiFlag
	var jsonOutput bool
	var noIOC bool
	var ignoreFile string

	flag.Var(&roots, "root", "Root directory to scan. Repeat the flag to scan multiple locations.")
	flag.Var(&skips, "skip-dir", "Directory name to skip during traversal. Repeat the flag to add more names.")
	flag.BoolVar(&jsonOutput, "json", false, "Print the full report as JSON.")
	flag.BoolVar(&noIOC, "no-ioc", false, "Disable host IOC checks and scan only project files.")
	flag.StringVar(&ignoreFile, "ignore-file", ".checkignore", "Ignore file name or absolute path. Default: .checkignore")
	flag.Parse()

	report := Scan(Config{
		Roots:      roots,
		SkipDirs:   skips,
		IncludeIOC: !noIOC,
		IgnoreFile: ignoreFile,
	})

	if jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "failed to encode report: %v\n", err)
			os.Exit(2)
		}
	} else {
		printTextReport(report)
	}

	switch {
	case report.FatalError != "":
		os.Exit(2)
	case len(report.Findings) > 0:
		os.Exit(1)
	default:
		os.Exit(0)
	}
}

func printTextReport(report Report) {
	fmt.Println("Axios Supply Chain Scanner")
	fmt.Println()
	fmt.Printf("Started:  %s\n", report.StartedAt.Format("2006-01-02 15:04:05 -0700"))
	fmt.Printf("Finished: %s\n", report.FinishedAt.Format("2006-01-02 15:04:05 -0700"))
	fmt.Printf("Duration: %s\n", report.Duration)
	fmt.Printf("Roots:    %s\n", strings.Join(report.Roots, ", "))
	if report.UsedDefaultRoot {
		fmt.Println("Mode:     default root (current user home)")
	}
	if len(report.IgnoreFiles) > 0 {
		fmt.Printf("Ignore:   %s\n", strings.Join(report.IgnoreFiles, ", "))
	}
	fmt.Println()

	fmt.Printf("Summary: %d finding(s), %d warning(s), %d skipped path error(s), %d ignored path(s)\n",
		len(report.Findings),
		report.WarningCount(),
		len(report.Errors),
		report.Stats.IgnoredPaths,
	)
	fmt.Printf("Scanned: %d directorie(s), %d file(s), %d manifest(s), %d lockfile(s), %d node_modules tree(s)\n",
		report.Stats.Directories,
		report.Stats.Files,
		report.Stats.Manifests,
		report.Stats.Lockfiles,
		report.Stats.NodeModules,
	)

	if len(report.Findings) == 0 {
		fmt.Println()
		fmt.Println("No suspicious Axios versions or related IOC evidence were found in the scanned roots.")
		if len(report.Errors) > 0 {
			fmt.Println("Some paths could not be read. Re-run with broader permissions if you need full coverage.")
		}
		if report.UsedDefaultRoot {
			fmt.Println("Tip: pass -root to scan only code directories such as ~/DEV, ~/Documents or use .checkignore to skip noisy paths.")
		}
		return
	}

	fmt.Println()
	for _, finding := range report.Findings {
		fmt.Printf("[%s] %s\n", strings.ToUpper(finding.Severity), finding.Title())
		fmt.Printf("Path: %s\n", finding.Path)
		if finding.Ecosystem != "" {
			fmt.Printf("Ecosystem: %s\n", finding.Ecosystem)
		}
		if finding.Package != "" {
			fmt.Printf("Package: %s@%s\n", finding.Package, finding.Version)
		}
		fmt.Printf("Category: %s\n", finding.Category)
		fmt.Printf("Details: %s\n", finding.Details)
		fmt.Println()
	}

	fmt.Println("Recommended next steps:")
	fmt.Println("1. If any critical finding came from a lockfile or installed dependency, treat installs from March 31, 2026 as potentially compromised.")
	fmt.Println("2. Delete affected node_modules and regenerate lockfiles with safe Axios versions.")
	fmt.Println("3. Rotate secrets that were reachable from impacted machines or CI runners.")
	fmt.Println("4. Re-run this scanner after cleanup to confirm the malicious versions are gone.")

	if len(report.Errors) > 0 {
		fmt.Println()
		fmt.Println("Unreadable paths:")
		for _, scanErr := range report.Errors {
			fmt.Printf("- %s: %s\n", scanErr.Path, scanErr.Message)
		}
	}
}
