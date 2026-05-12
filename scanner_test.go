package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanDetectsManifestLockfileAndInstalledPackage(t *testing.T) {
	root := t.TempDir()

	writeFile(t, filepath.Join(root, "repo", "package.json"), `{
  "name": "demo",
  "dependencies": {
    "axios": "^1.14.1"
  }
}`)

	writeFile(t, filepath.Join(root, "repo", "package-lock.json"), `{
  "name": "demo",
  "packages": {
    "": {
      "name": "demo"
    },
    "node_modules/axios": {
      "version": "1.14.1"
    },
    "node_modules/plain-crypto-js": {
      "version": "4.2.1"
    }
  }
}`)

	writeFile(t, filepath.Join(root, "repo", "node_modules", "axios", "package.json"), `{
  "name": "axios",
  "version": "1.14.1"
}`)

	report := Scan(Config{
		Roots:      []string{root},
		IncludeIOC: false,
	})

	if len(report.Findings) != 4 {
		t.Fatalf("expected 4 findings, got %d: %#v", len(report.Findings), report.Findings)
	}
	if len(report.Usages) != 4 {
		t.Fatalf("expected 4 usages, got %d: %#v", len(report.Usages), report.Usages)
	}
}

func TestScanDetectsYarnAndPNPMLockfiles(t *testing.T) {
	root := t.TempDir()

	writeFile(t, filepath.Join(root, "workspace", "yarn.lock"), `"axios@^1.13.0":
  version "1.14.1"
  resolution "axios@npm:1.14.1"

"plain-crypto-js@^4.0.0":
  version "4.2.1"
`)

	writeFile(t, filepath.Join(root, "workspace", "pnpm-lock.yaml"), `lockfileVersion: '9.0'

packages:
  axios@0.30.4:
    resolution: {integrity: sha512-demo}
  plain-crypto-js@4.2.1:
    resolution: {integrity: sha512-demo}
`)

	report := Scan(Config{
		Roots:      []string{root},
		IncludeIOC: false,
	})

	assertHasFinding(t, report, "axios", "1.14.1", "lockfile")
	assertHasFinding(t, report, "axios", "0.30.4", "lockfile")
	assertHasFinding(t, report, "plain-crypto-js", "4.2.1", "lockfile")
}

func TestScanDetectsLiteLLMInPythonFilesAndInstalledMetadata(t *testing.T) {
	root := t.TempDir()

	writeFile(t, filepath.Join(root, "python-app", "requirements.txt"), `
litellm==1.82.7
requests==2.32.0
`)

	writeFile(t, filepath.Join(root, "python-app", "uv.lock"), `
version = 1

[[package]]
name = "litellm"
version = "1.82.8"

[[package]]
name = "httpx"
version = "0.28.1"
`)

	writeFile(t, filepath.Join(root, "python-app", ".venv", "lib", "python3.12", "site-packages", "litellm-1.82.8.dist-info", "METADATA"), `
Metadata-Version: 2.1
Name: litellm
Version: 1.82.8
`)

	report := Scan(Config{
		Roots:      []string{root},
		IncludeIOC: false,
	})

	assertHasFinding(t, report, "litellm", "1.82.7", "manifest-reference")
	assertHasFinding(t, report, "litellm", "1.82.8", "lockfile")
	assertHasFinding(t, report, "litellm", "1.82.8", "installed-package")
	assertHasUsageWithStatus(t, report, "litellm", "1.82.8", "installed-package", "compromised")
}

func TestContainsVersionToken(t *testing.T) {
	tests := []struct {
		spec    string
		version string
		match   bool
	}{
		{spec: "^1.14.1", version: "1.14.1", match: true},
		{spec: "npm:axios@1.14.1", version: "1.14.1", match: true},
		{spec: "1.14.10", version: "1.14.1", match: false},
	}

	for _, test := range tests {
		if result := containsVersionToken(test.spec, test.version); result != test.match {
			t.Fatalf("containsVersionToken(%q, %q) = %v, want %v", test.spec, test.version, result, test.match)
		}
	}
}

func TestCheckIgnoreSkipsIgnoredDirectories(t *testing.T) {
	root := t.TempDir()

	writeFile(t, filepath.Join(root, ".checkignore"), `
# ignore noisy locations
ignored-dir/
repo/private
`)

	writeFile(t, filepath.Join(root, "ignored-dir", "package-lock.json"), `{
  "packages": {
    "node_modules/axios": {
      "version": "1.14.1"
    }
  }
}`)

	writeFile(t, filepath.Join(root, "repo", "private", "package-lock.json"), `{
  "packages": {
    "node_modules/plain-crypto-js": {
      "version": "4.2.1"
    }
  }
}`)

	writeFile(t, filepath.Join(root, "repo", "visible", "package-lock.json"), `{
  "packages": {
    "node_modules/axios": {
      "version": "0.30.4"
    }
  }
}`)

	report := Scan(Config{
		Roots:      []string{root},
		IncludeIOC: false,
		IgnoreFile: ".checkignore",
	})

	if report.Stats.IgnoredPaths != 2 {
		t.Fatalf("expected 2 ignored paths, got %d", report.Stats.IgnoredPaths)
	}

	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 visible finding, got %d: %#v", len(report.Findings), report.Findings)
	}

	assertHasFinding(t, report, "axios", "0.30.4", "lockfile")
}

func TestScanDetectsScopedInstalledPackage(t *testing.T) {
	root := t.TempDir()

	writeFile(t, filepath.Join(root, "app", "node_modules", "@tanstack", "react-router", "package.json"), `{
  "name": "@tanstack/react-router",
  "version": "1.169.5"
}`)
	writeFile(t, filepath.Join(root, "app", "node_modules", "@cap-js", "sqlite", "package.json"), `{
  "name": "@cap-js/sqlite",
  "version": "2.2.2"
}`)

	report := Scan(Config{Roots: []string{root}, IncludeIOC: false})

	assertHasFinding(t, report, "@tanstack/react-router", "1.169.5", "installed-package")
	assertHasFinding(t, report, "@cap-js/sqlite", "2.2.2", "installed-package")
}

func TestScanDetectsNestedNodeModulesInstall(t *testing.T) {
	root := t.TempDir()

	// Outer dep (untracked) with a tracked dep nested inside its own
	// node_modules. Real-world example: a build tool pinning an old
	// vulnerable transitive that npm/yarn could not hoist.
	writeFile(t, filepath.Join(root, "app", "node_modules", "outer-pkg", "package.json"), `{
  "name": "outer-pkg",
  "version": "9.9.9"
}`)
	writeFile(t, filepath.Join(root, "app", "node_modules", "outer-pkg", "node_modules", "@mistralai", "mistralai", "package.json"), `{
  "name": "@mistralai/mistralai",
  "version": "2.2.3"
}`)
	writeFile(t, filepath.Join(root, "app", "node_modules", "outer-pkg", "node_modules", "pgserve", "package.json"), `{
  "name": "pgserve",
  "version": "1.1.12"
}`)

	report := Scan(Config{Roots: []string{root}, IncludeIOC: false})

	assertHasFinding(t, report, "@mistralai/mistralai", "2.2.3", "installed-package")
	assertHasFinding(t, report, "pgserve", "1.1.12", "installed-package")
}

func TestScanDetectsScopedInPnpmStore(t *testing.T) {
	root := t.TempDir()

	// pnpm flattens scoped packages with "+" in the store directory name.
	storeDir := filepath.Join(root, "app", "node_modules", ".pnpm", "@tanstack+react-router@1.169.5_react@18.3.1")
	writeFile(t, filepath.Join(storeDir, "node_modules", "@tanstack", "react-router", "package.json"), `{
  "name": "@tanstack/react-router",
  "version": "1.169.5"
}`)

	report := Scan(Config{Roots: []string{root}, IncludeIOC: false})

	// Expect both signals: the store-dir-name finding AND the deep install finding.
	assertHasFinding(t, report, "@tanstack/react-router", "1.169.5", "installed-package")

	// The deep install finding's path is the package.json under the store entry.
	gotInstall := false
	gotStoreDir := false
	for _, f := range report.Findings {
		if f.Package != "@tanstack/react-router" || f.Version != "1.169.5" {
			continue
		}
		if strings.Contains(f.Path, "package.json") {
			gotInstall = true
		}
		if strings.HasSuffix(f.Path, "@tanstack+react-router@1.169.5_react@18.3.1") {
			gotStoreDir = true
		}
	}
	if !gotInstall {
		t.Fatalf("expected installed-package finding pointing at package.json under .pnpm store; got %#v", report.Findings)
	}
	if !gotStoreDir {
		t.Fatalf("expected separate finding for the .pnpm store directory name itself; got %#v", report.Findings)
	}
}

func TestScanDetectsYarnPnPCacheArchive(t *testing.T) {
	root := t.TempDir()

	// Three cache entries: one tracked scoped, one tracked unscoped, one safe.
	cacheDir := filepath.Join(root, "app", ".yarn", "cache")
	writeFile(t, filepath.Join(cacheDir, "@tanstack-react-router-npm-1.169.5-deadbeef-cafebabe.zip"), "synthetic")
	writeFile(t, filepath.Join(cacheDir, "pgserve-npm-1.1.12-abc12345.zip"), "synthetic")
	writeFile(t, filepath.Join(cacheDir, "react-npm-18.3.1-fa1afe1.zip"), "synthetic")

	report := Scan(Config{Roots: []string{root}, IncludeIOC: false})

	assertHasFinding(t, report, "@tanstack/react-router", "1.169.5", "installed-package")
	assertHasFinding(t, report, "pgserve", "1.1.12", "installed-package")
	// react is not tracked; must not produce any finding or usage.
	for _, f := range report.Findings {
		if f.Package == "react" {
			t.Errorf("unexpected finding for untracked react: %#v", f)
		}
	}
	for _, u := range report.Usages {
		if u.Package == "react" {
			t.Errorf("untracked react surfaced as usage: %#v", u)
		}
	}
}

func TestScanDetectsBunIsolatedStore(t *testing.T) {
	root := t.TempDir()

	// Bun's isolated linker uses node_modules/.bun/<pkg>@<ver>/node_modules/<pkg>
	storeDir := filepath.Join(root, "app", "node_modules", ".bun", "pgserve@1.1.13")
	writeFile(t, filepath.Join(storeDir, "node_modules", "pgserve", "package.json"), `{
  "name": "pgserve",
  "version": "1.1.13"
}`)

	report := Scan(Config{Roots: []string{root}, IncludeIOC: false})

	assertHasFinding(t, report, "pgserve", "1.1.13", "installed-package")
}

func TestScanFollowsSymlinkToGlobalStoreForTrackedPackage(t *testing.T) {
	root := t.TempDir()

	// Synthetic "global store" outside the project tree: contains a real
	// package.json for the tracked @mistralai/mistralai@2.2.3 install.
	storeRoot := filepath.Join(root, "global-store", "files", "ab", "cdef")
	writeFile(t, filepath.Join(storeRoot, "package.json"), `{
  "name": "@mistralai/mistralai",
  "version": "2.2.3"
}`)

	// Project tree: node_modules/@mistralai/mistralai is a symlink into the
	// store. Untracked react also symlinked — must NOT be followed.
	projectModules := filepath.Join(root, "app", "node_modules")
	if err := os.MkdirAll(filepath.Join(projectModules, "@mistralai"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(storeRoot, filepath.Join(projectModules, "@mistralai", "mistralai")); err != nil {
		t.Fatalf("symlink mistralai: %v", err)
	}
	reactTarget := filepath.Join(root, "global-store", "files", "ff", "react")
	writeFile(t, filepath.Join(reactTarget, "package.json"), `{"name":"react","version":"18.3.1"}`)
	if err := os.Symlink(reactTarget, filepath.Join(projectModules, "react")); err != nil {
		t.Fatalf("symlink react: %v", err)
	}

	report := Scan(Config{Roots: []string{filepath.Join(root, "app")}, IncludeIOC: false})

	assertHasFinding(t, report, "@mistralai/mistralai", "2.2.3", "installed-package")
	for _, u := range report.Usages {
		if u.Package == "react" {
			t.Errorf("untracked react symlink was followed: %#v", u)
		}
	}
}

func TestPnpmTokenBoundaryRejectsExtendedVersion(t *testing.T) {
	// Version "1.169.5" must NOT match a future "1.169.55".
	if _, _, ok := matchPackageVersionToken("npm", "@tanstack+react-router@1.169.55_react@18.3.1"); ok {
		t.Fatal("matchPackageVersionToken should not match 1.169.5 inside 1.169.55")
	}
	// Sanity: exact "1.169.5" still matches.
	pkg, ver, ok := matchPackageVersionToken("npm", "@tanstack+react-router@1.169.5_react@18.3.1")
	if !ok || pkg != "@tanstack/react-router" || ver != "1.169.5" {
		t.Fatalf("expected (@tanstack/react-router, 1.169.5, true), got (%q, %q, %v)", pkg, ver, ok)
	}
}

func TestScanReportsSafeTrackedUsage(t *testing.T) {
	root := t.TempDir()

	writeFile(t, filepath.Join(root, "repo", "package.json"), `{
  "name": "demo",
  "dependencies": {
    "axios": "^1.14.0"
  }
}`)

	writeFile(t, filepath.Join(root, "repo", "node_modules", "axios", "package.json"), `{
  "name": "axios",
  "version": "1.14.0"
}`)

	report := Scan(Config{
		Roots:      []string{root},
		IncludeIOC: false,
	})

	if len(report.Findings) != 0 {
		t.Fatalf("expected no findings, got %#v", report.Findings)
	}

	assertHasUsageWithStatus(t, report, "axios", "", "manifest", "unknown")
	assertHasUsageWithStatus(t, report, "axios", "1.14.0", "installed-package", "safe")
}

func TestProjectInferenceUsesProjectRoot(t *testing.T) {
	root := t.TempDir()
	projectDir := filepath.Join(root, "repo")

	writeFile(t, filepath.Join(projectDir, "package.json"), `{"name":"demo","dependencies":{"axios":"1.14.0"}}`)
	writeFile(t, filepath.Join(projectDir, "node_modules", "axios", "package.json"), `{"name":"axios","version":"1.14.0"}`)

	report := Scan(Config{
		Roots:      []string{root},
		IncludeIOC: false,
	})

	for _, usage := range report.Usages {
		if usage.Package == "axios" && usage.Source == "installed-package" {
			if usage.Project != projectDir {
				t.Fatalf("expected project %s, got %s", projectDir, usage.Project)
			}
			return
		}
	}

	t.Fatalf("expected installed-package usage, got %#v", report.Usages)
}

func TestScanDetectsLiteLLMInPipfileLock(t *testing.T) {
	root := t.TempDir()

	writeFile(t, filepath.Join(root, "python-app", "Pipfile.lock"), `{
  "default": {
    "litellm": {
      "version": "==1.82.8"
    }
  }
}`)

	report := Scan(Config{
		Roots:      []string{root},
		IncludeIOC: false,
	})

	assertHasFinding(t, report, "litellm", "1.82.8", "lockfile")
}

func TestEndToEndAgainstFixtures(t *testing.T) {
	// Scans the real on-disk fixtures shipped under test/fixtures/.
	// Asserts:
	//   - every "compromised" fixture is detected at least once.
	//   - safe-controls/ never produces a finding.
	//   - exit semantics: findings present (would exit 1 in CLI).
	const fixturesRoot = "test/fixtures"
	if _, err := os.Stat(fixturesRoot); err != nil {
		t.Skipf("fixtures dir missing (%v); run from repo root", err)
	}

	report := Scan(Config{
		Roots:      []string{fixturesRoot},
		IncludeIOC: false,
	})

	type expected struct {
		ecosystem string
		pkg       string
		version   string
	}
	mustDetect := []expected{
		{"npm", "axios", "1.14.1"},
		{"npm", "axios", "0.30.4"},
		{"npm", "plain-crypto-js", "4.2.1"},
		{"npm", "pgserve", "1.1.12"},
		{"npm", "@bitwarden/cli", "2026.4.0"},
		{"npm", "@cap-js/sqlite", "2.2.2"},
		{"npm", "@cap-js/postgres", "2.2.2"},
		{"npm", "@cap-js/db-service", "2.10.1"},
		{"npm", "mbt", "1.2.48"},
		{"npm", "intercom-client", "7.0.5"},
		{"pypi", "litellm", "1.82.7"},
		{"pypi", "telnyx", "4.87.1"},
		{"pypi", "xinference", "2.6.1"},
		{"pypi", "elementary-data", "0.23.3"},
		{"pypi", "lightning", "2.6.3"},
	}

	detected := make(map[expected]bool)
	for _, f := range report.Findings {
		key := expected{f.Ecosystem, f.Package, f.Version}
		detected[key] = true
	}

	missing := []expected{}
	for _, want := range mustDetect {
		if !detected[want] {
			missing = append(missing, want)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("scanner failed to detect %d expected compromised package(s): %#v", len(missing), missing)
	}

	// Negative control: safe-controls/ MUST NOT yield any findings.
	for _, f := range report.Findings {
		if strings.Contains(f.Path, "safe-controls/") {
			t.Errorf("false positive in safe-controls: %#v", f)
		}
	}

	// Sanity: untracked package (react) must not appear at all in usages either.
	for _, u := range report.Usages {
		if u.Package == "react" {
			t.Errorf("untracked package react surfaced as usage: %#v", u)
		}
	}

	if len(report.Findings) == 0 {
		t.Fatal("expected findings > 0, got 0 (smoke check)")
	}

	t.Logf("end-to-end: %d findings across %d expected incidents (no false positives in safe-controls)",
		len(report.Findings), len(mustDetect))
}

func TestNormalizeRootsReportsDefaultHomeUsage(t *testing.T) {
	_, usedDefaultRoot, err := normalizeRoots(nil)
	if err != nil {
		t.Fatalf("normalizeRoots returned error: %v", err)
	}
	if !usedDefaultRoot {
		t.Fatal("expected normalizeRoots to mark default home usage")
	}
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("failed to create directory for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
}

func assertHasFinding(t *testing.T, report Report, packageName, version, category string) {
	t.Helper()
	for _, finding := range report.Findings {
		if finding.Package == packageName && finding.Version == version && finding.Category == category {
			return
		}
	}
	t.Fatalf("expected finding %s@%s (%s), got %#v", packageName, version, category, report.Findings)
}

func assertHasUsageWithStatus(t *testing.T, report Report, packageName, version, source, status string) {
	t.Helper()
	for _, usage := range report.Usages {
		if usage.Package == packageName && usage.Source == source && usage.Status == status {
			if version == "" || usage.Version == version {
				return
			}
		}
	}
	t.Fatalf("expected usage %s@%s source=%s status=%s, got %#v", packageName, version, source, status, report.Usages)
}
