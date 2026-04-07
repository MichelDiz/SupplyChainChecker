package main

import (
	"os"
	"path/filepath"
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
