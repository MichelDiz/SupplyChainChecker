package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

const defaultMaxReadBytes = 64 << 20

var (
	manifestVersionMatchers = map[string][]string{
		"axios":           {"1.14.1", "0.30.4"},
		"plain-crypto-js": {"4.2.1"},
	}
	defaultSkipDirs = map[string]struct{}{
		".git":           {},
		".hg":            {},
		".svn":           {},
		".cache":         {},
		".idea":          {},
		".vscode":        {},
		".turbo":         {},
		"dist":           {},
		"build":          {},
		"coverage":       {},
		"target":         {},
		"vendor":         {},
		"bin":            {},
		"obj":            {},
		".next":          {},
		".Trash":         {},
		"Library/Caches": {},
	}
	interestingFiles = map[string]struct{}{
		"package.json":        {},
		"package-lock.json":   {},
		"npm-shrinkwrap.json": {},
		"yarn.lock":           {},
		"pnpm-lock.yaml":      {},
		"bun.lock":            {},
		"bun.lockb":           {},
	}
	pnpmLockPattern       = regexp.MustCompile(`(?m)^\s*\/?((?:@[^/\s:]+/)?[^@\s:()]+)@([0-9]+\.[0-9]+\.[0-9]+)(?:\(|:|$)`)
	versionLinePattern    = regexp.MustCompile(`(?i)^\s*version[: ]+"?([0-9]+\.[0-9]+\.[0-9]+)"?\s*$`)
	resolutionLinePattern = regexp.MustCompile(`(?i)^\s*resolution[: ]+"?([^"]+)"?\s*$`)
)

type Config struct {
	Roots      []string
	SkipDirs   []string
	IncludeIOC bool
	IgnoreFile string
}

type Report struct {
	Roots           []string      `json:"roots"`
	UsedDefaultRoot bool          `json:"used_default_root"`
	IgnoreFiles     []string      `json:"ignore_files,omitempty"`
	StartedAt       time.Time     `json:"started_at"`
	FinishedAt      time.Time     `json:"finished_at"`
	Duration        time.Duration `json:"duration"`
	Stats           Stats         `json:"stats"`
	Findings        []Finding     `json:"findings"`
	Errors          []ScanError   `json:"errors"`
	FatalError      string        `json:"fatal_error,omitempty"`
}

type Stats struct {
	Directories  int `json:"directories"`
	Files        int `json:"files"`
	Manifests    int `json:"manifests"`
	Lockfiles    int `json:"lockfiles"`
	NodeModules  int `json:"node_modules"`
	IOCChecks    int `json:"ioc_checks"`
	IgnoredPaths int `json:"ignored_paths"`
}

type Finding struct {
	Severity string `json:"severity"`
	Category string `json:"category"`
	Package  string `json:"package,omitempty"`
	Version  string `json:"version,omitempty"`
	Path     string `json:"path"`
	Details  string `json:"details"`
}

func (f Finding) Title() string {
	switch {
	case f.Package != "" && f.Version != "":
		return fmt.Sprintf("%s@%s", f.Package, f.Version)
	case f.Package != "":
		return f.Package
	default:
		return f.Category
	}
}

type ScanError struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

type scanner struct {
	report    Report
	skipNames map[string]struct{}
	dedup     map[string]struct{}
}

type ignoreMatcher struct {
	rules []ignoreRule
}

type ignoreRule struct {
	Mode  ignoreRuleMode
	Value string
}

type ignoreRuleMode int

const (
	ignoreByBaseName ignoreRuleMode = iota
	ignoreByRelativePrefix
	ignoreByAbsolutePrefix
)

type manifestPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func Scan(cfg Config) Report {
	startedAt := time.Now()
	sc := &scanner{
		report: Report{
			StartedAt: startedAt,
		},
		skipNames: make(map[string]struct{}),
		dedup:     make(map[string]struct{}),
	}

	for name := range defaultSkipDirs {
		sc.skipNames[name] = struct{}{}
	}
	for _, name := range cfg.SkipDirs {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		sc.skipNames[name] = struct{}{}
	}

	roots, usedDefaultRoot, err := normalizeRoots(cfg.Roots)
	if err != nil {
		sc.report.FatalError = err.Error()
		sc.finish()
		return sc.report
	}

	sc.report.Roots = roots
	sc.report.UsedDefaultRoot = usedDefaultRoot
	for _, root := range roots {
		matcher, ignoreFilePath, loadErr := loadIgnoreMatcher(root, cfg.IgnoreFile)
		if loadErr != nil {
			sc.addError(root, loadErr)
		}
		if ignoreFilePath != "" {
			sc.report.IgnoreFiles = append(sc.report.IgnoreFiles, ignoreFilePath)
		}
		sc.walk(root, matcher)
	}

	if cfg.IncludeIOC {
		sc.scanHostIOCs()
	}

	sc.finish()
	return sc.report
}

func (r Report) WarningCount() int {
	count := 0
	for _, finding := range r.Findings {
		if finding.Severity == "warning" {
			count++
		}
	}
	return count
}

func (s *scanner) finish() {
	s.report.FinishedAt = time.Now()
	s.report.Duration = s.report.FinishedAt.Sub(s.report.StartedAt).Round(time.Millisecond)
	sort.Slice(s.report.Findings, func(i, j int) bool {
		left := s.report.Findings[i]
		right := s.report.Findings[j]
		leftKey := strings.Join([]string{left.Severity, left.Category, left.Path, left.Package, left.Version}, "|")
		rightKey := strings.Join([]string{right.Severity, right.Category, right.Path, right.Package, right.Version}, "|")
		return leftKey < rightKey
	})
	sort.Slice(s.report.Errors, func(i, j int) bool {
		return s.report.Errors[i].Path < s.report.Errors[j].Path
	})
}

func normalizeRoots(input []string) ([]string, bool, error) {
	if len(input) == 0 {
		currentUser, err := user.Current()
		if err != nil {
			return nil, false, fmt.Errorf("could not resolve home directory: %w", err)
		}
		return []string{currentUser.HomeDir}, true, nil
	}

	seen := make(map[string]struct{})
	roots := make([]string, 0, len(input))
	for _, root := range input {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		absoluteRoot, err := filepath.Abs(root)
		if err != nil {
			return nil, false, fmt.Errorf("could not resolve root %q: %w", root, err)
		}
		if _, exists := seen[absoluteRoot]; exists {
			continue
		}
		seen[absoluteRoot] = struct{}{}
		roots = append(roots, absoluteRoot)
	}

	if len(roots) == 0 {
		return nil, false, fmt.Errorf("no valid roots were provided")
	}

	return roots, false, nil
}

func (s *scanner) walk(root string, matcher ignoreMatcher) {
	info, err := os.Stat(root)
	if err != nil {
		s.addError(root, err)
		return
	}
	if !info.IsDir() {
		s.addError(root, fmt.Errorf("root is not a directory"))
		return
	}

	s.scanDir(root, root, matcher)
}

func (s *scanner) scanDir(root, dir string, matcher ignoreMatcher) {
	s.report.Stats.Directories++
	entries, err := os.ReadDir(dir)
	if err != nil {
		s.addError(dir, err)
		return
	}

	for _, entry := range entries {
		fullPath := filepath.Join(dir, entry.Name())
		if entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		if s.shouldIgnorePath(root, fullPath, entry.Name(), matcher) {
			s.report.Stats.IgnoredPaths++
			continue
		}

		if entry.IsDir() {
			if entry.Name() == "node_modules" {
				s.scanNodeModules(fullPath)
				continue
			}
			if s.shouldSkipDir(dir, entry.Name()) {
				continue
			}
			s.scanDir(root, fullPath, matcher)
			continue
		}

		if _, ok := interestingFiles[entry.Name()]; !ok {
			continue
		}
		s.report.Stats.Files++
		s.scanFile(fullPath)
	}
}

func (s *scanner) shouldSkipDir(parent, name string) bool {
	if _, ok := s.skipNames[name]; ok {
		return true
	}
	combined := filepath.ToSlash(filepath.Join(filepath.Base(parent), name))
	_, ok := s.skipNames[combined]
	return ok
}

func (s *scanner) shouldIgnorePath(root, fullPath, baseName string, matcher ignoreMatcher) bool {
	return matcher.matches(root, fullPath, baseName)
}

func (s *scanner) scanFile(path string) {
	switch filepath.Base(path) {
	case "package.json":
		s.report.Stats.Manifests++
		s.scanManifest(path)
	case "package-lock.json", "npm-shrinkwrap.json":
		s.report.Stats.Lockfiles++
		s.scanNPMJSONLockfile(path)
	case "yarn.lock":
		s.report.Stats.Lockfiles++
		s.scanYarnLock(path)
	case "pnpm-lock.yaml":
		s.report.Stats.Lockfiles++
		s.scanPNPMLock(path)
	case "bun.lock", "bun.lockb":
		s.report.Stats.Lockfiles++
		s.scanRawLockfile(path)
	}
}

func (s *scanner) scanManifest(path string) {
	data, err := readFile(path)
	if err != nil {
		s.addError(path, err)
		return
	}

	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		s.addError(path, fmt.Errorf("invalid JSON: %w", err))
		return
	}

	sections := []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"}
	for _, section := range sections {
		rawSection, ok := payload[section]
		if !ok {
			continue
		}
		s.scanManifestSection(path, section, rawSection)
	}

	for _, section := range []string{"overrides", "resolutions"} {
		rawSection, ok := payload[section]
		if !ok {
			continue
		}
		s.scanNestedDependencyConfig(path, section, rawSection)
	}
}

func (s *scanner) scanManifestSection(path, section string, raw any) {
	mapping, ok := raw.(map[string]any)
	if !ok {
		return
	}

	for dependencyName, rawValue := range mapping {
		spec, ok := rawValue.(string)
		if !ok {
			continue
		}
		for _, version := range manifestVersionMatchers[dependencyName] {
			if !containsVersionToken(spec, version) {
				continue
			}
			s.addFinding(Finding{
				Severity: "warning",
				Category: "manifest-reference",
				Package:  dependencyName,
				Version:  version,
				Path:     path,
				Details:  fmt.Sprintf("%s references %s with spec %q. This does not prove installation, but it could have resolved to the malicious version during the March 31, 2026 attack window.", section, dependencyName, spec),
			})
		}
	}
}

func (s *scanner) scanNestedDependencyConfig(path, section string, raw any) {
	mapping, ok := raw.(map[string]any)
	if !ok {
		return
	}

	for dependencyName, nested := range mapping {
		switch value := nested.(type) {
		case string:
			for _, version := range manifestVersionMatchers[dependencyName] {
				if !containsVersionToken(value, version) {
					continue
				}
				s.addFinding(Finding{
					Severity: "warning",
					Category: "manifest-reference",
					Package:  dependencyName,
					Version:  version,
					Path:     path,
					Details:  fmt.Sprintf("%s pins %s with value %q. This is a suspicious manifest reference and should be reviewed.", section, dependencyName, value),
				})
			}
		case map[string]any:
			s.scanNestedDependencyConfig(path, section, value)
		}
	}
}

func (s *scanner) scanNPMJSONLockfile(path string) {
	data, err := readFile(path)
	if err != nil {
		s.addError(path, err)
		return
	}

	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		s.addError(path, fmt.Errorf("invalid JSON lockfile: %w", err))
		return
	}

	if packagesRaw, ok := payload["packages"].(map[string]any); ok {
		for packagePath, rawValue := range packagesRaw {
			mapping, ok := rawValue.(map[string]any)
			if !ok {
				continue
			}
			name, _ := mapping["name"].(string)
			if name == "" {
				name = inferPackageNameFromPath(packagePath)
			}
			version, _ := mapping["version"].(string)
			s.addLockfileFinding(path, name, version, fmt.Sprintf("npm lockfile resolves %s to %s at %s", name, version, packagePath))
		}
	}

	if dependenciesRaw, ok := payload["dependencies"].(map[string]any); ok {
		s.walkNPMDependencies(path, dependenciesRaw)
	}
}

func (s *scanner) walkNPMDependencies(path string, dependencies map[string]any) {
	for packageName, rawValue := range dependencies {
		mapping, ok := rawValue.(map[string]any)
		if !ok {
			continue
		}
		version, _ := mapping["version"].(string)
		s.addLockfileFinding(path, packageName, version, fmt.Sprintf("npm lockfile resolves %s to %s", packageName, version))

		nestedDependencies, ok := mapping["dependencies"].(map[string]any)
		if ok {
			s.walkNPMDependencies(path, nestedDependencies)
		}
	}
}

func (s *scanner) scanYarnLock(path string) {
	data, err := readFile(path)
	if err != nil {
		s.addError(path, err)
		return
	}

	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	blocks := strings.Split(text, "\n\n")
	for _, block := range blocks {
		block = strings.TrimSpace(block)
		if block == "" {
			continue
		}

		lines := strings.Split(block, "\n")
		if len(lines) == 0 {
			continue
		}

		keyLine := strings.TrimSpace(lines[0])
		if !strings.HasSuffix(keyLine, ":") {
			continue
		}

		var version string
		var resolution string
		for _, line := range lines[1:] {
			trimmed := strings.TrimSpace(line)
			if matches := versionLinePattern.FindStringSubmatch(trimmed); len(matches) == 2 {
				version = matches[1]
			}
			if matches := resolutionLinePattern.FindStringSubmatch(trimmed); len(matches) == 2 {
				resolution = matches[1]
			}
		}

		for _, selector := range splitYarnSelectors(strings.TrimSuffix(keyLine, ":")) {
			packageName := yarnSelectorPackageName(selector)
			if packageName == "" {
				continue
			}
			s.addLockfileFinding(path, packageName, version, fmt.Sprintf("yarn lockfile resolves %s through selector %q", packageName, selector))
			s.addResolutionFinding(path, packageName, resolution)
		}
	}

	s.scanRawTokens(path, data)
}

func (s *scanner) scanPNPMLock(path string) {
	data, err := readFile(path)
	if err != nil {
		s.addError(path, err)
		return
	}

	matches := pnpmLockPattern.FindAllStringSubmatch(string(data), -1)
	for _, match := range matches {
		if len(match) != 3 {
			continue
		}
		s.addLockfileFinding(path, match[1], match[2], fmt.Sprintf("pnpm lockfile contains %s@%s", match[1], match[2]))
	}

	s.scanRawTokens(path, data)
}

func (s *scanner) scanRawLockfile(path string) {
	data, err := readFile(path)
	if err != nil {
		s.addError(path, err)
		return
	}
	s.scanRawTokens(path, data)
}

func (s *scanner) scanRawTokens(path string, data []byte) {
	for packageName, versions := range manifestVersionMatchers {
		for _, version := range versions {
			token := []byte(packageName + "@" + version)
			if !bytes.Contains(data, token) {
				continue
			}
			s.addFinding(Finding{
				Severity: "critical",
				Category: "lockfile",
				Package:  packageName,
				Version:  version,
				Path:     path,
				Details:  fmt.Sprintf("raw lockfile content contains %s@%s", packageName, version),
			})
		}
	}
}

func (s *scanner) addResolutionFinding(path, packageName, resolution string) {
	if resolution == "" {
		return
	}
	for _, version := range manifestVersionMatchers[packageName] {
		token := packageName + "@npm:" + version
		if !strings.Contains(resolution, token) {
			continue
		}
		s.addFinding(Finding{
			Severity: "critical",
			Category: "lockfile",
			Package:  packageName,
			Version:  version,
			Path:     path,
			Details:  fmt.Sprintf("yarn resolution explicitly pins %s", token),
		})
	}
}

func (s *scanner) addLockfileFinding(path, packageName, version, details string) {
	if !isMaliciousPackageVersion(packageName, version) {
		return
	}
	s.addFinding(Finding{
		Severity: "critical",
		Category: "lockfile",
		Package:  packageName,
		Version:  version,
		Path:     path,
		Details:  details,
	})
}

func (s *scanner) scanNodeModules(root string) {
	s.report.Stats.NodeModules++
	entries, err := os.ReadDir(root)
	if err != nil {
		s.addError(root, err)
		return
	}

	for _, entry := range entries {
		fullPath := filepath.Join(root, entry.Name())
		if entry.Type()&os.ModeSymlink != 0 {
			continue
		}

		if !entry.IsDir() {
			continue
		}

		switch entry.Name() {
		case "axios", "plain-crypto-js":
			s.scanInstalledPackage(filepath.Join(fullPath, "package.json"))
		case ".pnpm":
			s.scanPnpmStore(fullPath)
		case "@types":
			continue
		}
	}
}

func (s *scanner) scanPnpmStore(root string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		s.addError(root, err)
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		fullPath := filepath.Join(root, entry.Name())
		if packageName, version, ok := matchPackageVersionToken(entry.Name()); ok {
			s.addFinding(Finding{
				Severity: "critical",
				Category: "installed-package",
				Package:  packageName,
				Version:  version,
				Path:     fullPath,
				Details:  fmt.Sprintf("pnpm store directory name indicates %s@%s is installed", packageName, version),
			})
		}

		for _, packageName := range []string{"axios", "plain-crypto-js"} {
			s.scanInstalledPackage(filepath.Join(fullPath, "node_modules", packageName, "package.json"))
		}
	}
}

func (s *scanner) scanInstalledPackage(path string) {
	data, err := readFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		s.addError(path, err)
		return
	}

	var manifest manifestPackage
	if err := json.Unmarshal(data, &manifest); err != nil {
		s.addError(path, fmt.Errorf("invalid package JSON: %w", err))
		return
	}

	if !isMaliciousPackageVersion(manifest.Name, manifest.Version) {
		return
	}
	s.addFinding(Finding{
		Severity: "critical",
		Category: "installed-package",
		Package:  manifest.Name,
		Version:  manifest.Version,
		Path:     path,
		Details:  fmt.Sprintf("installed dependency %s@%s is currently present under node_modules", manifest.Name, manifest.Version),
	})
}

func (s *scanner) scanHostIOCs() {
	s.report.Stats.IOCChecks++
	switch runtime.GOOS {
	case "windows":
		s.scanWindowsIOCs()
	default:
		s.scanUnixLikeIOCs()
	}
}

func (s *scanner) scanUnixLikeIOCs() {
	roots := candidateTempRoots()
	for _, root := range roots {
		s.scanIOCSearchRoot(root, 3)
	}
}

func (s *scanner) scanWindowsIOCs() {
	roots := candidateTempRoots()
	for _, root := range roots {
		s.scanIOCSearchRoot(root, 3)
	}

	programData := os.Getenv("PROGRAMDATA")
	if programData == "" {
		return
	}

	systemBat := filepath.Join(programData, "system.bat")
	s.matchFileHash(systemBat, "f7d335205b8d7b20208fb3ef93ee6dc817905dc3ae0c10a0b164f4e7d07121cd", "ioc-file", "Malicious Windows persistence batch file matches the published IOC hash.")

	wtPath := filepath.Join(programData, "wt.exe")
	if fileExists(wtPath) {
		s.addFinding(Finding{
			Severity: "critical",
			Category: "ioc-file",
			Path:     wtPath,
			Details:  "ProgramData contains wt.exe, which matches the published Axios compromise persistence location.",
		})
	}

	command := exec.Command("reg", "query", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "/v", "MicrosoftUpdate")
	output, err := command.CombinedOutput()
	if err == nil && bytes.Contains(output, []byte("MicrosoftUpdate")) {
		s.addFinding(Finding{
			Severity: "critical",
			Category: "ioc-registry",
			Path:     `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate`,
			Details:  "Windows Run persistence key exists and matches the published IOC.",
		})
	}
}

func (s *scanner) scanIOCSearchRoot(root string, maxDepth int) {
	if root == "" {
		return
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return
	}

	s.scanIOCSearchDir(root, 0, maxDepth)
}

func (s *scanner) scanIOCSearchDir(root string, depth, maxDepth int) {
	if depth > maxDepth {
		return
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			continue
		}

		fullPath := filepath.Join(root, entry.Name())
		if entry.IsDir() {
			s.scanIOCSearchDir(fullPath, depth+1, maxDepth)
			continue
		}

		switch entry.Name() {
		case "com.apple.act.mond":
			s.matchFileHash(fullPath, "92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a", "ioc-file", "macOS payload file matches the published IOC hash.")
		case "6202033.ps1":
			s.matchFileHash(fullPath, "617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101", "ioc-file", "PowerShell payload file matches the published IOC hash.")
		case "ld.py":
			s.matchFileHash(fullPath, "fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf", "ioc-file", "Linux payload file matches the published IOC hash.")
		case "system.bat":
			s.matchFileHash(fullPath, "f7d335205b8d7b20208fb3ef93ee6dc817905dc3ae0c10a0b164f4e7d07121cd", "ioc-file", "Windows batch payload matches the published IOC hash.")
		case "setup.js":
			s.matchFileHash(fullPath, "e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09", "ioc-file", "Malicious plain-crypto-js setup.js matches the published IOC hash.")
		}
	}
}

func (s *scanner) matchFileHash(path, expectedHash, category, details string) {
	data, err := readFile(path)
	if err != nil {
		return
	}
	sum := sha256.Sum256(data)
	actualHash := hex.EncodeToString(sum[:])
	if !strings.EqualFold(actualHash, expectedHash) {
		return
	}

	s.addFinding(Finding{
		Severity: "critical",
		Category: category,
		Path:     path,
		Details:  details,
	})
}

func (s *scanner) addFinding(finding Finding) {
	key := strings.Join([]string{finding.Severity, finding.Category, finding.Path, finding.Package, finding.Version, finding.Details}, "|")
	if _, exists := s.dedup[key]; exists {
		return
	}
	s.dedup[key] = struct{}{}
	s.report.Findings = append(s.report.Findings, finding)
}

func (s *scanner) addError(path string, err error) {
	if err == nil {
		return
	}
	s.report.Errors = append(s.report.Errors, ScanError{
		Path:    path,
		Message: err.Error(),
	})
}

func readFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if info.Size() > defaultMaxReadBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", defaultMaxReadBytes)
	}
	return os.ReadFile(path)
}

func inferPackageNameFromPath(packagePath string) string {
	normalized := filepath.ToSlash(packagePath)
	parts := strings.Split(normalized, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] != "node_modules" || i+1 >= len(parts) {
			continue
		}
		if strings.HasPrefix(parts[i+1], "@") && i+2 < len(parts) {
			return parts[i+1] + "/" + parts[i+2]
		}
		return parts[i+1]
	}
	return ""
}

func containsVersionToken(spec, version string) bool {
	replacer := strings.NewReplacer(".", `\.`, "-", `\-`)
	pattern := fmt.Sprintf(`(^|[^0-9])%s([^0-9]|$)`, replacer.Replace(version))
	matcher := regexp.MustCompile(pattern)
	return matcher.MatchString(spec)
}

func isMaliciousPackageVersion(packageName, version string) bool {
	switch packageName {
	case "axios":
		return version == "1.14.1" || version == "0.30.4"
	case "plain-crypto-js":
		return version == "4.2.1"
	default:
		return false
	}
}

func splitYarnSelectors(line string) []string {
	parts := strings.Split(line, ",")
	selectors := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, `"`)
		if part == "" {
			continue
		}
		selectors = append(selectors, part)
	}
	return selectors
}

func yarnSelectorPackageName(selector string) string {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return ""
	}
	selector = strings.TrimPrefix(selector, "npm:")
	if strings.HasPrefix(selector, "@") {
		secondAt := strings.Index(selector[1:], "@")
		if secondAt == -1 {
			return ""
		}
		return selector[:secondAt+1]
	}
	firstAt := strings.Index(selector, "@")
	if firstAt == -1 {
		return ""
	}
	return selector[:firstAt]
}

func matchPackageVersionToken(name string) (string, string, bool) {
	for packageName, versions := range manifestVersionMatchers {
		for _, version := range versions {
			if strings.Contains(name, packageName+"@"+version) {
				return packageName, version, true
			}
		}
	}
	return "", "", false
}

func candidateTempRoots() []string {
	roots := []string{os.TempDir()}
	switch runtime.GOOS {
	case "darwin", "linux":
		roots = append(roots, "/tmp", "/var/tmp")
	}

	seen := make(map[string]struct{})
	unique := make([]string, 0, len(roots))
	for _, root := range roots {
		if root == "" {
			continue
		}
		if _, ok := seen[root]; ok {
			continue
		}
		seen[root] = struct{}{}
		unique = append(unique, root)
	}
	return unique
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func loadIgnoreMatcher(root, ignoreFile string) (ignoreMatcher, string, error) {
	if strings.TrimSpace(ignoreFile) == "" {
		return ignoreMatcher{}, "", nil
	}

	ignorePath := ignoreFile
	if !filepath.IsAbs(ignorePath) {
		ignorePath = filepath.Join(root, ignoreFile)
	}

	data, err := os.ReadFile(ignorePath)
	if err != nil {
		if os.IsNotExist(err) {
			return ignoreMatcher{}, "", nil
		}
		return ignoreMatcher{}, "", fmt.Errorf("could not read ignore file %s: %w", ignorePath, err)
	}

	matcher := ignoreMatcher{}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		normalized := filepath.ToSlash(line)
		normalized = strings.TrimPrefix(normalized, "./")
		normalized = strings.TrimSuffix(normalized, "/")
		normalized = strings.TrimSuffix(normalized, string(filepath.Separator))
		if normalized == "" {
			continue
		}

		switch {
		case filepath.IsAbs(line):
			matcher.rules = append(matcher.rules, ignoreRule{
				Mode:  ignoreByAbsolutePrefix,
				Value: filepath.ToSlash(filepath.Clean(line)),
			})
		case strings.Contains(normalized, "/"):
			matcher.rules = append(matcher.rules, ignoreRule{
				Mode:  ignoreByRelativePrefix,
				Value: normalized,
			})
		default:
			matcher.rules = append(matcher.rules, ignoreRule{
				Mode:  ignoreByBaseName,
				Value: normalized,
			})
		}
	}

	return matcher, ignorePath, nil
}

func (m ignoreMatcher) matches(root, fullPath, baseName string) bool {
	if len(m.rules) == 0 {
		return false
	}

	normalizedFullPath := filepath.ToSlash(filepath.Clean(fullPath))
	relativePath, err := filepath.Rel(root, fullPath)
	if err != nil {
		relativePath = ""
	}
	normalizedRelativePath := filepath.ToSlash(filepath.Clean(relativePath))

	for _, rule := range m.rules {
		switch rule.Mode {
		case ignoreByBaseName:
			if baseName == rule.Value {
				return true
			}
		case ignoreByRelativePrefix:
			if matchesPrefix(normalizedRelativePath, rule.Value) {
				return true
			}
		case ignoreByAbsolutePrefix:
			if matchesPrefix(normalizedFullPath, rule.Value) {
				return true
			}
		}
	}

	return false
}

func matchesPrefix(candidate, prefix string) bool {
	if candidate == "" || prefix == "" {
		return false
	}
	return candidate == prefix || strings.HasPrefix(candidate, prefix+"/")
}
