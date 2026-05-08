package main

import (
	"regexp"
	"strings"
)

type packageIncident struct {
	Ecosystem string
	Package   string
	Versions  []string
	Summary   string
}

type indexedIncident struct {
	Ecosystem  string
	Package    string
	Versions   []string
	Summary    string
	versionSet map[string]struct{}
}

var (
	pypiNameSeparatorPattern = regexp.MustCompile(`[-_.]+`)
	knownIncidents           = []packageIncident{
		{
			Ecosystem: "npm",
			Package:   "axios",
			Versions:  []string{"1.14.1", "0.30.4"},
			Summary:   "Axios npm supply chain compromise published on 2026-03-31.",
		},
		{
			Ecosystem: "npm",
			Package:   "plain-crypto-js",
			Versions:  []string{"4.2.1"},
			Summary:   "Malicious dependency used in the Axios npm supply chain compromise.",
		},
		{
			Ecosystem: "pypi",
			Package:   "litellm",
			Versions:  []string{"1.82.7", "1.82.8"},
			Summary:   "LiteLLM PyPI supply chain compromise reported on 2026-03-24.",
		},
		// --- 2026-03 to 2026-05 wave additions ---
		{
			Ecosystem: "pypi",
			Package:   "telnyx",
			Versions:  []string{"4.87.1", "4.87.2"},
			Summary:   "Unauthorized Telnyx PyPI releases (2026-03-27). Treat affected environments as compromised and rotate API keys, cloud credentials, SSH keys, and environment secrets.",
		},
		{
			Ecosystem: "pypi",
			Package:   "xinference",
			Versions:  []string{"2.6.0", "2.6.1", "2.6.2"},
			Summary:   "Compromised Xinference PyPI releases with install/runtime payload; environment takeover risk.",
		},
		{
			Ecosystem: "pypi",
			Package:   "elementary-data",
			Versions:  []string{"0.23.3"},
			Summary:   "Malicious elementary-data PyPI release via CI/CD injection. Steals dbt, Snowflake/BigQuery/Redshift/AWS/GCP/Azure credentials, SSH keys and .env content. Drops marker .trinny-security-update.",
		},
		{
			Ecosystem: "pypi",
			Package:   "lightning",
			Versions:  []string{"2.6.2", "2.6.3"},
			Summary:   "Malicious Lightning PyPI releases with hidden _runtime downloader and obfuscated credential-stealing payload (uses Bun).",
		},
		{
			Ecosystem: "npm",
			Package:   "pgserve",
			Versions:  []string{"1.1.11", "1.1.12", "1.1.13"},
			Summary:   "Malicious pgserve npm releases with postinstall credential harvester and worm-like reinfection of packages owned by the victim.",
		},
		{
			Ecosystem: "npm",
			Package:   "@bitwarden/cli",
			Versions:  []string{"2026.4.0"},
			Summary:   "Invalid/malicious Bitwarden CLI npm release published in the Checkmarx supply chain incident window. Affected users should rotate secrets and remove the package.",
		},
		{
			Ecosystem: "npm",
			Package:   "@cap-js/sqlite",
			Versions:  []string{"2.2.2"},
			Summary:   "Mini Shai-Hulud (SAP cap-js) campaign release with malicious preinstall payload targeting developer and CI/CD secrets.",
		},
		{
			Ecosystem: "npm",
			Package:   "@cap-js/postgres",
			Versions:  []string{"2.2.2"},
			Summary:   "Mini Shai-Hulud (SAP cap-js) campaign release with malicious preinstall payload targeting developer and CI/CD secrets.",
		},
		{
			Ecosystem: "npm",
			Package:   "@cap-js/db-service",
			Versions:  []string{"2.10.1"},
			Summary:   "Mini Shai-Hulud (SAP cap-js) campaign release with malicious preinstall payload targeting developer and CI/CD secrets.",
		},
		{
			Ecosystem: "npm",
			Package:   "mbt",
			Versions:  []string{"1.2.48"},
			Summary:   "Mini Shai-Hulud (SAP build tools) campaign release with malicious preinstall payload targeting developer and CI/CD secrets.",
		},
		{
			Ecosystem: "npm",
			Package:   "intercom-client",
			Versions:  []string{"7.0.5"},
			Summary:   "Trojanized npm release reported in the same TeamPCP/Mini Shai-Hulud wave; public analysis was still in progress when added.",
		},
	}
	incidentIndex = buildIncidentIndex(knownIncidents)
)

func buildIncidentIndex(incidents []packageIncident) map[string]indexedIncident {
	index := make(map[string]indexedIncident, len(incidents))
	for _, incident := range incidents {
		versionSet := make(map[string]struct{}, len(incident.Versions))
		for _, version := range incident.Versions {
			versionSet[version] = struct{}{}
		}
		index[incidentLookupKey(incident.Ecosystem, incident.Package)] = indexedIncident{
			Ecosystem:  incident.Ecosystem,
			Package:    incident.Package,
			Versions:   append([]string(nil), incident.Versions...),
			Summary:    incident.Summary,
			versionSet: versionSet,
		}
	}
	return index
}

func incidentLookupKey(ecosystem, packageName string) string {
	return strings.ToLower(strings.TrimSpace(ecosystem)) + "|" + normalizePackageName(ecosystem, packageName)
}

func normalizePackageName(ecosystem, packageName string) string {
	normalized := strings.ToLower(strings.TrimSpace(packageName))
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "pypi":
		return pypiNameSeparatorPattern.ReplaceAllString(normalized, "-")
	default:
		return normalized
	}
}

func incidentForPackage(ecosystem, packageName string) (indexedIncident, bool) {
	incident, ok := incidentIndex[incidentLookupKey(ecosystem, packageName)]
	return incident, ok
}

func incidentsForEcosystem(ecosystem string) []indexedIncident {
	incidents := make([]indexedIncident, 0)
	for _, incident := range knownIncidents {
		if incident.Ecosystem != ecosystem {
			continue
		}
		indexed, ok := incidentForPackage(incident.Ecosystem, incident.Package)
		if ok {
			incidents = append(incidents, indexed)
		}
	}
	return incidents
}

func isCompromisedPackageVersion(ecosystem, packageName, version string) bool {
	incident, ok := incidentForPackage(ecosystem, packageName)
	if !ok {
		return false
	}
	_, ok = incident.versionSet[version]
	return ok
}

func packageNameCandidates(ecosystem, packageName string) []string {
	normalized := normalizePackageName(ecosystem, packageName)
	if normalized == "" {
		return nil
	}

	candidateSet := map[string]struct{}{
		normalized: {},
	}
	if ecosystem == "pypi" {
		candidateSet[strings.ReplaceAll(normalized, "-", "_")] = struct{}{}
		candidateSet[strings.ReplaceAll(normalized, "-", ".")] = struct{}{}
	}

	candidates := make([]string, 0, len(candidateSet))
	for candidate := range candidateSet {
		candidates = append(candidates, candidate)
	}
	return candidates
}
