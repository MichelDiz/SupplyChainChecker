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
