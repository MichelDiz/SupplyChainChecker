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
			Versions:  []string{"7.0.4", "7.0.5"},
			Summary:   "Trojanized npm release reported in the TeamPCP/Mini Shai-Hulud wave; Wiz catalogued 7.0.4 and 7.0.5 as compromised.",
		},
		// --- Mini Shai-Hulud TanStack wave (2026-05-11) ---
		// 84 versions across 42 @tanstack/* packages, published 19:20-19:26 UTC
		// via GitHub Actions cache poisoning of TanStack/router (PR #7378). Each
		// release ships a ~2.3 MB router_init.js that harvests dev/cloud/CI
		// secrets and self-propagates through packages maintained by the victim.
		// Source: GHSA-g7cv-rxg3-hmpx + https://tanstack.com/blog/npm-supply-chain-compromise-postmortem
		{Ecosystem: "npm", Package: "@tanstack/arktype-adapter", Versions: []string{"1.166.12", "1.166.15"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/eslint-plugin-router", Versions: []string{"1.161.9", "1.161.12"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/eslint-plugin-start", Versions: []string{"0.0.4", "0.0.7"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/history", Versions: []string{"1.161.9", "1.161.12"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/nitro-v2-vite-plugin", Versions: []string{"1.154.12", "1.154.15"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/react-router", Versions: []string{"1.169.5", "1.169.8"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/react-router-devtools", Versions: []string{"1.166.16", "1.166.19"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/react-router-ssr-query", Versions: []string{"1.166.15", "1.166.18"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/react-start", Versions: []string{"1.167.68", "1.167.71"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/react-start-client", Versions: []string{"1.166.51", "1.166.54"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/react-start-rsc", Versions: []string{"0.0.47", "0.0.50"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/react-start-server", Versions: []string{"1.166.55", "1.166.58"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/router-cli", Versions: []string{"1.166.46", "1.166.49"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/router-core", Versions: []string{"1.169.5", "1.169.8"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/router-devtools", Versions: []string{"1.166.16", "1.166.19"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/router-devtools-core", Versions: []string{"1.167.6", "1.167.9"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/router-generator", Versions: []string{"1.166.45", "1.166.48"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/router-plugin", Versions: []string{"1.167.38", "1.167.41"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/router-ssr-query-core", Versions: []string{"1.168.3", "1.168.6"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/router-utils", Versions: []string{"1.161.11", "1.161.14"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/router-vite-plugin", Versions: []string{"1.166.53", "1.166.56"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/solid-router", Versions: []string{"1.169.5", "1.169.8"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/solid-router-devtools", Versions: []string{"1.166.16", "1.166.19"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/solid-router-ssr-query", Versions: []string{"1.166.15", "1.166.18"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/solid-start", Versions: []string{"1.167.65", "1.167.68"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/solid-start-client", Versions: []string{"1.166.50", "1.166.53"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/solid-start-server", Versions: []string{"1.166.54", "1.166.57"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/start-client-core", Versions: []string{"1.168.5", "1.168.8"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/start-fn-stubs", Versions: []string{"1.161.9", "1.161.12"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/start-plugin-core", Versions: []string{"1.169.23", "1.169.26"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/start-server-core", Versions: []string{"1.167.33", "1.167.36"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/start-static-server-functions", Versions: []string{"1.166.44", "1.166.47"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/start-storage-context", Versions: []string{"1.166.38", "1.166.41"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/valibot-adapter", Versions: []string{"1.166.12", "1.166.15"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/virtual-file-routes", Versions: []string{"1.161.10", "1.161.13"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/vue-router", Versions: []string{"1.169.5", "1.169.8"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/vue-router-devtools", Versions: []string{"1.166.16", "1.166.19"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/vue-router-ssr-query", Versions: []string{"1.166.15", "1.166.18"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/vue-start", Versions: []string{"1.167.61", "1.167.64"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/vue-start-client", Versions: []string{"1.166.46", "1.166.49"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/vue-start-server", Versions: []string{"1.166.50", "1.166.53"}, Summary: tanstackMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@tanstack/zod-adapter", Versions: []string{"1.166.12", "1.166.15"}, Summary: tanstackMiniShaiHuludSummary},
		// Peer compromise in the same wave: Mistral AI SDKs published 2026-05-11.
		// Same router_init.js-style payload. Source: Wiz, Aikido, Safedep.
		{Ecosystem: "npm", Package: "@mistralai/mistralai", Versions: []string{"2.2.2", "2.2.3", "2.2.4"}, Summary: mistralMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@mistralai/mistralai-azure", Versions: []string{"1.7.1", "1.7.2", "1.7.3"}, Summary: mistralMiniShaiHuludSummary},
		{Ecosystem: "npm", Package: "@mistralai/mistralai-gcp", Versions: []string{"1.7.1", "1.7.2", "1.7.3"}, Summary: mistralMiniShaiHuludSummary},
		// PyPI side of the same wave — first time the campaign crossed registries.
		{Ecosystem: "pypi", Package: "mistralai", Versions: []string{"2.4.6"}, Summary: mistralMiniShaiHuludSummary},
		{Ecosystem: "pypi", Package: "guardrails-ai", Versions: []string{"0.10.1"}, Summary: miniShaiHuludPeerSummary},
		// --- Peer compromises catalogued by Wiz/Aikido in the Mini Shai-Hulud TanStack wave (2026-05-11) ---
		// @opensearch-project — high-impact, ~1.3M weekly downloads.
		{Ecosystem: "npm", Package: "@opensearch-project/opensearch", Versions: []string{"3.5.3", "3.6.2", "3.7.0", "3.8.0"}, Summary: miniShaiHuludPeerSummary},
		// @uipath/* automation tooling (65 packages).
		{Ecosystem: "npm", Package: "@uipath/access-policy-sdk", Versions: []string{"0.3.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/access-policy-tool", Versions: []string{"0.3.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/admin-tool", Versions: []string{"0.1.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/agent-sdk", Versions: []string{"1.0.2"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/agent-tool", Versions: []string{"1.0.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/agent.sdk", Versions: []string{"0.0.18"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/aops-policy-tool", Versions: []string{"0.3.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/ap-chat", Versions: []string{"1.5.7"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/api-workflow-tool", Versions: []string{"1.0.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/apollo-core", Versions: []string{"5.9.2"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/apollo-react", Versions: []string{"4.24.5"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/apollo-wind", Versions: []string{"2.16.2"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/auth", Versions: []string{"1.0.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/case-tool", Versions: []string{"1.0.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/cli", Versions: []string{"1.0.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/codedagent-tool", Versions: []string{"1.0.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/codedagents-tool", Versions: []string{"0.1.12"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/codedapp-tool", Versions: []string{"1.0.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/common", Versions: []string{"1.0.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/context-grounding-tool", Versions: []string{"0.1.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/data-fabric-tool", Versions: []string{"1.0.2"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/docsai-tool", Versions: []string{"1.0.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/filesystem", Versions: []string{"1.0.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/flow-tool", Versions: []string{"1.0.2"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/functions-tool", Versions: []string{"1.0.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/gov-tool", Versions: []string{"0.3.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/identity-tool", Versions: []string{"0.1.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/insights-sdk", Versions: []string{"1.0.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/insights-tool", Versions: []string{"1.0.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/integrationservice-sdk", Versions: []string{"1.0.2"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/integrationservice-tool", Versions: []string{"1.0.2"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/llmgw-tool", Versions: []string{"1.0.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/maestro-sdk", Versions: []string{"1.0.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/maestro-tool", Versions: []string{"1.0.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/orchestrator-tool", Versions: []string{"1.0.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/packager-tool-apiworkflow", Versions: []string{"0.0.19"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/packager-tool-bpmn", Versions: []string{"0.0.9"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/packager-tool-case", Versions: []string{"0.0.9"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/packager-tool-connector", Versions: []string{"0.0.19"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/packager-tool-flow", Versions: []string{"0.0.19"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/packager-tool-functions", Versions: []string{"0.1.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/packager-tool-webapp", Versions: []string{"1.0.6"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/packager-tool-workflowcompiler", Versions: []string{"0.0.16"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/packager-tool-workflowcompiler-browser", Versions: []string{"0.0.34"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/platform-tool", Versions: []string{"1.0.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/project-packager", Versions: []string{"1.1.16"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/resource-tool", Versions: []string{"1.0.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/resourcecatalog-tool", Versions: []string{"0.1.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/resources-tool", Versions: []string{"0.1.11"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/robot", Versions: []string{"1.3.4"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/rpa-legacy-tool", Versions: []string{"1.0.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/rpa-tool", Versions: []string{"0.9.5"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/solution-packager", Versions: []string{"0.0.35"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/solution-tool", Versions: []string{"1.0.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/solutionpackager-sdk", Versions: []string{"1.0.11"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/solutionpackager-tool-core", Versions: []string{"0.0.34"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/tasks-tool", Versions: []string{"1.0.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/telemetry", Versions: []string{"0.0.7"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/test-manager-tool", Versions: []string{"1.0.2"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/tool-workflowcompiler", Versions: []string{"0.0.12"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/traces-tool", Versions: []string{"1.0.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/ui-widgets-multi-file-upload", Versions: []string{"1.0.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/uipath-python-bridge", Versions: []string{"1.0.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/vertical-solutions-tool", Versions: []string{"1.0.1"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/vss", Versions: []string{"0.1.6"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@uipath/widget.sdk", Versions: []string{"1.2.3"}, Summary: miniShaiHuludPeerSummary},
		// @squawk/* aviation data libraries (22 packages, 5 versions each).
		{Ecosystem: "npm", Package: "@squawk/airport-data", Versions: []string{"0.7.4", "0.7.5", "0.7.6", "0.7.7", "0.7.8"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@squawk/airports", Versions: []string{"0.6.2", "0.6.3", "0.6.4", "0.6.5", "0.6.6"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@squawk/airspace", Versions: []string{"0.8.1", "0.8.2", "0.8.3", "0.8.4", "0.8.5"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@squawk/airspace-data", Versions: []string{"0.5.3", "0.5.4", "0.5.5", "0.5.6", "0.5.7"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@squawk/airway-data", Versions: []string{"0.5.4", "0.5.5", "0.5.6", "0.5.7", "0.5.8"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@squawk/airways", Versions: []string{"0.4.2", "0.4.3", "0.4.4", "0.4.5", "0.4.6"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@squawk/fix-data", Versions: []string{"0.6.4", "0.6.5", "0.6.6", "0.6.7", "0.6.8"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@squawk/fixes", Versions: []string{"0.3.2", "0.3.3", "0.3.4", "0.3.5", "0.3.6"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@squawk/flight-math", Versions: []string{"0.5.4", "0.5.5", "0.5.6", "0.5.7", "0.5.8"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@squawk/flightplan", Versions: []string{"0.5.2", "0.5.3", "0.5.4", "0.5.5", "0.5.6"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@squawk/geo", Versions: []string{"0.4.4", "0.4.5", "0.4.6", "0.4.7", "0.4.8"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@squawk/icao-registry", Versions: []string{"0.5.2", "0.5.3", "0.5.4", "0.5.5", "0.5.6"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@squawk/icao-registry-data", Versions: []string{"0.8.4", "0.8.5", "0.8.6", "0.8.7", "0.8.8"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@squawk/mcp", Versions: []string{"0.9.1", "0.9.2", "0.9.3", "0.9.4", "0.9.5"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@squawk/navaid-data", Versions: []string{"0.6.4", "0.6.5", "0.6.6", "0.6.7", "0.6.8"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@squawk/navaids", Versions: []string{"0.4.2", "0.4.3", "0.4.4", "0.4.5", "0.4.6"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@squawk/notams", Versions: []string{"0.3.6", "0.3.7", "0.3.8", "0.3.9", "0.3.10"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@squawk/procedure-data", Versions: []string{"0.7.3", "0.7.4", "0.7.5", "0.7.6", "0.7.7"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@squawk/procedures", Versions: []string{"0.5.2", "0.5.3", "0.5.4", "0.5.5", "0.5.6"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@squawk/types", Versions: []string{"0.8.1", "0.8.2", "0.8.3", "0.8.4", "0.8.5"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@squawk/units", Versions: []string{"0.4.3", "0.4.4", "0.4.5", "0.4.6", "0.4.7"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@squawk/weather", Versions: []string{"0.5.6", "0.5.7", "0.5.8", "0.5.9", "0.5.10"}, Summary: miniShaiHuludPeerSummary},
		// @tallyui/* commerce connectors (10 packages, 3 versions each).
		{Ecosystem: "npm", Package: "@tallyui/components", Versions: []string{"1.0.1", "1.0.2", "1.0.3"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@tallyui/connector-medusa", Versions: []string{"1.0.1", "1.0.2", "1.0.3"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@tallyui/connector-shopify", Versions: []string{"1.0.1", "1.0.2", "1.0.3"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@tallyui/connector-vendure", Versions: []string{"1.0.1", "1.0.2", "1.0.3"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@tallyui/connector-woocommerce", Versions: []string{"1.0.1", "1.0.2", "1.0.3"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@tallyui/core", Versions: []string{"0.2.1", "0.2.2", "0.2.3"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@tallyui/database", Versions: []string{"1.0.1", "1.0.2", "1.0.3"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@tallyui/pos", Versions: []string{"0.1.1", "0.1.2", "0.1.3"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@tallyui/storage-sqlite", Versions: []string{"0.2.1", "0.2.2", "0.2.3"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@tallyui/theme", Versions: []string{"0.2.1", "0.2.2", "0.2.3"}, Summary: miniShaiHuludPeerSummary},
		// Other scoped peers in the same wave.
		{Ecosystem: "npm", Package: "@beproduct/nestjs-auth", Versions: []string{"0.1.2", "0.1.3", "0.1.4", "0.1.5", "0.1.6", "0.1.7", "0.1.8", "0.1.9", "0.1.10", "0.1.11", "0.1.12", "0.1.13", "0.1.14", "0.1.15", "0.1.16", "0.1.17", "0.1.18", "0.1.19"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@dirigible-ai/sdk", Versions: []string{"0.6.2", "0.6.3"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@draftauth/client", Versions: []string{"0.2.1", "0.2.2"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@draftauth/core", Versions: []string{"0.13.1", "0.13.2"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@draftlab/auth", Versions: []string{"0.24.1", "0.24.2"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@draftlab/auth-router", Versions: []string{"0.5.1", "0.5.2"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@draftlab/db", Versions: []string{"0.16.1", "0.16.2"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@mesadev/rest", Versions: []string{"0.28.3"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@mesadev/saguaro", Versions: []string{"0.4.22"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@mesadev/sdk", Versions: []string{"0.28.3"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@ml-toolkit-ts/preprocessing", Versions: []string{"1.0.2", "1.0.3"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@ml-toolkit-ts/xgboost", Versions: []string{"1.0.3", "1.0.4"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@supersurkhet/cli", Versions: []string{"0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6", "0.0.7"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@supersurkhet/sdk", Versions: []string{"0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6", "0.0.7"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@taskflow-corp/cli", Versions: []string{"0.1.24", "0.1.25", "0.1.26", "0.1.27", "0.1.28", "0.1.29"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "@tolka/cli", Versions: []string{"1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6"}, Summary: miniShaiHuludPeerSummary},
		// Unscoped peers.
		{Ecosystem: "npm", Package: "agentwork-cli", Versions: []string{"0.1.4", "0.1.5"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "cmux-agent-mcp", Versions: []string{"0.1.3", "0.1.4", "0.1.5", "0.1.6", "0.1.7", "0.1.8"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "cross-stitch", Versions: []string{"1.1.3", "1.1.4", "1.1.5", "1.1.6", "1.1.7"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "git-branch-selector", Versions: []string{"1.3.3", "1.3.4", "1.3.5", "1.3.6", "1.3.7"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "git-git-git", Versions: []string{"1.0.8", "1.0.9", "1.0.10", "1.0.11", "1.0.12"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "ml-toolkit-ts", Versions: []string{"1.0.4", "1.0.5"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "nextmove-mcp", Versions: []string{"0.1.3", "0.1.4", "0.1.5", "0.1.6", "0.1.7"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "safe-action", Versions: []string{"0.8.3", "0.8.4"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "ts-dna", Versions: []string{"3.0.1", "3.0.2", "3.0.3", "3.0.4", "3.0.5"}, Summary: miniShaiHuludPeerSummary},
		{Ecosystem: "npm", Package: "wot-api", Versions: []string{"0.8.1", "0.8.2", "0.8.3", "0.8.4"}, Summary: miniShaiHuludPeerSummary},
	}
	incidentIndex = buildIncidentIndex(knownIncidents)
)

const (
	tanstackMiniShaiHuludSummary = "Mini Shai-Hulud (TanStack) campaign release published 2026-05-11 via GitHub Actions cache poisoning. Drops router_init.js (~2.3 MB) on install; harvests developer, cloud, and CI/CD secrets and self-propagates to other npm packages owned by the victim. Treat affected environments as compromised and rotate npm/cloud/CI credentials."
	mistralMiniShaiHuludSummary  = "Mini Shai-Hulud compromised release in the same TanStack wave (2026-05-11). Same router_init.js-style payload targeting developer/cloud/CI secrets. Rotate Mistral API keys, npm tokens, and cloud credentials."
	miniShaiHuludPeerSummary     = "Peer compromise in the Mini Shai-Hulud TanStack wave (2026-05-11), catalogued by Wiz and Aikido. Same self-propagating credential-harvesting payload. Rotate npm/PyPI tokens, cloud credentials, and any SDK API keys associated with the package vendor."
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
