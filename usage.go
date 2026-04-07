package main

type PackageUsage struct {
	Status      string `json:"status"`
	Source      string `json:"source"`
	Ecosystem   string `json:"ecosystem"`
	Package     string `json:"package"`
	Version     string `json:"version,omitempty"`
	VersionSpec string `json:"version_spec,omitempty"`
	Path        string `json:"path"`
	Project     string `json:"project,omitempty"`
	Details     string `json:"details"`
}

func (u PackageUsage) Title() string {
	switch {
	case u.Package != "" && u.Version != "":
		return u.Package + "@" + u.Version
	case u.Package != "" && u.VersionSpec != "":
		return u.Package + " (" + u.VersionSpec + ")"
	default:
		return u.Package
	}
}
