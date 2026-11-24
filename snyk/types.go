package snyk

// Output types mirror github.com/project-copacetic/copacetic/pkg/types/v1alpha2.
// They are redefined here so the plugin doesn't pull in Copa's full dependency tree.

const APIVersion = "v1alpha2"

type UpdateManifest struct {
	APIVersion  string          `json:"apiVersion"`
	Metadata    Metadata        `json:"metadata"`
	OSUpdates   []UpdatePackage `json:"osupdates"`
	LangUpdates []UpdatePackage `json:"langupdates"`
}

type Metadata struct {
	OS     OS     `json:"os"`
	Config Config `json:"config"`
}

type OS struct {
	Type    string `json:"type"`
	Version string `json:"version"`
}

type Config struct {
	Arch    string `json:"arch"`
	Variant string `json:"variant,omitempty"`
}

type UpdatePackage struct {
	Name             string `json:"name"`
	InstalledVersion string `json:"installedVersion"`
	FixedVersion     string `json:"fixedVersion"`
	VulnerabilityID  string `json:"vulnerabilityID"`
	Type             string `json:"type"`
	Class            string `json:"class"`
}

// Input types: the subset of `snyk container test --json` that the plugin reads.

type Report struct {
	PackageManager  string          `json:"packageManager"`
	Platform        string          `json:"platform"`
	ProjectName     string          `json:"projectName"`
	Docker          Docker          `json:"docker"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	// Applications holds the --app-vulns projects (npm, pip, ...) nested in the OS project.
	Applications []Report `json:"applications"`
}

type Docker struct {
	BaseImage string `json:"baseImage"`
}

type Vulnerability struct {
	ID                    string      `json:"id"`
	Name                  string      `json:"name"`
	Version               string      `json:"version"`
	NearestFixedInVersion string      `json:"nearestFixedInVersion"`
	FixedIn               []string    `json:"fixedIn"`
	From                  []string    `json:"from"`
	Identifiers           Identifiers `json:"identifiers"`
}

type Identifiers struct {
	CVE []string `json:"CVE"`
}
