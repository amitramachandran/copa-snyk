package snyk

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

const (
	classOS   = "os-pkgs"
	classLang = "lang-pkgs"
)

// osPackageManagers maps Snyk's packageManager for OS projects to the package type Copa expects.
var osPackageManagers = map[string]string{
	"deb": "debian",
	"apk": "alpine",
	"rpm": "rpm",
}

// langPackageTypes maps Snyk's packageManager for application projects to the
// package types Copa's language managers act on. Anything else is skipped because
// Copa has no patcher for it.
var langPackageTypes = map[string]string{
	"pip":          "python-pkg",
	"npm":          "node-pkg",
	"yarn":         "node-pkg",
	"gomodules":    "gomod",
	"golangbinary": "gobinary",
	"nuget":        "dotnet-core",
}

// Snyk vulnerability IDs encode the distro, e.g. SNYK-DEBIAN11-CURL-1234, SNYK-ALPINE314-APKTOOLS-1234.
var distroIDPattern = regexp.MustCompile(`^SNYK-([A-Z]+?)(\d[\dA-Z.]*)?-`)

// distroPrefixes maps the distro token in a Snyk ID to Copa's OS type.
var distroPrefixes = map[string]string{
	"DEBIAN": "debian",
	"ALPINE": "alpine",
	"UBUNTU": "ubuntu",
	"AMZN":   "amazon",
	"RHEL":   "redhat",
	"CENTOS": "centos",
	"ORACLE": "oracle",
	"ROCKY":  "rocky",
	"ALMA":   "alma",
	"SLES":   "sles",
}

type Parser struct{}

func NewParser() *Parser { return &Parser{} }

// Parse reads a Snyk JSON report (a single object, or an array when --app-vulns is used)
// and converts it to a Copa v1alpha2 update manifest.
func (p *Parser) Parse(file string) (*UpdateManifest, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	reports, err := decode(data)
	if err != nil {
		return nil, err
	}

	m := &UpdateManifest{
		APIVersion:  APIVersion,
		OSUpdates:   []UpdatePackage{},
		LangUpdates: []UpdatePackage{},
	}

	sawOS := false
	for i := range reports {
		r := &reports[i]
		if osType, ok := osPackageManagers[r.PackageManager]; ok {
			sawOS = true
			setMetadata(m, r)
			m.OSUpdates = append(m.OSUpdates, updates(r, osType, classOS, binaryName, nearestFix)...)
		} else if langType, ok := langPackageTypes[r.PackageManager]; ok {
			m.LangUpdates = append(m.LangUpdates, updates(r, langType, classLang, plainName, allFixes)...)
		}
	}
	if !sawOS {
		return nil, errors.New("snyk report has no OS project (packageManager deb, apk or rpm); Copa needs the image's OS")
	}
	if m.Metadata.OS.Type == "" {
		return nil, errors.New("could not determine the OS type from the snyk report")
	}
	return m, nil
}

func decode(data []byte) ([]Report, error) {
	data = bytes.TrimSpace(data)
	var reports []Report
	if len(data) > 0 && data[0] == '[' {
		if err := json.Unmarshal(data, &reports); err != nil {
			return nil, fmt.Errorf("error parsing snyk report: %w", err)
		}
	} else {
		var r Report
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, fmt.Errorf("error parsing snyk report: %w", err)
		}
		reports = []Report{r}
	}
	// --app-vulns nests application projects inside the OS project; flatten them.
	var flat []Report
	for _, r := range reports {
		flat = append(flat, r)
		flat = append(flat, r.Applications...)
	}
	reports = flat
	// json.Unmarshal accepts any object, so require a field only Snyk reports carry.
	for _, r := range reports {
		if r.PackageManager == "" {
			return nil, errors.New("report format not supported by snyk: missing packageManager")
		}
	}
	return reports, nil
}

func setMetadata(m *UpdateManifest, r *Report) {
	m.Metadata.OS = detectOS(r)
	m.Metadata.Config.Arch, m.Metadata.Config.Variant = splitPlatform(r.Platform)
}

// detectOS reads the distro from vulnerability IDs, falling back to docker.baseImage.
func detectOS(r *Report) OS {
	for _, v := range r.Vulnerabilities {
		if match := distroIDPattern.FindStringSubmatch(v.ID); match != nil {
			if t, ok := distroPrefixes[match[1]]; ok {
				return OS{Type: t, Version: normalizeVersion(t, match[2])}
			}
		}
	}
	// "debian:11-slim" -> debian, 11
	name, tag, _ := strings.Cut(r.Docker.BaseImage, ":")
	name = name[strings.LastIndex(name, "/")+1:]
	if t, ok := distroPrefixes[strings.ToUpper(name)]; ok {
		return OS{Type: t, Version: strings.SplitN(tag, "-", 2)[0]}
	}
	return OS{}
}

// normalizeVersion turns Snyk's compact distro version into Copa's dotted form:
// alpine "314" -> "3.14", ubuntu "2004" -> "20.04"; others pass through.
func normalizeVersion(osType, v string) string {
	switch {
	case osType == "alpine" && len(v) >= 3 && !strings.Contains(v, "."):
		return v[:1] + "." + v[1:]
	case osType == "ubuntu" && len(v) == 4 && !strings.Contains(v, "."):
		return v[:2] + "." + v[2:]
	}
	return v
}

// splitPlatform turns "linux/arm64/v8" into ("arm64", "v8").
func splitPlatform(p string) (arch, variant string) {
	parts := strings.Split(p, "/")
	if len(parts) >= 2 {
		arch = parts[1]
	}
	if len(parts) >= 3 {
		variant = parts[2]
	}
	return arch, variant
}

// updates emits one row per fixable (package, CVE) pair.
func updates(r *Report, pkgType, class string, name func(*Vulnerability) string, fix func(*Vulnerability) string) []UpdatePackage {
	var out []UpdatePackage
	// Snyk repeats a finding once per dependency path, so drop exact duplicates.
	seen := map[UpdatePackage]bool{}
	for i := range r.Vulnerabilities {
		v := &r.Vulnerabilities[i]
		if isUpstream(v) {
			continue
		}
		fixed := fix(v)
		if fixed == "" {
			continue
		}
		ids := v.Identifiers.CVE
		if len(ids) == 0 {
			ids = []string{v.ID}
		}
		for _, id := range ids {
			u := UpdatePackage{
				Name:             name(v),
				InstalledVersion: v.Version,
				FixedVersion:     fixed,
				VulnerabilityID:  id,
				Type:             pkgType,
				Class:            class,
			}
			if !seen[u] {
				seen[u] = true
				out = append(out, u)
			}
		}
	}
	return out
}

// isUpstream reports findings Snyk attributes to software that isn't installed by the
// package manager (e.g. a source-built Node.js runtime): from is ["Upstream", ...] and the
// ID is SNYK-UPSTREAM-*. Copa can't upgrade these with apt/apk/yum, and asking it to
// install a package of that name fails the whole patch.
func isUpstream(v *Vulnerability) bool {
	return strings.HasPrefix(v.ID, "SNYK-UPSTREAM-") || (len(v.From) > 0 && v.From[0] == "Upstream")
}

// nearestFix is the single version to install for an OS package.
func nearestFix(v *Vulnerability) string {
	if v.NearestFixedInVersion != "" {
		return v.NearestFixedInVersion
	}
	if len(v.FixedIn) > 0 {
		return v.FixedIn[0]
	}
	return ""
}

// allFixes lists every fixed version for a library, comma-separated. Snyk gives one per
// affected major line (e.g. "0.2.1,1.2.3") and leaves nearestFixedInVersion null for
// npm; Copa picks the best candidate for the requested --library-patch-level.
func allFixes(v *Vulnerability) string {
	if len(v.FixedIn) > 0 {
		return strings.Join(v.FixedIn, ",")
	}
	return v.NearestFixedInVersion
}

func plainName(v *Vulnerability) string { return v.Name }

// binaryName prefers the installed binary package. For OS projects Snyk reports the
// source package in `name`, but the last `from` entry looks like "source/binary@version",
// and Copa installs by binary name.
func binaryName(v *Vulnerability) string {
	if len(v.From) > 0 {
		last := v.From[len(v.From)-1]
		last, _, _ = strings.Cut(last, "@")
		if _, bin, ok := strings.Cut(last, "/"); ok && bin != "" {
			return bin
		}
	}
	return v.Name
}
