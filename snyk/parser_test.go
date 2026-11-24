package snyk

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func parse(t *testing.T, file string) *UpdateManifest {
	t.Helper()
	m, err := NewParser().Parse(file)
	if err != nil {
		t.Fatalf("Parse(%s): %v", file, err)
	}
	return m
}

func TestDebianReport(t *testing.T) {
	m := parse(t, "../testdata/snyk_debian.json")

	if want := (Metadata{OS: OS{Type: "debian", Version: "11"}, Config: Config{Arch: "amd64"}}); m.Metadata != want {
		t.Errorf("metadata = %+v, want %+v", m.Metadata, want)
	}
	want := []UpdatePackage{
		// binary name from `from`, one row per CVE
		{"libcurl4", "7.74.0-1.3+deb11u1", "7.74.0-1.3+deb11u2", "CVE-2021-22945", "debian", "os-pkgs"},
		{"libcurl4", "7.74.0-1.3+deb11u1", "7.74.0-1.3+deb11u2", "CVE-2021-22946", "debian", "os-pkgs"},
		// no CVE -> Snyk ID; no "/" in from -> source name; unfixed glibc skipped
		{"zlib", "1:1.2.11", "1:1.2.12", "SNYK-DEBIAN11-ZLIB-5678", "debian", "os-pkgs"},
	}
	if !reflect.DeepEqual(m.OSUpdates, want) {
		t.Errorf("osupdates = %+v\nwant %+v", m.OSUpdates, want)
	}
	if len(m.LangUpdates) != 0 {
		t.Errorf("langupdates = %+v, want none", m.LangUpdates)
	}
}

func TestMultiProjectReport(t *testing.T) {
	m := parse(t, "../testdata/snyk_apps.json")

	if want := (Metadata{OS: OS{Type: "alpine", Version: "3.14"}, Config: Config{Arch: "arm64", Variant: "v8"}}); m.Metadata != want {
		t.Errorf("metadata = %+v, want %+v", m.Metadata, want)
	}
	if len(m.OSUpdates) != 1 || m.OSUpdates[0].Name != "apk-tools" || m.OSUpdates[0].Type != "alpine" {
		t.Errorf("osupdates = %+v", m.OSUpdates)
	}
	// pip is kept as python-pkg; unsupported maven project is dropped
	want := []UpdatePackage{{"requests", "2.25.1", "2.31.0", "CVE-2023-32681", "python-pkg", "lang-pkgs"}}
	if !reflect.DeepEqual(m.LangUpdates, want) {
		t.Errorf("langupdates = %+v, want %+v", m.LangUpdates, want)
	}
}

func TestOutputJSONFieldNames(t *testing.T) {
	b, err := json.Marshal(parse(t, "../testdata/snyk_apps.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"apiVersion", "metadata", "osupdates", "langupdates"} {
		if _, ok := got[k]; !ok {
			t.Errorf("missing top-level key %q", k)
		}
	}
	if got["apiVersion"] != "v1alpha2" {
		t.Errorf("apiVersion = %v", got["apiVersion"])
	}
	pkg := got["osupdates"].([]any)[0].(map[string]any)
	for _, k := range []string{"name", "installedVersion", "fixedVersion", "vulnerabilityID", "type", "class"} {
		if _, ok := pkg[k]; !ok {
			t.Errorf("missing package key %q", k)
		}
	}
}

func TestErrors(t *testing.T) {
	for _, f := range []string{"../testdata/invalid.json", "../testdata/no_os.json", "../testdata/missing.json"} {
		if _, err := NewParser().Parse(f); err == nil {
			t.Errorf("Parse(%s) succeeded, want error", f)
		}
	}
}

func TestNormalizeVersion(t *testing.T) {
	for _, c := range [][3]string{
		{"alpine", "314", "3.14"}, {"ubuntu", "2004", "20.04"}, {"debian", "11", "11"}, {"alpine", "3.14", "3.14"},
	} {
		if got := normalizeVersion(c[0], c[1]); got != c[2] {
			t.Errorf("normalizeVersion(%s,%s) = %s, want %s", c[0], c[1], got, c[2])
		}
	}
}

func TestDuplicateFindingsCollapsed(t *testing.T) {
	v := Vulnerability{
		ID: "SNYK-DEBIAN9-X-1", Name: "x/x-bin", Version: "1", NearestFixedInVersion: "2",
		From: []string{"img", "x@1", "x/x-bin@1"}, Identifiers: Identifiers{CVE: []string{"CVE-1"}},
	}
	r := &Report{Vulnerabilities: []Vulnerability{v, v}}
	if got := updates(r, "debian", classOS, binaryName, nearestFix); len(got) != 1 || got[0].Name != "x-bin" {
		t.Errorf("updates = %+v, want one x-bin row", got)
	}
}

func TestNestedApplications(t *testing.T) {
	r := Report{
		PackageManager: "apk", Platform: "linux/amd64",
		Vulnerabilities: []Vulnerability{{ID: "SNYK-ALPINE318-X-1", Name: "x", Version: "1", NearestFixedInVersion: "2"}},
		Applications: []Report{{
			PackageManager: "npm",
			Vulnerabilities: []Vulnerability{{
				ID: "SNYK-JS-MINIMIST-1", Name: "minimist", Version: "1.2.0",
				FixedIn: []string{"0.2.1", "1.2.3"}, Identifiers: Identifiers{CVE: []string{"CVE-2020-7598"}},
			}},
		}},
	}
	b, _ := json.Marshal(r)
	f := t.TempDir() + "/r.json"
	if err := os.WriteFile(f, b, 0o600); err != nil {
		t.Fatal(err)
	}
	m := parse(t, f)
	want := []UpdatePackage{{"minimist", "1.2.0", "0.2.1,1.2.3", "CVE-2020-7598", "node-pkg", "lang-pkgs"}}
	if !reflect.DeepEqual(m.LangUpdates, want) {
		t.Errorf("langupdates = %+v, want %+v", m.LangUpdates, want)
	}
}

func TestUpstreamFindingsSkipped(t *testing.T) {
	r := &Report{Vulnerabilities: []Vulnerability{{
		ID: "SNYK-UPSTREAM-NODE-1", Name: "node", Version: "16.0.0",
		FixedIn: []string{"20.19.2"}, From: []string{"Upstream", "node@16.0.0"},
	}}}
	if got := updates(r, "alpine", classOS, binaryName, nearestFix); len(got) != 0 {
		t.Errorf("updates = %+v, want none", got)
	}
}
