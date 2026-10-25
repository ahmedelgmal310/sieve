// Package trivy reads Trivy JSON reports into scanner-neutral findings.
package trivy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Finding is one vulnerable package in one scanned target.
type Finding struct {
	Target           string  `json:"target"`
	CVE              string  `json:"cve"`
	Package          string  `json:"package"`
	PURL             string  `json:"purl,omitempty"`
	InstalledVersion string  `json:"installedVersion"`
	FixedVersion     string  `json:"fixedVersion,omitempty"`
	Severity         string  `json:"severity"`
	CVSS             float64 `json:"cvss"`
	Title            string  `json:"title,omitempty"`
	URL              string  `json:"url,omitempty"`
	Class            string  `json:"class"` // os-pkgs or lang-pkgs
}

// Key identifies a finding across runs.
func (f Finding) Key() string {
	return f.Target + "|" + f.CVE + "|" + f.Package + "|" + f.InstalledVersion
}

type report struct {
	ArtifactName string `json:"ArtifactName"`
	Results      []struct {
		Class           string `json:"Class"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
			PrimaryURL       string `json:"PrimaryURL"`
			PkgIdentifier    struct {
				PURL string `json:"PURL"`
			} `json:"PkgIdentifier"`
			CVSS map[string]struct {
				V3Score float64 `json:"V3Score"`
				V40     float64 `json:"V40Score"`
			} `json:"CVSS"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// Read parses one Trivy JSON report. target names the scanned artifact; when
// empty the report's own ArtifactName is used. The second return value is the
// raw number of vulnerability rows, before any de-duplication.
func Read(path, target string) ([]Finding, int, error) {
	b, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- report paths come from the operator
	if err != nil {
		return nil, 0, err
	}
	var r report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, 0, fmt.Errorf("%s: not a Trivy JSON report: %w", path, err)
	}
	if target == "" {
		target = r.ArtifactName
	}
	var out []Finding
	raw := 0
	for _, res := range r.Results {
		for _, v := range res.Vulnerabilities {
			raw++
			if v.VulnerabilityID == "" {
				continue
			}
			score := 0.0
			for _, c := range v.CVSS {
				s := c.V3Score
				if c.V40 > s {
					s = c.V40
				}
				if s > score {
					score = s
				}
			}
			out = append(out, Finding{
				Target:           target,
				CVE:              v.VulnerabilityID,
				Package:          v.PkgName,
				PURL:             v.PkgIdentifier.PURL,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     v.FixedVersion,
				Severity:         strings.ToUpper(v.Severity),
				CVSS:             score,
				Title:            v.Title,
				URL:              v.PrimaryURL,
				Class:            res.Class,
			})
		}
	}
	return out, raw, nil
}
