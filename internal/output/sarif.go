package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/ahmedelgmal310/sieve/internal/triage"
)

// SARIF writes the actionable vulnerabilities (P0-P2 by default) as SARIF 2.1.0
// so they show up in GitHub code scanning. Every result points at the target's
// entry in the configuration file, because container images have no source
// lines of their own.
func SARIF(w io.Writer, r triage.Result, configPath string, targetLines map[string]int, maxPriority, version string) error {
	type msg struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID               string         `json:"id"`
		ShortDescription msg            `json:"shortDescription"`
		HelpURI          string         `json:"helpUri,omitempty"`
		Properties       map[string]any `json:"properties"`
	}
	type location struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine int `json:"startLine"`
			} `json:"region"`
		} `json:"physicalLocation"`
	}
	type result struct {
		RuleID              string            `json:"ruleId"`
		Level               string            `json:"level"`
		Message             msg               `json:"message"`
		Locations           []location        `json:"locations"`
		PartialFingerprints map[string]string `json:"partialFingerprints"`
	}

	var rules []rule
	var results []result
	seen := map[string]bool{}
	for _, it := range r.Items {
		if triage.Order[it.Priority] > triage.Order[maxPriority] {
			continue
		}
		if !seen[it.CVE] {
			seen[it.CVE] = true
			rules = append(rules, rule{
				ID:               it.CVE,
				ShortDescription: msg{Text: firstNonEmpty(it.Title, it.CVE)},
				HelpURI:          it.URL,
				Properties: map[string]any{
					// GitHub maps this 0-10 score to its own severity badge.
					"security-severity": fmt.Sprintf("%.1f", securitySeverity(it)),
					"tags":              []string{"security", "vulnerability", it.Priority},
				},
			})
		}
		level := "warning"
		if it.Priority == triage.P0 || it.Priority == triage.P1 {
			level = "error"
		}
		var loc location
		loc.PhysicalLocation.ArtifactLocation.URI = configPath
		loc.PhysicalLocation.Region.StartLine = max(1, targetLines[it.Target])
		fix := "no fix released yet"
		if it.FixedVersion != "" {
			fix = "upgrade to " + it.FixedVersion
		}
		results = append(results, result{
			RuleID: it.CVE,
			Level:  level,
			Message: msg{Text: fmt.Sprintf("[%s] %s %s in %s: %s. %s (due %s).",
				it.Priority, it.Package, it.InstalledVersion, it.Target, it.Reason, fix, it.Due)},
			Locations:           []location{loc},
			PartialFingerprints: map[string]string{"sieveFinding": it.Key()},
		})
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": "Sieve", "version": version,
				"informationUri": "https://github.com/ahmedelgmal310/sieve",
				"rules":          rules,
			}},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	return enc.Encode(doc)
}

// securitySeverity raises the scanner score for exploited vulnerabilities, so
// GitHub ranks a KEV-listed medium above an unexploited critical.
func securitySeverity(it triage.Item) float64 {
	s := it.CVSS
	if s == 0 {
		s = map[string]float64{"CRITICAL": 9.5, "HIGH": 8, "MEDIUM": 5.5, "LOW": 3}[it.Severity]
	}
	if it.Priority == triage.P0 {
		s = max(s, 9.5)
	}
	return min(s, 10)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
