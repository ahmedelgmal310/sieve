package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ahmedelgmal310/sieve/internal/config"
	"github.com/ahmedelgmal310/sieve/internal/intel"
	"github.com/ahmedelgmal310/sieve/internal/triage"
	"github.com/ahmedelgmal310/sieve/internal/trivy"
	"github.com/ahmedelgmal310/sieve/internal/vex"
)

func sample() (triage.Result, *config.Config) {
	cfg := &config.Config{
		Targets: []config.Target{{Name: "web", Image: "example/web:1", Exposure: "internet", Gate: true}},
		Policy:  config.Policy{EPSSUrgent: 0.5, EPSSHigh: 0.1, SLADays: map[string]int{"P0": 2, "P1": 7, "P2": 30, "P3": 90}},
	}
	item := func(cve, prio string, cvss float64, sev string) triage.Item {
		return triage.Item{
			Finding:  trivy.Finding{Target: "web", CVE: cve, Package: "libc6", PURL: "pkg:deb/debian/libc6@1", InstalledVersion: "1", FixedVersion: "2", Severity: sev, CVSS: cvss, Title: "a | title", URL: "https://x/" + cve},
			Priority: prio, Reason: "because", Due: "2026-10-28", EPSS: intel.EPSS{Score: 0.7}, Gated: true,
		}
	}
	p0 := item("CVE-1", triage.P0, 0, "HIGH")
	p0.KEV = &intel.KEVEntry{DateAdded: "2024-01-01"}
	p0.Overdue = true
	sup := item("CVE-3", triage.Suppressed, 7, "HIGH")
	sup.VEX = &vex.Statement{Status: vex.NotAffected, Justification: "component_not_present"}
	sup2 := item("CVE-3", triage.Suppressed, 7, "HIGH")
	sup2.PURL = ""
	sup2.VEX = sup.VEX
	r := triage.Result{
		Date:       "2026-10-26",
		Items:      []triage.Item{p0, item("CVE-2", triage.P2, 6.1, "MEDIUM"), sup, sup2},
		Funnel:     triage.Funnel{Raw: 12345, Unique: 4, Affected: 2, Fixable: 2, Actionable: 2, Urgent: 1},
		ByPriority: map[string]int{"P0": 1, "P2": 1, "suppressed": 2},
		ByTarget:   []triage.TargetStats{{Name: "web", Image: "example/web:1", Exposure: "internet", Gated: true, Raw: 12345, ByPriority: map[string]int{"P0": 1}}},
	}
	return r, cfg
}

func TestMarkdown(t *testing.T) {
	r, _ := sample()
	var b bytes.Buffer
	if err := Markdown(&b, r, "https://dash"); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	for _, want := range []string{"12,345 raw findings", "99.99% of the scanner noise", "Dashboard: https://dash", "[CVE-1](https://x/CVE-1) a \\| title", "2026-10-28 ⚠️", "`example/web:1`"} {
		if !strings.Contains(s, want) {
			t.Errorf("markdown misses %q:\n%s", want, s)
		}
	}
}

func TestSARIF(t *testing.T) {
	r, _ := sample()
	var b bytes.Buffer
	if err := SARIF(&b, r, "sieve.json", map[string]int{"web": 4}, triage.P2, "v1"); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID         string         `json:"id"`
						Properties map[string]any `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				Level string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	run := doc.Runs[0]
	if len(run.Results) != 2 || run.Results[0].Level != "error" || run.Results[1].Level != "warning" {
		t.Errorf("results = %+v", run.Results)
	}
	if run.Tool.Driver.Rules[0].Properties["security-severity"] != "9.5" {
		t.Errorf("an exploited finding without CVSS must rank critical: %v", run.Tool.Driver.Rules[0].Properties)
	}
}

func TestDashboardAndOpenVEX(t *testing.T) {
	r, cfg := sample()
	var b bytes.Buffer
	if err := Dashboard(&b, r, cfg, "https://github.com/x/sieve", "v1"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"12,345</b> raw findings", `class="kev"`, `class="over"`, "blocks release", "a | title"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("dashboard misses %q", want)
		}
	}
	b.Reset()
	if err := OpenVEX(&b, r, "https://github.com/x/sieve", "v1", time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Statements []struct {
			Products []struct {
				ID string `json:"@id"`
			} `json:"products"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Statements) != 1 || len(doc.Statements[0].Products) != 2 || doc.Statements[0].Products[1].ID != "web" {
		t.Errorf("one statement per CVE and decision, products merged: %+v", doc.Statements)
	}
}

func TestJSONDropsSuppressed(t *testing.T) {
	r, _ := sample()
	var b bytes.Buffer
	if err := JSON(&b, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), `"suppressed"`+",") || strings.Count(b.String(), `"cve"`) != 2 {
		t.Errorf("suppressed items must be dropped: %s", b.String())
	}
}

func TestHelpers(t *testing.T) {
	cases := map[int]string{0: "0", 999: "999", 1000: "1,000", 1234567: "1,234,567"}
	for n, want := range cases {
		if num(n) != want {
			t.Errorf("num(%d) = %s", n, num(n))
		}
	}
	if got := esc(strings.Repeat("x", 100)); len(got) != 90 {
		t.Errorf("esc truncates: %d", len(got))
	}
	if securitySeverity(triage.Item{Finding: trivy.Finding{Severity: "LOW"}, Priority: triage.P3}) != 3 {
		t.Error("severity fallback")
	}
	if securitySeverity(triage.Item{Finding: trivy.Finding{CVSS: 12}}) != 10 {
		t.Error("severity cap")
	}
}
