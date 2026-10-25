package output

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"

	"github.com/ahmedelgmal310/sieve/internal/config"
	"github.com/ahmedelgmal310/sieve/internal/triage"
)

//go:embed dashboard.html
var dashboardHTML string

const maxDashboardGroups = 300

var dashboard = template.Must(template.New("dashboard").Funcs(template.FuncMap{
	"num": num,
	"mul": func(a, b float64) float64 { return a * b },
	"pct": func(part, whole int) string {
		if whole == 0 {
			return "0%"
		}
		return fmt.Sprintf("%.2f%%", 100-100*float64(part)/float64(whole))
	},
	"pctf": func(f float64) string { return fmt.Sprintf("%.0f%%", f*100) },
	"sub":  func(a, b int) int { return a - b },
	"firstN": func(s []string, n int) []string {
		if len(s) > n {
			return s[:n]
		}
		return s
	},
	"trunc": func(s string, n int) string {
		if len(s) <= n {
			return s
		}
		return s[:n-1] + "…"
	},
}).Parse(dashboardHTML))

type stage struct {
	Label string
	N     int
	Width float64
}

// Dashboard writes a self-contained HTML page (no external assets) for GitHub
// Pages.
func Dashboard(w io.Writer, r triage.Result, cfg *config.Config, repo, version string) error {
	groups := triage.Groups(r.Items, triage.P2)
	more := 0
	if len(groups) > maxDashboardGroups {
		more = len(groups) - maxDashboardGroups
		groups = groups[:maxDashboardGroups]
	}
	f := r.Funnel
	stages := []stage{
		{"Raw scanner findings", f.Raw, 0},
		{"Affected (after VEX rules)", f.Affected, 0},
		{"A fix exists", f.Fixable, 0},
		{"Actionable (P0-P3)", f.Actionable, 0},
		{"Urgent (P0 + P1)", f.Urgent, 0},
	}
	for i := range stages {
		if f.Raw > 0 {
			stages[i].Width = 100 * float64(stages[i].N) / float64(f.Raw)
		}
	}
	return dashboard.Execute(w, map[string]any{
		"R":       r,
		"Groups":  groups,
		"More":    more,
		"Stages":  stages,
		"SLA":     cfg.Policy.SLADays,
		"Policy":  cfg.Policy,
		"Repo":    repo,
		"Version": version,
	})
}
