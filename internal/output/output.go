// Package output renders a triage result for people (Markdown, HTML) and for
// machines (JSON, SARIF for GitHub code scanning).
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/ahmedelgmal310/sieve/internal/triage"
)

// JSON writes the result. Suppressed findings are left out (they are listed,
// with their reasons, in the OpenVEX output) to keep the file small.
func JSON(w io.Writer, r triage.Result) error {
	kept := make([]triage.Item, 0, len(r.Items))
	for _, it := range r.Items {
		if it.Priority != triage.Suppressed {
			kept = append(kept, it)
		}
	}
	r.Items = kept
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	return enc.Encode(r)
}

// Markdown writes the job summary: the funnel, then the work, most urgent
// first.
func Markdown(w io.Writer, r triage.Result, dashboardURL string) error {
	var b strings.Builder
	f := r.Funnel
	fmt.Fprintf(&b, "## Sieve: vulnerability triage, %s\n\n", r.Date)
	fmt.Fprintf(&b, "**%s raw findings → %s that need action → %s urgent.** ", num(f.Raw), num(f.Actionable), num(f.Urgent))
	if f.Raw > 0 {
		fmt.Fprintf(&b, "%.2f%% of the scanner noise was filtered out.", 100-100*float64(f.Urgent)/float64(f.Raw))
	}
	b.WriteString("\n\n")
	if dashboardURL != "" {
		fmt.Fprintf(&b, "Dashboard: %s\n\n", dashboardURL)
	}
	b.WriteString("| Stage | Findings |\n|---|---:|\n")
	fmt.Fprintf(&b, "| Raw scanner rows | %s |\n| Affected (after VEX and not-affected rules) | %s |\n| Fix available | %s |\n| Actionable (P0-P3) | %s |\n| Urgent (P0 + P1) | %s |\n\n",
		num(f.Raw), num(f.Affected), num(f.Fixable), num(f.Actionable), num(f.Urgent))

	fmt.Fprintf(&b, "**P0** %d · **P1** %d · **P2** %d · **P3** %d · watch %d · suppressed by VEX %d · in CISA KEV %d · overdue %d · new %d · resolved %d\n\n",
		r.ByPriority[triage.P0], r.ByPriority[triage.P1], r.ByPriority[triage.P2], r.ByPriority[triage.P3],
		r.ByPriority[triage.Watch], r.ByPriority[triage.Suppressed], r.KEVHits, r.Overdue, r.New, r.Resolved)

	groups := triage.Groups(r.Items, triage.P1)
	if len(groups) > 0 {
		b.WriteString("### Urgent\n\n| Priority | Vulnerability | Why | EPSS | Targets | Fix | Due |\n|---|---|---|---:|---|---|---|\n")
		for i, g := range groups {
			if i == 40 {
				fmt.Fprintf(&b, "\n…and %d more on the dashboard.\n", len(groups)-40)
				break
			}
			fix := "none yet"
			if len(g.Fixes) > 0 {
				fix = strings.Join(g.Fixes, "<br>")
			}
			due := g.Due
			if g.Overdue {
				due += " ⚠️"
			}
			fmt.Fprintf(&b, "| %s | [%s](%s) %s | %s | %.1f%% | %s | %s | %s |\n",
				g.Priority, g.CVE, g.URL, esc(g.Title), esc(g.Reason), g.EPSS.Score*100,
				strings.Join(g.Targets, ", "), esc(fix), due)
		}
		b.WriteString("\n")
	}
	b.WriteString("### Targets\n\n| Target | Exposure | Gated | Raw | P0 | P1 | P2 | P3 |\n|---|---|---|---:|---:|---:|---:|---:|\n")
	for _, t := range r.ByTarget {
		fmt.Fprintf(&b, "| `%s` | %s | %v | %s | %d | %d | %d | %d |\n", t.Image, t.Exposure, t.Gated, num(t.Raw),
			t.ByPriority[triage.P0], t.ByPriority[triage.P1], t.ByPriority[triage.P2], t.ByPriority[triage.P3])
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func esc(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 90 {
		s = s[:87] + "..."
	}
	return s
}

func num(n int) string {
	s := fmt.Sprint(n)
	if len(s) <= 3 {
		return s
	}
	var out []string
	for len(s) > 3 {
		out = append([]string{s[len(s)-3:]}, out...)
		s = s[:len(s)-3]
	}
	return s + "," + strings.Join(out, ",")
}
