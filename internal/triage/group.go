package triage

import (
	"sort"
	"strings"

	"github.com/ahmedelgmal310/sieve/internal/intel"
)

// Group is one vulnerability across every target and package it affects: the
// unit of work a team picks up and the unit Sieve opens an issue for.
type Group struct {
	CVE       string          `json:"cve"`
	Priority  string          `json:"priority"`
	Reason    string          `json:"reason"`
	Severity  string          `json:"severity"`
	CVSS      float64         `json:"cvss"`
	EPSS      intel.EPSS      `json:"epss"`
	KEV       *intel.KEVEntry `json:"kev,omitempty"`
	Title     string          `json:"title"`
	URL       string          `json:"url"`
	Targets   []string        `json:"targets"`
	Packages  []string        `json:"packages"`
	Fixes     []string        `json:"fixes"`
	Due       string          `json:"due"`
	Overdue   bool            `json:"overdue"`
	Gated     bool            `json:"gated"`
	Instances int             `json:"instances"`
}

// Groups collapses actionable items by CVE, keeping each group's most urgent
// priority and earliest deadline, ordered most urgent first.
func Groups(items []Item, maxPriority string) []Group {
	idx := map[string]*Group{}
	var order []string
	targets := map[string]map[string]bool{}
	pkgs := map[string]map[string]bool{}
	fixes := map[string]map[string]bool{}
	for _, it := range items {
		if Order[it.Priority] > Order[maxPriority] {
			continue
		}
		g, ok := idx[it.CVE]
		if !ok {
			g = &Group{CVE: it.CVE, Priority: it.Priority, Reason: it.Reason, Severity: it.Severity,
				CVSS: it.CVSS, EPSS: it.EPSS, KEV: it.KEV, Title: it.Title, URL: it.URL, Due: it.Due}
			idx[it.CVE] = g
			order = append(order, it.CVE)
			targets[it.CVE], pkgs[it.CVE], fixes[it.CVE] = map[string]bool{}, map[string]bool{}, map[string]bool{}
		}
		if Order[it.Priority] < Order[g.Priority] {
			g.Priority, g.Reason = it.Priority, it.Reason
		}
		if it.Due != "" && (g.Due == "" || it.Due < g.Due) {
			g.Due = it.Due
		}
		if it.CVSS > g.CVSS {
			g.CVSS = it.CVSS
		}
		g.Overdue = g.Overdue || it.Overdue
		g.Gated = g.Gated || it.Gated
		g.Instances++
		targets[it.CVE][it.Target] = true
		pkgs[it.CVE][it.Package+" "+it.InstalledVersion] = true
		if it.FixedVersion != "" {
			fixes[it.CVE][it.Package+" "+it.FixedVersion] = true
		}
	}
	out := make([]Group, 0, len(order))
	for _, cve := range order {
		g := idx[cve]
		g.Targets, g.Packages, g.Fixes = keys(targets[cve]), keys(pkgs[cve]), keys(fixes[cve])
		out = append(out, *g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if Order[a.Priority] != Order[b.Priority] {
			return Order[a.Priority] < Order[b.Priority]
		}
		if (a.KEV != nil) != (b.KEV != nil) {
			return a.KEV != nil
		}
		if a.EPSS.Score != b.EPSS.Score {
			return a.EPSS.Score > b.EPSS.Score
		}
		return a.CVE < b.CVE
	})
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Summary is a one-line description of a group for titles and tables.
func (g Group) Summary() string {
	pkg := ""
	if len(g.Packages) > 0 {
		pkg = strings.SplitN(g.Packages[0], " ", 2)[0]
	}
	t := strings.Join(g.Targets, ", ")
	return g.CVE + " in " + pkg + " (" + t + ")"
}
