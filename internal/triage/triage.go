// Package triage turns raw scanner output into a short, ordered list of work:
// it de-duplicates findings, applies VEX decisions, enriches each finding with
// exploit intelligence and assigns a priority with a remediation deadline.
package triage

import (
	"fmt"
	"sort"
	"time"

	"github.com/ahmedelgmal310/sieve/internal/config"
	"github.com/ahmedelgmal310/sieve/internal/intel"
	"github.com/ahmedelgmal310/sieve/internal/state"
	"github.com/ahmedelgmal310/sieve/internal/trivy"
	"github.com/ahmedelgmal310/sieve/internal/vex"
)

// Priorities, most urgent first. Watch has no SLA: no fix exists and nothing
// says it is being exploited. Suppressed findings carry a VEX decision.
const (
	P0         = "P0"
	P1         = "P1"
	P2         = "P2"
	P3         = "P3"
	Watch      = "watch"
	Suppressed = "suppressed"
)

// Order ranks priorities for sorting.
var Order = map[string]int{P0: 0, P1: 1, P2: 2, P3: 3, Watch: 4, Suppressed: 5}

// Item is one prioritised finding.
type Item struct {
	trivy.Finding
	Priority  string          `json:"priority"`
	Reason    string          `json:"reason"`
	KEV       *intel.KEVEntry `json:"kev,omitempty"`
	EPSS      intel.EPSS      `json:"epss"`
	Exposure  string          `json:"exposure"`
	Owner     string          `json:"owner"`
	Gated     bool            `json:"gated"`
	VEX       *vex.Statement  `json:"vex,omitempty"`
	FirstSeen string          `json:"firstSeen"`
	Due       string          `json:"due,omitempty"`
	Overdue   bool            `json:"overdue"`
	AgeDays   int             `json:"ageDays"`
}

// Funnel shows how much noise each stage removes.
type Funnel struct {
	Raw        int `json:"raw"`        // rows in the scanner reports
	Unique     int `json:"unique"`     // distinct target+CVE+package+version
	Affected   int `json:"affected"`   // unique, minus VEX and policy not-affected
	Fixable    int `json:"fixable"`    // affected and a fixed version exists
	Actionable int `json:"actionable"` // P0-P3 after VEX
	Urgent     int `json:"urgent"`     // P0 + P1
}

// Result is a complete triage run.
type Result struct {
	Date       string             `json:"date"`
	Items      []Item             `json:"items"`
	Funnel     Funnel             `json:"funnel"`
	ByPriority map[string]int     `json:"byPriority"`
	ByTarget   []TargetStats      `json:"byTarget"`
	KEVHits    int                `json:"kevHits"`
	Overdue    int                `json:"overdue"`
	New        int                `json:"new"`
	Resolved   int                `json:"resolved"`
	MTTRDays   map[string]float64 `json:"mttrDays,omitempty"`
	Intel      IntelInfo          `json:"intel"`
	VEXCount   int                `json:"vexStatements"`
}

// IntelInfo records which feeds the run used.
type IntelInfo struct {
	KEVEntries int    `json:"kevEntries"`
	EPSSScores int    `json:"epssScores"`
	EPSSDate   string `json:"epssDate"`
}

// TargetStats summarises one target.
type TargetStats struct {
	Name       string         `json:"name"`
	Image      string         `json:"image"`
	Exposure   string         `json:"exposure"`
	Gated      bool           `json:"gated"`
	Raw        int            `json:"raw"`
	Unique     int            `json:"unique"`
	ByPriority map[string]int `json:"byPriority"`
}

// Input is everything a run needs.
type Input struct {
	Config   *config.Config
	Findings []trivy.Finding
	Raw      map[string]int // raw rows per target
	Intel    *intel.Intel
	VEX      *vex.Set
	State    *state.State
	Today    time.Time
}

// Run triages the findings and advances the state.
func Run(in Input) Result {
	today := in.Today.UTC().Format("2006-01-02")
	res := Result{
		Date:       today,
		ByPriority: map[string]int{P0: 0, P1: 0, P2: 0, P3: 0, Watch: 0, Suppressed: 0},
		Intel: IntelInfo{
			KEVEntries: len(in.Intel.KEV),
			EPSSScores: len(in.Intel.EPSS),
			EPSSDate:   in.Intel.EPSSDate,
		},
		VEXCount: in.VEX.Len(),
	}

	seen := map[string]bool{}
	targets := map[string]*TargetStats{}
	for _, t := range in.Config.Targets {
		targets[t.Name] = &TargetStats{
			Name: t.Name, Image: t.Image, Exposure: t.Exposure, Gated: t.Gate,
			Raw: in.Raw[t.Name], ByPriority: map[string]int{},
		}
		res.Funnel.Raw += in.Raw[t.Name]
	}

	for _, f := range in.Findings {
		key := f.Key()
		if seen[key] {
			continue
		}
		seen[key] = true
		t, ok := in.Config.Target(f.Target)
		if !ok {
			continue
		}
		it := classify(f, t, in)
		it.FirstSeen = in.State.FirstSeen(key, today)
		if days, ok := in.Config.Policy.SLADays[it.Priority]; ok {
			first, err := time.Parse("2006-01-02", it.FirstSeen)
			if err == nil {
				due := first.AddDate(0, 0, days)
				it.Due = due.Format("2006-01-02")
				it.Overdue = in.Today.UTC().After(due)
				it.AgeDays = int(in.Today.UTC().Sub(first).Hours() / 24)
			}
		}
		res.Items = append(res.Items, it)
	}

	current := map[string]string{}
	for _, it := range res.Items {
		res.ByPriority[it.Priority]++
		ts := targets[it.Target]
		ts.Unique++
		ts.ByPriority[it.Priority]++
		res.Funnel.Unique++
		if it.Priority != Suppressed {
			res.Funnel.Affected++
			if it.FixedVersion != "" {
				res.Funnel.Fixable++
			}
		}
		if Order[it.Priority] <= Order[P3] {
			res.Funnel.Actionable++
			current[it.Key()] = it.Priority
		}
		if it.Priority == P0 || it.Priority == P1 {
			res.Funnel.Urgent++
		}
		if it.KEV != nil && it.Priority != Suppressed {
			res.KEVHits++
		}
		if it.Overdue {
			res.Overdue++
		}
	}
	res.New, res.Resolved = in.State.Advance(today, current)
	res.MTTRDays = mttr(in.State.Resolved)

	sort.SliceStable(res.Items, func(i, j int) bool {
		a, b := res.Items[i], res.Items[j]
		if Order[a.Priority] != Order[b.Priority] {
			return Order[a.Priority] < Order[b.Priority]
		}
		if (a.KEV != nil) != (b.KEV != nil) {
			return a.KEV != nil
		}
		if a.EPSS.Score != b.EPSS.Score {
			return a.EPSS.Score > b.EPSS.Score
		}
		if a.CVSS != b.CVSS {
			return a.CVSS > b.CVSS
		}
		return a.Key() < b.Key()
	})
	for _, t := range in.Config.Targets {
		res.ByTarget = append(res.ByTarget, *targets[t.Name])
	}
	return res
}

// classify decides one finding's priority and explains why, in words a
// developer can act on.
func classify(f trivy.Finding, t config.Target, in Input) Item {
	it := Item{Finding: f, Exposure: t.Exposure, Owner: t.Owner, Gated: t.Gate}
	if k, ok := in.Intel.KEV[f.CVE]; ok {
		k := k
		it.KEV = &k
	}
	it.EPSS = in.Intel.EPSS[f.CVE]

	if rule, ok := in.Config.Policy.Match(f.PURL); ok {
		it.VEX = &vex.Statement{
			Vulnerability: f.CVE, Products: []string{f.PURL}, Status: vex.NotAffected,
			Justification: rule.Justification, Impact: rule.Impact, Author: "sieve policy",
		}
		it.Priority = Suppressed
		it.Reason = "Not affected: " + rule.Impact
		return it
	}
	if st, ok := in.VEX.Match(f.CVE, f.Target, f.PURL); ok && st.Suppresses() {
		st := st
		it.VEX = &st
		it.Priority = Suppressed
		it.Reason = fmt.Sprintf("VEX %s (%s) by %s", st.Status, firstNonEmpty(st.Justification, "impact statement"), st.Author)
		return it
	}

	p := in.Config.Policy
	severe := f.Severity == "CRITICAL" || f.Severity == "HIGH" || f.CVSS >= 7
	switch {
	case it.KEV != nil:
		it.Priority = P0
		it.Reason = "Actively exploited in the wild (CISA KEV since " + it.KEV.DateAdded + ")"
		if it.KEV.Ransomware {
			it.Reason += ", used in ransomware campaigns"
		}
	case it.EPSS.Score >= p.EPSSUrgent:
		it.Priority = P0
		it.Reason = fmt.Sprintf("%.0f%% probability of exploitation in the next 30 days (EPSS)", it.EPSS.Score*100)
	case it.EPSS.Score >= p.EPSSHigh && severe:
		it.Priority = P1
		it.Reason = fmt.Sprintf("%s severity with a %.0f%% exploitation probability (EPSS)", title(f.Severity), it.EPSS.Score*100)
	case f.Severity == "CRITICAL" && t.Exposure == "internet":
		it.Priority = P1
		it.Reason = "Critical severity on an internet-facing service"
	case severe && f.FixedVersion != "":
		it.Priority = P2
		it.Reason = title(f.Severity) + " severity, fix available, no known exploitation"
	case f.FixedVersion != "":
		it.Priority = P3
		it.Reason = "Fix available, low exploitation likelihood"
	default:
		it.Priority = Watch
		it.Reason = "No fix released and no sign of exploitation; re-evaluated every run"
	}
	if f.FixedVersion == "" && (it.Priority == P0 || it.Priority == P1) {
		it.Reason += "; no fix yet: mitigate or replace the component"
	}
	return it
}

func mttr(resolved []state.Resolution) map[string]float64 {
	sum := map[string]float64{}
	n := map[string]int{}
	for _, r := range resolved {
		o, err1 := time.Parse("2006-01-02", r.Opened)
		c, err2 := time.Parse("2006-01-02", r.Closed)
		if err1 != nil || err2 != nil {
			continue
		}
		sum[r.Priority] += c.Sub(o).Hours() / 24
		n[r.Priority]++
	}
	out := map[string]float64{}
	for k, v := range sum {
		out[k] = v / float64(n[k])
	}
	return out
}

func title(sev string) string {
	switch sev {
	case "CRITICAL":
		return "Critical"
	case "HIGH":
		return "High"
	case "MEDIUM":
		return "Medium"
	case "LOW":
		return "Low"
	}
	return "Unknown"
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Gate returns the findings that must stop the pipeline: P0 or overdue
// findings on gated targets.
func Gate(r Result) []Item {
	var out []Item
	for _, it := range r.Items {
		if it.Gated && (it.Priority == P0 || (it.Overdue && Order[it.Priority] <= Order[P3])) {
			out = append(out, it)
		}
	}
	return out
}
