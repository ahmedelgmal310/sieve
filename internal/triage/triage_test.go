package triage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/ahmedelgmal310/sieve/internal/config"
	"github.com/ahmedelgmal310/sieve/internal/intel"
	"github.com/ahmedelgmal310/sieve/internal/state"
	"github.com/ahmedelgmal310/sieve/internal/trivy"
	"github.com/ahmedelgmal310/sieve/internal/vex"
)

var today = time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)

func fixture(t *testing.T, st *state.State) Result {
	t.Helper()
	td := filepath.Join("..", "..", "testdata")
	cfg, err := config.Load(filepath.Join(td, "sieve.json"))
	if err != nil {
		t.Fatal(err)
	}
	var findings []trivy.Finding
	raw := map[string]int{}
	for _, tg := range cfg.Targets {
		f, n, err := trivy.Read(filepath.Join(td, "reports", tg.Name+".json"), tg.Name)
		if err != nil {
			t.Fatal(err)
		}
		findings = append(findings, f...)
		raw[tg.Name] = n
	}
	in, err := intel.Load(context.Background(), filepath.Join(td, "kev.json"), filepath.Join(td, "epss.csv"))
	if err != nil {
		t.Fatal(err)
	}
	vs, err := vex.LoadDir(filepath.Join(td, "vex"))
	if err != nil {
		t.Fatal(err)
	}
	if st == nil {
		st, _ = state.Load("")
	}
	return Run(Input{Config: cfg, Findings: findings, Raw: raw, Intel: in, VEX: vs, State: st, Today: today})
}

func find(r Result, target, cve string) Item {
	for _, it := range r.Items {
		if it.Target == target && it.CVE == cve {
			return it
		}
	}
	return Item{}
}

func TestPriorities(t *testing.T) {
	r := fixture(t, nil)
	cases := []struct {
		target, cve, want string
	}{
		{"web", "CVE-2023-4911", P0},         // CISA KEV
		{"web", "CVE-2024-0001", P0},         // medium, but EPSS 72%
		{"web", "CVE-2024-0002", P1},         // critical, internet-facing, no fix
		{"web", "CVE-2024-0004", P1},         // high with EPSS 15%
		{"web", "CVE-2024-0003", Suppressed}, // kernel headers policy rule
		{"web", "CVE-2024-0007", Suppressed}, // VEX not_affected
		{"web", "CVE-2024-0005", P3},         // VEX under_investigation does not suppress
		{"web", "CVE-2024-0006", Watch},      // no fix, no signal
		{"api", "CVE-2023-4911", P0},
		{"api", "CVE-2024-0008", P2}, // critical with a fix, internal, low EPSS
	}
	for _, c := range cases {
		if got := find(r, c.target, c.cve); got.Priority != c.want {
			t.Errorf("%s %s: priority %q (%s), want %q", c.target, c.cve, got.Priority, got.Reason, c.want)
		}
	}

	kev := find(r, "web", "CVE-2023-4911")
	if kev.KEV == nil || kev.Due != "2026-10-28" || kev.FirstSeen != "2026-10-26" {
		t.Errorf("KEV item = %+v", kev)
	}
	if got := find(r, "web", "CVE-2024-0002").Reason; got != "Critical severity on an internet-facing service; no fix yet: mitigate or replace the component" {
		t.Errorf("reason = %q", got)
	}
	if v := find(r, "web", "CVE-2024-0007").VEX; v == nil || v.Author != "Security Team" {
		t.Errorf("VEX suppression must keep its statement: %+v", v)
	}
	if v := find(r, "web", "CVE-2024-0003").VEX; v == nil || v.Author != "sieve policy" {
		t.Errorf("policy suppression must be recorded as a VEX statement: %+v", v)
	}
}

func TestFunnelAndCounts(t *testing.T) {
	r := fixture(t, nil)
	want := Funnel{Raw: 12, Unique: 10, Affected: 8, Fixable: 6, Actionable: 7, Urgent: 5}
	if r.Funnel != want {
		t.Errorf("funnel = %+v, want %+v", r.Funnel, want)
	}
	if r.ByPriority[P0] != 3 || r.ByPriority[Suppressed] != 2 || r.ByPriority[Watch] != 1 {
		t.Errorf("by priority = %v", r.ByPriority)
	}
	if r.KEVHits != 2 || r.New != 7 || r.Resolved != 0 {
		t.Errorf("kev=%d new=%d resolved=%d", r.KEVHits, r.New, r.Resolved)
	}
	if r.Items[0].Priority != P0 || r.Items[0].KEV == nil {
		t.Errorf("KEV findings must sort first, got %+v", r.Items[0])
	}
	if len(r.ByTarget) != 2 || r.ByTarget[0].Name != "web" || r.ByTarget[0].Raw != 10 || r.ByTarget[1].ByPriority[P0] != 1 {
		t.Errorf("by target = %+v", r.ByTarget)
	}
	if r.Intel.EPSSDate != "2026-10-25" || r.VEXCount != 2 {
		t.Errorf("intel=%+v vex=%d", r.Intel, r.VEXCount)
	}
}

func TestSLAsSurviveRunsAndResolutionsAreTracked(t *testing.T) {
	st, _ := state.Load("")
	st.Findings["web|CVE-2023-4911|libc6|2.36-9"] = state.Entry{FirstSeen: "2026-10-20", Priority: P0}
	st.Findings["web|CVE-2020-0001|old|1"] = state.Entry{FirstSeen: "2026-10-16", Priority: P2}
	r := fixture(t, st)

	it := find(r, "web", "CVE-2023-4911")
	if it.FirstSeen != "2026-10-20" || it.Due != "2026-10-22" || !it.Overdue || it.AgeDays != 6 {
		t.Errorf("first-seen must survive runs and drive the SLA: %+v", it)
	}
	if r.Overdue != 1 || r.Resolved != 1 || r.New != 6 {
		t.Errorf("overdue=%d resolved=%d new=%d", r.Overdue, r.Resolved, r.New)
	}
	if got := r.MTTRDays[P2]; got != 10 {
		t.Errorf("MTTR P2 = %v, want 10 days", got)
	}
}

func TestGateBlocksOnlyGatedTargets(t *testing.T) {
	r := fixture(t, nil)
	blocked := Gate(r)
	if len(blocked) != 1 || blocked[0].Target != "api" || blocked[0].CVE != "CVE-2023-4911" {
		t.Errorf("gate = %+v", blocked)
	}
}

func TestGroups(t *testing.T) {
	r := fixture(t, nil)
	g := Groups(r.Items, P1)
	if len(g) != 4 {
		t.Fatalf("urgent groups = %d, want 4", len(g))
	}
	first := g[0]
	if first.CVE != "CVE-2023-4911" || first.Instances != 2 || len(first.Targets) != 2 || !first.Gated {
		t.Errorf("one CVE across two images must be one group: %+v", first)
	}
	if first.Summary() != "CVE-2023-4911 in libc6 (api, web)" {
		t.Errorf("summary = %q", first.Summary())
	}
	if all := Groups(r.Items, Watch); len(all) != 7 {
		t.Errorf("groups up to watch = %d", len(all))
	}
}

func TestTitle(t *testing.T) {
	for in, want := range map[string]string{"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "": "Unknown"} {
		if title(in) != want {
			t.Errorf("title(%q)", in)
		}
	}
	if firstNonEmpty("", "b") != "b" || firstNonEmpty("a", "b") != "a" {
		t.Error("firstNonEmpty")
	}
}
