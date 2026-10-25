package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	td  = filepath.Join("..", "..", "testdata")
	now = time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
)

func baseArgs(out string) []string {
	return []string{"triage",
		"-config", filepath.Join(td, "sieve.json"),
		"-reports", filepath.Join(td, "reports"),
		"-kev", filepath.Join(td, "kev.json"),
		"-epss", filepath.Join(td, "epss.csv.gz"),
		"-vex", filepath.Join(td, "vex"),
		"-out", out,
		"-dashboard-url", "https://example.test/sieve/",
	}
}

func TestTriageEndToEnd(t *testing.T) {
	out := t.TempDir()
	summary := filepath.Join(out, "step-summary.md")
	t.Setenv("GITHUB_STEP_SUMMARY", summary)
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), baseArgs(out), &stdout, &stderr, now)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "12 raw → 10 unique → 7 actionable → 5 urgent (P0 3, P1 2, KEV 2") {
		t.Errorf("stdout = %s", stdout.String())
	}
	for _, f := range []string{"results.json", "summary.md", "sieve.sarif", "index.html", "state.json", "vex.openvex.json"} {
		if st, err := os.Stat(filepath.Join(out, f)); err != nil || st.Size() == 0 {
			t.Errorf("%s missing: %v", f, err)
		}
	}

	var sarif struct {
		Runs []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
				Locs   []struct {
					PL struct {
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	readJSON(t, filepath.Join(out, "sieve.sarif"), &sarif)
	if n := len(sarif.Runs[0].Results); n != 5 {
		t.Errorf("SARIF carries the urgent findings only: %d", n)
	}
	if r := sarif.Runs[0].Results[0]; r.Level != "error" || r.Locs[0].PL.Region.StartLine < 2 {
		t.Errorf("SARIF result = %+v", r)
	}

	var res struct {
		Items []struct {
			Priority string `json:"priority"`
		} `json:"items"`
	}
	readJSON(t, filepath.Join(out, "results.json"), &res)
	for _, it := range res.Items {
		if it.Priority == "suppressed" {
			t.Error("results.json must leave suppressed findings to the VEX output")
		}
	}

	var openvex struct {
		Context    string `json:"@context"`
		Statements []struct {
			Vulnerability struct {
				Name string `json:"name"`
			} `json:"vulnerability"`
			Status string `json:"status"`
		} `json:"statements"`
	}
	readJSON(t, filepath.Join(out, "vex.openvex.json"), &openvex)
	if openvex.Context != "https://openvex.dev/ns/v0.2.0" || len(openvex.Statements) != 2 {
		t.Errorf("OpenVEX export = %+v", openvex)
	}

	html, _ := os.ReadFile(filepath.Join(out, "index.html"))
	for _, want := range []string{"12</b> raw findings", "CVE-2023-4911", `<span class="kev">KEV</span>`, "blocks release"} {
		if !bytes.Contains(html, []byte(want)) {
			t.Errorf("dashboard misses %q", want)
		}
	}
	md, _ := os.ReadFile(summary)
	if !bytes.Contains(md, []byte("12 raw findings → 7 that need action → 5 urgent")) {
		t.Errorf("job summary = %s", md)
	}

	// Second run with the saved state: nothing new, SLA clocks keep running.
	stdout.Reset()
	args := append(baseArgs(t.TempDir()), "-state", filepath.Join(out, "state.json"))
	if code := run(context.Background(), args, &stdout, &stderr, now.AddDate(0, 0, 3)); code != exitOK {
		t.Fatalf("second run exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "overdue 3") {
		t.Errorf("P0 findings must be overdue after 3 days: %s", stdout.String())
	}
}

func TestGateAndIssuesDryRun(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := append(baseArgs(t.TempDir()), "-gate", "-issues", "-dry-run")
	code := run(context.Background(), args, &stdout, &stderr, now)
	if code != exitGateHit {
		t.Fatalf("exit %d, want %d: %s %s", code, exitGateHit, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "issues: 4 opened") || !strings.Contains(stdout.String(), "GATE P0 CVE-2023-4911 libc6 in api") {
		t.Errorf("stdout = %s", stdout.String())
	}
}

func TestUsageAndErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if run(context.Background(), []string{"version"}, &stdout, &stderr, now) != exitOK || !strings.HasPrefix(stdout.String(), "sieve ") {
		t.Error("version")
	}
	if run(context.Background(), nil, &stdout, &stderr, now) != exitError {
		t.Error("no command")
	}
	if run(context.Background(), []string{"triage", "-nope"}, &stdout, &stderr, now) != exitError {
		t.Error("bad flag")
	}
	t.Setenv("GITHUB_TOKEN", "")
	for name, mutate := range map[string]func([]string) []string{
		"missing config": func(a []string) []string { return replace(a, "-config", "nope.json") },
		"missing report": func(a []string) []string { return replace(a, "-reports", t.TempDir()) },
		"missing kev":    func(a []string) []string { return replace(a, "-kev", "nope.json") },
		"bad vex":        func(a []string) []string { return replace(a, "-vex", filepath.Join(td, "reports")) },
		"bad state":      func(a []string) []string { return append(a, "-state", filepath.Join(td, "epss.csv")) },
		"issues no auth": func(a []string) []string { return append(a, "-issues") },
	} {
		stderr.Reset()
		if code := run(context.Background(), mutate(baseArgs(t.TempDir())), &stdout, &stderr, now); code != exitError {
			t.Errorf("%s: exit %d", name, code)
		}
	}
}

func replace(args []string, flag, value string) []string {
	out := append([]string(nil), args...)
	for i := range out {
		if out[i] == flag {
			out[i+1] = value
		}
	}
	return out
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func TestCheck(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"check", "-config", filepath.Join(td, "sieve.json"), "-vex", filepath.Join(td, "vex")}, &stdout, &stderr, now); code != exitOK {
		t.Fatalf("check exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "ok: 2 targets, 1 not-affected rules, 2 VEX statements") {
		t.Errorf("stdout = %s", stdout.String())
	}
	for _, args := range [][]string{
		{"check", "-config", "nope.json"},
		{"check", "-config", filepath.Join(td, "sieve.json"), "-vex", filepath.Join(td, "reports")},
		{"check", "-bad"},
	} {
		if run(context.Background(), args, &stdout, &stderr, now) != exitError {
			t.Errorf("%v must fail", args)
		}
	}
}
