// Command sieve triages container vulnerability scans: it de-duplicates
// Trivy findings, applies OpenVEX decisions, ranks what is left with CISA KEV
// and EPSS, tracks remediation SLAs, and publishes the result as a dashboard,
// SARIF, a job summary and GitHub issues.
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ahmedelgmal310/sieve/internal/config"
	"github.com/ahmedelgmal310/sieve/internal/intel"
	"github.com/ahmedelgmal310/sieve/internal/issues"
	"github.com/ahmedelgmal310/sieve/internal/output"
	"github.com/ahmedelgmal310/sieve/internal/state"
	"github.com/ahmedelgmal310/sieve/internal/triage"
	"github.com/ahmedelgmal310/sieve/internal/trivy"
	"github.com/ahmedelgmal310/sieve/internal/vex"
)

// Set at build time with -ldflags.
var version = "dev"

var nameField = regexp.MustCompile(`"name"\s*:\s*"([^"]+)"`)

// Exit codes.
const (
	exitOK      = 0
	exitError   = 1
	exitGateHit = 3
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, time.Now()))
}

type options struct {
	config, reports, kev, epss, vexDir, state, out string
	dashboardURL, repoURL                          string
	issues, dryRun, gate                           bool
	issuesMax                                      int
	repo, token                                    string
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, now time.Time) int {
	if len(args) > 0 && args[0] == "version" {
		fmt.Fprintln(stdout, "sieve", version)
		return exitOK
	}
	if len(args) > 0 && args[0] == "check" {
		return check(args[1:], stdout, stderr)
	}
	if len(args) == 0 || args[0] != "triage" {
		fmt.Fprintln(stderr, "usage: sieve triage [flags] | sieve check [flags] | sieve version")
		return exitError
	}
	var o options
	fs := flag.NewFlagSet("triage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.config, "config", "sieve.json", "targets and policy")
	fs.StringVar(&o.reports, "reports", "reports", "directory of Trivy JSON reports named <target>.json")
	fs.StringVar(&o.kev, "kev", intel.KEVURL, "CISA KEV catalogue (URL or file)")
	fs.StringVar(&o.epss, "epss", intel.EPSSURL, "EPSS scores CSV (URL or file, may be gzipped)")
	fs.StringVar(&o.vexDir, "vex", "vex", "directory of OpenVEX documents")
	fs.StringVar(&o.state, "state", "", "previous state file (first-seen dates); empty for a first run")
	fs.StringVar(&o.out, "out", "out", "output directory")
	fs.StringVar(&o.dashboardURL, "dashboard-url", "", "public dashboard URL, linked from summaries and issues")
	fs.StringVar(&o.repoURL, "repo-url", "https://github.com/ahmedelgmal310/sieve", "source repository URL")
	fs.BoolVar(&o.issues, "issues", false, "open, update and close GitHub issues for P0/P1 vulnerabilities")
	fs.BoolVar(&o.dryRun, "dry-run", false, "with -issues: print the plan without calling GitHub")
	fs.IntVar(&o.issuesMax, "issues-max", 15, "with -issues: most new issues per run")
	fs.BoolVar(&o.gate, "gate", false, "exit 3 when a gated target has a P0 or an overdue finding")
	fs.StringVar(&o.repo, "github-repo", os.Getenv("GITHUB_REPOSITORY"), "owner/name for issues")
	if err := fs.Parse(args[1:]); err != nil {
		return exitError
	}
	o.token = os.Getenv("GITHUB_TOKEN")

	code, err := triageCmd(ctx, o, stdout, now)
	if err != nil {
		fmt.Fprintln(stderr, "sieve:", err)
		return exitError
	}
	return code
}

func triageCmd(ctx context.Context, o options, stdout io.Writer, now time.Time) (int, error) {
	cfg, err := config.Load(o.config)
	if err != nil {
		return exitError, err
	}
	var findings []trivy.Finding
	raw := map[string]int{}
	for _, t := range cfg.Targets {
		path := filepath.Join(o.reports, t.Name+".json")
		f, n, err := trivy.Read(path, t.Name)
		if err != nil {
			return exitError, fmt.Errorf("report for %s: %w", t.Name, err)
		}
		findings = append(findings, f...)
		raw[t.Name] = n
	}
	in, err := intel.Load(ctx, o.kev, o.epss)
	if err != nil {
		return exitError, err
	}
	vexSet, err := vex.LoadDir(o.vexDir)
	if err != nil {
		return exitError, err
	}
	st, err := state.Load(o.state)
	if err != nil {
		return exitError, err
	}

	res := triage.Run(triage.Input{Config: cfg, Findings: findings, Raw: raw, Intel: in, VEX: vexSet, State: st, Today: now})

	if err := os.MkdirAll(o.out, 0o750); err != nil {
		return exitError, err
	}
	var md bytes.Buffer
	if err := output.Markdown(&md, res, o.dashboardURL); err != nil {
		return exitError, err
	}
	lines, err := targetLines(o.config)
	if err != nil {
		return exitError, err
	}
	writers := map[string]func(io.Writer) error{
		"results.json": func(w io.Writer) error { return output.JSON(w, res) },
		"summary.md":   func(w io.Writer) error { _, err := w.Write(md.Bytes()); return err },
		"sieve.sarif": func(w io.Writer) error {
			return output.SARIF(w, res, filepath.ToSlash(o.config), lines, triage.P1, version)
		},
		"index.html": func(w io.Writer) error { return output.Dashboard(w, res, cfg, o.repoURL, version) },
		"vex.openvex.json": func(w io.Writer) error {
			return output.OpenVEX(w, res, o.repoURL, version, now)
		},
	}
	for name, write := range writers {
		if err := writeFile(filepath.Join(o.out, name), write); err != nil {
			return exitError, err
		}
	}
	if err := st.Save(filepath.Join(o.out, "state.json")); err != nil {
		return exitError, err
	}
	if p := os.Getenv("GITHUB_STEP_SUMMARY"); p != "" {
		if err := appendFile(p, md.Bytes()); err != nil {
			return exitError, err
		}
	}

	f := res.Funnel
	fmt.Fprintf(stdout, "sieve %s: %d raw → %d unique → %d actionable → %d urgent (P0 %d, P1 %d, KEV %d, overdue %d)\n",
		res.Date, f.Raw, f.Unique, f.Actionable, f.Urgent, res.ByPriority[triage.P0], res.ByPriority[triage.P1], res.KEVHits, res.Overdue)

	if o.issues {
		if !o.dryRun && (o.repo == "" || o.token == "") {
			return exitError, errors.New("-issues needs GITHUB_REPOSITORY and GITHUB_TOKEN (or -dry-run)")
		}
		var api issues.API = issues.NewGitHub(o.repo, o.token)
		if o.dryRun && (o.repo == "" || o.token == "") {
			api = issues.Offline{}
		}
		plan, err := issues.Sync(ctx, api, triage.Groups(res.Items, triage.P1), o.dashboardURL, o.issuesMax, o.dryRun)
		if err != nil {
			return exitError, err
		}
		fmt.Fprintf(stdout, "issues: %d opened, %d updated, %d closed, %d deferred (cap %d)\n",
			len(plan.Opened), len(plan.Updated), len(plan.Closed), plan.Skipped, o.issuesMax)
	}

	if blocked := triage.Gate(res); o.gate && len(blocked) > 0 {
		for _, it := range blocked {
			fmt.Fprintf(stdout, "GATE %s %s %s in %s: %s\n", it.Priority, it.CVE, it.Package, it.Target, it.Reason)
		}
		return exitGateHit, nil
	}
	return exitOK, nil
}

// check validates the configuration and the OpenVEX documents without
// scanning anything, so a bad edit fails in review instead of at triage time.
func check(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "sieve.json", "targets and policy")
	vexDir := fs.String("vex", "vex", "directory of OpenVEX documents")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "sieve:", err)
		return exitError
	}
	vs, err := vex.LoadDir(*vexDir)
	if err != nil {
		fmt.Fprintln(stderr, "sieve:", err)
		return exitError
	}
	fmt.Fprintf(stdout, "ok: %d targets, %d not-affected rules, %d VEX statements\n",
		len(cfg.Targets), len(cfg.Policy.NotAffected), vs.Len())
	return exitOK
}

func writeFile(path string, write func(io.Writer) error) error {
	f, err := os.Create(filepath.Clean(path)) // #nosec G304 -- inside the operator's output directory
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	if err := write(w); err != nil {
		_ = f.Close()
		return err
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func appendFile(path string, b []byte) error {
	f, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- GITHUB_STEP_SUMMARY
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// targetLines finds the line of each target's "name" in the config, so SARIF
// results point at the entry that owns the image.
func targetLines(path string) (map[string]int, error) {
	b, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- operator-supplied config path
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for i, line := range strings.Split(string(b), "\n") {
		if m := nameField.FindStringSubmatch(line); m != nil {
			if _, dup := out[m[1]]; !dup {
				out[m[1]] = i + 1
			}
		}
	}
	return out, nil
}
