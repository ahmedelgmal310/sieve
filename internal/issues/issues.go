// Package issues keeps one GitHub issue per urgent vulnerability: opened when
// it appears, updated while it lasts, closed with a note when it is fixed.
package issues

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ahmedelgmal310/sieve/internal/triage"
)

// Label marks every issue Sieve manages; nothing without it is ever touched.
const Label = "sieve"

var marker = regexp.MustCompile(`<!-- sieve:([A-Z0-9-]+) -->`)

// Issue is the part of a GitHub issue Sieve reads.
type Issue struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	Body   string `json:"body"`
	State  string `json:"state"`
}

// API is the subset of the GitHub REST API used. It is an interface so the
// sync logic is tested without the network.
type API interface {
	OpenIssues(ctx context.Context) ([]Issue, error)
	Create(ctx context.Context, title, body string, labels []string) (int, error)
	Update(ctx context.Context, number int, title, body string, labels []string) error
	Close(ctx context.Context, number int, comment string) error
}

// Plan is what a sync did (or, in dry-run mode, would do).
type Plan struct {
	Opened  []string `json:"opened"`
	Updated []string `json:"updated"`
	Closed  []string `json:"closed"`
	Skipped int      `json:"skipped"` // urgent groups beyond the per-run cap
}

// Sync reconciles the urgent groups with the open Sieve issues. max caps how
// many new issues one run may open, so a first scan cannot flood a backlog.
func Sync(ctx context.Context, api API, groups []triage.Group, dashboardURL string, max int, dryRun bool) (Plan, error) {
	var plan Plan
	open, err := api.OpenIssues(ctx)
	if err != nil {
		return plan, err
	}
	existing := map[string]Issue{}
	for _, is := range open {
		if m := marker.FindStringSubmatch(is.Body); m != nil {
			existing[m[1]] = is
		}
	}
	wanted := map[string]bool{}
	for _, g := range groups {
		wanted[g.CVE] = true
		title := fmt.Sprintf("[%s] %s", g.Priority, g.Summary())
		body := Body(g, dashboardURL)
		labels := []string{Label, "security", "priority:" + g.Priority}
		if is, ok := existing[g.CVE]; ok {
			if is.Title != title || strings.TrimSpace(is.Body) != strings.TrimSpace(body) {
				plan.Updated = append(plan.Updated, g.CVE)
				if !dryRun {
					if err := api.Update(ctx, is.Number, title, body, labels); err != nil {
						return plan, err
					}
				}
			}
			continue
		}
		if len(plan.Opened) >= max {
			plan.Skipped++
			continue
		}
		plan.Opened = append(plan.Opened, g.CVE)
		if !dryRun {
			if _, err := api.Create(ctx, title, body, labels); err != nil {
				return plan, err
			}
		}
	}
	for cve, is := range existing {
		if wanted[cve] {
			continue
		}
		plan.Closed = append(plan.Closed, cve)
		if !dryRun {
			msg := "Resolved: Sieve no longer finds " + cve + " as P0/P1 in any scanned image (fixed, upgraded or closed by a VEX decision)."
			if err := api.Close(ctx, is.Number, msg); err != nil {
				return plan, err
			}
		}
	}
	return plan, nil
}

// Body renders the issue text. The hidden marker ties the issue to its CVE.
func Body(g triage.Group, dashboardURL string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<!-- sieve:%s -->\n", g.CVE)
	fmt.Fprintf(&b, "**%s** · %s\n\n", g.Priority, g.Reason)
	fmt.Fprintf(&b, "| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| Vulnerability | [%s](%s) %s |\n", g.CVE, g.URL, strings.ReplaceAll(g.Title, "|", "/"))
	fmt.Fprintf(&b, "| Severity | %s (CVSS %.1f) |\n", g.Severity, g.CVSS)
	fmt.Fprintf(&b, "| Exploitation | EPSS %.1f%% (percentile %.0f)", g.EPSS.Score*100, g.EPSS.Percentile*100)
	if g.KEV != nil {
		fmt.Fprintf(&b, ", **CISA KEV** since %s", g.KEV.DateAdded)
	}
	b.WriteString(" |\n")
	fmt.Fprintf(&b, "| Images | %s |\n", "`"+strings.Join(g.Targets, "`, `")+"`")
	fmt.Fprintf(&b, "| Packages | %s |\n", strings.Join(g.Packages, ", "))
	fix := "No fixed version yet: mitigate, or replace the component."
	if len(g.Fixes) > 0 {
		fix = "Upgrade to " + strings.Join(g.Fixes, ", ")
	}
	fmt.Fprintf(&b, "| Fix | %s |\n", fix)
	due := g.Due
	if g.Overdue {
		due += " (**overdue**)"
	}
	fmt.Fprintf(&b, "| Due | %s |\n\n", due)
	b.WriteString("If this does not affect us, record why in an OpenVEX document under `vex/` instead of closing the issue by hand.\n")
	if dashboardURL != "" {
		fmt.Fprintf(&b, "\n[Dashboard](%s)\n", dashboardURL)
	}
	return b.String()
}

// Offline is an API with no existing issues, for dry runs without GitHub
// credentials. It refuses writes.
type Offline struct{}

// OpenIssues returns nothing.
func (Offline) OpenIssues(context.Context) ([]Issue, error) { return nil, nil }

// Create refuses.
func (Offline) Create(context.Context, string, string, []string) (int, error) {
	return 0, errors.New("offline: no GitHub credentials")
}

// Update refuses.
func (Offline) Update(context.Context, int, string, string, []string) error {
	return errors.New("offline: no GitHub credentials")
}

// Close refuses.
func (Offline) Close(context.Context, int, string) error {
	return errors.New("offline: no GitHub credentials")
}

// GitHub implements API against api.github.com.
type GitHub struct {
	Repo  string // owner/name
	Token string
	Base  string
	HTTP  *http.Client
}

// NewGitHub returns a client for the repository.
func NewGitHub(repo, token string) *GitHub {
	return &GitHub{Repo: repo, Token: token, Base: "https://api.github.com", HTTP: &http.Client{Timeout: 30 * time.Second}}
}

func (g *GitHub) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, g.Base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+g.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := g.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %s: %.200s", method, path, resp.Status, data)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// OpenIssues lists open issues carrying the Sieve label.
func (g *GitHub) OpenIssues(ctx context.Context) ([]Issue, error) {
	var all []Issue
	for page := 1; page <= 20; page++ {
		var batch []Issue
		path := fmt.Sprintf("/repos/%s/issues?state=open&labels=%s&per_page=100&page=%d", g.Repo, Label, page)
		if err := g.do(ctx, http.MethodGet, path, nil, &batch); err != nil {
			return nil, err
		}
		all = append(all, batch...)
		if len(batch) < 100 {
			break
		}
	}
	return all, nil
}

// Create opens an issue.
func (g *GitHub) Create(ctx context.Context, title, body string, labels []string) (int, error) {
	var out Issue
	err := g.do(ctx, http.MethodPost, "/repos/"+g.Repo+"/issues",
		map[string]any{"title": title, "body": body, "labels": labels}, &out)
	return out.Number, err
}

// Update rewrites an issue.
func (g *GitHub) Update(ctx context.Context, number int, title, body string, labels []string) error {
	return g.do(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/issues/%d", g.Repo, number),
		map[string]any{"title": title, "body": body, "labels": labels}, nil)
}

// Close comments on an issue and closes it as completed.
func (g *GitHub) Close(ctx context.Context, number int, comment string) error {
	if err := g.do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/issues/%d/comments", g.Repo, number),
		map[string]any{"body": comment}, nil); err != nil {
		return err
	}
	return g.do(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/issues/%d", g.Repo, number),
		map[string]any{"state": "closed", "state_reason": "completed"}, nil)
}
