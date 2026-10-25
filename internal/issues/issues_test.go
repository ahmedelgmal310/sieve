package issues

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ahmedelgmal310/sieve/internal/intel"
	"github.com/ahmedelgmal310/sieve/internal/triage"
)

type fakeAPI struct {
	open    []Issue
	created []string
	updated []int
	closed  []int
	failOn  string
}

func (f *fakeAPI) OpenIssues(context.Context) ([]Issue, error) {
	if f.failOn == "list" {
		return nil, errors.New("boom")
	}
	return f.open, nil
}
func (f *fakeAPI) Create(_ context.Context, title, _ string, _ []string) (int, error) {
	if f.failOn == "create" {
		return 0, errors.New("boom")
	}
	f.created = append(f.created, title)
	return len(f.created), nil
}
func (f *fakeAPI) Update(_ context.Context, n int, _, _ string, _ []string) error {
	if f.failOn == "update" {
		return errors.New("boom")
	}
	f.updated = append(f.updated, n)
	return nil
}
func (f *fakeAPI) Close(_ context.Context, n int, _ string) error {
	if f.failOn == "close" {
		return errors.New("boom")
	}
	f.closed = append(f.closed, n)
	return nil
}

func group(cve, prio string) triage.Group {
	return triage.Group{CVE: cve, Priority: prio, Reason: "why", Severity: "HIGH", CVSS: 8,
		EPSS: intel.EPSS{Score: 0.6, Percentile: 0.99}, Targets: []string{"web"}, Packages: []string{"libc6 2.36"},
		Fixes: []string{"libc6 2.37"}, Due: "2026-10-28"}
}

func TestSyncOpensUpdatesAndCloses(t *testing.T) {
	keep := group("CVE-1", "P0")
	api := &fakeAPI{open: []Issue{
		{Number: 10, Title: "[P0] " + keep.Summary(), Body: Body(keep, "https://dash")}, // unchanged
		{Number: 11, Title: "old", Body: "<!-- sieve:CVE-2 -->\nstale"},                 // changed
		{Number: 12, Title: "gone", Body: "<!-- sieve:CVE-9 -->\nfixed now"},            // resolved
		{Number: 13, Title: "manual", Body: "no marker"},                                // never touched
	}}
	groups := []triage.Group{keep, group("CVE-2", "P1"), group("CVE-3", "P0"), group("CVE-4", "P1")}

	plan, err := Sync(context.Background(), api, groups, "https://dash", 1, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Opened) != 1 || plan.Skipped != 1 || len(api.created) != 1 {
		t.Errorf("the per-run cap must hold: %+v", plan)
	}
	if len(api.updated) != 1 || api.updated[0] != 11 {
		t.Errorf("only the changed issue is updated: %v", api.updated)
	}
	if len(api.closed) != 1 || api.closed[0] != 12 {
		t.Errorf("only resolved Sieve issues are closed: %v", api.closed)
	}

	dry := &fakeAPI{open: api.open}
	plan, err = Sync(context.Background(), dry, groups, "", 15, true)
	if err != nil || len(plan.Opened) != 2 || len(dry.created)+len(dry.updated)+len(dry.closed) != 0 {
		t.Errorf("dry run must not call GitHub: %+v %v", plan, err)
	}
}

func TestSyncErrors(t *testing.T) {
	g := []triage.Group{group("CVE-1", "P0")}
	for _, op := range []string{"list", "create"} {
		if _, err := Sync(context.Background(), &fakeAPI{failOn: op}, g, "", 5, false); err == nil {
			t.Errorf("%s failure must surface", op)
		}
	}
	upd := &fakeAPI{failOn: "update", open: []Issue{{Number: 1, Body: "<!-- sieve:CVE-1 -->"}}}
	if _, err := Sync(context.Background(), upd, g, "", 5, false); err == nil {
		t.Error("update failure must surface")
	}
	cl := &fakeAPI{failOn: "close", open: []Issue{{Number: 1, Body: "<!-- sieve:CVE-7 -->"}}}
	if _, err := Sync(context.Background(), cl, g, "", 5, false); err == nil {
		t.Error("close failure must surface")
	}
}

func TestBody(t *testing.T) {
	g := group("CVE-1", "P0")
	g.KEV = &intel.KEVEntry{DateAdded: "2024-01-01"}
	g.Overdue = true
	b := Body(g, "https://dash")
	for _, want := range []string{"<!-- sieve:CVE-1 -->", "CISA KEV", "overdue", "Upgrade to libc6 2.37", "vex/", "[Dashboard](https://dash)"} {
		if !strings.Contains(b, want) {
			t.Errorf("body misses %q:\n%s", want, b)
		}
	}
	g.Fixes = nil
	if !strings.Contains(Body(g, ""), "No fixed version yet") {
		t.Error("no-fix wording")
	}
}

func TestGitHubClient(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		calls = append(calls, r.Method+" "+r.URL.RequestURI()+" "+string(body))
		switch {
		case r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode([]Issue{{Number: 5, Body: "<!-- sieve:CVE-1 -->"}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/issues"):
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(Issue{Number: 6})
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	gh := NewGitHub("o/r", "tok")
	gh.Base = srv.URL
	ctx := context.Background()

	open, err := gh.OpenIssues(ctx)
	if err != nil || len(open) != 1 {
		t.Fatalf("list = %v %v", open, err)
	}
	if n, err := gh.Create(ctx, "t", "b", []string{Label}); err != nil || n != 6 {
		t.Errorf("create = %d %v", n, err)
	}
	if err := gh.Update(ctx, 5, "t", "b", nil); err != nil {
		t.Error(err)
	}
	if err := gh.Close(ctx, 5, "done"); err != nil {
		t.Error(err)
	}
	joined := strings.Join(calls, "\n")
	for _, want := range []string{"GET /repos/o/r/issues?state=open&labels=sieve", "POST /repos/o/r/issues/5/comments", `"state":"closed"`, `"state_reason":"completed"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing call %q in\n%s", want, joined)
		}
	}
	gh.Token = "bad"
	if _, err := gh.OpenIssues(ctx); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("auth error = %v", err)
	}
}

func TestOffline(t *testing.T) {
	var o Offline
	ctx := context.Background()
	if is, err := o.OpenIssues(ctx); err != nil || is != nil {
		t.Error("offline list")
	}
	if _, err := o.Create(ctx, "", "", nil); err == nil {
		t.Error("offline create must refuse")
	}
	if o.Update(ctx, 1, "", "", nil) == nil || o.Close(ctx, 1, "") == nil {
		t.Error("offline writes must refuse")
	}
}
