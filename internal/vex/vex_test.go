package vex

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAndMatch(t *testing.T) {
	s, err := LoadDir(filepath.Join("..", "..", "testdata", "vex"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Len() != 2 {
		t.Fatalf("statements = %d", s.Len())
	}
	st, ok := s.Match("CVE-2024-0007", "web", "")
	if !ok || !st.Suppresses() || st.Author != "Security Team" || st.Document != "web.openvex.json" {
		t.Errorf("match by target = %+v %v", st, ok)
	}
	st, ok = s.Match("CVE-2024-0005", "other", "pkg:deb/debian/tar@1.34")
	if !ok || st.Suppresses() {
		t.Errorf("under_investigation matches by purl prefix but must not suppress: %+v", st)
	}
	if _, ok := s.Match("CVE-2024-0007", "api", "pkg:x"); ok {
		t.Error("statements must not leak to other products")
	}
	empty, err := LoadDir(filepath.Join(t.TempDir(), "missing"))
	if err != nil || empty.Len() != 0 {
		t.Errorf("missing dir = %v %v", empty, err)
	}
}

func TestNewestStatementWins(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.json", `{"@context":"https://openvex.dev/ns/v0.2.0","author":"a","timestamp":"2026-01-01T00:00:00Z",
	 "statements":[{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"*"}],"status":"not_affected","justification":"component_not_present"}]}`)
	write(t, dir, "b.json", `{"@context":"https://openvex.dev/ns/v0.2.0","author":"b","timestamp":"2026-02-01T00:00:00Z",
	 "statements":[{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"web"}],"status":"affected"}]}`)
	s, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := s.Match("CVE-1", "web", "")
	if st.Status != Affected || st.Suppresses() {
		t.Errorf("a later 'affected' must override an earlier 'not_affected': %+v", st)
	}
}

func TestInvalidDocumentsFailLoudly(t *testing.T) {
	cases := map[string]string{
		"not json":         `{`,
		"wrong context":    `{"@context":"x","author":"a","statements":[]}`,
		"no author":        `{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`,
		"bad id":           stmt(`"vulnerability":{"name":"X-1"},"products":[{"@id":"a"}],"status":"affected"`),
		"bad status":       stmt(`"vulnerability":{"name":"CVE-1"},"products":[{"@id":"a"}],"status":"maybe"`),
		"no products":      stmt(`"vulnerability":{"name":"CVE-1"},"products":[],"status":"affected"`),
		"no justification": stmt(`"vulnerability":{"name":"CVE-1"},"products":[{"@id":"a"}],"status":"not_affected"`),
		"bad timestamp":    `{"@context":"https://openvex.dev/ns/v0.2.0","author":"a","timestamp":"yesterday","statements":[{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"a"}],"status":"affected"}]}`,
	}
	for name, body := range cases {
		dir := t.TempDir()
		write(t, dir, "doc.json", body)
		if _, err := LoadDir(dir); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func stmt(inner string) string {
	return `{"@context":"https://openvex.dev/ns/v0.2.0","author":"a","timestamp":"2026-01-01T00:00:00Z","statements":[{` + inner + `}]}`
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(strings.TrimSpace(body)), 0o600); err != nil {
		t.Fatal(err)
	}
}
