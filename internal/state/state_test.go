package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAdvanceAndPersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s, err := Load(path)
	if err != nil || len(s.Findings) != 0 {
		t.Fatalf("first run = %+v %v", s, err)
	}
	added, resolved := s.Advance("2026-10-01", map[string]string{"a": "P0", "b": "P2"})
	if added != 2 || resolved != 0 {
		t.Errorf("added=%d resolved=%d", added, resolved)
	}
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}

	s2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if s2.FirstSeen("a", "2026-10-05") != "2026-10-01" || s2.FirstSeen("new", "2026-10-05") != "2026-10-05" {
		t.Error("first-seen must persist")
	}
	added, resolved = s2.Advance("2026-10-05", map[string]string{"a": "P1", "c": "P3"})
	if added != 1 || resolved != 1 || s2.Findings["a"].Priority != "P1" || s2.Findings["a"].FirstSeen != "2026-10-01" {
		t.Errorf("added=%d resolved=%d state=%+v", added, resolved, s2.Findings)
	}
	if len(s2.Resolved) != 1 || s2.Resolved[0].Key != "b" || s2.Resolved[0].Opened != "2026-10-01" {
		t.Errorf("resolved = %+v", s2.Resolved)
	}
}

func TestResolvedHistoryIsBounded(t *testing.T) {
	s, _ := Load("")
	cur := map[string]string{}
	for i := 0; i < maxResolved+50; i++ {
		cur[string(rune('a'+i%26))+string(rune(i))] = "P3"
	}
	s.Advance("2026-01-01", cur)
	s.Advance("2026-01-02", map[string]string{})
	if len(s.Resolved) != maxResolved {
		t.Errorf("history = %d, want %d", len(s.Resolved), maxResolved)
	}
}

func TestLoadEdgeCases(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.json")
	_ = os.WriteFile(empty, nil, 0o600)
	if s, err := Load(empty); err != nil || s.Findings == nil {
		t.Errorf("empty file = %v", err)
	}
	null := filepath.Join(dir, "null.json")
	_ = os.WriteFile(null, []byte(`{"version":1}`), 0o600)
	if s, err := Load(null); err != nil || s.Findings == nil {
		t.Errorf("no findings key = %v", err)
	}
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte(`{`), 0o600)
	if _, err := Load(bad); err == nil {
		t.Error("corrupt state must fail")
	}
	if _, err := Load(dir); err == nil {
		t.Error("a directory is not a state file")
	}
}
