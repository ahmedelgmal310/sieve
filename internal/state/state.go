// Package state remembers when each finding was first seen, so remediation
// SLAs are measured from discovery and not reset by every scan.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// Entry is what is remembered about one finding.
type Entry struct {
	FirstSeen string `json:"firstSeen"` // YYYY-MM-DD
	Priority  string `json:"priority"`
}

// State maps finding keys to entries.
type State struct {
	Version  int              `json:"version"`
	Updated  string           `json:"updated"`
	Findings map[string]Entry `json:"findings"`
	// Resolved keeps a short history: days to fix per priority, used for MTTR.
	Resolved []Resolution `json:"resolved,omitempty"`
}

// Resolution records a finding that disappeared from the scans.
type Resolution struct {
	Key      string `json:"key"`
	Priority string `json:"priority"`
	Opened   string `json:"opened"`
	Closed   string `json:"closed"`
}

const maxResolved = 2000

// Load reads a state file. A missing file is a first run, not an error.
func Load(path string) (*State, error) {
	s := &State{Version: 1, Findings: map[string]Entry{}}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- operator-supplied state path
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if s.Findings == nil {
		s.Findings = map[string]Entry{}
	}
	return s, nil
}

// Save writes the state file.
func (s *State) Save(path string) error {
	b, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// Advance records today's scan: findings keep their first-seen date, new ones
// start today, and findings no longer present are logged as resolved. It
// returns how many findings are new and how many were resolved.
func (s *State) Advance(today string, current map[string]string) (added, resolved int) {
	next := make(map[string]Entry, len(current))
	for key, prio := range current {
		e, ok := s.Findings[key]
		if !ok {
			e = Entry{FirstSeen: today}
			added++
		}
		e.Priority = prio
		next[key] = e
	}
	keys := make([]string, 0)
	for key := range s.Findings {
		if _, still := current[key]; !still {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		e := s.Findings[key]
		s.Resolved = append(s.Resolved, Resolution{Key: key, Priority: e.Priority, Opened: e.FirstSeen, Closed: today})
		resolved++
	}
	if len(s.Resolved) > maxResolved {
		s.Resolved = s.Resolved[len(s.Resolved)-maxResolved:]
	}
	s.Findings = next
	s.Updated = today
	return added, resolved
}

// FirstSeen returns when a finding was first seen, or today for a new one.
func (s *State) FirstSeen(key, today string) string {
	if e, ok := s.Findings[key]; ok {
		return e.FirstSeen
	}
	return today
}
