// Package vex applies OpenVEX statements: signed-off, reviewable decisions
// that a vulnerability does not affect a product, with the reason why.
package vex

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Statuses defined by OpenVEX.
const (
	NotAffected        = "not_affected"
	Affected           = "affected"
	Fixed              = "fixed"
	UnderInvestigation = "under_investigation"
)

// Justifications OpenVEX allows for not_affected.
var justifications = map[string]bool{
	"component_not_present":                             true,
	"vulnerable_code_not_present":                       true,
	"vulnerable_code_not_in_execute_path":               true,
	"vulnerable_code_cannot_be_controlled_by_adversary": true,
	"inline_mitigations_already_exist":                  true,
}

// Statement is one decision about one vulnerability.
type Statement struct {
	Vulnerability string   `json:"vulnerability"`
	Products      []string `json:"products"`
	Status        string   `json:"status"`
	Justification string   `json:"justification,omitempty"`
	Impact        string   `json:"impact,omitempty"`
	Author        string   `json:"author"`
	Timestamp     string   `json:"timestamp"`
	Document      string   `json:"document"`
}

// Set is every statement Sieve knows about.
type Set struct {
	statements []Statement
}

type document struct {
	Context    string `json:"@context"`
	ID         string `json:"@id"`
	Author     string `json:"author"`
	Timestamp  string `json:"timestamp"`
	Statements []struct {
		Vulnerability struct {
			Name string `json:"name"`
		} `json:"vulnerability"`
		Products []struct {
			ID string `json:"@id"`
		} `json:"products"`
		Status        string `json:"status"`
		Justification string `json:"justification"`
		Impact        string `json:"impact_statement"`
		Timestamp     string `json:"timestamp"`
	} `json:"statements"`
}

// LoadDir reads every *.json OpenVEX document in dir. A missing directory is
// an empty set; a malformed or non-compliant document is an error, so a typo
// can never silently suppress a vulnerability.
func LoadDir(dir string) (*Set, error) {
	s := &Set{}
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	for _, p := range paths {
		if err := s.load(p); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Set) load(path string) error {
	b, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- documents live in the repository
	if err != nil {
		return err
	}
	var d document
	if err := json.Unmarshal(b, &d); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if !strings.HasPrefix(d.Context, "https://openvex.dev/ns") {
		return fmt.Errorf("%s: not an OpenVEX document (@context %q)", path, d.Context)
	}
	if d.Author == "" {
		return fmt.Errorf("%s: OpenVEX documents must name an author", path)
	}
	for i, st := range d.Statements {
		where := fmt.Sprintf("%s statement %d", path, i+1)
		if !strings.HasPrefix(st.Vulnerability.Name, "CVE-") && !strings.HasPrefix(st.Vulnerability.Name, "GHSA-") {
			return fmt.Errorf("%s: unknown vulnerability id %q", where, st.Vulnerability.Name)
		}
		switch st.Status {
		case NotAffected:
			if !justifications[st.Justification] && st.Impact == "" {
				return fmt.Errorf("%s: not_affected needs a valid justification or an impact statement", where)
			}
		case Affected, Fixed, UnderInvestigation:
		default:
			return fmt.Errorf("%s: unknown status %q", where, st.Status)
		}
		if len(st.Products) == 0 {
			return fmt.Errorf("%s: no products", where)
		}
		ts := st.Timestamp
		if ts == "" {
			ts = d.Timestamp
		}
		if _, err := time.Parse(time.RFC3339, ts); err != nil {
			return fmt.Errorf("%s: timestamp must be RFC 3339: %w", where, err)
		}
		stmt := Statement{
			Vulnerability: st.Vulnerability.Name,
			Status:        st.Status,
			Justification: st.Justification,
			Impact:        st.Impact,
			Author:        d.Author,
			Timestamp:     ts,
			Document:      filepath.Base(path),
		}
		for _, p := range st.Products {
			stmt.Products = append(stmt.Products, p.ID)
		}
		s.statements = append(s.statements, stmt)
	}
	return nil
}

// Len is the number of statements loaded.
func (s *Set) Len() int { return len(s.statements) }

// Match returns the most recent statement about cve that covers the target or
// the package. A product matches when it equals the target name, when it is
// "*", or when the package URL starts with it (so "pkg:deb/debian/openssl"
// covers every version).
func (s *Set) Match(cve, target, purl string) (Statement, bool) {
	var best Statement
	found := false
	for _, st := range s.statements {
		if st.Vulnerability != cve {
			continue
		}
		for _, p := range st.Products {
			if p == "*" || p == target || (purl != "" && strings.HasPrefix(purl, p)) {
				if !found || st.Timestamp > best.Timestamp {
					best, found = st, true
				}
			}
		}
	}
	return best, found
}

// Suppresses reports whether the statement removes the finding from the
// actionable list.
func (st Statement) Suppresses() bool {
	return st.Status == NotAffected || st.Status == Fixed
}
