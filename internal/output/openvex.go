package output

import (
	"encoding/json"
	"io"
	"sort"
	"time"

	"github.com/ahmedelgmal310/sieve/internal/triage"
)

// OpenVEX writes every suppression of this run, from policy rules and from
// VEX documents alike, as one OpenVEX v0.2.0 document. Downstream tools (and
// auditors) can then see exactly what was set aside and why.
func OpenVEX(w io.Writer, r triage.Result, repo, version string, now time.Time) error {
	type product struct {
		ID string `json:"@id"`
	}
	type statement struct {
		Vulnerability struct {
			Name string `json:"name"`
		} `json:"vulnerability"`
		Products      []product `json:"products"`
		Status        string    `json:"status"`
		Justification string    `json:"justification,omitempty"`
		Impact        string    `json:"impact_statement,omitempty"`
	}
	byKey := map[string]*statement{}
	var keys []string
	for _, it := range r.Items {
		if it.Priority != triage.Suppressed || it.VEX == nil {
			continue
		}
		k := it.CVE + "|" + it.VEX.Status + "|" + it.VEX.Justification + "|" + it.VEX.Impact
		st, ok := byKey[k]
		if !ok {
			st = &statement{Status: it.VEX.Status, Justification: it.VEX.Justification, Impact: it.VEX.Impact}
			st.Vulnerability.Name = it.CVE
			byKey[k] = st
			keys = append(keys, k)
		}
		id := it.PURL
		if id == "" {
			id = it.Target
		}
		st.Products = append(st.Products, product{ID: id})
	}
	sort.Strings(keys)
	statements := make([]statement, 0, len(keys))
	for _, k := range keys {
		statements = append(statements, *byKey[k])
	}
	doc := map[string]any{
		"@context":   "https://openvex.dev/ns/v0.2.0",
		"@id":        repo + "/vex/" + r.Date,
		"author":     "Sieve " + version,
		"timestamp":  now.UTC().Format(time.RFC3339),
		"version":    1,
		"statements": statements,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	return enc.Encode(doc)
}
