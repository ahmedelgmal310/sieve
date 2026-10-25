// Package intel loads the exploit intelligence Sieve prioritises with: the
// CISA Known Exploited Vulnerabilities catalogue and FIRST's EPSS scores.
package intel

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Public feeds. Both are free and need no API key.
const (
	KEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	EPSSURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

	maxFeedBytes = 64 << 20
)

// KEVEntry is one actively exploited vulnerability.
type KEVEntry struct {
	DateAdded  string `json:"dateAdded"`
	DueDate    string `json:"dueDate"`
	Ransomware bool   `json:"ransomware"`
	Name       string `json:"name"`
}

// EPSS is the probability (0..1) that a CVE is exploited in the next 30 days,
// and where that probability ranks among all CVEs.
type EPSS struct {
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
}

// Intel bundles both feeds.
type Intel struct {
	KEV       map[string]KEVEntry
	EPSS      map[string]EPSS
	EPSSDate  string
	KEVCount  int
	FetchedAt time.Time
}

// Load reads both feeds. Each source is a URL or a local file path, so CI can
// download once and tests can use fixtures.
func Load(ctx context.Context, kevSrc, epssSrc string) (*Intel, error) {
	in := &Intel{FetchedAt: time.Now().UTC()}
	kevData, err := open(ctx, kevSrc)
	if err != nil {
		return nil, fmt.Errorf("load KEV: %w", err)
	}
	in.KEV, err = parseKEV(kevData)
	if err != nil {
		return nil, err
	}
	in.KEVCount = len(in.KEV)

	epssData, err := open(ctx, epssSrc)
	if err != nil {
		return nil, fmt.Errorf("load EPSS: %w", err)
	}
	in.EPSS, in.EPSSDate, err = parseEPSS(epssData)
	if err != nil {
		return nil, err
	}
	return in, nil
}

func open(ctx context.Context, src string) ([]byte, error) {
	if !strings.HasPrefix(src, "https://") {
		return os.ReadFile(filepath.Clean(src)) // #nosec G304 -- operator-supplied feed path
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sieve-vuln-triage")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", src, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFeedBytes {
		return nil, fmt.Errorf("GET %s: feed larger than %d bytes", src, maxFeedBytes)
	}
	return b, nil
}

func parseKEV(b []byte) (map[string]KEVEntry, error) {
	var doc struct {
		Vulnerabilities []struct {
			CVE        string `json:"cveID"`
			Name       string `json:"vulnerabilityName"`
			DateAdded  string `json:"dateAdded"`
			DueDate    string `json:"dueDate"`
			Ransomware string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("parse KEV: %w", err)
	}
	if len(doc.Vulnerabilities) == 0 {
		return nil, errors.New("parse KEV: catalogue is empty")
	}
	out := make(map[string]KEVEntry, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		out[v.CVE] = KEVEntry{
			DateAdded:  v.DateAdded,
			DueDate:    v.DueDate,
			Ransomware: strings.EqualFold(v.Ransomware, "Known"),
			Name:       v.Name,
		}
	}
	return out, nil
}

// parseEPSS reads the daily CSV, gzipped or not:
//
//	#model_version:v2025.03.14,score_date:2026-10-25T00:00:00+0000
//	cve,epss,percentile
//	CVE-1999-0001,0.0102,0.765
func parseEPSS(b []byte) (map[string]EPSS, string, error) {
	var r io.Reader = bytes.NewReader(b)
	if len(b) > 2 && b[0] == 0x1f && b[1] == 0x8b {
		gz, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, "", fmt.Errorf("parse EPSS: %w", err)
		}
		defer gz.Close()
		r = io.LimitReader(gz, maxFeedBytes)
	}
	br := bufio.NewReader(r)
	date := ""
	if peek, err := br.Peek(1); err == nil && peek[0] == '#' {
		line, _ := br.ReadString('\n')
		if i := strings.Index(line, "score_date:"); i >= 0 {
			date = strings.TrimSpace(line[i+len("score_date:"):])
			if len(date) >= 10 {
				date = date[:10]
			}
		}
	}
	cr := csv.NewReader(br)
	cr.ReuseRecord = true
	header, err := cr.Read()
	if err != nil {
		return nil, "", fmt.Errorf("parse EPSS header: %w", err)
	}
	if len(header) < 3 || header[0] != "cve" {
		return nil, "", fmt.Errorf("parse EPSS: unexpected header %v", header)
	}
	out := make(map[string]EPSS, 300000)
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("parse EPSS: %w", err)
		}
		score, err1 := strconv.ParseFloat(rec[1], 64)
		pct, err2 := strconv.ParseFloat(rec[2], 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out[rec[0]] = EPSS{Score: score, Percentile: pct}
	}
	if len(out) == 0 {
		return nil, "", errors.New("parse EPSS: no scores")
	}
	return out, date, nil
}
