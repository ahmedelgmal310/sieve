// Package config loads sieve.json: what is scanned and how findings are
// prioritised and gated.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Target is one scanned artifact.
type Target struct {
	Name  string `json:"name"`
	Image string `json:"image"`
	Owner string `json:"owner"`
	// Exposure is "internet" or "internal"; internet-facing targets get a
	// tighter priority for critical findings.
	Exposure string `json:"exposure"`
	// Gate makes the pipeline fail on this target's P0 or overdue findings.
	// Third-party images are monitored, not gated.
	Gate bool `json:"gate"`
}

// Policy holds the prioritisation thresholds and remediation SLAs.
type Policy struct {
	// EPSSUrgent: exploitation probability that makes a finding P0.
	EPSSUrgent float64 `json:"epssUrgent"`
	// EPSSHigh: probability that makes a high/critical finding P1.
	EPSSHigh float64 `json:"epssHigh"`
	// SLADays per priority, counted from the day a finding was first seen.
	SLADays map[string]int `json:"slaDays"`
	// NotAffected marks whole components as not affected, for reasons that
	// hold for every CVE in them (kernel headers in a container, for
	// example). Each rule must say why; Sieve exports the result as OpenVEX.
	NotAffected []ComponentRule `json:"notAffected,omitempty"`
}

// ComponentRule is a reviewed, component-wide not-affected decision.
type ComponentRule struct {
	PURLPrefix    string `json:"purlPrefix"`
	Justification string `json:"justification"`
	Impact        string `json:"impact"`
}

// Match returns the first rule covering the package URL.
func (p Policy) Match(purl string) (ComponentRule, bool) {
	for _, r := range p.NotAffected {
		if purl != "" && strings.HasPrefix(purl, r.PURLPrefix) {
			return r, true
		}
	}
	return ComponentRule{}, false
}

// Config is the whole file.
type Config struct {
	Targets []Target `json:"targets"`
	Policy  Policy   `json:"policy"`
}

var safeName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// Load reads and validates the configuration.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- operator-supplied config path
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, c.Validate()
}

// Validate rejects configurations that would mis-prioritise silently.
func (c *Config) Validate() error {
	if len(c.Targets) == 0 {
		return errors.New("config: no targets")
	}
	seen := map[string]bool{}
	for _, t := range c.Targets {
		if !safeName.MatchString(t.Name) {
			return fmt.Errorf("config: target name %q must be lowercase letters, digits, '.', '_' or '-'", t.Name)
		}
		if seen[t.Name] {
			return fmt.Errorf("config: duplicate target %q", t.Name)
		}
		seen[t.Name] = true
		if t.Image == "" {
			return fmt.Errorf("config: target %q has no image", t.Name)
		}
		if t.Exposure != "internet" && t.Exposure != "internal" {
			return fmt.Errorf("config: target %q exposure must be internet or internal", t.Name)
		}
	}
	p := c.Policy
	if p.EPSSUrgent <= 0 || p.EPSSUrgent > 1 || p.EPSSHigh <= 0 || p.EPSSHigh >= p.EPSSUrgent {
		return errors.New("config: need 0 < epssHigh < epssUrgent <= 1")
	}
	for _, k := range []string{"P0", "P1", "P2", "P3"} {
		if p.SLADays[k] <= 0 {
			return fmt.Errorf("config: slaDays.%s must be positive", k)
		}
	}
	for i, r := range p.NotAffected {
		if !strings.HasPrefix(r.PURLPrefix, "pkg:") || len(r.PURLPrefix) < 10 {
			return fmt.Errorf("config: notAffected[%d] needs a specific package URL prefix", i)
		}
		if r.Justification == "" || r.Impact == "" {
			return fmt.Errorf("config: notAffected[%d] needs a justification and an impact statement", i)
		}
	}
	if !(p.SLADays["P0"] <= p.SLADays["P1"] && p.SLADays["P1"] <= p.SLADays["P2"] && p.SLADays["P2"] <= p.SLADays["P3"]) {
		return errors.New("config: SLAs must not get shorter as priority drops")
	}
	return nil
}

// Target returns the named target.
func (c *Config) Target(name string) (Target, bool) {
	for _, t := range c.Targets {
		if t.Name == name {
			return t, true
		}
	}
	return Target{}, false
}
