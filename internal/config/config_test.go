package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShippedConfigs(t *testing.T) {
	for _, p := range []string{filepath.Join("..", "..", "sieve.json"), filepath.Join("..", "..", "testdata", "sieve.json")} {
		c, err := Load(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if _, ok := c.Target(c.Targets[0].Name); !ok {
			t.Error("Target lookup")
		}
		if _, ok := c.Target("nope"); ok {
			t.Error("unknown target must not resolve")
		}
	}
}

func TestPolicyMatch(t *testing.T) {
	p := Policy{NotAffected: []ComponentRule{{PURLPrefix: "pkg:deb/debian/linux-libc-dev@", Justification: "x", Impact: "y"}}}
	if _, ok := p.Match("pkg:deb/debian/linux-libc-dev@6.1"); !ok {
		t.Error("prefix must match")
	}
	for _, purl := range []string{"pkg:deb/debian/linux-libc-dev-extra@1", ""} {
		if _, ok := p.Match(purl); ok {
			t.Errorf("%q must not match", purl)
		}
	}
}

func TestValidation(t *testing.T) {
	good := `"policy":{"epssUrgent":0.5,"epssHigh":0.1,"slaDays":{"P0":2,"P1":7,"P2":30,"P3":90}}`
	target := `{"name":"web","image":"x","exposure":"internet"}`
	cases := map[string]string{
		"no targets":       `{"targets":[],` + good + `}`,
		"bad name":         `{"targets":[{"name":"Web App","image":"x","exposure":"internet"}],` + good + `}`,
		"duplicate":        `{"targets":[` + target + `,` + target + `],` + good + `}`,
		"no image":         `{"targets":[{"name":"web","exposure":"internet"}],` + good + `}`,
		"bad exposure":     `{"targets":[{"name":"web","image":"x","exposure":"dmz"}],` + good + `}`,
		"epss order":       `{"targets":[` + target + `],"policy":{"epssUrgent":0.1,"epssHigh":0.5,"slaDays":{"P0":2,"P1":7,"P2":30,"P3":90}}}`,
		"missing sla":      `{"targets":[` + target + `],"policy":{"epssUrgent":0.5,"epssHigh":0.1,"slaDays":{"P0":2}}}`,
		"sla order":        `{"targets":[` + target + `],"policy":{"epssUrgent":0.5,"epssHigh":0.1,"slaDays":{"P0":9,"P1":7,"P2":30,"P3":90}}}`,
		"vague rule":       `{"targets":[` + target + `],"policy":{"epssUrgent":0.5,"epssHigh":0.1,"slaDays":{"P0":2,"P1":7,"P2":30,"P3":90},"notAffected":[{"purlPrefix":"pkg:","justification":"x","impact":"y"}]}}`,
		"unexplained rule": `{"targets":[` + target + `],"policy":{"epssUrgent":0.5,"epssHigh":0.1,"slaDays":{"P0":2,"P1":7,"P2":30,"P3":90},"notAffected":[{"purlPrefix":"pkg:deb/debian/x@"}]}}`,
		"not json":         `{`,
	}
	dir := t.TempDir()
	for name, body := range cases {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := Load(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("missing file")
	}
}
