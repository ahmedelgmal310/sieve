package intel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var td = filepath.Join("..", "..", "testdata")

func TestLoadFiles(t *testing.T) {
	for _, epss := range []string{"epss.csv", "epss.csv.gz"} {
		in, err := Load(context.Background(), filepath.Join(td, "kev.json"), filepath.Join(td, epss))
		if err != nil {
			t.Fatalf("%s: %v", epss, err)
		}
		if in.KEVCount != 2 || !in.KEV["CVE-2024-9999"].Ransomware || in.KEV["CVE-2023-4911"].DateAdded != "2023-11-21" {
			t.Errorf("KEV = %+v", in.KEV)
		}
		if len(in.EPSS) != 5 || in.EPSS["CVE-2024-0001"].Score != 0.72 || in.EPSSDate != "2026-10-25" {
			t.Errorf("%s: EPSS = %v (%s); unparsable rows must be skipped", epss, in.EPSS, in.EPSSDate)
		}
	}
}

func TestLoadOverHTTPS(t *testing.T) {
	kev, _ := os.ReadFile(filepath.Join(td, "kev.json"))
	epss, _ := os.ReadFile(filepath.Join(td, "epss.csv.gz"))
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kev.json":
			_, _ = w.Write(kev)
		case "/epss.csv.gz":
			_, _ = w.Write(epss)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	old := http.DefaultClient
	http.DefaultClient = srv.Client()
	defer func() { http.DefaultClient = old }()

	in, err := Load(context.Background(), srv.URL+"/kev.json", srv.URL+"/epss.csv.gz")
	if err != nil || in.KEVCount != 2 || len(in.EPSS) != 5 {
		t.Fatalf("over https: %v %+v", err, in)
	}
	if _, err := Load(context.Background(), srv.URL+"/missing", srv.URL+"/epss.csv.gz"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("missing feed error = %v", err)
	}
}

func TestBadFeeds(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	kev := filepath.Join(td, "kev.json")
	epss := filepath.Join(td, "epss.csv")
	cases := map[string][2]string{
		"kev not json":  {write("k1.json", "{"), epss},
		"kev empty":     {write("k2.json", `{"vulnerabilities":[]}`), epss},
		"kev missing":   {filepath.Join(dir, "nope.json"), epss},
		"epss header":   {kev, write("e1.csv", "a,b,c\n")},
		"epss empty":    {kev, write("e2.csv", "cve,epss,percentile\n")},
		"epss no lines": {kev, write("e3.csv", "")},
		"epss bad gzip": {kev, write("e4.csv.gz", "\x1f\x8bnot gzip")},
		"epss missing":  {kev, filepath.Join(dir, "nope.csv")},
	}
	for name, c := range cases {
		if _, err := Load(context.Background(), c[0], c[1]); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
