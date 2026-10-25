package trivy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRead(t *testing.T) {
	f, raw, err := Read(filepath.Join("..", "..", "testdata", "reports", "web.json"), "web")
	if err != nil {
		t.Fatal(err)
	}
	if raw != 10 || len(f) != 9 {
		t.Fatalf("raw=%d findings=%d (rows without an id are dropped)", raw, len(f))
	}
	ssl := f[2]
	if ssl.CVE != "CVE-2024-0001" || ssl.CVSS != 6.5 || ssl.Class != "os-pkgs" || ssl.PURL != "pkg:deb/debian/openssl@3.0.11" {
		t.Errorf("highest CVSS across sources must win: %+v", ssl)
	}
	if f[0].Key() != "web|CVE-2023-4911|libc6|2.36-9" {
		t.Errorf("key = %q", f[0].Key())
	}

	f, _, err = Read(filepath.Join("..", "..", "testdata", "reports", "api.json"), "")
	if err != nil || f[0].Target != "ghcr.io/example/api:main" {
		t.Errorf("empty target falls back to ArtifactName: %+v %v", f, err)
	}
}

func TestReadErrors(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := Read(filepath.Join(dir, "missing.json"), "x"); err == nil {
		t.Error("missing file")
	}
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte("not json"), 0o600)
	if _, _, err := Read(bad, "x"); err == nil {
		t.Error("not json")
	}
}
