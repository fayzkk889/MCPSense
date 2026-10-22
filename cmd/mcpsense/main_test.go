package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSingleScanJSONAndSARIF(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "manifest.json")
	out := filepath.Join(dir, "result.json")
	sarif := filepath.Join(dir, "result.sarif")
	if err := os.WriteFile(target, []byte(`{"name":"test","version":"1","protocolVersion":"2025-11-25","tools":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	c := rootCmd()
	c.SetArgs([]string{"scan", target, "--offline", "--no-baseline", "--checks", "SPEC-005", "--format", "json", "--output", out, "--sarif-output", sarif})
	if err := c.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{out, sarif} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if !json.Valid(b) {
			t.Fatalf("invalid JSON in %s", p)
		}
	}
}
func TestOfflineCLIRejectsLive(t *testing.T) {
	c := rootCmd()
	c.SetArgs([]string{"scan", "https://synthetic.invalid", "--offline", "--no-baseline"})
	if err := c.Execute(); err == nil {
		t.Fatal("offline live accepted")
	}
}
