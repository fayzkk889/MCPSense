package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
func TestOutputAndBaselineCannotOverwriteTarget(t *testing.T) {
	for _, flag := range []string{"--output", "--baseline"} {
		p := filepath.Join(t.TempDir(), "manifest.json")
		original := `{"name":"test","version":"1","tools":[]}`
		if err := os.WriteFile(p, []byte(original), 0600); err != nil {
			t.Fatal(err)
		}
		c := rootCmd()
		c.SetArgs([]string{"scan", p, "--offline", flag, p, "--update-baseline"})
		if err := c.Execute(); err == nil {
			t.Fatal("target overwrite accepted")
		}
		b, err := os.ReadFile(p)
		if err != nil || string(b) != original {
			t.Fatal("target changed")
		}
	}
}
func TestInvalidProjectConfigFails(t *testing.T) {
	before, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(before); err != nil {
			t.Error(err)
		}
	}()
	if err := os.WriteFile(configFile, []byte("{malformed"), 0600); err != nil {
		t.Fatal(err)
	}
	c := rootCmd()
	c.SetArgs([]string{"scan", "synthetic-missing", "--offline"})
	err = c.Execute()
	if err == nil || !strings.Contains(err.Error(), "configuration") {
		t.Fatalf("invalid config ignored: %v", err)
	}
}
func TestOfflineCLIRejectsLive(t *testing.T) {
	c := rootCmd()
	c.SetArgs([]string{"scan", "https://synthetic.invalid", "--offline", "--no-baseline"})
	if err := c.Execute(); err == nil {
		t.Fatal("offline live accepted")
	}
}
