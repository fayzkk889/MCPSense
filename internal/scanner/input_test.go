package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMalformedDiscoveredManifestFails(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "server.go"), []byte("package demo"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{bad"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := New(Options{Offline: true}).Scan(dir); err == nil {
		t.Fatal("malformed discovered input silently skipped")
	}
}
func TestAllDiscoveredConfigsAreIncluded(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".cursor"), 0700); err != nil {
		t.Fatal(err)
	}
	for p, data := range map[string]string{"mcp.json": `{"mcpServers":{"one":{"command":"node"}}}`, ".cursor/mcp.json": `{"mcpServers":{"two":{"command":"python"}}}`} {
		if err := os.WriteFile(filepath.Join(dir, p), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	_, ctx, err := New(Options{Offline: true}).Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if ctx.ClientConfig == nil || len(ctx.ClientConfig.MCPServers) != 2 {
		t.Fatal("second config skipped")
	}
}
