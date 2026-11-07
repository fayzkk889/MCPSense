package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fayzkk889/MCPSense/internal/checks"
	"github.com/fayzkk889/MCPSense/internal/nodebridge"
	"github.com/spf13/pflag"
)

func TestCancelledMCPCallsDoNotCreateFiles(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	policy := mcpPolicy{Root: t.TempDir(), Write: true}
	if _, err := policy.operation(ctx, "mcpsense_init", json.RawMessage(`{"example":true}`)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled operation was executed: %v", err)
	}
	if _, _, err := runMCPCommand(ctx, []string{"init", "--example"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled CLI operation was executed: %v", err)
	}
}

func TestMCPScanFeatureParity(t *testing.T) {
	// Every new CLI option must be deliberately mapped or classified here. This
	// release gate prevents a new scanner feature silently missing from MCP.
	mapped := map[string]string{
		"mode": "mode", "dependencies": "dependencies", "format": "format", "severity": "severity",
		"checks": "checks", "exclude": "exclude", "output": "output", "sarif-output": "sarif_output",
		"baseline": "baseline", "require-metadata-baseline": "require_metadata_baseline",
		"no-cve": "no_cve", "offline": "offline", "allow-exec": "allow_exec", "server-arg": "server_args",
		"protocol": "protocol", "allow-private-network": "allow_private_network",
	}
	classified := map[string]string{
		"probe":           "unimplemented in both interfaces",
		"no-color":        "MCP formatted reports always disable terminal color",
		"no-baseline":     "MCP skips baseline handling unless an explicit existing baseline is supplied",
		"update-baseline": "separate reviewed mcpsense_accept_baseline tool",
		"show-diff":       "CLI compatibility flag; protected snapshots omit raw before/after text",
	}
	var properties map[string]interface{}
	for _, tool := range mcpTools(mcpPolicy{}) {
		if tool.Name == "mcpsense_scan" {
			properties = tool.InputSchema["properties"].(map[string]interface{})
		}
	}
	scanCmd().Flags().VisitAll(func(flag *pflag.Flag) {
		property, ok := mapped[flag.Name]
		if ok && properties[property] == nil {
			t.Errorf("CLI flag %s has no MCP property", flag.Name)
		}
		if !ok && classified[flag.Name] == "" {
			t.Errorf("new CLI flag %s needs an MCP mapping or explicit classification", flag.Name)
		}
	})
	policy := mcpPolicy{Root: t.TempDir()}
	result, err := policy.operation(context.Background(), "mcpsense_checks", json.RawMessage("{}"))
	if err != nil {
		t.Fatal(err)
	}
	catalog := result.StructuredContent.(map[string]interface{})["checks"].([]map[string]interface{})
	if len(catalog) != len(checks.NewRegistry().AllChecks()) {
		t.Fatal("MCP and CLI check catalogs differ")
	}
}

func TestMCPPathsRejectTraversalAndSymlinkEscapes(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	root, err := nodebridge.RealPath(root)
	if err != nil {
		t.Fatal(err)
	}
	policy := mcpPolicy{Root: root}
	secret := filepath.Join(outside, "private.json")
	if err := os.WriteFile(secret, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{secret, filepath.Join("..", filepath.Base(outside), "private.json"), ""} {
		if _, err := policy.path(path, false); err == nil {
			t.Fatalf("outside target accepted: %s", path)
		}
	}
	link := filepath.Join(root, "escape.json")
	if err := os.Symlink(secret, link); err != nil {
		t.Log("symlink creation unavailable on this platform")
	} else if _, err := policy.path(link, false); err == nil {
		t.Fatal("symlink escaped the approved root")
	}
	target := filepath.Join(root, "new.json")
	if _, err := policy.path(target, true); err != nil {
		t.Fatal(err)
	}
}

func TestMCPSetupPreservesConflictingEntriesAndComments(t *testing.T) {
	for _, isTOML := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "settings")
		key, text := "mcpServers", `{"theme":"dark","mcpServers":{"mcpsense":{"command":"other"}}}`
		if isTOML {
			key, text = "mcp_servers", "# personal settings\n[mcp_servers.mcpsense]\ncommand = \"other\"\n"
		}
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := installMCPConfig(path, key, map[string]interface{}{"command": "mcpsense"}, isTOML); err == nil {
			t.Fatal("conflicting existing entry overwritten")
		}
		current, _ := os.ReadFile(path)
		if string(current) != text {
			t.Fatal("existing client settings changed")
		}
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	original := "# keep the user's comments\nmodel = \"custom\"\n[mcp_servers.'an existing server']\ncommand = \"something\"\n"
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	backup, changed, err := installMCPConfig(path, "mcp_servers", map[string]interface{}{"command": "mcpsense", "args": []string{"mcp", "serve"}}, true)
	if err != nil || !changed {
		t.Fatal(backup, changed, err)
	}
	stored, _ := os.ReadFile(path)
	saved, _ := os.ReadFile(backup)
	if !strings.HasPrefix(string(stored), original) || string(saved) != original {
		t.Fatal("comments or exact backup lost")
	}
}
