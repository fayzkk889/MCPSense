package drift

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fayzkk889/MCPSense/internal/models"
)

func TestSnapshotMinimizesSensitiveData(t *testing.T) {
	secret := "SYNTHETIC_PRIVATE_VALUE"
	m := &models.MCPManifest{Tools: []models.MCPTool{{Name: "read", Description: secret, InputSchema: json.RawMessage(`{"type":"object"}`)}}, Resources: []models.MCPResource{{URI: "https://user:" + secret + "@example.invalid/?token=" + secret, Name: secret}}}
	cfg := &models.MCPClientConfig{MCPServers: map[string]models.MCPServerEntry{secret: {Command: secret, Args: []string{"--token", secret}, Env: map[string]string{"TOKEN": secret}}}}
	before := BuildSnapshot(m, cfg, "https://example.invalid/?token="+secret, "config")
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := Save(path, before); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatal("baseline retained secret")
	}
	m.Tools[0].Description = "changed"
	cfg.MCPServers[secret] = models.MCPServerEntry{Command: "other", Args: []string{"new"}}
	after := BuildSnapshot(m, cfg, "synthetic", "config")
	findings := Diff(before, after)
	data, err = json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatal("drift leaked secret")
	}
	if len(findings) == 0 {
		t.Fatal("drift lost")
	}
}

func TestSnapshotRejectsLegacyAndFuture(t *testing.T) {
	for _, data := range []string{`{"target":"old","tools":{}}`, `{"format_version":999}`} {
		p := filepath.Join(t.TempDir(), "baseline.json")
		if err := os.WriteFile(p, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Fatal("unsupported baseline accepted")
		}
	}
}

func TestSnapshotRoundTripAndArgumentBoundaries(t *testing.T) {
	cfg := &models.MCPClientConfig{MCPServers: map[string]models.MCPServerEntry{"s": {Command: "node", Args: []string{"a b", "c"}}}}
	before := BuildSnapshot(nil, cfg, "target", "config")
	p := filepath.Join(t.TempDir(), "baseline.json")
	if err := Save(p, before); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(Diff(loaded, before)) != 0 {
		t.Fatal("roundtrip drift")
	}
	cfg.MCPServers["s"] = models.MCPServerEntry{Command: "node", Args: []string{"a", "b c"}}
	if len(Diff(loaded, BuildSnapshot(nil, cfg, "target", "config"))) != 1 {
		t.Fatal("argument boundary change missed")
	}
}
