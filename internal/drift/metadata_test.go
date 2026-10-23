package drift

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/fayzkk889/MCPSense/internal/models"
)

func metadataFixture() *models.MCPManifest {
	return &models.MCPManifest{Description: "Record service", Instructions: "Use record identifiers.",
		Tools:     []models.MCPTool{{Name: "read", Title: "Read record", Description: "Retrieve one record.", InputSchema: json.RawMessage(`{"type":"object"}`), OutputSchema: json.RawMessage(`{"type":"object"}`), Annotations: &models.ToolAnnotations{Title: "Reader"}}},
		Resources: []models.MCPResource{{URI: "record://catalog", Name: "Catalog", Description: "Available records."}},
		Prompts:   []models.MCPPrompt{{Name: "summarize", Description: "Summarize a record.", Arguments: json.RawMessage(`[{"name":"record","required":true}]`)}}}
}

func TestLegacyMetadataCoverageIsExplicitAndReadOnly(t *testing.T) {
	m := metadataFixture()
	before := BuildSnapshot(m, nil, "target", "manifest")
	before.Metadata = nil // Existing format-2 snapshot made before the extension.
	p := filepath.Join(t.TempDir(), "baseline.json")
	if err := Save(p, before); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	m.Instructions = "Changed instructions."
	after := BuildSnapshot(m, nil, "target", "manifest")
	if fs := Diff(loaded, after); len(fs) != 0 {
		t.Fatalf("invented legacy drift: %+v", fs)
	}
	fields, warning := ComparisonCoverage(loaded, after)
	if warning == "" || strings.Contains(strings.Join(fields, ","), "server.instructions") {
		t.Fatal("legacy scope overstated")
	}
	m.Tools[0].Description += " Changed."
	if fs := Diff(loaded, BuildSnapshot(m, nil, "target", "manifest")); len(fs) != 1 || fs[0].ID != "DRIFT-002" {
		t.Fatalf("legacy comparison lost: %+v", fs)
	}
	unchanged, err := os.ReadFile(p)
	if err != nil || string(original) != string(unchanged) {
		t.Fatal("comparison changed legacy baseline")
	}
	fields, warning = ComparisonCoverage(after, after)
	if warning != "" || !strings.Contains(strings.Join(fields, ","), "server.instructions") {
		t.Fatal("new metadata coverage missing")
	}
	config := BuildSnapshot(nil, &models.MCPClientConfig{}, "target", "config")
	fields, warning = ComparisonCoverage(config, config)
	if warning != "" || !reflect.DeepEqual(fields, []string{"servers.existing_configuration_without_env_values"}) {
		t.Fatal("config-only scope changed")
	}
}

func TestExtendedMetadataCanonicalizationPrivacyAndRoundTrip(t *testing.T) {
	secret := "SYNTHETIC_METADATA_PRIVATE_VALUE"
	m := metadataFixture()
	m.Description, m.Instructions, m.Tools[0].Title = secret, secret, secret
	m.Tools[0].OutputSchema = json.RawMessage(`{"description":"` + secret + `","maximum":9007199254740992}`)
	m.Prompts[0].Name, m.Prompts[0].Description = secret, secret
	m.Prompts[0].Arguments = json.RawMessage(`[{"name":"` + secret + `","required":true}]`)
	before := BuildSnapshot(m, nil, "target", "manifest")
	p := filepath.Join(t.TempDir(), "baseline.json")
	if err := Save(p, before); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(p)
	if err != nil || strings.Contains(string(data), secret) {
		t.Fatal("metadata leaked")
	}
	loaded, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	m.Tools[0].OutputSchema = json.RawMessage(`{ "maximum": 9007199254740992, "description": "` + secret + `" }`)
	m.Prompts[0].Arguments = json.RawMessage(`[{ "required": true, "name": "` + secret + `" }]`)
	if fs := Diff(loaded, BuildSnapshot(m, nil, "target", "manifest")); len(fs) != 0 {
		t.Fatalf("formatting created drift: %+v", fs)
	}
	m.Tools[0].OutputSchema = json.RawMessage(`{"description":"` + secret + `","maximum":9007199254740993}`)
	fs := Diff(loaded, BuildSnapshot(m, nil, "target", "manifest"))
	if len(fs) != 1 || fs[0].ID != "DRIFT-010" {
		t.Fatal("numeric change rounded away")
	}
	data, err = json.Marshal(fs)
	if err != nil || strings.Contains(string(data), secret) {
		t.Fatal("finding leaked metadata")
	}
}

func TestExtensionVersionAndProfile(t *testing.T) {
	before := BuildSnapshot(metadataFixture(), nil, "target", "manifest")
	before.Metadata.Version = 999
	if _, err := MarshalSnapshot(before); err == nil {
		t.Fatal("unsupported extension serialized")
	}
	data, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("unsupported extension loaded")
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".go") && !strings.HasSuffix(entry.Name(), "_test.go") {
			if _, err := driftSources.ReadFile(entry.Name()); err != nil {
				t.Fatalf("unfingerprinted drift code: %s", entry.Name())
			}
		}
	}
	if len(Profile()) != 64 {
		t.Fatal("missing drift profile")
	}
}

func TestReadOnlyWeakeningKeepsExistingFinding(t *testing.T) {
	m := metadataFixture()
	yes := true
	m.Tools[0].Annotations.ReadOnlyHint = &yes
	before := BuildSnapshot(m, nil, "target", "manifest")
	m.Tools[0].Annotations = nil
	fs := Diff(before, BuildSnapshot(m, nil, "target", "manifest"))
	if len(fs) != 1 || fs[0].ID != "DRIFT-004" {
		t.Fatalf("existing weakening semantics changed: %+v", fs)
	}
}

func TestExpandedMetadataChanges(t *testing.T) {
	cases := []struct {
		name, id string
		edit     func(*models.MCPManifest)
	}{
		{"server description", "DRIFT-011", func(m *models.MCPManifest) { m.Description += " Changed." }},
		{"server instructions", "DRIFT-011", func(m *models.MCPManifest) { m.Instructions += " Changed." }},
		{"tool title", "DRIFT-010", func(m *models.MCPManifest) { m.Tools[0].Title += " Changed." }},
		{"output schema", "DRIFT-010", func(m *models.MCPManifest) { m.Tools[0].OutputSchema = json.RawMessage(`{"type":"string"}`) }},
		{"annotation title", "DRIFT-008", func(m *models.MCPManifest) { m.Tools[0].Annotations.Title += " Changed." }},
		{"resource description", "DRIFT-009", func(m *models.MCPManifest) { m.Resources[0].Description += " Changed." }},
		{"new prompt", "DRIFT-012", func(m *models.MCPManifest) { m.Prompts = append(m.Prompts, models.MCPPrompt{Name: "other"}) }},
		{"prompt description", "DRIFT-013", func(m *models.MCPManifest) { m.Prompts[0].Description += " Changed." }},
		{"prompt arguments", "DRIFT-013", func(m *models.MCPManifest) { m.Prompts[0].Arguments = json.RawMessage(`[{"name":"other"}]`) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := metadataFixture()
			before := BuildSnapshot(m, nil, "target", "manifest")
			tc.edit(m)
			fs := Diff(before, BuildSnapshot(m, nil, "target", "manifest"))
			if len(fs) != 1 || fs[0].ID != tc.id {
				t.Fatalf("expected %s, got %+v", tc.id, fs)
			}
		})
	}
}
