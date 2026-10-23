package drift

import (
	"encoding/json"
	"testing"

	"github.com/fayzkk889/MCPSense/internal/models"
)

func metadataFixture() *models.MCPManifest {
	return &models.MCPManifest{Description: "Record service", Instructions: "Use record identifiers.",
		Tools: []models.MCPTool{{Name: "read", Title: "Read record", Description: "Retrieve one record.", InputSchema: json.RawMessage(`{"type":"object"}`), OutputSchema: json.RawMessage(`{"type":"object"}`), Annotations: &models.ToolAnnotations{Title: "Reader"}}},
		Resources: []models.MCPResource{{URI: "record://catalog", Name: "Catalog", Description: "Available records."}},
		Prompts: []models.MCPPrompt{{Name: "summarize", Description: "Summarize a record.", Arguments: json.RawMessage(`[{"name":"record","required":true}]`)}}}
}

func TestExpandedMetadataChanges(t *testing.T) {
	cases := []struct {
		name, id string
		edit func(*models.MCPManifest)
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
