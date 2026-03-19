package checks

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/faizan/mcpsense/internal/models"
)

func TestSpecManifestStructureCheck_MissingName(t *testing.T) {
	ctx := newTestCtx()
	ctx.Manifest = &models.MCPManifest{Version: "1.0.0"}

	check := &SpecManifestStructureCheck{}
	findings := check.Run(ctx)
	require.NotEmpty(t, findings)
	assert.Equal(t, "SPEC-001", findings[0].ID)
}

func TestSpecManifestStructureCheck_ValidManifest(t *testing.T) {
	ctx := newTestCtx()
	ctx.Manifest = &models.MCPManifest{
		Name:    "my_server",
		Version: "1.0.0",
		Tools:   []models.MCPTool{{Name: "do_thing", Description: "Does a thing."}},
	}

	check := &SpecManifestStructureCheck{}
	findings := check.Run(ctx)
	assert.Empty(t, findings, "valid manifest should produce no findings")
}

func TestSpecToolSchemaCheck_InvalidJSON(t *testing.T) {
	ctx := newTestCtx()
	ctx.Manifest = &models.MCPManifest{
		Name:    "test",
		Version: "1.0.0",
		Tools: []models.MCPTool{
			{Name: "bad_tool", Description: "A tool.", InputSchema: json.RawMessage(`{invalid json}`)},
		},
	}

	check := &SpecToolSchemaCheck{}
	findings := check.Run(ctx)
	require.NotEmpty(t, findings)
	assert.Equal(t, "SPEC-002", findings[0].ID)
	assert.Equal(t, models.SeverityHigh, findings[0].Severity)
}

func TestSpecToolSchemaCheck_ValidSchema(t *testing.T) {
	ctx := newTestCtx()
	ctx.Manifest = &models.MCPManifest{
		Name:    "test",
		Version: "1.0.0",
		Tools: []models.MCPTool{
			{
				Name:        "search",
				Description: "Searches things.",
				InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"}}}`),
			},
		},
	}

	check := &SpecToolSchemaCheck{}
	findings := check.Run(ctx)
	// No high severity findings expected for valid schema.
	for _, f := range findings {
		assert.NotEqual(t, models.SeverityHigh, f.Severity)
		assert.NotEqual(t, models.SeverityCritical, f.Severity)
	}
}

func TestSpecToolNamingCheck_BadName(t *testing.T) {
	ctx := newTestCtx()
	ctx.Manifest = &models.MCPManifest{
		Name:    "test",
		Version: "1.0.0",
		Tools: []models.MCPTool{
			{Name: "RUN-CMD!", Description: "Bad name."},
		},
	}

	check := &SpecToolNamingCheck{}
	findings := check.Run(ctx)
	require.NotEmpty(t, findings)
	assert.Equal(t, "SPEC-003", findings[0].ID)
}

func TestSpecToolNamingCheck_GoodName(t *testing.T) {
	ctx := newTestCtx()
	ctx.Manifest = &models.MCPManifest{
		Name:    "test",
		Version: "1.0.0",
		Tools: []models.MCPTool{
			{Name: "search_documents", Description: "Searches documents."},
		},
	}

	check := &SpecToolNamingCheck{}
	findings := check.Run(ctx)
	assert.Empty(t, findings)
}

func TestSpecResourceURICheck_PathTraversalURI(t *testing.T) {
	ctx := newTestCtx()
	ctx.Manifest = &models.MCPManifest{
		Name:    "test",
		Version: "1.0.0",
		Resources: []models.MCPResource{
			{URI: "file:///workspace/../etc", Name: "etc"},
		},
	}

	check := &SpecResourceURICheck{}
	// Should not crash and should parse the URI.
	findings := check.Run(ctx)
	_ = findings // May or may not flag depending on scheme, just verify no panic.
}

func TestSpecProtocolVersionCheck_KnownVersion(t *testing.T) {
	ctx := newTestCtx()
	ctx.Manifest = &models.MCPManifest{Name: "test", Version: "2024-11-05"}

	check := &SpecProtocolVersionCheck{}
	findings := check.Run(ctx)
	assert.Empty(t, findings, "known version should not produce findings")
}

func TestSpecProtocolVersionCheck_UnknownVersion(t *testing.T) {
	ctx := newTestCtx()
	ctx.Manifest = &models.MCPManifest{Name: "test", Version: "0.0.0-unknown"}

	check := &SpecProtocolVersionCheck{}
	findings := check.Run(ctx)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "SPEC-005", findings[0].ID)
	assert.Equal(t, models.SeverityInfo, findings[0].Severity)
}
