package checks

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/faizan/mcpsense/internal/models"
)

func TestDescriptionClarityCheck_TooShort(t *testing.T) {
	ctx := newTestCtx()
	ctx.Manifest = &models.MCPManifest{
		Name:    "test",
		Version: "1.0.0",
		Tools: []models.MCPTool{
			{Name: "do_thing", Description: "Does stuff.", InputSchema: json.RawMessage(`{"type":"object"}`)},
		},
	}

	check := &DescriptionClarityCheck{}
	findings := check.Run(ctx)
	require.NotEmpty(t, findings, "short description should trigger finding")
	assert.Equal(t, "QUAL-001", findings[0].ID)
	assert.Equal(t, models.SeverityMedium, findings[0].Severity)
}

func TestDescriptionClarityCheck_GoodDescription(t *testing.T) {
	ctx := newTestCtx()
	ctx.Manifest = &models.MCPManifest{
		Name:    "test",
		Version: "1.0.0",
		Tools: []models.MCPTool{
			{
				Name:        "search_documents",
				Description: "Searches workspace documents by keyword and returns matching titles and snippets.",
				InputSchema: json.RawMessage(`{"type":"object"}`),
			},
		},
	}

	check := &DescriptionClarityCheck{}
	findings := check.Run(ctx)
	// Should have no medium or high severity findings.
	for _, f := range findings {
		assert.NotEqual(t, models.SeverityMedium, f.Severity)
		assert.NotEqual(t, models.SeverityHigh, f.Severity)
	}
}

func TestAmbiguousParamCheck_AmbiguousName(t *testing.T) {
	ctx := newTestCtx()
	ctx.Manifest = &models.MCPManifest{
		Name:    "test",
		Version: "1.0.0",
		Tools: []models.MCPTool{
			{
				Name:        "process",
				Description: "Processes something.",
				InputSchema: json.RawMessage(`{"type":"object","properties":{"data":{"type":"string"},"input":{"type":"string"}}}`),
			},
		},
	}

	check := &AmbiguousParamCheck{}
	findings := check.Run(ctx)
	require.NotEmpty(t, findings, "should flag ambiguous param names")
	for _, f := range findings {
		assert.Equal(t, "QUAL-002", f.ID)
	}
}

func TestAmbiguousParamCheck_DescriptiveName(t *testing.T) {
	ctx := newTestCtx()
	ctx.Manifest = &models.MCPManifest{
		Name:    "test",
		Version: "1.0.0",
		Tools: []models.MCPTool{
			{
				Name:        "search_documents",
				Description: "Searches documents.",
				InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string","description":"Search keyword"}}}`),
			},
		},
	}

	check := &AmbiguousParamCheck{}
	findings := check.Run(ctx)
	assert.Empty(t, findings, "descriptive param names should not be flagged")
}

func TestMissingParamDescCheck_MissingDescription(t *testing.T) {
	ctx := newTestCtx()
	ctx.Manifest = &models.MCPManifest{
		Name:    "test",
		Version: "1.0.0",
		Tools: []models.MCPTool{
			{
				Name:        "my_tool",
				Description: "Does something useful and important.",
				InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"}}}`),
			},
		},
	}

	check := &MissingParamDescCheck{}
	findings := check.Run(ctx)
	require.NotEmpty(t, findings, "should flag parameter without description")
	assert.Equal(t, "QUAL-003", findings[0].ID)
}

func TestDuplicateToolCheck_SimilarNames(t *testing.T) {
	ctx := newTestCtx()
	ctx.Manifest = &models.MCPManifest{
		Name:    "test",
		Version: "1.0.0",
		Tools: []models.MCPTool{
			{Name: "search_doc", Description: "Searches documents."},
			{Name: "search_docs", Description: "Searches all documents."},
		},
	}

	check := &DuplicateToolCheck{}
	findings := check.Run(ctx)
	require.NotEmpty(t, findings, "should flag very similar tool names")
	assert.Equal(t, "QUAL-004", findings[0].ID)
}

func TestDuplicateToolCheck_DistinctNames(t *testing.T) {
	ctx := newTestCtx()
	ctx.Manifest = &models.MCPManifest{
		Name:    "test",
		Version: "1.0.0",
		Tools: []models.MCPTool{
			{Name: "create_note", Description: "Creates a note."},
			{Name: "delete_record", Description: "Deletes a record."},
		},
	}

	check := &DuplicateToolCheck{}
	findings := check.Run(ctx)
	assert.Empty(t, findings, "distinct tool names should not be flagged")
}

func TestExcessiveToolCountCheck_UnderLimit(t *testing.T) {
	ctx := newTestCtx()
	tools := make([]models.MCPTool, 10)
	ctx.Manifest = &models.MCPManifest{Name: "test", Version: "1.0.0", Tools: tools}

	check := &ExcessiveToolCountCheck{}
	findings := check.Run(ctx)
	assert.Empty(t, findings)
}

func TestExcessiveToolCountCheck_OverLimit(t *testing.T) {
	ctx := newTestCtx()
	tools := make([]models.MCPTool, 55)
	for i := range tools {
		tools[i] = models.MCPTool{Name: "tool"}
	}
	ctx.Manifest = &models.MCPManifest{Name: "test", Version: "1.0.0", Tools: tools}

	check := &ExcessiveToolCountCheck{}
	findings := check.Run(ctx)
	require.NotEmpty(t, findings)
	assert.Equal(t, "QUAL-006", findings[0].ID)
	assert.Equal(t, models.SeverityInfo, findings[0].Severity)
}

func TestLevenshtein(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"abc", "abc", 0},
		{"abc", "abcd", 1},
		{"kitten", "sitting", 3},
		{"search_doc", "search_docs", 1},
	}
	for _, tt := range tests {
		t.Run(tt.a+"_"+tt.b, func(t *testing.T) {
			assert.Equal(t, tt.want, levenshtein(tt.a, tt.b))
		})
	}
}
