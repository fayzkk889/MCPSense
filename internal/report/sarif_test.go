package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/fayzkk889/MCPSense/internal/models"
)

func TestSARIFReporterOutput(t *testing.T) {
	findings := []models.Finding{
		{
			ID:          "SEC-009",
			Title:       "Invisible Unicode characters in tool definition",
			Description: "Tool \"evil_tool\" description contains zero-width space characters.",
			Severity:    models.SeverityCritical,
			Category:    models.CategorySecurity,
			Location:    models.Location{ToolName: "evil_tool"},
			Remediation: "Remove invisible Unicode characters from tool definitions.",
		},
		{
			ID:          "SEC-014",
			Title:       "Shell metacharacters in config server command",
			Description: "MCP server entry \"injected\" has command containing shell metacharacters.",
			Severity:    models.SeverityCritical,
			Category:    models.CategorySecurity,
			Location:    models.Location{File: "mcp.json"},
			Remediation: "Remove shell metacharacters from the command field.",
		},
		{
			ID:          "QUAL-001",
			Title:       "Tool has very short description",
			Description: "Tool description for \"short_tool\" is too short.",
			Severity:    models.SeverityMedium,
			Category:    models.CategoryQuality,
			Location:    models.Location{ToolName: "short_tool"},
			Remediation: "Write a description of at least 20 characters.",
		},
	}

	report := models.NewReport("testdata/test.json", "manifest", findings)

	var buf bytes.Buffer
	reporter := &SARIFReporter{}
	if err := reporter.Write(report, &buf); err != nil {
		t.Fatalf("SARIFReporter.Write() error: %v", err)
	}

	// Verify it is valid JSON.
	var sarif map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}

	// Verify top-level structure.
	if sarif["version"] != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %v", sarif["version"])
	}
	if sarif["$schema"] == nil {
		t.Error("expected $schema field in SARIF output")
	}

	// Verify runs array.
	runs, ok := sarif["runs"].([]interface{})
	if !ok || len(runs) != 1 {
		t.Fatalf("expected exactly 1 run, got %v", runs)
	}
	run := runs[0].(map[string]interface{})

	// Verify tool driver.
	tool := run["tool"].(map[string]interface{})
	driver := tool["driver"].(map[string]interface{})
	if driver["name"] != "MCPSense" {
		t.Errorf("expected tool name MCPSense, got %v", driver["name"])
	}

	// Verify rules (should have 3 unique rule IDs).
	rules := driver["rules"].([]interface{})
	if len(rules) != 3 {
		t.Errorf("expected 3 rules, got %d", len(rules))
	}

	// Verify results count matches findings.
	results := run["results"].([]interface{})
	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}

	// Verify first result has correct level.
	firstResult := results[0].(map[string]interface{})
	if firstResult["level"] != "error" {
		t.Errorf("expected level 'error' for critical finding, got %v", firstResult["level"])
	}

	// Verify second result has physical location (file-based finding).
	secondResult := results[1].(map[string]interface{})
	locations := secondResult["locations"].([]interface{})
	if len(locations) == 0 {
		t.Error("expected locations for file-based finding")
	}

	// Verify third result has logical location (tool-based finding).
	thirdResult := results[2].(map[string]interface{})
	thirdLocs := thirdResult["locations"].([]interface{})
	if len(thirdLocs) == 0 {
		t.Error("expected locations for tool-based finding")
	}
}

func TestSARIFReporterEmptyReport(t *testing.T) {
	report := models.NewReport("empty_target", "manifest", nil)

	var buf bytes.Buffer
	reporter := &SARIFReporter{}
	if err := reporter.Write(report, &buf); err != nil {
		t.Fatalf("SARIFReporter.Write() error on empty report: %v", err)
	}

	var sarif map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("empty SARIF output is not valid JSON: %v", err)
	}

	runs := sarif["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty report, got %d", len(results))
	}
}

func TestSARIFSeverityMapping(t *testing.T) {
	tests := []struct {
		severity models.Severity
		expected string
	}{
		{models.SeverityCritical, "error"},
		{models.SeverityHigh, "error"},
		{models.SeverityMedium, "warning"},
		{models.SeverityLow, "note"},
		{models.SeverityInfo, "note"},
	}
	for _, tt := range tests {
		got := severityToSARIFLevel(tt.severity)
		if got != tt.expected {
			t.Errorf("severityToSARIFLevel(%s) = %s, want %s", tt.severity, got, tt.expected)
		}
	}
}
