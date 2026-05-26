package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/fayzkk889/MCPSense/internal/models"
)

// SARIFReporter writes a SARIF 2.1.0 JSON report.
type SARIFReporter struct{}

// SARIF 2.1.0 schema types

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	InformationURI  string      `json:"informationUri"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string             `json:"id"`
	Name             string             `json:"name"`
	ShortDescription sarifMessage       `json:"shortDescription"`
	FullDescription  *sarifMessage      `json:"fullDescription,omitempty"`
	DefaultConfig    sarifDefaultConfig `json:"defaultConfiguration"`
	HelpURI          string             `json:"helpUri,omitempty"`
	Properties       sarifProperties    `json:"properties,omitempty"`
}

type sarifDefaultConfig struct {
	Level string `json:"level"`
}

type sarifProperties struct {
	Tags     []string `json:"tags,omitempty"`
	Category string   `json:"category,omitempty"`
}

type sarifResult struct {
	RuleID    string             `json:"ruleId"`
	Level     string             `json:"level"`
	Message   sarifMessage       `json:"message"`
	Locations []sarifLocation    `json:"locations,omitempty"`
	Fixes     []sarifFix         `json:"fixes,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

type sarifLogicalLocation struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type sarifFix struct {
	Description sarifMessage `json:"description"`
}

// severityToSARIFLevel maps MCPSense severity to SARIF result levels.
func severityToSARIFLevel(s models.Severity) string {
	switch s {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	case models.SeverityLow:
		return "note"
	case models.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}

// categoryToTags maps MCPSense category to SARIF tags.
func categoryToTags(cat models.Category) []string {
	switch cat {
	case models.CategorySecurity:
		return []string{"security", "mcp"}
	case models.CategorySpec:
		return []string{"compliance", "mcp"}
	case models.CategoryQuality:
		return []string{"quality", "mcp"}
	default:
		return []string{"mcp"}
	}
}

// ruleNameFromID converts a check ID like "SEC-009" to a PascalCase name for SARIF.
func ruleNameFromID(id string) string {
	// Remove the dash: "SEC-009" -> "SEC009"
	return strings.ReplaceAll(id, "-", "")
}

// Write renders the report as SARIF 2.1.0 JSON.
func (r *SARIFReporter) Write(report *models.Report, w io.Writer) error {
	// Build rules from unique finding IDs.
	ruleMap := make(map[string]sarifRule)
	ruleOrder := make([]string, 0)
	for _, f := range report.Findings {
		if _, exists := ruleMap[f.ID]; !exists {
			ruleOrder = append(ruleOrder, f.ID)
			ruleMap[f.ID] = sarifRule{
				ID:               f.ID,
				Name:             ruleNameFromID(f.ID),
				ShortDescription: sarifMessage{Text: f.Title},
				DefaultConfig:    sarifDefaultConfig{Level: severityToSARIFLevel(f.Severity)},
				HelpURI:          fmt.Sprintf("https://github.com/fayzkk889/MCPSense#%s", strings.ToLower(f.ID)),
				Properties: sarifProperties{
					Tags:     categoryToTags(f.Category),
					Category: string(f.Category),
				},
			}
		}
	}
	rules := make([]sarifRule, 0, len(ruleOrder))
	for _, id := range ruleOrder {
		rules = append(rules, ruleMap[id])
	}

	// Build results from findings.
	results := make([]sarifResult, 0, len(report.Findings))
	for _, f := range report.Findings {
		result := sarifResult{
			RuleID:  f.ID,
			Level:   severityToSARIFLevel(f.Severity),
			Message: sarifMessage{Text: f.Description},
		}

		// Build location based on what info is available.
		if f.Location.File != "" {
			loc := sarifLocation{
				PhysicalLocation: &sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.Location.File},
				},
			}
			if f.Location.Line > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: f.Location.Line}
			}
			result.Locations = append(result.Locations, loc)
		} else if f.Location.ToolName != "" {
			result.Locations = append(result.Locations, sarifLocation{
				LogicalLocations: []sarifLogicalLocation{
					{Name: f.Location.ToolName, Kind: "member"},
				},
			})
		}

		// Add remediation as a fix suggestion.
		if f.Remediation != "" {
			result.Fixes = append(result.Fixes, sarifFix{
				Description: sarifMessage{Text: f.Remediation},
			})
		}

		results = append(results, result)
	}

	sarif := sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "MCPSense",
						Version:        "0.2.2",
						InformationURI: "https://github.com/fayzkk889/MCPSense",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarif)
}
