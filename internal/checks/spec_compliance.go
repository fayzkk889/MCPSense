package checks

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/faizan/mcpsense/internal/models"
)

// knownMCPVersions lists protocol versions considered valid.
var knownMCPVersions = []string{"2024-11-05", "2025-03-26", "0.1", "0.2", "1.0"}

// toolNamePattern matches valid tool names: snake_case, alphanumeric and underscores only.
var toolNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// allowedResourceSchemes lists URI schemes permitted for MCP resources.
var allowedResourceSchemes = []string{"file", "https", "http", "resource", "memory"}

// SpecManifestStructureCheck verifies the manifest has all required top-level fields.
type SpecManifestStructureCheck struct{}

func (c *SpecManifestStructureCheck) ID() string            { return "SPEC-001" }
func (c *SpecManifestStructureCheck) Name() string          { return "Valid manifest structure" }
func (c *SpecManifestStructureCheck) Category() models.Category { return models.CategorySpec }

func (c *SpecManifestStructureCheck) Run(ctx *ScanContext) []models.Finding {
	if ctx.Manifest == nil {
		return nil
	}
	var findings []models.Finding
	m := ctx.Manifest

	if strings.TrimSpace(m.Name) == "" {
		findings = append(findings, models.Finding{
			ID:          "SPEC-001",
			Title:       "Manifest missing required field: name",
			Description: "The MCP manifest does not declare a server name.",
			Severity:    models.SeverityMedium,
			Category:    models.CategorySpec,
			Remediation: `Add a "name" field to your manifest with a short, descriptive identifier for the server.`,
		})
	}
	if strings.TrimSpace(m.Version) == "" {
		findings = append(findings, models.Finding{
			ID:          "SPEC-001",
			Title:       "Manifest missing required field: version",
			Description: "The MCP manifest does not declare a server version.",
			Severity:    models.SeverityLow,
			Category:    models.CategorySpec,
			Remediation: `Add a "version" field using semantic versioning, e.g., "1.0.0".`,
		})
	}
	if len(m.Tools) == 0 && len(m.Resources) == 0 {
		findings = append(findings, models.Finding{
			ID:          "SPEC-001",
			Title:       "Manifest declares no tools or resources",
			Description: "A valid MCP server should expose at least one tool or resource.",
			Severity:    models.SeverityInfo,
			Category:    models.CategorySpec,
			Remediation: "Add at least one tool or resource definition to the manifest.",
		})
	}
	return findings
}

// SpecToolSchemaCheck verifies each tool's inputSchema is valid JSON Schema.
type SpecToolSchemaCheck struct{}

func (c *SpecToolSchemaCheck) ID() string            { return "SPEC-002" }
func (c *SpecToolSchemaCheck) Name() string          { return "Tool input schema validity" }
func (c *SpecToolSchemaCheck) Category() models.Category { return models.CategorySpec }

func (c *SpecToolSchemaCheck) Run(ctx *ScanContext) []models.Finding {
	if ctx.Manifest == nil {
		return nil
	}
	var findings []models.Finding
	for _, tool := range ctx.Manifest.Tools {
		if len(tool.InputSchema) == 0 {
			findings = append(findings, models.Finding{
				ID:       "SPEC-002",
				Title:    fmt.Sprintf("Tool %q has no inputSchema", tool.Name),
				Description: fmt.Sprintf("Tool %q does not define an inputSchema. All tools should declare their expected inputs.", tool.Name),
				Severity: models.SeverityMedium,
				Category: models.CategorySpec,
				Location: models.Location{ToolName: tool.Name},
				Remediation: "Add an inputSchema object following JSON Schema draft-07. At minimum, include a properties object and a type of 'object'.",
			})
			continue
		}
		// Validate it is parseable JSON.
		var schemaObj map[string]interface{}
		if err := json.Unmarshal(tool.InputSchema, &schemaObj); err != nil {
			findings = append(findings, models.Finding{
				ID:       "SPEC-002",
				Title:    fmt.Sprintf("Tool %q has invalid inputSchema JSON", tool.Name),
				Description: fmt.Sprintf("Tool %q inputSchema is not valid JSON: %v", tool.Name, err),
				Severity: models.SeverityHigh,
				Category: models.CategorySpec,
				Location: models.Location{ToolName: tool.Name},
				Remediation: "Fix the inputSchema to be valid JSON conforming to JSON Schema draft-07.",
			})
			continue
		}
		// Must have a "type" field equal to "object" at the top level.
		if t, ok := schemaObj["type"]; !ok || t != "object" {
			findings = append(findings, models.Finding{
				ID:       "SPEC-002",
				Title:    fmt.Sprintf("Tool %q inputSchema missing top-level type: object", tool.Name),
				Description: fmt.Sprintf("Tool %q inputSchema should have a top-level type of 'object'.", tool.Name),
				Severity: models.SeverityLow,
				Category: models.CategorySpec,
				Location: models.Location{ToolName: tool.Name},
				Remediation: `Add "type": "object" to the top level of the inputSchema.`,
			})
		}
	}
	return findings
}

// SpecToolNamingCheck verifies tool names follow snake_case conventions.
type SpecToolNamingCheck struct{}

func (c *SpecToolNamingCheck) ID() string            { return "SPEC-003" }
func (c *SpecToolNamingCheck) Name() string          { return "Tool naming conventions" }
func (c *SpecToolNamingCheck) Category() models.Category { return models.CategorySpec }

func (c *SpecToolNamingCheck) Run(ctx *ScanContext) []models.Finding {
	if ctx.Manifest == nil {
		return nil
	}
	var findings []models.Finding
	for _, tool := range ctx.Manifest.Tools {
		if !toolNamePattern.MatchString(tool.Name) {
			findings = append(findings, models.Finding{
				ID:       "SPEC-003",
				Title:    fmt.Sprintf("Tool %q violates naming convention", tool.Name),
				Description: fmt.Sprintf("Tool name %q should be lowercase snake_case with no special characters.", tool.Name),
				Severity: models.SeverityLow,
				Category: models.CategorySpec,
				Location: models.Location{ToolName: tool.Name},
				Remediation: fmt.Sprintf("Rename tool to snake_case, e.g., %q.", toSnakeCase(tool.Name)),
			})
		}
		if len(tool.Name) > 64 {
			findings = append(findings, models.Finding{
				ID:       "SPEC-003",
				Title:    fmt.Sprintf("Tool %q name is too long", tool.Name),
				Description: fmt.Sprintf("Tool name %q is %d characters, which exceeds the recommended 64-character limit.", tool.Name, len(tool.Name)),
				Severity: models.SeverityInfo,
				Category: models.CategorySpec,
				Location: models.Location{ToolName: tool.Name},
				Remediation: "Shorten the tool name to 64 characters or fewer.",
			})
		}
	}
	return findings
}

// SpecResourceURICheck verifies resource URIs follow RFC 3986 and use allowed schemes.
type SpecResourceURICheck struct{}

func (c *SpecResourceURICheck) ID() string            { return "SPEC-004" }
func (c *SpecResourceURICheck) Name() string          { return "Resource URI format" }
func (c *SpecResourceURICheck) Category() models.Category { return models.CategorySpec }

func (c *SpecResourceURICheck) Run(ctx *ScanContext) []models.Finding {
	if ctx.Manifest == nil {
		return nil
	}
	var findings []models.Finding
	for _, res := range ctx.Manifest.Resources {
		if strings.TrimSpace(res.URI) == "" {
			findings = append(findings, models.Finding{
				ID:       "SPEC-004",
				Title:    fmt.Sprintf("Resource %q has empty URI", res.Name),
				Description: "A resource must declare a non-empty URI.",
				Severity: models.SeverityMedium,
				Category: models.CategorySpec,
				Remediation: "Set the URI to a valid RFC 3986 URI identifying this resource.",
			})
			continue
		}
		parsed, err := url.Parse(res.URI)
		if err != nil {
			findings = append(findings, models.Finding{
				ID:       "SPEC-004",
				Title:    fmt.Sprintf("Resource %q has invalid URI: %s", res.Name, res.URI),
				Description: fmt.Sprintf("Resource URI %q is not a valid RFC 3986 URI: %v", res.URI, err),
				Severity: models.SeverityMedium,
				Category: models.CategorySpec,
				Remediation: "Fix the URI to conform to RFC 3986.",
			})
			continue
		}
		scheme := strings.ToLower(parsed.Scheme)
		if scheme == "" {
			continue // Relative URIs are acceptable
		}
		allowed := false
		for _, s := range allowedResourceSchemes {
			if scheme == s {
				allowed = true
				break
			}
		}
		if !allowed {
			findings = append(findings, models.Finding{
				ID:       "SPEC-004",
				Title:    fmt.Sprintf("Resource %q uses non-standard URI scheme %q", res.Name, scheme),
				Description: fmt.Sprintf("Resource URI scheme %q is not in the approved list: %s", scheme, strings.Join(allowedResourceSchemes, ", ")),
				Severity: models.SeverityLow,
				Category: models.CategorySpec,
				Remediation: fmt.Sprintf("Change the URI scheme to one of: %s", strings.Join(allowedResourceSchemes, ", ")),
			})
		}
	}
	return findings
}

// SpecProtocolVersionCheck verifies the manifest declares a known protocol version.
type SpecProtocolVersionCheck struct{}

func (c *SpecProtocolVersionCheck) ID() string            { return "SPEC-005" }
func (c *SpecProtocolVersionCheck) Name() string          { return "Protocol version compatibility" }
func (c *SpecProtocolVersionCheck) Category() models.Category { return models.CategorySpec }

func (c *SpecProtocolVersionCheck) Run(ctx *ScanContext) []models.Finding {
	if ctx.Manifest == nil {
		return nil
	}
	version := strings.TrimSpace(ctx.Manifest.Version)
	if version == "" {
		return nil // Already reported by SPEC-001
	}
	for _, known := range knownMCPVersions {
		if version == known {
			return nil
		}
	}
	return []models.Finding{{
		ID:          "SPEC-005",
		Title:       fmt.Sprintf("Unknown protocol version %q", version),
		Description: fmt.Sprintf("The declared version %q is not a recognized MCP protocol version.", version),
		Severity:    models.SeverityInfo,
		Category:    models.CategorySpec,
		Remediation: fmt.Sprintf("Use a known MCP protocol version. Known versions: %s", strings.Join(knownMCPVersions, ", ")),
	}}
}

// toSnakeCase is a simple heuristic to suggest a snake_case version of a tool name.
func toSnakeCase(s string) string {
	s = strings.ToLower(s)
	re := regexp.MustCompile(`[^a-z0-9]+`)
	return re.ReplaceAllString(s, "_")
}
