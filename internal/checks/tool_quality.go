package checks

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/faizan/mcpsense/internal/models"
)

// ambiguousParamNames lists generic parameter names that provide little context.
var ambiguousParamNames = []string{
	"data", "input", "value", "args", "params", "payload", "body", "content", "info", "object", "item",
}

// actionVerbs lists common verbs that indicate a well-formed tool description.
var actionVerbs = regexp.MustCompile(`(?i)^(get|set|create|update|delete|list|search|find|fetch|send|read|write|execute|run|check|validate|generate|parse|format|convert|download|upload|query|insert|remove|add|modify|enable|disable|start|stop|restart|build|deploy|analyze|process|calculate|compute|retrieve|submit|register|authenticate|authorize|configure|manage|monitor|scan|detect)`)

// DescriptionClarityCheck scores tool descriptions and flags vague or overly long ones.
type DescriptionClarityCheck struct{}

func (c *DescriptionClarityCheck) ID() string            { return "QUAL-001" }
func (c *DescriptionClarityCheck) Name() string          { return "Description clarity score" }
func (c *DescriptionClarityCheck) Category() models.Category { return models.CategoryQuality }

func (c *DescriptionClarityCheck) Run(ctx *ScanContext) []models.Finding {
	if ctx.Manifest == nil {
		return nil
	}
	var findings []models.Finding
	for _, tool := range ctx.Manifest.Tools {
		desc := strings.TrimSpace(tool.Description)
		if len(desc) < 20 {
			findings = append(findings, models.Finding{
				ID:       "QUAL-001",
				Title:    fmt.Sprintf("Tool %q has a very short description (%d chars)", tool.Name, len(desc)),
				Description: fmt.Sprintf("Tool description for %q is too short to be useful to an agent. Short descriptions lead to unpredictable tool selection.", tool.Name),
				Severity: models.SeverityMedium,
				Category: models.CategoryQuality,
				Location: models.Location{ToolName: tool.Name},
				Remediation: "Write a description of at least 20 characters that explains what the tool does, what inputs it expects, and what it returns.",
			})
		} else if len(desc) > 500 {
			findings = append(findings, models.Finding{
				ID:       "QUAL-001",
				Title:    fmt.Sprintf("Tool %q has an excessively long description (%d chars)", tool.Name, len(desc)),
				Description: fmt.Sprintf("Tool description for %q is %d characters, which may confuse agent tool selection.", tool.Name, len(desc)),
				Severity: models.SeverityLow,
				Category: models.CategoryQuality,
				Location: models.Location{ToolName: tool.Name},
				Remediation: "Trim the description to under 500 characters. Focus on what the tool does, its key inputs, and its output.",
			})
		}
		if len(desc) >= 20 && !actionVerbs.MatchString(desc) {
			findings = append(findings, models.Finding{
				ID:       "QUAL-001",
				Title:    fmt.Sprintf("Tool %q description does not start with an action verb", tool.Name),
				Description: fmt.Sprintf("Tool description for %q does not begin with an action verb, making it harder for agents to understand the tool's purpose.", tool.Name),
				Severity: models.SeverityLow,
				Category: models.CategoryQuality,
				Location: models.Location{ToolName: tool.Name},
				Remediation: "Start the description with an action verb such as 'Fetches', 'Creates', 'Searches', or 'Validates' to clearly convey the tool's function.",
			})
		}
	}
	return findings
}

// AmbiguousParamCheck flags tool input parameters with generic, unhelpful names.
type AmbiguousParamCheck struct{}

func (c *AmbiguousParamCheck) ID() string            { return "QUAL-002" }
func (c *AmbiguousParamCheck) Name() string          { return "Ambiguous parameter names" }
func (c *AmbiguousParamCheck) Category() models.Category { return models.CategoryQuality }

func (c *AmbiguousParamCheck) Run(ctx *ScanContext) []models.Finding {
	if ctx.Manifest == nil {
		return nil
	}
	var findings []models.Finding
	for _, tool := range ctx.Manifest.Tools {
		if len(tool.InputSchema) == 0 {
			continue
		}
		var schema map[string]interface{}
		if err := json.Unmarshal(tool.InputSchema, &schema); err != nil {
			continue
		}
		props, ok := schema["properties"].(map[string]interface{})
		if !ok {
			continue
		}
		for paramName, propVal := range props {
			nameLower := strings.ToLower(paramName)
			for _, ambiguous := range ambiguousParamNames {
				if nameLower == ambiguous {
					// Check if it has a description.
					propMap, _ := propVal.(map[string]interface{})
					hasDesc := false
					if propMap != nil {
						desc, _ := propMap["description"].(string)
						hasDesc = strings.TrimSpace(desc) != ""
					}
					severity := models.SeverityMedium
					remNote := "Rename the parameter to something descriptive, such as 'markdown_content' or 'csv_file_path', and add a description field."
					if hasDesc {
						severity = models.SeverityLow
						remNote = "Although a description exists, rename the parameter to something more descriptive to improve clarity for agents."
					}
					findings = append(findings, models.Finding{
						ID:       "QUAL-002",
						Title:    fmt.Sprintf("Ambiguous parameter name %q in tool %q", paramName, tool.Name),
						Description: fmt.Sprintf("Parameter %q in tool %q is a generic name that gives agents no context about the expected input.", paramName, tool.Name),
						Severity: severity,
						Category: models.CategoryQuality,
						Location: models.Location{ToolName: tool.Name},
						Remediation: remNote,
					})
					break
				}
			}
		}
	}
	return findings
}

// MissingParamDescCheck flags input schema properties without description fields.
type MissingParamDescCheck struct{}

func (c *MissingParamDescCheck) ID() string            { return "QUAL-003" }
func (c *MissingParamDescCheck) Name() string          { return "Missing parameter descriptions" }
func (c *MissingParamDescCheck) Category() models.Category { return models.CategoryQuality }

func (c *MissingParamDescCheck) Run(ctx *ScanContext) []models.Finding {
	if ctx.Manifest == nil {
		return nil
	}
	var findings []models.Finding
	for _, tool := range ctx.Manifest.Tools {
		if len(tool.InputSchema) == 0 {
			continue
		}
		var schema map[string]interface{}
		if err := json.Unmarshal(tool.InputSchema, &schema); err != nil {
			continue
		}
		props, ok := schema["properties"].(map[string]interface{})
		if !ok {
			continue
		}
		for paramName, propVal := range props {
			propMap, _ := propVal.(map[string]interface{})
			if propMap == nil {
				findings = append(findings, models.Finding{
					ID:       "QUAL-003",
					Title:    fmt.Sprintf("Parameter %q in tool %q has no description", paramName, tool.Name),
					Description: fmt.Sprintf("Input parameter %q in tool %q lacks a description, leaving agents without guidance on the expected value.", paramName, tool.Name),
					Severity: models.SeverityLow,
					Category: models.CategoryQuality,
					Location: models.Location{ToolName: tool.Name},
					Remediation: fmt.Sprintf("Add a description field to parameter %q explaining the expected format, range, and purpose.", paramName),
				})
				continue
			}
			desc, _ := propMap["description"].(string)
			if strings.TrimSpace(desc) == "" {
				findings = append(findings, models.Finding{
					ID:       "QUAL-003",
					Title:    fmt.Sprintf("Parameter %q in tool %q has no description", paramName, tool.Name),
					Description: fmt.Sprintf("Input parameter %q in tool %q lacks a description.", paramName, tool.Name),
					Severity: models.SeverityLow,
					Category: models.CategoryQuality,
					Location: models.Location{ToolName: tool.Name},
					Remediation: fmt.Sprintf("Add a description field to parameter %q explaining the expected format, range, and purpose.", paramName),
				})
			}
		}
	}
	return findings
}

// DuplicateToolCheck flags tools with highly similar names or descriptions.
type DuplicateToolCheck struct{}

func (c *DuplicateToolCheck) ID() string            { return "QUAL-004" }
func (c *DuplicateToolCheck) Name() string          { return "Duplicate or overlapping tools" }
func (c *DuplicateToolCheck) Category() models.Category { return models.CategoryQuality }

func (c *DuplicateToolCheck) Run(ctx *ScanContext) []models.Finding {
	if ctx.Manifest == nil || len(ctx.Manifest.Tools) < 2 {
		return nil
	}
	var findings []models.Finding
	tools := ctx.Manifest.Tools
	reported := make(map[string]bool)

	for i := 0; i < len(tools); i++ {
		for j := i + 1; j < len(tools); j++ {
			a, b := tools[i], tools[j]
			dist := levenshtein(a.Name, b.Name)
			maxLen := len(a.Name)
			if len(b.Name) > maxLen {
				maxLen = len(b.Name)
			}
			// Flag if edit distance is within 2 or similarity ratio > 80%.
			similar := dist <= 2 || (maxLen > 0 && float64(maxLen-dist)/float64(maxLen) >= 0.8)
			if similar {
				key := a.Name + "|" + b.Name
				if !reported[key] {
					reported[key] = true
					findings = append(findings, models.Finding{
						ID:       "QUAL-004",
						Title:    fmt.Sprintf("Potentially duplicate tools: %q and %q", a.Name, b.Name),
						Description: fmt.Sprintf("Tools %q and %q have very similar names (edit distance: %d), which may confuse agent tool selection.", a.Name, b.Name, dist),
						Severity: models.SeverityLow,
						Category: models.CategoryQuality,
						Location: models.Location{ToolName: a.Name},
						Remediation: "Review these tools for overlap and either merge them or give them clearly distinct names and descriptions that explain their differences.",
					})
				}
			}
		}
	}
	return findings
}

// levenshtein computes the edit distance between two strings.
func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	row := make([]int, lb+1)
	for j := range row {
		row[j] = j
	}
	for i := 1; i <= la; i++ {
		prev := row[0]
		row[0] = i
		for j := 1; j <= lb; j++ {
			tmp := row[j]
			if ra[i-1] == rb[j-1] {
				row[j] = prev
			} else {
				min := prev
				if row[j-1] < min {
					min = row[j-1]
				}
				if row[j] < min {
					min = row[j]
				}
				row[j] = min + 1
			}
			prev = tmp
		}
	}
	return row[lb]
}

// MissingExamplesCheck flags tool definitions without example values.
type MissingExamplesCheck struct{}

func (c *MissingExamplesCheck) ID() string            { return "QUAL-005" }
func (c *MissingExamplesCheck) Name() string          { return "Missing examples" }
func (c *MissingExamplesCheck) Category() models.Category { return models.CategoryQuality }

func (c *MissingExamplesCheck) Run(ctx *ScanContext) []models.Finding {
	if ctx.Manifest == nil {
		return nil
	}
	var findings []models.Finding
	for _, tool := range ctx.Manifest.Tools {
		if len(tool.InputSchema) == 0 {
			continue
		}
		var schema map[string]interface{}
		if err := json.Unmarshal(tool.InputSchema, &schema); err != nil {
			continue
		}
		// Check for top-level "examples" array or "example" field.
		_, hasExamples := schema["examples"]
		_, hasExample := schema["example"]
		if !hasExamples && !hasExample {
			findings = append(findings, models.Finding{
				ID:       "QUAL-005",
				Title:    fmt.Sprintf("Tool %q has no example values in schema", tool.Name),
				Description: fmt.Sprintf("Tool %q does not provide example inputs, making it harder for agents to understand correct usage.", tool.Name),
				Severity: models.SeverityInfo,
				Category: models.CategoryQuality,
				Location: models.Location{ToolName: tool.Name},
				Remediation: `Add an "examples" array to the inputSchema with one or more complete example input objects demonstrating typical usage.`,
			})
		}
	}
	return findings
}

// ExcessiveToolCountCheck flags servers exposing too many tools.
type ExcessiveToolCountCheck struct{}

func (c *ExcessiveToolCountCheck) ID() string            { return "QUAL-006" }
func (c *ExcessiveToolCountCheck) Name() string          { return "Excessive tool count" }
func (c *ExcessiveToolCountCheck) Category() models.Category { return models.CategoryQuality }

const maxRecommendedTools = 50

func (c *ExcessiveToolCountCheck) Run(ctx *ScanContext) []models.Finding {
	if ctx.Manifest == nil {
		return nil
	}
	count := len(ctx.Manifest.Tools)
	if count < maxRecommendedTools {
		return nil
	}
	return []models.Finding{{
		ID:          "QUAL-006",
		Title:       fmt.Sprintf("High tool count (%d tools)", count),
		Description: fmt.Sprintf("The server exposes %d tools. Agents perform poorly when presented with a large number of tool choices.", count),
		Severity:    models.SeverityInfo,
		Category:    models.CategoryQuality,
		Remediation: "Consider grouping related tools into fewer, more focused tools, or splitting the server into multiple specialized servers each exposing a smaller set of tools.",
	}}
}

// InputConstraintCheck flags string parameters missing validation constraints.
type InputConstraintCheck struct{}

func (c *InputConstraintCheck) ID() string            { return "QUAL-007" }
func (c *InputConstraintCheck) Name() string          { return "Missing input constraints" }
func (c *InputConstraintCheck) Category() models.Category { return models.CategoryQuality }

func (c *InputConstraintCheck) Run(ctx *ScanContext) []models.Finding {
	if ctx.Manifest == nil {
		return nil
	}
	var findings []models.Finding
	for _, tool := range ctx.Manifest.Tools {
		if len(tool.InputSchema) == 0 {
			continue
		}
		var schema map[string]interface{}
		if err := json.Unmarshal(tool.InputSchema, &schema); err != nil {
			continue
		}
		props, ok := schema["properties"].(map[string]interface{})
		if !ok {
			continue
		}
		for paramName, propVal := range props {
			propMap, _ := propVal.(map[string]interface{})
			if propMap == nil {
				continue
			}
			typeVal, _ := propMap["type"].(string)
			if typeVal != "string" {
				continue
			}
			_, hasMaxLen := propMap["maxLength"]
			_, hasEnum := propMap["enum"]
			_, hasPattern := propMap["pattern"]
			if !hasMaxLen && !hasEnum && !hasPattern {
				findings = append(findings, models.Finding{
					ID:       "QUAL-007",
					Title:    fmt.Sprintf("String parameter %q in tool %q has no constraints", paramName, tool.Name),
					Description: fmt.Sprintf("String parameter %q in tool %q has no maxLength, enum, or pattern constraint.", paramName, tool.Name),
					Severity: models.SeverityLow,
					Category: models.CategoryQuality,
					Location: models.Location{ToolName: tool.Name},
					Remediation: fmt.Sprintf("Add maxLength, enum, or pattern constraints to parameter %q to limit input size and shape.", paramName),
				})
			}
		}
	}
	return findings
}
