package checks

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/fayzkk889/MCPSense/internal/models"
)

// InjectionCheck screens enumerated metadata for prompt injection signals.
type InjectionCheck struct{}

func (c *InjectionCheck) ID() string                { return "SEC-001" }
func (c *InjectionCheck) Name() string              { return "Prompt injection in enumerated metadata" }
func (c *InjectionCheck) Category() models.Category { return models.CategorySecurity }

func (c *InjectionCheck) Run(ctx *ScanContext) []models.Finding {
	if ctx.Manifest == nil || ctx.Patterns == nil {
		return nil
	}
	var findings []models.Finding
	texts, err := metadataTexts(ctx.Manifest)
	if err != nil {
		ctx.Errors = append(ctx.Errors, err)
		return nil
	}
	for _, text := range texts {
		matches := ctx.Patterns.ScanToolDescription(text.text)
		if text.instructions {
			matches = ctx.Patterns.ScanInstructions(text.text)
		}
		seen := make(map[string]bool)
		for _, m := range matches {
			key := text.owner + ":" + text.field + ":" + m.PatternID
			if seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, models.Finding{
				ID:          "SEC-001",
				Title:       fmt.Sprintf("Possible prompt injection in metadata: %s (%s)", text.owner, text.field),
				Description: fmt.Sprintf("Metadata field %s for %q triggered pattern %s (%s). %s Evidence excerpt: %q", text.field, text.owner, m.PatternID, m.PatternName, m.Description, m.MatchedText),
				Severity:    m.Severity,
				Category:    models.CategorySecurity,
				Location:    models.Location{ToolName: text.owner},
				Remediation: "Review the complete metadata field and remove unauthorized directives. Enforce permissions in the host; screening cannot establish authorization or prevent execution.",
			})
		}
	}
	return findings
}

// shellExecPatterns detects shell execution patterns in source files.
var shellExecPatterns = []*regexp.Regexp{
	regexp.MustCompile(`exec\.command\s*\(\s*"(sh|bash|cmd|powershell|zsh|fish)"`),
	regexp.MustCompile(`exec\.commandcontext\s*\([^,]+,\s*"(sh|bash|cmd|powershell|zsh|fish)"`),
	regexp.MustCompile(`subprocess\.(run|call|popen|check_output)\s*\([^)]*shell\s*=\s*true`),
	regexp.MustCompile(`os\.system\s*\(`),
	regexp.MustCompile(`child_process\.exec\s*\(`),
}

// ShellExecCheck detects shell command execution in source files.
type ShellExecCheck struct{}

func (c *ShellExecCheck) ID() string                { return "SEC-002" }
func (c *ShellExecCheck) Name() string              { return "Shell command execution" }
func (c *ShellExecCheck) Category() models.Category { return models.CategorySecurity }

func (c *ShellExecCheck) Run(ctx *ScanContext) []models.Finding {
	var findings []models.Finding
	for filePath, content := range ctx.SourceFiles {
		lines := strings.Split(content, "\n")
		for lineNum, line := range lines {
			for _, pat := range shellExecPatterns {
				if pat.MatchString(strings.ToLower(line)) {
					findings = append(findings, models.Finding{
						ID:          "SEC-002",
						Title:       "Shell command execution detected",
						Description: fmt.Sprintf("A shell interpreter is invoked at %s:%d. If tool input flows into this call, arbitrary command execution is possible.", filePath, lineNum+1),
						Severity:    models.SeverityHigh,
						Category:    models.CategorySecurity,
						Location:    models.Location{File: filePath, Line: lineNum + 1},
						Remediation: "Avoid spawning shell interpreters. Use exec.Command with explicit argument lists and never pass user input as a shell command string.",
					})
					break
				}
			}
		}
	}
	return findings
}

// ssrfPatterns detect HTTP requests made using variable URLs.
var ssrfPatterns = []*regexp.Regexp{
	regexp.MustCompile(`http\.get\s*\(\s*[^"')\s]+`),
	regexp.MustCompile(`http\.post\s*\(\s*[^"')\s]+`),
	regexp.MustCompile(`http\.newrequest\s*\([^,]+,\s*[^"')\s]+`),
	regexp.MustCompile(`requests\.(get|post|put|delete)\s*\(\s*[^"')\s]+`),
	regexp.MustCompile(`fetch\s*\(\s*[^"')\s]+`),
	regexp.MustCompile(`axios\.(get|post|put|delete)\s*\(\s*[^"')\s]+`),
}

// SSRFCheck detects server-side request forgery risks.
type SSRFCheck struct{}

func (c *SSRFCheck) ID() string                { return "SEC-003" }
func (c *SSRFCheck) Name() string              { return "SSRF risk" }
func (c *SSRFCheck) Category() models.Category { return models.CategorySecurity }

func (c *SSRFCheck) Run(ctx *ScanContext) []models.Finding {
	var findings []models.Finding
	for filePath, content := range ctx.SourceFiles {
		lines := strings.Split(content, "\n")
		for lineNum, line := range lines {
			for _, pat := range ssrfPatterns {
				if pat.MatchString(strings.ToLower(line)) {
					findings = append(findings, models.Finding{
						ID:          "SEC-003",
						Title:       "Potential SSRF: HTTP request from variable URL",
						Description: fmt.Sprintf("An HTTP request uses a dynamic URL at %s:%d without apparent domain validation.", filePath, lineNum+1),
						Severity:    models.SeverityHigh,
						Category:    models.CategorySecurity,
						Location:    models.Location{File: filePath, Line: lineNum + 1},
						Remediation: "Validate all user-supplied URLs against an allowlist of permitted domains before making outbound requests. Reject requests to private IP ranges (10.x.x.x, 172.16.x.x, 192.168.x.x) and internal hostnames.",
					})
					break
				}
			}
		}
	}
	return findings
}

// traversalPatterns detect path traversal in source code and manifests.
var traversalPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\.\./`),
	regexp.MustCompile(`\.\.\\`),
	regexp.MustCompile(`%2e%2e%2f`),
	regexp.MustCompile(`%252e%252e`),
}

// PathTraversalCheck detects path traversal vulnerabilities.
type PathTraversalCheck struct{}

func (c *PathTraversalCheck) ID() string                { return "SEC-004" }
func (c *PathTraversalCheck) Name() string              { return "Path traversal" }
func (c *PathTraversalCheck) Category() models.Category { return models.CategorySecurity }

func (c *PathTraversalCheck) Run(ctx *ScanContext) []models.Finding {
	var findings []models.Finding

	// Check resource URIs in manifest.
	if ctx.Manifest != nil {
		for _, res := range ctx.Manifest.Resources {
			for _, pat := range traversalPatterns {
				if pat.MatchString(strings.ToLower(res.URI)) {
					findings = append(findings, models.Finding{
						ID:          "SEC-004",
						Title:       fmt.Sprintf("Path traversal in resource URI: %s", res.Name),
						Description: fmt.Sprintf("Resource URI %q contains a path traversal sequence.", res.URI),
						Severity:    models.SeverityHigh,
						Category:    models.CategorySecurity,
						Location:    models.Location{ToolName: res.Name},
						Remediation: "Remove path traversal sequences from resource URIs and validate all paths with filepath.Clean().",
					})
					break
				}
			}
		}
	}

	// Check source files.
	for filePath, content := range ctx.SourceFiles {
		lines := strings.Split(content, "\n")
		for lineNum, line := range lines {
			for _, pat := range traversalPatterns {
				if pat.MatchString(strings.ToLower(line)) {
					findings = append(findings, models.Finding{
						ID:          "SEC-004",
						Title:       "Path traversal pattern in source code",
						Description: fmt.Sprintf("Path traversal sequence found at %s:%d.", filePath, lineNum+1),
						Severity:    models.SeverityHigh,
						Category:    models.CategorySecurity,
						Location:    models.Location{File: filePath, Line: lineNum + 1},
						Remediation: "Use filepath.Clean() and verify all paths are within the intended base directory before performing any file operations.",
					})
					break
				}
			}
		}
	}
	return findings
}

// sensitivePaths lists tool/resource name fragments that suggest sensitive operations.
var sensitivePaths = []string{"file", "exec", "run", "command", "shell", "database", "db", "admin", "secret", "key", "password", "token"}

// MissingAuthCheck flags servers that expose sensitive tools/resources without auth.
type MissingAuthCheck struct{}

func (c *MissingAuthCheck) ID() string                { return "SEC-005" }
func (c *MissingAuthCheck) Name() string              { return "Missing authentication" }
func (c *MissingAuthCheck) Category() models.Category { return models.CategorySecurity }

func (c *MissingAuthCheck) Run(ctx *ScanContext) []models.Finding {
	if ctx.Manifest == nil {
		return nil
	}
	if ctx.Manifest.Auth != nil && ctx.Manifest.Auth.Type != "none" {
		return nil
	}

	// Check for sensitive-sounding tools or resources.
	var sensitiveTools []string
	for _, tool := range ctx.Manifest.Tools {
		nameLower := strings.ToLower(tool.Name)
		for _, sens := range sensitivePaths {
			if strings.Contains(nameLower, sens) {
				sensitiveTools = append(sensitiveTools, tool.Name)
				break
			}
		}
	}

	if len(sensitiveTools) == 0 && len(ctx.Manifest.Resources) == 0 {
		return nil
	}

	desc := "The server declares no authentication but exposes"
	if len(sensitiveTools) > 0 {
		desc += fmt.Sprintf(" potentially sensitive tools: %s", strings.Join(sensitiveTools, ", "))
	} else {
		desc += " resources with no access control"
	}
	desc += "."

	return []models.Finding{{
		ID:          "SEC-005",
		Title:       "Missing authentication on server with sensitive tools",
		Description: desc,
		Severity:    models.SeverityMedium,
		Category:    models.CategorySecurity,
		Remediation: `Add an "auth" field to the manifest specifying oauth2 or api_key authentication. Ensure sensitive tools require valid credentials before execution.`,
	}}
}

// ResourceScopeCheck flags overly broad resource URI patterns.
type ResourceScopeCheck struct{}

func (c *ResourceScopeCheck) ID() string                { return "SEC-006" }
func (c *ResourceScopeCheck) Name() string              { return "Overly permissive resource access" }
func (c *ResourceScopeCheck) Category() models.Category { return models.CategorySecurity }

var broadURIPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^file:///\*$`),
	regexp.MustCompile(`^\*$`),
	regexp.MustCompile(`^\*\*$`),
	regexp.MustCompile(`^/\*\*$`),
	regexp.MustCompile(`^/\*$`),
	regexp.MustCompile(`^file:///[^"]*\*[^"]*$`),
}

func (c *ResourceScopeCheck) Run(ctx *ScanContext) []models.Finding {
	if ctx.Manifest == nil {
		return nil
	}
	var findings []models.Finding
	for _, res := range ctx.Manifest.Resources {
		for _, pat := range broadURIPatterns {
			if pat.MatchString(res.URI) {
				findings = append(findings, models.Finding{
					ID:          "SEC-006",
					Title:       fmt.Sprintf("Overly broad resource scope: %s", res.Name),
					Description: fmt.Sprintf("Resource URI %q uses a wildcard pattern that grants access to an excessive number of files or paths.", res.URI),
					Severity:    models.SeverityMedium,
					Category:    models.CategorySecurity,
					Location:    models.Location{ToolName: res.Name},
					Remediation: "Restrict the resource URI to the minimum required scope. Use explicit paths instead of broad wildcards.",
				})
				break
			}
		}
	}
	return findings
}

// CommandInjectionCheck detects user input interpolated into command strings.
type CommandInjectionCheck struct{}

func (c *CommandInjectionCheck) ID() string                { return "SEC-007" }
func (c *CommandInjectionCheck) Name() string              { return "Command injection via string interpolation" }
func (c *CommandInjectionCheck) Category() models.Category { return models.CategorySecurity }

var cmdInjectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`os\.system\s*\([^)]*\+`),
	regexp.MustCompile(`os\.system\s*\([^)]*%`),
	regexp.MustCompile(`child_process\.exec\s*\([^)]*\+`),
}

func (c *CommandInjectionCheck) Run(ctx *ScanContext) []models.Finding {
	var findings []models.Finding
	for filePath, content := range ctx.SourceFiles {
		shellLines := map[int]bool{}
		if strings.HasSuffix(filePath, ".go") {
			shellLines = goShellInterpolation(content)
		}
		if strings.HasSuffix(filePath, ".py") {
			shellLines = pythonShellInterpolation(content)
		}
		lines := strings.Split(content, "\n")
		for lineNum, line := range lines {
			matched := shellLines[lineNum+1]
			for _, pat := range cmdInjectionPatterns {
				matched = matched || pat.MatchString(strings.ToLower(line))
			}
			if matched {
				findings = append(findings, models.Finding{
					ID:          "SEC-007",
					Title:       "Review formatted data reaching shell evaluation",
					Description: fmt.Sprintf("Formatted data reaches an explicit shell-evaluation API at %s:%d. Review its origin and quoting; this is not proof of exploitability.", filePath, lineNum+1),
					Severity:    models.SeverityCritical,
					Category:    models.CategorySecurity,
					Location:    models.Location{File: filePath, Line: lineNum + 1},
					Remediation: "Use parameterized execution. Pass command arguments as separate strings to exec.Command rather than building a command string with fmt.Sprintf or string concatenation.",
				})
			}
		}
	}
	return findings
}

// DataExfilCheck detects tools that return raw file or database contents.
type DataExfilCheck struct{}

func (c *DataExfilCheck) ID() string                { return "SEC-008" }
func (c *DataExfilCheck) Name() string              { return "Data exfiltration vectors" }
func (c *DataExfilCheck) Category() models.Category { return models.CategorySecurity }

var dataExfilPatterns = []*regexp.Regexp{
	regexp.MustCompile(`os\.readfile\s*\([^)]*\w+\s*\)`),
	regexp.MustCompile(`ioutil\.readfile\s*\([^)]*\w+\s*\)`),
	regexp.MustCompile(`open\s*\([^)]*\w+[^)]*\)\s*\.read\(\)`),
	regexp.MustCompile(`select\s+\*\s+from`),
	regexp.MustCompile(`db\.query\s*\([^)]*select\s+\*`),
}

func (c *DataExfilCheck) Run(ctx *ScanContext) []models.Finding {
	var findings []models.Finding

	// Check tool descriptions for suspicious keywords.
	if ctx.Manifest != nil {
		for _, tool := range ctx.Manifest.Tools {
			descLower := strings.ToLower(tool.Description)
			if (strings.Contains(descLower, "read file") || strings.Contains(descLower, "return file contents") ||
				strings.Contains(descLower, "file contents") || strings.Contains(descLower, "database contents") ||
				strings.Contains(descLower, "dump")) && len(tool.InputSchema) > 0 {
				var schema map[string]interface{}
				if err := json.Unmarshal(tool.InputSchema, &schema); err == nil {
					if props, ok := schema["properties"].(map[string]interface{}); ok {
						for paramName := range props {
							paramLower := strings.ToLower(paramName)
							if strings.Contains(paramLower, "path") || strings.Contains(paramLower, "file") {
								findings = append(findings, models.Finding{
									ID:          "SEC-008",
									Title:       fmt.Sprintf("Potential data exfiltration via tool: %s", tool.Name),
									Description: fmt.Sprintf("Tool %q appears to read and return file contents based on a user-supplied path parameter.", tool.Name),
									Severity:    models.SeverityMedium,
									Category:    models.CategorySecurity,
									Location:    models.Location{ToolName: tool.Name},
									Remediation: "Restrict file access to a defined allowlist of paths. Never return raw file contents for user-controlled paths without strict access controls.",
								})
								break
							}
						}
					}
				}
			}
		}
	}

	// Check source files for raw data access patterns.
	for filePath, content := range ctx.SourceFiles {
		lines := strings.Split(content, "\n")
		for lineNum, line := range lines {
			for _, pat := range dataExfilPatterns {
				if pat.MatchString(strings.ToLower(line)) {
					findings = append(findings, models.Finding{
						ID:          "SEC-008",
						Title:       "Raw file or database data returned without filtering",
						Description: fmt.Sprintf("Raw file or database read at %s:%d may expose sensitive data if paths or queries are user-controlled.", filePath, lineNum+1),
						Severity:    models.SeverityMedium,
						Category:    models.CategorySecurity,
						Location:    models.Location{File: filePath, Line: lineNum + 1},
						Remediation: "Validate and sanitize all paths before file access. Apply output filtering to remove sensitive data. Consider field-level access controls for database queries.",
					})
					break
				}
			}
		}
	}
	return findings
}
