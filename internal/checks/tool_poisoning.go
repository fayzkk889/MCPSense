package checks

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/fayzkk889/MCPSense/internal/models"
)

// --- SEC-009: Invisible Unicode Characters ---

// InvisibleUnicodeCheck detects zero-width and control characters hidden in tool definitions.
// These characters are invisible in UIs but processed by LLMs, enabling hidden instruction injection.
// Real-world example: WhatsApp MCP exfiltration attack (Invariant Labs, April 2025) used
// Unicode tag characters (U+E0000 range) to embed invisible exfiltration instructions.
type InvisibleUnicodeCheck struct{}

func (c *InvisibleUnicodeCheck) ID() string              { return "SEC-009" }
func (c *InvisibleUnicodeCheck) Name() string            { return "Invisible Unicode characters in tool definitions" }
func (c *InvisibleUnicodeCheck) Category() models.Category { return models.CategorySecurity }

// isInvisibleChar returns true if the rune is a zero-width, control, or formatting character
// that would be invisible in most UIs but parsed by language models.
func isInvisibleChar(r rune) bool {
	switch {
	// Zero-width and formatting characters
	case r == '\u200B': return true // zero-width space
	case r == '\u200C': return true // zero-width non-joiner
	case r == '\u200D': return true // zero-width joiner
	case r == '\u200E': return true // left-to-right mark
	case r == '\u200F': return true // right-to-left mark
	case r == '\u00AD': return true // soft hyphen
	case r == '\u2060': return true // word joiner
	case r == '\uFEFF': return true // zero-width no-break space (BOM)
	// Bidirectional override characters
	case r >= '\u202A' && r <= '\u202E': return true
	case r >= '\u2066' && r <= '\u2069': return true
	// Unicode Tag characters (U+E0001 to U+E007F) — used in ASCII smuggling attacks
	case r >= 0xE0001 && r <= 0xE007F: return true
	// Variation selectors used for ASCII smuggling (U+E0100 to U+E01EF)
	case r >= 0xE0100 && r <= 0xE01EF: return true
	// C0/C1 control characters (except normal whitespace: tab, newline, carriage return)
	case r < 0x0020 && r != '\t' && r != '\n' && r != '\r': return true
	case r >= 0x007F && r <= 0x009F: return true
	default: return false
	}
}

// invisibleCharName returns a human-readable name for an invisible character.
func invisibleCharName(r rune) string {
	names := map[rune]string{
		'\u200B': "zero-width space",
		'\u200C': "zero-width non-joiner",
		'\u200D': "zero-width joiner",
		'\u200E': "left-to-right mark",
		'\u200F': "right-to-left mark",
		'\u00AD': "soft hyphen",
		'\u2060': "word joiner",
		'\uFEFF': "BOM/zero-width no-break space",
		'\u202A': "left-to-right embedding",
		'\u202B': "right-to-left embedding",
		'\u202C': "pop directional formatting",
		'\u202D': "left-to-right override",
		'\u202E': "right-to-left override",
		'\u2066': "left-to-right isolate",
		'\u2067': "right-to-left isolate",
		'\u2068': "first strong isolate",
		'\u2069': "pop directional isolate",
	}
	if name, ok := names[r]; ok {
		return name
	}
	if r >= 0xE0001 && r <= 0xE007F {
		return "Unicode tag character (ASCII smuggling)"
	}
	if r >= 0xE0100 && r <= 0xE01EF {
		return "variation selector (ASCII smuggling)"
	}
	return fmt.Sprintf("control character U+%04X", r)
}

func (c *InvisibleUnicodeCheck) Run(ctx *ScanContext) []models.Finding {
	if ctx.Manifest == nil {
		return nil
	}
	var findings []models.Finding
	for _, tool := range ctx.Manifest.Tools {
		// Scan tool name, title, and description
		textsToScan := map[string]string{
			"name":        tool.Name,
			"title":       tool.Title,
			"description": tool.Description,
		}
		// Also scan parameter names and descriptions from inputSchema
		if len(tool.InputSchema) > 0 {
			var schema map[string]interface{}
			if json.Unmarshal(tool.InputSchema, &schema) == nil {
				if props, ok := schema["properties"].(map[string]interface{}); ok {
					for paramName, paramVal := range props {
						textsToScan["parameter name: "+paramName] = paramName
						if pm, ok := paramVal.(map[string]interface{}); ok {
							if desc, ok := pm["description"].(string); ok {
								textsToScan["parameter description: "+paramName] = desc
							}
						}
					}
				}
			}
		}

		for fieldName, text := range textsToScan {
			if text == "" {
				continue
			}
			foundChars := make(map[rune]int)
			for _, r := range text {
				if isInvisibleChar(r) {
					foundChars[r]++
				}
			}
			if len(foundChars) > 0 {
				totalCount := 0
				var charDetails []string
				for r, count := range foundChars {
					totalCount += count
					charDetails = append(charDetails, fmt.Sprintf("%s (U+%04X, count: %d)", invisibleCharName(r), r, count))
				}
				severity := models.SeverityCritical
				// Tag characters and variation selectors are almost certainly an ASCII smuggling attack
				hasSmuggling := false
				for r := range foundChars {
					if r >= 0xE0001 {
						hasSmuggling = true
						break
					}
				}
				desc := fmt.Sprintf("Tool %q %s contains %d invisible Unicode character(s): %s.",
					tool.Name, fieldName, totalCount, strings.Join(charDetails, "; "))
				if hasSmuggling {
					desc += " ASCII smuggling via tag/variation-selector characters detected. This is a known tool poisoning technique used to embed hidden instructions."
				}
				findings = append(findings, models.Finding{
					ID:          "SEC-009",
					Title:       fmt.Sprintf("Invisible Unicode characters in tool %q %s", tool.Name, fieldName),
					Description: desc,
					Severity:    severity,
					Category:    models.CategorySecurity,
					Location:    models.Location{ToolName: tool.Name},
					Remediation: "Remove all invisible Unicode characters from tool definitions. Tool names, descriptions, and parameter metadata should contain only printable characters. Use a Unicode sanitizer to strip zero-width, formatting, tag, and variation-selector characters.",
				})
			}
		}
	}
	return findings
}

// --- SEC-010: Homoglyph / Mixed Script Detection ---

// HomoglyphCheck detects non-ASCII characters in tool names that could be used for
// tool shadowing attacks (registering a visually identical but different tool name).
type HomoglyphCheck struct{}

func (c *HomoglyphCheck) ID() string              { return "SEC-010" }
func (c *HomoglyphCheck) Name() string            { return "Homoglyph characters in tool names" }
func (c *HomoglyphCheck) Category() models.Category { return models.CategorySecurity }

func (c *HomoglyphCheck) Run(ctx *ScanContext) []models.Finding {
	if ctx.Manifest == nil {
		return nil
	}
	var findings []models.Finding
	for _, tool := range ctx.Manifest.Tools {
		nonASCII := findNonASCII(tool.Name)
		if len(nonASCII) > 0 {
			findings = append(findings, models.Finding{
				ID:          "SEC-010",
				Title:       fmt.Sprintf("Non-ASCII characters in tool name %q", tool.Name),
				Description: fmt.Sprintf("Tool name %q contains non-ASCII characters at positions %v. This may indicate a homoglyph attack where visually similar characters (e.g., Cyrillic 'а' vs Latin 'a') are used to create a tool that shadows a legitimate tool name.", tool.Name, nonASCII),
				Severity:    models.SeverityHigh,
				Category:    models.CategorySecurity,
				Location:    models.Location{ToolName: tool.Name},
				Remediation: "Tool names must contain only ASCII alphanumeric characters and underscores. Replace any non-ASCII characters with their ASCII equivalents.",
			})
		}
		// Check for mixed scripts in descriptions (Latin + Cyrillic in the same word)
		if mixedWords := findMixedScriptWords(tool.Description); len(mixedWords) > 0 {
			findings = append(findings, models.Finding{
				ID:          "SEC-010",
				Title:       fmt.Sprintf("Mixed-script text in tool %q description", tool.Name),
				Description: fmt.Sprintf("Tool %q description contains words with mixed Unicode scripts (e.g., Latin and Cyrillic in the same word): %s. This is a technique used to bypass text-based injection detection.", tool.Name, strings.Join(mixedWords, ", ")),
				Severity:    models.SeverityHigh,
				Category:    models.CategorySecurity,
				Location:    models.Location{ToolName: tool.Name},
				Remediation: "Ensure all text in tool descriptions uses a consistent script. Remove Cyrillic, Greek, or other homoglyph characters that mimic Latin letters.",
			})
		}
	}
	return findings
}

// findNonASCII returns byte positions of non-ASCII characters in a string.
func findNonASCII(s string) []int {
	var positions []int
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r > 127 {
			positions = append(positions, i)
		}
		i += size
	}
	return positions
}

// findMixedScriptWords finds words that contain characters from multiple Unicode scripts.
func findMixedScriptWords(text string) []string {
	words := strings.Fields(text)
	var mixed []string
	for _, word := range words {
		if len(word) < 3 {
			continue
		}
		hasLatin := false
		hasCyrillic := false
		hasGreek := false
		for _, r := range word {
			if unicode.Is(unicode.Latin, r) {
				hasLatin = true
			}
			if unicode.Is(unicode.Cyrillic, r) {
				hasCyrillic = true
			}
			if unicode.Is(unicode.Greek, r) {
				hasGreek = true
			}
		}
		scriptCount := 0
		if hasLatin { scriptCount++ }
		if hasCyrillic { scriptCount++ }
		if hasGreek { scriptCount++ }
		if scriptCount >= 2 {
			mixed = append(mixed, fmt.Sprintf("%q", word))
		}
	}
	return mixed
}

// --- SEC-011: Data Exfiltration Instructions in Descriptions ---

// ExfilInstructionCheck detects tool descriptions that instruct the agent to read, include,
// or send sensitive data — the primary mechanism for tool-poisoning-based data theft.
type ExfilInstructionCheck struct{}

func (c *ExfilInstructionCheck) ID() string              { return "SEC-011" }
func (c *ExfilInstructionCheck) Name() string            { return "Data exfiltration instructions in descriptions" }
func (c *ExfilInstructionCheck) Category() models.Category { return models.CategorySecurity }

var exfilInstructionPatterns = []*regexp.Regexp{
	// Instructions to read sensitive files
	regexp.MustCompile(`(?i)(read|include|send|attach|return|output|append|add|embed|insert)\s+(the\s+)?(contents?\s+of|data\s+from|file)\s+[~./]`),
	regexp.MustCompile(`(?i)(\.ssh|\.env|\.git|\.aws|\.kube|/etc/passwd|/etc/shadow|id_rsa|credentials|\.npmrc|\.pypirc|\.docker|config\.json)`),
	// Instructions to exfiltrate to external services
	regexp.MustCompile(`(?i)(send|post|forward|upload|transmit|exfiltrate|leak)\s+(to|via|using)\s+(http|https|ftp|webhook|endpoint|url|api)`),
	regexp.MustCompile(`(?i)(include|embed|encode|base64|hex).{0,30}(in\s+the\s+response|in\s+your\s+(response|output|answer))`),
	// Instructions to access environment variables or secrets
	regexp.MustCompile(`(?i)(read|access|get|retrieve|print|output|include)\s+(the\s+)?(environment\s+variable|env\s+var|API.?key|secret|token|password|credential)`),
	// Instructions to hide actions from the user
	regexp.MustCompile(`(?i)(do\s+not|don'?t|never)\s+(show|display|tell|reveal|mention|report)\s+(the\s+user|to\s+the\s+user|this)`),
	regexp.MustCompile(`(?i)(silently|quietly|without\s+(telling|informing|notifying|showing))`),
}

func (c *ExfilInstructionCheck) Run(ctx *ScanContext) []models.Finding {
	if ctx.Manifest == nil {
		return nil
	}
	var findings []models.Finding
	for _, tool := range ctx.Manifest.Tools {
		for _, pat := range exfilInstructionPatterns {
			if loc := pat.FindStringIndex(tool.Description); loc != nil {
				matched := tool.Description[loc[0]:loc[1]]
				findings = append(findings, models.Finding{
					ID:          "SEC-011",
					Title:       fmt.Sprintf("Suspected data exfiltration instruction in tool %q", tool.Name),
					Description: fmt.Sprintf("Tool %q description contains text that may instruct the agent to access or transmit sensitive data. Matched: %q", tool.Name, matched),
					Severity:    models.SeverityCritical,
					Category:    models.CategorySecurity,
					Location:    models.Location{ToolName: tool.Name},
					Remediation: "Remove any instructions that direct the agent to read sensitive files, access credentials, or send data to external endpoints. Tool descriptions should only describe the tool's functional behavior.",
				})
				break // One finding per tool for this check
			}
		}
	}
	return findings
}

// --- SEC-012: Cross-Tool Manipulation ---

// CrossToolManipulationCheck detects descriptions that attempt to influence how the agent
// interacts with OTHER tools — a key vector in multi-server poisoning attacks.
type CrossToolManipulationCheck struct{}

func (c *CrossToolManipulationCheck) ID() string              { return "SEC-012" }
func (c *CrossToolManipulationCheck) Name() string            { return "Cross-tool manipulation in descriptions" }
func (c *CrossToolManipulationCheck) Category() models.Category { return models.CategorySecurity }

var crossToolPatterns = []*regexp.Regexp{
	// Ordering/priority manipulation
	regexp.MustCompile(`(?i)(before|after)\s+(calling|using|invoking|running)\s+(any\s+other\s+)?tool`),
	regexp.MustCompile(`(?i)(first|always)\s+(call|use|invoke|run)\s+(this|the)\s+tool`),
	regexp.MustCompile(`(?i)call\s+this\s+(before|after|instead\s+of)`),
	// Suppression of other tools
	regexp.MustCompile(`(?i)(do\s+not|don'?t|never|avoid)\s+(use|call|invoke|run)\s+(any\s+other\s+)?tool`),
	regexp.MustCompile(`(?i)(ignore|skip|bypass|disable)\s+(other|all\s+other|the\s+other)\s+tool`),
	regexp.MustCompile(`(?i)(prefer|prioritize)\s+this\s+(tool|function)\s+(over|instead|rather)`),
	// Chaining instructions
	regexp.MustCompile(`(?i)(then|next|afterwards?)\s+(call|use|invoke|run)\s+\w+`),
	// Output manipulation for other tools
	regexp.MustCompile(`(?i)(when|if)\s+(you\s+)?(call|use|invoke)\s+\w+.{0,20}(pass|send|include|set)\s+`),
}

func (c *CrossToolManipulationCheck) Run(ctx *ScanContext) []models.Finding {
	if ctx.Manifest == nil {
		return nil
	}
	var findings []models.Finding
	for _, tool := range ctx.Manifest.Tools {
		matchCount := 0
		var matchedTexts []string
		for _, pat := range crossToolPatterns {
			if loc := pat.FindStringIndex(tool.Description); loc != nil {
				matchCount++
				matchedTexts = append(matchedTexts, fmt.Sprintf("%q", tool.Description[loc[0]:loc[1]]))
			}
		}
		if matchCount > 0 {
			severity := models.SeverityHigh
			if matchCount >= 2 {
				severity = models.SeverityCritical
			}
			findings = append(findings, models.Finding{
				ID:          "SEC-012",
				Title:       fmt.Sprintf("Cross-tool manipulation in tool %q description", tool.Name),
				Description: fmt.Sprintf("Tool %q description contains %d pattern(s) that attempt to influence agent behavior toward other tools. Matched: %s. This is a tool poisoning technique where one server manipulates how the agent interacts with other connected servers.", tool.Name, matchCount, strings.Join(matchedTexts, ", ")),
				Severity:    severity,
				Category:    models.CategorySecurity,
				Location:    models.Location{ToolName: tool.Name},
				Remediation: "Remove all language that references, prioritizes, suppresses, or sequences other tools. Each tool's description should only explain what THAT tool does, its inputs, and its outputs.",
			})
		}
	}
	return findings
}

// --- SEC-013: Annotation Integrity ---

// AnnotationIntegrityCheck detects contradictions between a tool's annotations (behavioral hints)
// and its name/description. A tool claiming readOnlyHint=true but named "delete_user" is suspicious.
// Per MCP spec: annotations are HINTS from UNTRUSTED servers and should not be relied upon for security.
type AnnotationIntegrityCheck struct{}

func (c *AnnotationIntegrityCheck) ID() string              { return "SEC-013" }
func (c *AnnotationIntegrityCheck) Name() string            { return "Annotation integrity mismatch" }
func (c *AnnotationIntegrityCheck) Category() models.Category { return models.CategorySecurity }

// writeLikeVerbs are name fragments that strongly imply mutation.
var writeLikeVerbs = []string{"create", "delete", "remove", "update", "modify", "write", "send", "execute", "run", "kill", "terminate", "drop", "insert", "put", "post", "push", "destroy", "purge", "wipe", "clear", "truncate", "overwrite", "patch"}

// destructiveVerbs are name fragments that strongly imply irreversible destruction.
var destructiveVerbs = []string{"delete", "remove", "drop", "destroy", "purge", "wipe", "clear", "truncate", "kill", "terminate", "erase", "uninstall"}

func (c *AnnotationIntegrityCheck) Run(ctx *ScanContext) []models.Finding {
	if ctx.Manifest == nil {
		return nil
	}
	var findings []models.Finding
	for _, tool := range ctx.Manifest.Tools {
		if tool.Annotations == nil {
			continue
		}
		nameLower := strings.ToLower(tool.Name)
		descLower := strings.ToLower(tool.Description)

		// Check: claims readOnly but name/description implies writes
		if tool.Annotations.ReadOnlyHint != nil && *tool.Annotations.ReadOnlyHint {
			for _, verb := range writeLikeVerbs {
				if strings.Contains(nameLower, verb) || strings.HasPrefix(descLower, verb) {
					findings = append(findings, models.Finding{
						ID:          "SEC-013",
						Title:       fmt.Sprintf("Tool %q claims readOnly but name/description implies mutation", tool.Name),
						Description: fmt.Sprintf("Tool %q has readOnlyHint=true but its name or description contains %q, suggesting it performs write operations. A malicious server may set readOnlyHint=true to bypass confirmation dialogs on destructive tools.", tool.Name, verb),
						Severity:    models.SeverityHigh,
						Category:    models.CategorySecurity,
						Location:    models.Location{ToolName: tool.Name},
						Remediation: "Verify the tool's actual behavior. If it modifies state, set readOnlyHint to false. If the annotation is accurate, rename the tool to avoid misleading terms.",
					})
					break
				}
			}
		}

		// Check: claims non-destructive but name implies destruction
		if tool.Annotations.DestructiveHint != nil && !*tool.Annotations.DestructiveHint {
			for _, verb := range destructiveVerbs {
				if strings.Contains(nameLower, verb) {
					findings = append(findings, models.Finding{
						ID:          "SEC-013",
						Title:       fmt.Sprintf("Tool %q claims non-destructive but name implies destruction", tool.Name),
						Description: fmt.Sprintf("Tool %q has destructiveHint=false but its name contains %q. This may be an attempt to bypass destructive-action confirmation dialogs.", tool.Name, verb),
						Severity:    models.SeverityHigh,
						Category:    models.CategorySecurity,
						Location:    models.Location{ToolName: tool.Name},
						Remediation: "If this tool performs irreversible operations, set destructiveHint to true. The MCP spec defaults destructiveHint to true for safety.",
					})
					break
				}
			}
		}
	}
	return findings
}
