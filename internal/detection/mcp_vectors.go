package detection

import "github.com/fayzkk889/MCPSense/internal/models"

// loadMCPPatterns registers MCP-specific attack vector patterns.
func (e *PatternEngine) loadMCPPatterns() {
	e.patterns = append(e.patterns, mcpSpecificPatterns()...)
}

func mcpSpecificPatterns() []Pattern {
	return []Pattern{
		// MCP-001: Tool description injection (directive language)
		compilePattern(
			"MCP-001",
			"Tool Description Directive Injection",
			`(always\s+(use|call|invoke|run)\s+this\s+tool|use\s+this\s+tool\s+(first|before|instead)|ignore\s+(other|all\s+other)\s+tools?|call\s+this\s+(before|after)\s+any)`,
			models.SeverityCritical,
			"Tool description contains directive language that attempts to manipulate agent behavior, such as prioritizing this tool over others.",
			"mcp-injection",
			"Remove directive language from tool descriptions. Descriptions should explain what the tool does, not instruct the agent on when or how to use it relative to other tools.",
		),

		// MCP-002: Path traversal in resource URIs or string values
		compilePattern(
			"MCP-002",
			"Path Traversal Pattern",
			`(\.\.\/|\.\.\\|%2e%2e%2f|%252e%252e|\.\.%2f|%2e%2e\/|file:///[^"'\s]*\.\.[^"'\s]*)`,
			models.SeverityHigh,
			"Content contains path traversal sequences that could allow access to files outside the intended directory.",
			"path-traversal",
			"Validate and sanitize all file paths. Use filepath.Clean() and verify the result is within the allowed base directory before any file operation.",
		),

		// MCP-003: Shell command execution patterns (Go)
		// Pattern runs against lowercased content, so uses lowercase identifiers.
		compilePattern(
			"MCP-003",
			"Shell Command Execution via exec.Command",
			`exec\.command\s*\(\s*"(sh|bash|cmd|powershell|zsh|fish)"`,
			models.SeverityCritical,
			"Source code invokes a shell interpreter via exec.Command, which can allow arbitrary command execution if inputs are not sanitized.",
			"command-exec",
			"Avoid spawning shell interpreters. Use exec.Command with explicit argument lists instead of shell -c. Never pass user input as part of a shell command string.",
		),

		// MCP-004: Shell command execution via string formatting (Go)
		compilePattern(
			"MCP-004",
			"User Input Interpolated into Shell Command",
			`exec\.command\s*\([^)]*fmt\.(sprintf|sprintf)\s*\(`,
			models.SeverityCritical,
			"User input is interpolated into an exec.Command call using fmt.Sprintf, enabling command injection.",
			"command-exec",
			"Never use string formatting to build command arguments. Pass arguments as separate strings to exec.Command.",
		),

		// MCP-005: Python subprocess with shell=True
		compilePattern(
			"MCP-005",
			"Python subprocess with shell=True",
			`subprocess\.(run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True`,
			models.SeverityCritical,
			"Python subprocess call uses shell=True, which enables shell injection if user input is included.",
			"command-exec",
			"Remove shell=True and pass command arguments as a list. Never interpolate user input into shell command strings.",
		),

		// MCP-006: Python os.system
		compilePattern(
			"MCP-006",
			"Python os.system Call",
			`os\.system\s*\(`,
			models.SeverityHigh,
			"Python os.system is used, which invokes a shell and is vulnerable to command injection.",
			"command-exec",
			"Replace os.system with subprocess.run using a list of arguments and shell=False.",
		),

		// MCP-007: Node.js child_process exec
		compilePattern(
			"MCP-007",
			"Node.js child_process.exec",
			`(child_process\.exec|require\s*\(\s*['\"]child_process['\"]\s*\)\s*\.\s*exec)\s*\(`,
			models.SeverityHigh,
			"Node.js child_process.exec is used, which invokes a shell and is vulnerable to command injection.",
			"command-exec",
			"Replace child_process.exec with child_process.execFile or child_process.spawn with an explicit argument array.",
		),

		// MCP-008: SSRF via unchecked URL input (patterns match lowercased content)
		compilePattern(
			"MCP-008",
			"Unchecked HTTP Request from Variable",
			`(http\.get\s*\(\s*[^"')\s]+\s*\)|fetch\s*\(\s*[^"')\s]+\s*\)|requests\.(get|post|put|delete)\s*\(\s*[^"')\s]+\s*\))`,
			models.SeverityHigh,
			"An HTTP request is made using a variable URL without apparent domain validation, creating a Server-Side Request Forgery risk.",
			"ssrf",
			"Validate URLs against an allowlist of permitted domains before making outbound requests. Reject requests to private IP ranges and internal hostnames.",
		),

		// MCP-009: Overly broad resource URI glob
		compilePattern(
			"MCP-009",
			"Overly Broad Resource URI Pattern",
			`"uri"\s*:\s*"(file:///\*|/\*\*|\*\*|/\*|file:///[^"]*\*[^"]*)"`,
			models.SeverityHigh,
			"Resource URI pattern uses a wildcard that grants access to an excessively broad set of files or paths.",
			"resource-scope",
			"Restrict resource URIs to the minimum required scope. Use explicit paths rather than wildcards, or constrain wildcards to specific subdirectories.",
		),

		// MCP-010: String fields in inline JSON schema definitions (heuristic)
		// Note: Go's RE2 does not support lookaheads. This pattern detects string type
		// declarations in schema JSON without maxLength on the same logical property.
		// Full constraint checking is handled by the InputConstraintCheck (QUAL-007).
		compilePattern(
			"MCP-010",
			"Unconstrained String Field in Inline Schema",
			`"type"\s*:\s*"string"\s*\}`,
			models.SeverityLow,
			"A string input field in an inline schema definition may lack a maxLength constraint.",
			"input-validation",
			"Add maxLength to all string input schema properties to prevent excessively large inputs and potential denial-of-service conditions.",
		),

		// MCP-011: SQL query string construction (patterns match lowercased content)
		compilePattern(
			"MCP-011",
			"SQL String Interpolation",
			`(fmt\.sprintf\s*\(\s*"[^"]*select[^"]*%[sv]|"select[^"]*"\s*\+\s*\w+|f"select[^"]*\{|`+"`"+`select[^`+"`"+`]*\$\{)`,
			models.SeverityCritical,
			"User input appears to be interpolated directly into a SQL query string, enabling SQL injection.",
			"sql-injection",
			"Use parameterized queries or prepared statements. Never concatenate or format user input into SQL strings.",
		),

		// MCP-012: Hardcoded secrets
		compilePattern(
			"MCP-012",
			"Hardcoded Secret or API Key",
			`(api_key|apikey|api-key|secret|password|passwd|token|bearer)\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']`,
			models.SeverityHigh,
			"A hardcoded secret, API key, or password was found in the source code.",
			"secrets",
			"Remove hardcoded secrets from source code. Use environment variables or a secrets manager. Rotate any exposed credentials immediately.",
		),
	}
}
