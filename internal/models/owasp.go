package models

// OWASP MCP Top 10 (MCP01:2025 through MCP10:2025).
// The official framework for Model Context Protocol security risks.
// Reference: https://owasp.org/www-project-mcp-top-10/

// OWASPCategory holds an OWASP MCP Top 10 entry.
type OWASPCategory struct {
	ID    string // e.g. "MCP05:2025"
	Title string // e.g. "Command Injection & Execution"
}

// OWASPCategories maps each OWASP MCP Top 10 ID to its title.
var OWASPCategories = map[string]string{
	"MCP01:2025": "Token Mismanagement & Secret Exposure",
	"MCP02:2025": "Privilege Escalation via Scope Creep",
	"MCP03:2025": "Tool Poisoning",
	"MCP04:2025": "Software Supply Chain Attacks & Dependency Tampering",
	"MCP05:2025": "Command Injection & Execution",
	"MCP06:2025": "Intent Flow Subversion",
	"MCP07:2025": "Insufficient Authentication & Authorization",
	"MCP08:2025": "Lack of Audit and Telemetry",
	"MCP09:2025": "Shadow MCP Servers",
	"MCP10:2025": "Context Injection & Over-Sharing",
}

// checkToOWASP maps each MCPSense check ID to its primary OWASP MCP Top 10 category.
// Spec-compliance (SPEC-*) and tool-quality (QUAL-*) checks are intentionally NOT
// mapped, because they are not OWASP security risk categories. They will have an
// empty OWASP field, which is correct and honest.
var checkToOWASP = map[string]string{
	// Security checks
	"SEC-001": "MCP03:2025", // Prompt injection in tool descriptions -> Tool Poisoning
	"SEC-002": "MCP05:2025", // Shell command execution -> Command Injection & Execution
	"SEC-003": "MCP05:2025", // SSRF risk -> Command Injection & Execution
	"SEC-004": "MCP05:2025", // Path traversal -> Command Injection & Execution
	"SEC-005": "MCP07:2025", // Missing authentication -> Insufficient Auth & Authz
	"SEC-006": "MCP07:2025", // Overly permissive resource access -> Insufficient Auth & Authz
	"SEC-007": "MCP05:2025", // Command injection via interpolation -> Command Injection & Execution
	"SEC-008": "MCP10:2025", // Data exfiltration vectors -> Context Injection & Over-Sharing

	// Tool poisoning checks
	"SEC-009": "MCP03:2025", // Invisible Unicode / ASCII smuggling -> Tool Poisoning
	"SEC-010": "MCP03:2025", // Homoglyph / mixed script -> Tool Poisoning
	"SEC-011": "MCP06:2025", // Data exfiltration instructions -> Intent Flow Subversion
	"SEC-012": "MCP03:2025", // Cross-tool manipulation -> Tool Poisoning
	"SEC-013": "MCP03:2025", // Annotation integrity mismatch -> Tool Poisoning

	// Client config checks
	"SEC-014": "MCP05:2025", // Config command injection -> Command Injection & Execution
	"SEC-015": "MCP01:2025", // Sensitive env var leakage -> Token Mismanagement & Secret Exposure
	"SEC-016": "MCP04:2025", // Unverified server source -> Software Supply Chain Attacks
}

// OWASPForCheckID returns the OWASP MCP Top 10 ID for a given check ID,
// or an empty string if the check does not map to an OWASP category.
func OWASPForCheckID(checkID string) string {
	return checkToOWASP[checkID]
}

// OWASPTitle returns the human-readable title for an OWASP MCP Top 10 ID,
// or an empty string if the ID is unknown.
func OWASPTitle(owaspID string) string {
	return OWASPCategories[owaspID]
}
